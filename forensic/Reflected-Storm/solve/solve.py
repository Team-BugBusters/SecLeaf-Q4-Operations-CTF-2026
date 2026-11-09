#!/usr/bin/env python3
"""Reflected Storm (SecLeaf CTF 2026, Forensics) - solver.

Finds the victim of a DNS reflection/amplification attack in
reflected-storm.pcap and counts the reflectors:

  * victim     = the host receiving the most UDP packets with source port 53
  * reflectors = the distinct sources of those packets
  * amplification = avg response size vs avg (spoofed) query size

Flag: FLOWTRIQ{<victim_ip>_<reflector_count>_reflectors}

Usage:  python3 solve.py [path/to/reflected-storm.pcap]
Needs the original capture in ../attachments/.
Stdlib only.
"""
import socket
import struct
import sys
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
PCAP = HERE.parent / "attachments" / "reflected-storm.pcap"

# ---------------------------------------------------------------------------
# Minimal stdlib packet reader: classic pcap (us/ns, either endianness) and
# pcapng (EPB/SPB), Ethernet / VLAN / Linux SLL / raw IP / BSD loopback,
# IPv4 + UDP/TCP/ICMP headers, DNS question section.
# ---------------------------------------------------------------------------

def _pcapng(data: bytes):
    off, e, links, idx = 0, "<", [], 0
    while off + 12 <= len(data):
        if data[off:off + 4] == b"\x0a\x0d\x0d\x0a":          # section header
            e = "<" if data[off + 8:off + 12] == b"\x4d\x3c\x2b\x1a" else ">"
            links = []
        btype, blen = struct.unpack(e + "II", data[off:off + 8])
        if blen < 12:
            break
        body = data[off + 8:off + blen - 4]
        if btype == 1:                                          # interface description
            links.append(struct.unpack(e + "H", body[:2])[0])
        elif btype == 6:                                        # enhanced packet
            iface, hi, lo, cap, _orig = struct.unpack(e + "IIIII", body[:20])
            idx += 1
            yield idx, ((hi << 32) | lo) / 1e6, links[iface], body[20:20 + cap]
        elif btype == 3:                                        # simple packet
            idx += 1
            yield idx, 0.0, links[0], body[4:]
        off += blen


def read_frames(path: Path):
    """Yield (frame_number, timestamp, linktype, frame_bytes); frames are 1-based like Wireshark."""
    data = path.read_bytes()
    magic = data[:4]
    if magic == b"\x0a\x0d\x0d\x0a":
        yield from _pcapng(data)
        return
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        e = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        e = ">"
    else:
        sys.exit(f"[-] {path.name}: not a pcap/pcapng file")
    div = 1e9 if magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d") else 1e6
    linktype = struct.unpack(e + "I", data[20:24])[0] & 0xFFFF
    off, idx = 24, 0
    while off + 16 <= len(data):
        sec, frac, incl, _orig = struct.unpack(e + "IIII", data[off:off + 16])
        off += 16
        idx += 1
        yield idx, sec + frac / div, linktype, data[off:off + incl]
        off += incl


def parse_ipv4(linktype: int, frame: bytes):
    """Return a dict describing the IPv4 packet in this frame, or None."""
    if linktype == 1:                                           # Ethernet (+ VLAN tags)
        off, et = 14, struct.unpack("!H", frame[12:14])[0]
        while et in (0x8100, 0x88A8) and len(frame) >= off + 4:
            et = struct.unpack("!H", frame[off + 2:off + 4])[0]
            off += 4
        if et != 0x0800:
            return None
        pkt = frame[off:]
    elif linktype == 113:                                       # Linux cooked capture
        if struct.unpack("!H", frame[14:16])[0] != 0x0800:
            return None
        pkt = frame[16:]
    elif linktype in (12, 101, 228):                            # raw IP
        pkt = frame
    elif linktype == 0:                                         # BSD loopback
        pkt = frame[4:]
    else:
        return None
    if len(pkt) < 20 or pkt[0] >> 4 != 4:
        return None
    ihl = (pkt[0] & 0x0F) * 4
    total = struct.unpack("!H", pkt[2:4])[0] or len(pkt)
    ip = {
        "src": socket.inet_ntoa(pkt[12:16]),
        "dst": socket.inet_ntoa(pkt[16:20]),
        "proto": pkt[9],
        "frame_len": len(frame),
        "sport": None, "dport": None, "flags": None, "icmp_type": None, "data": b"",
    }
    l4 = pkt[ihl:total]
    if ip["proto"] == 17 and len(l4) >= 8:                      # UDP
        ip["sport"], ip["dport"] = struct.unpack("!HH", l4[:4])
        ip["data"] = l4[8:]
    elif ip["proto"] == 6 and len(l4) >= 20:                    # TCP
        ip["sport"], ip["dport"], ip["seq"] = struct.unpack("!HHI", l4[:8])
        ip["flags"] = l4[13]
        ip["data"] = l4[(l4[12] >> 4) * 4:]
    elif ip["proto"] == 1 and len(l4) >= 4:                     # ICMP
        ip["icmp_type"] = l4[0]
    return ip


def parse_dns(payload: bytes):
    """Return (is_response, [(qname, qtype), ...]) for a DNS message, or None."""
    if len(payload) < 12:
        return None
    flags, qdcount = struct.unpack("!HH", payload[2:6])
    off, questions = 12, []
    for _ in range(qdcount):
        labels, jumped, pos, end = [], False, off, off
        for _guard in range(128):
            if pos >= len(payload):
                return None
            ln = payload[pos]
            if ln == 0:
                pos += 1
                break
            if ln & 0xC0 == 0xC0:                               # compression pointer
                if not jumped:
                    end = pos + 2
                jumped = True
                pos = ((ln & 0x3F) << 8) | payload[pos + 1]
                continue
            labels.append(payload[pos + 1:pos + 1 + ln].decode("latin-1"))
            pos += 1 + ln
        off = end if jumped else pos
        if off + 4 > len(payload):
            return None
        qtype = struct.unpack("!H", payload[off:off + 2])[0]
        off += 4
        questions.append((".".join(labels), qtype))
    return bool(flags & 0x8000), questions
# ---------------------------------------------------------------------------

def main() -> None:
    pcap = Path(sys.argv[1]) if len(sys.argv) > 1 else PCAP
    if not pcap.exists():
        sys.exit(f"[-] {pcap} not found. Place reflected-storm.pcap in attachments/ to run.")

    responses = defaultdict(Counter)          # dst -> Counter(src)
    resp_sizes = defaultdict(list)            # dst -> frame lengths
    query_sizes = defaultdict(list)           # claimed src -> frame lengths
    udp_dst = Counter()

    for _n, _ts, link, frame in read_frames(pcap):
        ip = parse_ipv4(link, frame)
        if ip is None or ip["proto"] != 17:
            continue
        udp_dst[ip["dst"]] += 1
        if ip["sport"] == 53:
            responses[ip["dst"]][ip["src"]] += 1
            resp_sizes[ip["dst"]].append(ip["frame_len"])
        elif ip["dport"] == 53:
            query_sizes[ip["src"]].append(ip["frame_len"])

    print(f"[*] top UDP destinations: {udp_dst.most_common(3)}")
    victim = max(responses, key=lambda d: sum(responses[d].values()))
    reflectors = responses[victim]
    total = sum(reflectors.values())
    print(f"[*] victim {victim}: {total} UDP packets from source port 53")
    print("[*] reflectors:")
    for src, n in reflectors.most_common():
        print(f"    {src:<16} {n}")

    rs = resp_sizes[victim]
    qs = query_sizes.get(victim, [])
    print(f"[*] avg response frame to victim: {sum(rs) / len(rs):.0f} bytes")
    if qs:
        print(f"[*] avg query frame 'from' victim (spoofed): {sum(qs) / len(qs):.0f} bytes "
              f"-> amplification ~{(sum(rs) / len(rs)) / (sum(qs) / len(qs)):.1f}x")

    print(f"[+] FLAG: FLOWTRIQ{{{victim}_{len(reflectors)}_reflectors}}")


if __name__ == "__main__":
    main()
