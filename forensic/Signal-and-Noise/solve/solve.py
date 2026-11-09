#!/usr/bin/env python3
"""Signal & Noise (SecLeaf CTF 2026, Forensics) - solver.

Splits signal-and-noise.pcap into its three apparent attack vectors and
correlates their source addresses:

  * ICMP Echo Requests flooding the victim
  * TCP SYNs to the victim on 443
  * DNS ANY queries (the trigger side of a DNS amplification)

The pivot is the one IP that shows up in two different vectors; the decoy is
the vector the pivot never touches.  Flag: FLOWTRIQ{decoy_<vector>_pivot_<ip>}.

Usage:  python3 solve.py [path/to/signal-and-noise.pcap]
Needs the original capture in ../attachments/.
Stdlib only.
"""
import socket
import struct
import sys
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
PCAP = HERE.parent / "attachments" / "signal-and-noise.pcap"

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

DNS_ANY = 255


def main() -> None:
    pcap = Path(sys.argv[1]) if len(sys.argv) > 1 else PCAP
    if not pcap.exists():
        sys.exit(f"[-] {pcap} not found. Place signal-and-noise.pcap in attachments/ to run.")

    first_ts = last_ts = None
    icmp_dst = Counter()
    icmp_src = defaultdict(set)              # victim -> sources
    icmp_ts = defaultdict(list)
    syn = defaultdict(set)                   # (dst, dport) -> sources
    syn_count = Counter()
    any_queries = []                         # (src, dst, qname)
    dns_resp_to = defaultdict(list)          # dst -> frame lengths

    for _n, ts, link, frame in read_frames(pcap):
        first_ts = ts if first_ts is None else first_ts
        last_ts = ts
        ip = parse_ipv4(link, frame)
        if ip is None:
            continue
        if ip["proto"] == 1 and ip["icmp_type"] == 8:                    # echo request
            icmp_dst[ip["dst"]] += 1
            icmp_src[ip["dst"]].add(ip["src"])
            icmp_ts[ip["dst"]].append(ts)
        elif ip["proto"] == 6 and ip["flags"] & 0x12 == 0x02:            # SYN, not SYN/ACK
            syn[(ip["dst"], ip["dport"])].add(ip["src"])
            syn_count[(ip["dst"], ip["dport"])] += 1
        elif ip["proto"] == 17 and 53 in (ip["sport"], ip["dport"]):
            dns = parse_dns(ip["data"])
            if dns is None:
                continue
            is_resp, questions = dns
            if is_resp:
                dns_resp_to[ip["dst"]].append(ip["frame_len"])
            else:
                for qname, qtype in questions:
                    if qtype == DNS_ANY:
                        any_queries.append((ip["src"], ip["dst"], qname))

    print(f"[*] capture span: {last_ts - first_ts:.1f} s")

    # Vector 1 - ICMP flood (the loudest thing in the capture)
    victim, n_icmp = icmp_dst.most_common(1)[0]
    span = max(icmp_ts[victim]) - min(icmp_ts[victim])
    print(f"[*] ICMP echo requests -> {victim}: {n_icmp} packets, "
          f"{len(icmp_src[victim])} sources, over {span:.1f} s")

    # Vector 2 - SYN flood on the victim
    (syn_dst, syn_port), n_syn = max(
        ((k, v) for k, v in syn_count.items() if k[0] == victim), key=lambda kv: kv[1])
    syn_sources = syn[(syn_dst, syn_port)]
    print(f"[*] TCP SYN -> {syn_dst}:{syn_port}: {n_syn} packets, {len(syn_sources)} sources")

    # Vector 3 - DNS ANY queries + the amplified answers landing on the victim
    any_sources = Counter(src for src, _dst, _q in any_queries)
    print(f"[*] DNS ANY queries: {len(any_queries)} from {dict(any_sources)}")
    for src in any_sources:
        servers = sorted({d for s, d, _q in any_queries if s == src})
        names = sorted({q for s, _d, q in any_queries if s == src})
        print(f"    {src} asked {names} via {len(servers)} resolvers: {servers}")
    resp = dns_resp_to.get(victim, [])
    if resp:
        print(f"[*] DNS responses -> {victim}: {len(resp)} "
              f"(avg frame {sum(resp) / len(resp):.0f} bytes)")

    # The pivot "reappears orchestrating a second vector": it is one of the
    # DNS ANY senders (the orchestration side) and also a source in a flood.
    floods = {"icmp": icmp_src[victim], "syn": syn_sources}
    for name, sources in floods.items():
        print(f"[*] {name} sources that also sent DNS ANY: {sorted(sources & set(any_sources))}")
    candidates = set(any_sources) & set().union(*floods.values())
    if len(candidates) != 1:
        sys.exit(f"[-] expected exactly one pivot IP, got {sorted(candidates)}")
    pivot = candidates.pop()

    untouched = [name for name, sources in floods.items() if pivot not in sources]
    print(f"[*] pivot {pivot}; flood vector(s) it never appears in: {untouched}")
    if len(untouched) != 1:
        sys.exit("[-] could not single out the decoy vector")
    decoy = untouched[0]

    print(f"[+] FLAG: FLOWTRIQ{{decoy_{decoy}_pivot_{pivot}}}")


if __name__ == "__main__":
    main()
