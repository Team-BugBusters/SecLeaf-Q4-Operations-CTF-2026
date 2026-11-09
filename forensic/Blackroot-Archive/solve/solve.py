#!/usr/bin/env python3
"""Blackroot Archive (SecLeaf CTF 2026, Forensics) - solver.

Three protocols, three pieces:
  HTTP  GET /exports/ledger-sync.manifest -> encoding=base64,
        key_source=mail:archive-notice, next_service=tcp/4711
  SMTP  archive-notice@ -> operations@    -> "Recovery key: rootleaf"
  TCP/4711 to 198.51.100.144              -> hex chunks
Decode: concat hex -> bytes -> repeating-key XOR with the key -> Base64 -> flag.

Decodes the hex chunks and key quoted in the writeup, then (if
../attachments/blackroot_archive.pcap is present, or a path is given) carves the
key and the TCP/4711 `blob=` records from the capture and requires they agree.
Stdlib only.
"""
import base64
import re
import socket
import struct
import sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
PCAP = HERE.parent / "attachments" / "blackroot_archive.pcap"

# Values quoted verbatim in the writeup.
KEY = b"rootleaf"
HEX_CHUNKS = [
    "275d391e382237",
    "0e28011b18092d",
    "231011013d1836",
    "2358102b021f18",
    "3556331c2a5c25",
    "180808370e1029",
    "56440d2237002b",
    "37251e0d220d54",
    "28395606363d0d",
    "5f",
]

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

def tcp_streams(pcap: Path):
    """Reassemble TCP payload per direction, ordered by sequence number."""
    segs = defaultdict(dict)
    for _n, _ts, link, frame in read_frames(pcap):
        ip = parse_ipv4(link, frame)
        if ip is None or ip["proto"] != 6 or not ip["data"]:
            continue
        key = (ip["src"], ip["sport"], ip["dst"], ip["dport"])
        segs[key].setdefault(ip["seq"], ip["data"])          # drop retransmissions
    return {k: b"".join(v[s] for s in sorted(v)) for k, v in segs.items()}


def from_pcap(pcap: Path):
    streams = tcp_streams(pcap)
    key, chunks = None, []
    for (src, sport, dst, dport), data in sorted(streams.items(), key=lambda kv: str(kv[0])):
        text = data.decode("latin-1")
        if text.startswith("GET ") and "ledger-sync.manifest" in text:
            print(f"[*] HTTP {src} -> {dst}: {text.splitlines()[0]}")
        if text.startswith("HTTP/"):
            body = text.split("\r\n\r\n", 1)[-1].strip()
            try:
                manifest = base64.b64decode(body, validate=True).decode()
            except ValueError:
                manifest = body
            if "next_service" in manifest:
                print(f"[*] HTTP {src} -> {dst}: manifest\n      "
                      + manifest.strip().replace("\n", "\n      "))
        m = re.search(r"Recovery key:\s*(\S+)", text)
        if m and 25 in (sport, dport):
            key = m.group(1).encode()
            print(f"[*] SMTP {src} -> {dst}: recovery key {key.decode()!r}")
        if dport == 4711 and "blob=" in text:
            # stream lines look like: record=01;blob=275d391e382237;state=ready
            recs = re.findall(r"record=(\d+);blob=([0-9a-fA-F]+);state=ready", text)
            found = [blob for _num, blob in sorted(recs, key=lambda r: int(r[0]))]
            if found:
                print(f"[*] TCP/4711 {src}:{sport} -> {dst}:{dport}: {len(found)} ready records")
                chunks.extend(found)
    return key, chunks


def decode(key: bytes, chunks: list[str]) -> str:
    blob = bytes.fromhex("".join(chunks))
    print(f"[*] {len(blob)} ciphertext bytes, key {key.decode()!r}")
    xored = bytes(b ^ key[i % len(key)] for i, b in enumerate(blob))
    print(f"[*] after repeating-key XOR: {xored.decode()}")
    flag = base64.b64decode(xored).decode()
    print(f"[*] after Base64 decode:     {flag}")
    return flag


def main() -> None:
    pcap = Path(sys.argv[1]) if len(sys.argv) > 1 else PCAP
    print("[*] decoding the chunks quoted in the writeup")
    flag = decode(KEY, HEX_CHUNKS)

    if pcap.exists():
        print(f"\n[*] cross-checking against {pcap.name}")
        key, chunks = from_pcap(pcap)
        if key is None or not chunks:
            sys.exit("[-] could not carve key/chunks from the capture")
        if decode(key, chunks) != flag:
            sys.exit("[-] capture disagrees with the writeup values")
        print("[*] capture agrees with the writeup values")
    else:
        print(f"[*] ({pcap.name} not present - skipped the capture cross-check)")

    print(f"[+] FLAG: {flag}")


if __name__ == "__main__":
    main()
