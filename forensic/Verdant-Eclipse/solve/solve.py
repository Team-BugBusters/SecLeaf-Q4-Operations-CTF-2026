#!/usr/bin/env python3
"""
Verdant Eclipse (SecLeaf CTF 2026) - offline solver.

The values below were transcribed from verdant_eclipse.pcap during the solve and are
embedded as constants. If ../attachments/verdant_eclipse.pcap is present (or a path is
passed as the first argument) the script also carves the DNS labels and UDP chunks
from the capture and requires them to match:
  * three DNS query labels from 10.55.10.15 -> Base64 fragments of the XOR key
  * ten `channel=leafsync` UDP chunks from 10.55.10.27 -> 198.51.100.77:6060
Chain: join DNS fragments -> Base64 -> key; join chunks by seq -> hex ->
repeating-key XOR -> Base64 -> flag.
"""
import base64
import re
import struct
import sys
from pathlib import Path

PCAP = Path(__file__).resolve().parent.parent / "attachments" / "verdant_eclipse.pcap"

DNS_QUERIES = [
    "01.Zm9s.alpha.verdant-lab.local",
    "02.aWFn.alpha.verdant-lab.local",
    "03.ZQ==.alpha.verdant-lab.local",
]

LEAFSYNC = {  # seq -> chunk
    1: "335d3a033520",
    2: "330e35021d15",
    3: "03321e5f0d31",
    4: "2f573c310b00",
    5: "315352090227",
    6: "081f020a1100",
    7: "350150183d32",
    8: "53150d3e2f1d",
    9: "3d545e040a52",
    10: "350905010050",
}


def carve(pcap: Path):
    """Classic little-endian pcap, Ethernet/IPv4/UDP only (all this capture needs)."""
    data = pcap.read_bytes()
    assert data[:4] == b"\xd4\xc3\xb2\xa1", "expected a little-endian microsecond pcap"
    off, dns, chunks = 24, [], {}
    while off + 16 <= len(data):
        incl = struct.unpack("<I", data[off + 8:off + 12])[0]
        frame, off = data[off + 16:off + 16 + incl], off + 16 + incl
        if frame[12:14] != b"\x08\x00" or frame[23] != 17:
            continue
        ihl = (frame[14] & 0x0F) * 4
        src = ".".join(map(str, frame[26:30]))
        dst = ".".join(map(str, frame[30:34]))
        udp = frame[14 + ihl:]
        dport, payload = struct.unpack("!H", udp[2:4])[0], udp[8:]
        if dport == 53 and src == "10.55.10.15" and not payload[2] & 0x80:
            name, pos = [], 12
            while payload[pos]:
                name.append(payload[pos + 1:pos + 1 + payload[pos]].decode())
                pos += 1 + payload[pos]
            if "alpha" in name:
                dns.append(".".join(name))
        elif dst == "198.51.100.77":
            m = re.match(rb"channel=leafsync;source=\S+?;seq=(\d+);chunk=([0-9a-f]+);", payload)
            if m:
                chunks[int(m.group(1))] = m.group(2).decode()
    return dns, chunks


def main() -> None:
    labels = sorted((q.split(".")[0], q.split(".")[1]) for q in DNS_QUERIES)
    b64_key = "".join(frag for _, frag in labels)
    key = base64.b64decode(b64_key)
    print(f"[*] DNS fragments joined: {b64_key}")
    print(f"[*] XOR key: {key.decode()}")

    ct = bytes.fromhex("".join(LEAFSYNC[i] for i in sorted(LEAFSYNC)))
    print(f"[*] leafsync ciphertext: {len(ct)} bytes")
    inner = bytes(b ^ key[i % len(key)] for i, b in enumerate(ct))
    print(f"[*] After XOR: {inner.decode()}")

    flag = base64.b64decode(inner).decode()

    pcap = Path(sys.argv[1]) if len(sys.argv) > 1 else PCAP
    if pcap.exists():
        dns, chunks = carve(pcap)
        assert dns == DNS_QUERIES, f"DNS labels differ from the writeup: {dns}"
        assert chunks == LEAFSYNC, "UDP chunks differ from the writeup"
        print(f"[*] {pcap.name}: DNS labels and {len(chunks)} leafsync chunks match the writeup")
    else:
        print(f"[*] ({pcap.name} not present - skipped the capture cross-check)")
    print(f"[+] FLAG: {flag}")


if __name__ == "__main__":
    main()
