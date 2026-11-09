# Signal & Noise

![Event](https://img.shields.io/badge/SecLeaf_CTF-2026-101518?style=flat-square)
![Category](https://img.shields.io/badge/Category-Forensics-B4441F?style=flat-square)
![Points](https://img.shields.io/badge/Points-300-2F5D3A?style=flat-square)

> **Solved by** [Vaidik](https://github.com/Vaidik-Makhasana) · **Team** Bug Busters · **Solved** 31 October 2026, 3:52 pm

## Challenge description

> An infrastructure team is under a multi-vector DDoS attack. They pulled a two-minute capture and handed it to you, but the traffic is messy. At least one of the apparent attack vectors is a decoy designed to waste your time. Your objectives:
>
> - Identify which traffic pattern is the decoy (the vector that looks hostile but is not the real threat).
> - Find the pivot: the single IP address that appears in one attack vector and then reappears orchestrating a second, different vector.

**Flag format:** `FLOWTRIQ{decoy_<vector>_pivot_<pivot_ip>}` (example given in the brief: `FLOWTRIQ{decoy_ntp_pivot_192.168.1.1}`)

**Attachments:** [`signal-and-noise.pcap`](attachments/signal-and-noise.pcap)

## Flag

```text
FLOWTRIQ{decoy_icmp_pivot_172.16.80.99}
```

## Writeup

Read the full solve: **[writeup.md](writeup.md)**

**In one line:** the loudest vector (an 800-packet ICMP flood) is the decoy; the real story is the one host, `172.16.80.99`, that sits in the TCP SYN flood *and* drives the DNS ANY amplification.

- Three apparent vectors against victim `10.0.88.10`: ICMP echo flood, TCP SYN flood on 443, DNS ANY amplification.
- ICMP: 800 echo requests from 50 sources in `10.99.0.0/24`, the biggest and most obvious pattern.
- TCP: 560 SYNs to port 443 from 44 sources, one of which is `172.16.80.99`.
- DNS: `172.16.80.99` sent 31 `ANY` queries for `big-record.example.org` to four resolvers; 350 large (~714-byte) DNS responses landed on the victim.

## Files

| Path | What it is |
| --- | --- |
| [`writeup.md`](writeup.md) | Full solve |
| [`solve/solve.py`](solve/solve.py) | Stdlib pcap parser: splits the capture into the three vectors, finds the IP shared between them, prints the flag |

## Run the solver

```bash
cd solve
python3 solve.py
```

Expected output ends with:

```text
[+] FLAG: FLOWTRIQ{decoy_icmp_pivot_172.16.80.99}
```

## Notes

- Verified on the original `signal-and-noise.pcap`. No third-party packages are needed: classic pcap and pcapng are both parsed with `struct`.
- `FLOWTRIQ{decoy_ntp_pivot_192.168.1.1}` is the **format example** from the brief, not an answer: there is no NTP traffic in the capture (only ICMP, TCP and DNS), and `192.168.1.1` is not one of the hosts involved.
- The flag-format line in our source notes lost its placeholders in the document conversion (`FLOWTRIQ{decoy_pivot<pivot_ip>}`); the format above is rebuilt from the brief's own example.

---

[← Back to Forensics](../README.md) · [All writeups](../../README.md)
