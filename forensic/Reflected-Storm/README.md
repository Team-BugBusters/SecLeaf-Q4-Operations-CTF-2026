# Reflected Storm

![Event](https://img.shields.io/badge/SecLeaf_CTF-2026-101518?style=flat-square)
![Category](https://img.shields.io/badge/Category-Forensics-B4441F?style=flat-square)
![Points](https://img.shields.io/badge/Points-100-2F5D3A?style=flat-square)

> **Solved by** [Vaidik](https://github.com/Vaidik-Makhasana) · **Team** Bug Busters · **Solved** 31 October 2026, 3:39 pm

## Challenge description

> A network operator noticed their monitoring dashboard lighting up. Bandwidth on one server spiked without explanation, and by the time they pulled a packet capture, the attack was already underway. Your job: open the capture, identify the victim being hammered by amplified traffic, and figure out how many reflectors the attacker abused to do it.

**Flag format:** `FLOWTRIQ{<victim_ip>_<reflector_count>_reflectors}` (example given in the brief: `FLOWTRIQ{192.168.1.1_3_reflectors}`)

**Attachments:** [`reflected-storm.pcap`](attachments/reflected-storm.pcap)

## Flag

```text
FLOWTRIQ{10.0.55.200_5_reflectors}
```

## Writeup

Read the full solve: **[writeup.md](writeup.md)**

**In one line:** in a reflection attack the victim *receives* the answers to queries it never really sent, so count the distinct DNS servers (source port 53) sending large responses to one host.

- Victim `10.0.55.200` received 600 UDP packets, all from source port 53 (DNS).
- Spoofed queries are ~75 bytes; the responses hitting the victim are ~1,014 bytes: roughly 13x amplification.
- Exactly five distinct reflectors sent those 600 responses (133 + 120 + 119 + 118 + 110).

## Files

| Path | What it is |
| --- | --- |
| [`writeup.md`](writeup.md) | Full solve |
| [`solve/solve.py`](solve/solve.py) | Stdlib pcap parser: finds the victim of the port-53 traffic, lists and counts reflectors, prints sizes and the flag |

## Run the solver

```bash
cd solve
python3 solve.py
```

Expected output ends with:

```text
[+] FLAG: FLOWTRIQ{10.0.55.200_5_reflectors}
```

## Notes

- Verified on the original `reflected-storm.pcap`. No third-party packages are needed.
- `FLOWTRIQ{192.168.1.1_3_reflectors}` is the brief's **format example**, not an answer: the victim is `10.0.55.200`, not `192.168.1.1`, and the capture shows five reflectors, not three.
- The flag-format line in our source notes lost its count placeholder in the document conversion (`FLOWTRIQ{<victim_ip>__reflectors}`); the format above is rebuilt from the brief's example.

---

[← Back to Forensics](../README.md) · [All writeups](../../README.md)
