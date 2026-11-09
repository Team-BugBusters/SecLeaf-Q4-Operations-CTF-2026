# Blackout Protocol

![Event](https://img.shields.io/badge/SecLeaf_CTF-2026-101518?style=flat-square)
![Category](https://img.shields.io/badge/Category-Reverse_Engineering-B4441F?style=flat-square)
![Points](https://img.shields.io/badge/Points-500-2F5D3A?style=flat-square)

> **Solved by** [Vaidik](https://github.com/Vaidik-Makhasana) · **Team** Bug Busters · **Solved** 31 October 2026, 10:50 pm

## Challenge description

A verification executable shipped together with three pieces of incident evidence: a retained memory image, an incident journal and a network capture. The executable accepts or rejects a candidate secret through a custom multi-round transformation whose parameters are scattered across the evidence files, mixed in with forged journal records and unrelated traffic.

*Brief reconstructed from the solve notes; the original text was not archived.*

**Flag format:** `SecLeaf{...}`

**Attachments:** [`blackout_protocol`](attachments/blackout_protocol) · [`incident.journal`](attachments/incident.journal) · [`retained.mem`](attachments/retained.mem) · [`transmission.pcap`](attachments/transmission.pcap)

## Flag

```text
SecLeaf{n01s3_1n_th3_w1r35_4nd_4ft3r1m4g3s!!!!!}
```

## Writeup

Read the full solve: **[writeup.md](writeup.md)**

**In one line:** no single file holds the answer – the memory image gives the seeds, the journal and the capture give the table data once forgeries are filtered out by their own integrity checks, and only the combination rebuilds the verifier's 52-round transform.

- `retained.mem` carries an `M16B` header and two 64-bit seeds: `0x72f23b4a1c67cd00`, `0xabfedf0984f04e18`.
- `incident.journal`: 48 authentic, uniquely indexed records, validated with FNV-1a.
- `transmission.pcap`: 32 of 290 packets pass the protocol-field and checksum checks; they rebuild a 384-byte lookup table.
- The verifier's transform: 256-byte S-box, byte permutation, forward and reverse diffusion, periodic operations, 52 rounds. The original binary prints `Authenticated.` and exits 0 on the flag.

## Files

| Path | What it is |
| --- | --- |
| [`writeup.md`](writeup.md) | Full solve |
| [`solve/verify.sh`](solve/verify.sh) | Runs the original verifier on a wrong flag and on the recovered flag |

## Run the verifier

```bash
cd solve
bash verify.sh      # Linux x86-64 runs it directly; anywhere else it re-runs itself in Docker (linux/amd64, no network)
```

Expected output:

```text
[*] wrong flag  -> Blackout.
[*] real flag   -> Authenticated.
[+] FLAG: SecLeaf{n01s3_1n_th3_w1r35_4nd_4ft3r1m4g3s!!!!!}
```

## Notes

- **Checked against the original binary:** in a linux/amd64 container with the archived `retained.mem`, `incident.journal` and `transmission.pcap`, the verifier prints `Authenticated.` (exit 0) for the flag and `Blackout.` (exit 1) for a wrong one, whether the flag comes via argv or stdin.
- No offline solver: the team's reconstruction script, the S-box, the permutation and diffusion constants and the 384-byte table were not saved, so we do not publish a re-implementation we cannot show is the one that produced the flag. The proof of correctness is the original verifier's `Authenticated.` / exit code 0.
- The source notes file this as "Digital Forensics / Reverse Engineering"; the platform listed it under Reverse Engineering.
- Flag reads "noise in the wires and afterimages" – the PCAP noise and the memory "afterimage" are exactly the two places the key material hid.

---

[← Back to Reverse Engineering](../README.md) · [All writeups](../../README.md)
