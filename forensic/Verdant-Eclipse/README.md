# Verdant Eclipse

![Event](https://img.shields.io/badge/SecLeaf_CTF-2026-101518?style=flat-square)
![Category](https://img.shields.io/badge/Category-Forensics-B4441F?style=flat-square)
![Points](https://img.shields.io/badge/Points-300-2F5D3A?style=flat-square)

> **Solved by** [Vaidik](https://github.com/Vaidik-Makhasana) · **Team** Bug Busters · **Solved** 1 November 2026, 7:12 am

## Challenge description

> A researcher downloaded a monitoring script from an internal documentation server. After the download, multiple systems generated unusual DNS and UDP traffic.
>
> Analyze the supplied PCAP, reconstruct the incident timeline, identify the relevant evidence, and recover the flag.

**Flag format:** `SecLeaf{...}`

**Attachments:** [`verdant_eclipse.pcap`](attachments/verdant_eclipse.pcap)

## Flag

```text
SecLeaf{multistage_network_forensics_mastery}
```

## Writeup

Read the full solve: **[writeup.md](writeup.md)**

**In one line:** one host leaked the XOR key through DNS query names and another leaked the ciphertext through a UDP "sync" channel; the HTTP download's `X-Incident-Route: DNS-ALPHA` header told us where to start.

- `plant-monitor.sh` was fetched over HTTP; the response carried `X-Incident-Route: DNS-ALPHA`.
- Three `NN.<b64>.alpha.verdant-lab.local` queries joined to `Zm9saWFnZQ==` → key `foliage`.
- Ten `channel=leafsync` UDP chunks (seq 01–10) joined to 60 bytes of hex ciphertext.
- Repeating-key XOR with `foliage` → Base64 → flag.

## Files

| Path | What it is |
| --- | --- |
| [`writeup.md`](writeup.md) | Full solve |
| [`solve/solve.py`](solve/solve.py) | DNS fragments → key, leafsync chunks → XOR → Base64 → flag (inputs embedded) |

## Run the solver

```bash
cd solve
python3 solve.py
```

Expected output ends with:

```text
[+] FLAG: SecLeaf{multistage_network_forensics_mastery}
```

## Notes

- The solver embeds the DNS labels and UDP chunks and, with `attachments/verdant_eclipse.pcap` present, carves them from the capture and requires them to match. Standard library only.
- The `metrics` (port 6060) and `backup` (port 9000) UDP channels to the same host were not needed for the flag.
- One line of our original notes wrote the flag with spaces inside the braces (`SecLeaf{ multistage_… }`). That was a formatting slip; the decoded value has no spaces.

---

[← Back to Forensics](../README.md) · [All writeups](../../README.md)
