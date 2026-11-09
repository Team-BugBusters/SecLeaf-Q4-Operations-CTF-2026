# Blackroot Archive

![Event](https://img.shields.io/badge/SecLeaf_CTF-2026-101518?style=flat-square)
![Category](https://img.shields.io/badge/Category-Forensics-B4441F?style=flat-square)
![Points](https://img.shields.io/badge/Points-200-2F5D3A?style=flat-square)

> **Solved by** [Vaidik](https://github.com/Vaidik-Makhasana) · **Team** Bug Busters · **Solved** 31 October 2026, 3:31 pm

## Challenge description

> A finance workstation downloaded a ledger synchronization manifest from an internal documentation portal. Around the same time, an internal archive notice was sent to operations, followed by unusual communication with an external archive service.
>
> Analyze the supplied PCAP and recover the flag.

**Flag format:** `SecLeaf{...}`

**Attachments:** [`blackroot_archive.pcap`](attachments/blackroot_archive.pcap)

## Flag

```text
SecLeaf{exported_objects_reveal_the_archive_key}
```

## Writeup

Read the full solve: **[writeup.md](writeup.md)**

**In one line:** each protocol holds one piece. The HTTP manifest says *how* to decode and *where* to look, the SMTP notice holds the key, and TCP/4711 carries the ciphertext; repeating-key XOR with `rootleaf` then Base64 gives the flag.

- HTTP `GET /exports/ledger-sync.manifest` from `docs.blackroot.internal`: `encoding=base64`, `key_source=mail:archive-notice`, `next_service=tcp/4711`.
- SMTP from `archive-notice@blackroot.internal`: `Recovery key: rootleaf`.
- TCP/4711 with the external archive service `198.51.100.144`: ten hex chunks, 64 bytes in total.
- `hex -> XOR("rootleaf") -> Base64 -> flag`.

## Files

| Path | What it is |
| --- | --- |
| [`writeup.md`](writeup.md) | Full solve |
| [`solve/solve.py`](solve/solve.py) | Decodes the hex chunks and key quoted in the writeup; if the pcap is present it also carves the manifest, key and chunks from the capture and cross-checks |

## Run the solver

```bash
cd solve
python3 solve.py
```

Expected output ends with:

```text
[+] FLAG: SecLeaf{exported_objects_reveal_the_archive_key}
```

## Notes

- The solver decodes the ten hex chunks and the key embedded from our notes, then carves the key (SMTP) and the `blob=` records (TCP/4711) from `attachments/blackroot_archive.pcap` and requires both to agree.
- Ports 4700–4703 on the same host only carry `HELLO … status=healthy` health checks; ignore them.
- The flag text itself, "exported objects", hints that Wireshark's *Export Objects* (HTTP/SMTP) is a fast route to the manifest and the email.
- The brief does not state a flag format; the recovered value follows the event's `SecLeaf{...}` format.

---

[← Back to Forensics](../README.md) · [All writeups](../../README.md)
