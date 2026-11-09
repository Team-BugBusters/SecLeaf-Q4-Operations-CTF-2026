# LeafSync

![Event](https://img.shields.io/badge/SecLeaf_CTF-2026-101518?style=flat-square)
![Category](https://img.shields.io/badge/Category-Forensics-B4441F?style=flat-square)
![Points](https://img.shields.io/badge/Points-150-2F5D3A?style=flat-square)

> **Solved by** [Vaidik](https://github.com/Vaidik-Makhasana) · **Team** Bug Busters · **Solved** 31 October 2026, 3:19 pm

## Challenge description

> A developer workstation downloaded a synchronization helper from an internal documentation server. Soon afterward, it started sending repeated DNS queries to an unfamiliar domain.
>
> Analyze the supplied packet capture and determine what data was exfiltrated.

**Flag format:** `SecLeaf{...}`

**Attachments:** [`leafsync.pcap`](attachments/leafsync.pcap)

## Flag

```text
SecLeaf{dns_labels_hide_the_truth}
```

## Writeup

Read the full solve: **[writeup.md](writeup.md)**

**In one line:** the "repeated DNS queries" are a data channel: each query name carries a sequence number and a Base64 chunk, so sorting by the number and decoding the joined chunks gives back the exfiltrated data.

- `10.20.30.15` queried `10.20.30.53` for six names under `sync-cache.training.local`.
- Each name is `<NN>.<base64 chunk>.sync-cache.training.local`, with `NN` running `01` to `06`.
- Joined in order: `U2VjTGVhZntkbnNfbGFiZWxzX2hpZGVfdGhlX3RydXRofQ==`, which Base64-decodes to the flag.

## Files

| Path | What it is |
| --- | --- |
| [`writeup.md`](writeup.md) | Full solve |
| [`solve/solve.py`](solve/solve.py) | Decodes the six query names quoted in the writeup; if the pcap is present it also carves them from the DNS queries and cross-checks |

## Run the solver

```bash
cd solve
python3 solve.py
```

Expected output ends with:

```text
[+] FLAG: SecLeaf{dns_labels_hide_the_truth}
```

## Notes

- The solver decodes the six query names embedded from our notes and, with `attachments/leafsync.pcap` present, carves the same names from the DNS queries and requires them to match.
- The brief does not state a flag format; the recovered value follows the event's `SecLeaf{...}` format.

---

[← Back to Forensics](../README.md) · [All writeups](../../README.md)
