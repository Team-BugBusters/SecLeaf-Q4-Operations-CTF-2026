# Subdomain Smuggling

![Event](https://img.shields.io/badge/SecLeaf_CTF-2026-101518?style=flat-square)
![Category](https://img.shields.io/badge/Category-Network-B4441F?style=flat-square)
![Points](https://img.shields.io/badge/Points-100-2F5D3A?style=flat-square)

> **Solved by** [Rutwik](https://github.com/Rutwik-712) · **Team** Bug Busters · **Solved** 31 October 2026, 2:48 pm

## Challenge description

> Our Security Operations Center (SOC) detected a subtle anomaly in the outbound network traffic from a compromised workstation. The attacker attempted to blend their activity with normal web browsing, but we suspect they successfully smuggled a confidential file out of our network using a covert channel.
>
> We managed to pull a packet capture of the workstation's traffic during the incident window. The firewall logs show no large file transfers or suspicious HTTP POST requests, leading us to believe they abused a core network protocol to slowly leak the data.
>
> Investigate the capture and uncover what happened.

**Flag format:** `SecLeaf{...}`

**Attachments:** [`suspicious_activity.pcap`](attachments/suspicious_activity.pcap)

## Flag

```text
SecLeaf{D474_3xf1l_DN5}
```

## Writeup

Read the full solve: **[writeup.md](writeup.md)**

**In one line:** with no uploads or POSTs, the "core protocol" is DNS; four queries from the workstation under `evil.com` carry a Base64 string sliced across their leftmost labels, which must be joined in frame order (case intact) before decoding.

- 1,038 packets: 960 TCP and 78 DNS (39 queries, 39 responses).
- Four A queries from `192.168.1.20` to resolver `8.8.8.8` in frames 167, 293, 395 and 502, all under `evil.com`.
- Labels `U2VjTGVhZn` + `tENDc0XzN4` + `ZjFsX0RONX` + `0=` → `U2VjTGVhZntENDc0XzN4ZjFsX0RONX0=` → 23-byte flag.

## Files

| Path | What it is |
| --- | --- |
| [`writeup.md`](writeup.md) | Full solve |
| [`solve/solve.py`](solve/solve.py) | Decodes the four query names quoted in the writeup; if the pcap is present it also carves the `evil.com` queries (requests only) in frame order and cross-checks |

## Run the solver

```bash
cd solve
python3 solve.py
```

Expected output ends with:

```text
[+] FLAG: SecLeaf{D474_3xf1l_DN5}
```

## Notes

- The solver decodes the four query names and frame numbers embedded from our notes and, with `attachments/suspicious_activity.pcap` present, carves the `evil.com` queries in frame order and requires them to match.
- `8.8.8.8` is only the public resolver the workstation used; it is not the attacker's endpoint. The data is addressed to whoever runs the authoritative server for `evil.com`.
- The capture proves these four fragments and the 23-byte payload they decode to. It does not show a separate confidential filename or a larger document.

---

[← Back to Network](../README.md) · [All writeups](../../README.md)
