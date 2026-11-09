# Ledger

![Event](https://img.shields.io/badge/SecLeaf_CTF-2026-101518?style=flat-square)
![Category](https://img.shields.io/badge/Category-Web-B4441F?style=flat-square)
![Points](https://img.shields.io/badge/Points-100-2F5D3A?style=flat-square)

> **Solved by** [Rutwik](https://github.com/Rutwik-712) · **Team** Bug Busters · **Solved** 1 November 2026, 12:48 pm
> **Challenge author:** 5h1kh4r

## Challenge description

*Case File 08 – Archive Consistency.* An evidence archive serves records through
an API. The gateway authorises a *view* before the renderer decides which version
of a record to return – two components, two decisions about the same request.

> "What's a Ledger? What does it do? Can I eat Ledger? Figure it out"

The goal was to read the protected revision of record **RD-947** (*Sealed
Reconciliation*), which the public view returns redacted.

**Flag format:** `SecLeaf{...}`

**Attachments:** none, live service (offline after the event).

## Flag

```text
SecLeaf{ledger_8dfe7383f5657393289a132423dfeaf5be6f}
```

## Writeup

Read the full solve: **[writeup.md](writeup.md)**

**In one line:** the gateway and the renderer disagree on which duplicate query
parameter wins, so `view=public&view=restricted` is authorised as public but
rendered as restricted.

- `GET /api/records/RD-947?view=public` returns an HTTP 200 **redacted** record; swapping to `view=restricted` alone is denied.
- Adding a second `view` value – `view=public&view=restricted` – is classic HTTP Parameter Pollution (HPP).
- nginx authorises on the **first** value (`public`); the Flask renderer selects on the **last** value (`restricted`).
- The response flips to `"status":"recovered"` and carries `X-CTF-Probe: duplicate-view`, exposing the flag.

## Files

| Path | What it is |
| --- | --- |
| [`writeup.md`](writeup.md) | Full solve |
| [`solve/exploit.py`](solve/exploit.py) | Reproduces the duplicate-`view` request (URL argument; target offline) |

## Run the solver

```bash
cd solve
python3 exploit.py                       # prints the request recipe, no network
python3 exploit.py https://ledger.secleaf.xyz   # live run (target offline after the event)
```

Against the live service the live run ended with:

```text
[+] FLAG: SecLeaf{ledger_8dfe7383f5657393289a132423dfeaf5be6f}
```

## Notes

- The service is **offline after the event**, so `exploit.py` only makes a request when you pass a target URL; with no argument it prints the request recipe and the recovered flag.
- The first-vs-last parsing split is *specific to this challenge's* nginx + Flask stack. It is not a general rule for either tool.
- No brute force, password, or forged session was needed – only the inconsistent parsing of a duplicated parameter.

---

[← Back to Web](../README.md) · [All writeups](../../README.md)
