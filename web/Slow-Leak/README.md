# Slow Leak

![Event](https://img.shields.io/badge/SecLeaf_CTF-2026-101518?style=flat-square)
![Category](https://img.shields.io/badge/Category-Web-B4441F?style=flat-square)
![Points](https://img.shields.io/badge/Points-50-2F5D3A?style=flat-square)

> **Solved by** [Ria](https://github.com/ri-Ria-ri) · **Team** Bug Busters · **Solved** 31 October 2026, 11:26 pm

## Challenge description

> Hollow Creek Water Authority keeps losing pressure on Main 07, but every display in the control room reads normal. The repair crews have left their notes in the incident log, and they all agree that something is getting out, one drop at a time.
>
> Plug in, read the log and work out what's leaking.

**Flag format:** `SecLeaf{...}`

**Attachments:** none, live service (offline after the event) – `http://web.secleaf.xyz:8080/`.

## Flag

```text
SecLeaf{h34d3r5_l34k_0n3_dr1p_4t_4_t1m3}
```

## Writeup

Read the full solve: **[writeup.md](writeup.md)**

**In one line:** the page body never changes – each response leaks one flag
character in a custom `X-Drip` response header, indexed by `X-Drip-Serial`, so
collect all 40 drops across requests (reusing the session cookie) and sort by
serial.

- The rendered HTML is identical on every refresh; two raw bodies diff to nothing.
- Each response carries `X-Drip: <char>` and `X-Drip-Serial: n/40` – the leak lives in the headers, not the page.
- A signed `work_order` cookie tracks per-visitor progress and the shuffle seed, so the cookie must persist or every request restarts at drop 1.
- Collecting 40/40 drops and sorting by serial yields the flag directly, no further decoding.

## Files

| Path | What it is |
| --- | --- |
| [`writeup.md`](writeup.md) | Full solve |
| [`solve/exploit.py`](solve/exploit.py) | Collects all 40 `X-Drip` drops reusing the cookie, sorts by serial (URL argument; target offline) |

## Run the solver

```bash
cd solve
python3 exploit.py                       # prints the recipe, no network
python3 exploit.py http://web.secleaf.xyz:8080   # live run (target offline after the event)
```

Against the live service the live run ended with:

```text
[+] FLAG: SecLeaf{h34d3r5_l34k_0n3_dr1p_4t_4_t1m3}
```

## Notes

- The service is **offline after the event**; `exploit.py` only makes requests when given a target URL, and prints the recipe otherwise.
- The leak is invisible to a browser's rendered view and to body-only scrapers – you must read the raw HTTP headers (`curl -i` or Burp's HTTP history).
- The `work_order` cookie seeds a per-visitor shuffle, so drops arrive out of order; the `X-Drip-Serial` index is what reassembles them. A fresh client (no cookie) always restarts at drop 1.

---

[← Back to Web](../README.md) · [All writeups](../../README.md)
