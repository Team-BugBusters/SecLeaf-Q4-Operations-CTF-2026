# Water Hammer

![Event](https://img.shields.io/badge/SecLeaf_CTF-2026-101518?style=flat-square)
![Category](https://img.shields.io/badge/Category-Web-B4441F?style=flat-square)
![Points](https://img.shields.io/badge/Points-100-2F5D3A?style=flat-square)

> **Solved by** [Shreya](https://github.com/doodleP) · **Team** Bug Busters · **Solved** 1 November 2026, 12:17 am

## Challenge description

> Hollow Creek has patched the leak and launched a customer portal. Every account gets 100 litres of quota, and each customer can claim one 50-litre goodwill voucher. Opening the Reserve Valve costs 1,000 litres.
>
> The billing team insists that the voucher can only be used once.

**Flag format:** `SecLeaf{...}`

**Attachments:** none, live service (offline after the event) – `http://web.secleaf.xyz:8880`.

## Flag

```text
SecLeaf{ch3ck_f1r5t_wr1t3_l4t3r_b00m}
```

## Writeup

Read the full solve: **[writeup.md](writeup.md)**

**In one line:** the "one voucher per customer" check and the quota write are not
atomic, so many redemptions fired at once all pass the check before any of them
records it – redeem the 50-litre voucher enough times to clear the 1,000-litre
valve.

- The voucher is supposed to be one-time; the server checks `voucher_claimed` and only later writes the new quota.
- Firing ~20–30 redemptions in parallel (Burp Repeater) all read "unclaimed" first – a check-then-write (TOCTOU) race.
- Each winning request adds 50 litres; the dashboard only updated after a log-out/log-in because it showed stale state.
- After a reset, 30 parallel redemptions pushed the quota past 1,000 litres and the Reserve Valve released the flag.

## Files

| Path | What it is |
| --- | --- |
| [`writeup.md`](writeup.md) | Full solve, with a race timeline |
| [`solve/exploit.py`](solve/exploit.py) | Reset → N parallel redeems → open valve (URL argument; target offline) |

## Run the solver

```bash
cd solve
python3 exploit.py                       # prints the recipe, no network
python3 exploit.py http://web.secleaf.xyz:8880      # live run (target offline after the event)
python3 exploit.py http://web.secleaf.xyz:8880 40   # with N parallel requests
```

Against the live service the live run ended with:

```text
[+] FLAG: SecLeaf{ch3ck_f1r5t_wr1t3_l4t3r_b00m}
```

## Notes

- The service is **offline after the event**; `exploit.py` only makes requests when given a target URL, and prints the recipe otherwise.
- The source recorded the behaviour (reset → parallel redeem → open valve) but **not the exact endpoint paths**. The `RESET`/`REDEEM`/`VALVE` routes in `exploit.py` are placeholders to adjust against the captured requests before any live run.
- Races are probabilistic: the writeup noted 20 parallel requests "worked" on the first try and 30 comfortably cleared the threshold. Re-run or raise N if a run comes up short.
- The dashboard showed stale quota until a log-out/log-in – confirm progress by re-reading the account, not the first page render.

---

[← Back to Web](../README.md) · [All writeups](../../README.md)
