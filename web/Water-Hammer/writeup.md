# Water Hammer – full writeup

[← Back to Web](../README.md) · [Challenge overview](README.md)

**Category:** Web · **Points:** 100 · **Flag:** `SecLeaf{ch3ck_f1r5t_wr1t3_l4t3r_b00m}`

**Author:** [Shreya](https://github.com/doodleP) · **Team:** Bug Busters

## TL;DR

1. The portal gives every account 100 litres and one 50-litre "goodwill voucher"; opening the Reserve Valve needs 1,000 litres.
2. The voucher is meant to be one-time, but the check (`voucher_claimed?`) and the write (`litres += 50`, mark claimed) are not in one atomic transaction.
3. Sending many redemptions **in parallel** (Burp Repeater) lets several requests pass the "unclaimed" check before any of them records the claim – a TOCTOU race.
4. After a reset, 30 parallel redemptions pushed the quota over 1,000 litres and opening the Reserve Valve returned the flag.

## The challenge

The dashboard had four actions:

| Control | Effect |
| --- | --- |
| Your Quota | shows the current balance (starts at 100 L) |
| Goodwill Voucher | adds 50 L, "limited to one redemption per customer" |
| Reserve Valve | requires 1,000 L to open |
| Start Over | resets the account to its initial quota |

The flag name *Water Hammer* is the hint: a water hammer is the pressure shock
from many flows slamming shut at once. The challenge explicitly promises the
voucher can be claimed **only once** – a business-logic restriction practically
begging to be tested for server-side enforcement under concurrency.

## Step 1 – Probe the one-time claim

We intercepted the "Redeem Voucher" request in Burp and sent it to Repeater.
Because the restriction is "one per customer", the natural test is whether the
server enforces it under *simultaneous* requests rather than sequential ones. We
configured Repeater to send **20 requests in parallel**.

The dashboard at first still showed the original quota, which looked like a
failure – but that was stale page state. After logging out and back in, the
balance had jumped well past 100 + 50 litres, i.e. **multiple** redemptions of a
supposedly single-use voucher had landed. That is the signature of a race
condition.

## Step 2 – Why the race works

The redemption handler runs roughly this sequence:

1. Retrieve the user's account.
2. Check whether the voucher is already claimed.
3. Contact the billing service.
4. Add 50 litres and mark the voucher claimed.

The vulnerable split is between the check and the write:

```python
# check
if user["voucher_claimed"]:
    return jsonify(ok=False), 409
```

```sql
-- write (later, non-atomically)
UPDATE users
SET litres = litres + 50, voucher_claimed = 1
WHERE id = ?;
```

Nothing holds a lock or a transaction across the check and the write. When
requests arrive almost together, each reads `voucher_claimed = 0` **before** any
of them has written `voucher_claimed = 1`, so they all pass the gate and each
applies its own `+50`.

### Timeline of the race

With the check and the write separated, three near-simultaneous requests
interleave like this:

| Time | Request A | Request B | Request C | Stored `voucher_claimed` | Stored litres |
| --- | --- | --- | --- | --- | --- |
| t0 | read: claimed? **no** | | | 0 | 100 |
| t1 | | read: claimed? **no** | | 0 | 100 |
| t2 | | | read: claimed? **no** | 0 | 100 |
| t3 | write +50, set claimed | | | 1 | 150 |
| t4 | | write +50, set claimed | | 1 | 200 |
| t5 | | | write +50, set claimed | 1 | 250 |

All three passed a check that should have let only one through. Serialised
(check-then-write under a lock) only A would succeed; concurrently, every
in-flight request is a winner. With `N` winners the quota becomes
`100 + 50·N` litres, so `N ≥ 18` already clears the 1,000-litre valve.

## Step 3 – Open the Reserve Valve

We used **Start Over** to reset to a clean 100 litres, then replayed the attack
with **30** parallel redemptions through Burp Repeater. After logging out and
back in to refresh the real account state, the quota was comfortably above
1,000 litres. Clicking **Open Valve** released the flag.

## Flag

```text
SecLeaf{ch3ck_f1r5t_wr1t3_l4t3r_b00m}
```

## Why this is the right answer

- **Forward check:** a single redemption adds exactly 50 L and then returns HTTP 409; only concurrent redemptions stack multiple `+50`s, which is the only way to reach 1,000 L.
- **The flag names the bug:** `ch3ck_f1r5t_wr1t3_l4t3r_b00m` is "check first, write later, boom" – the exact check-then-write (TOCTOU) order described above.
- **Format match:** the value matches `SecLeaf{...}`.

## What we learned

- **Test one-time restrictions under concurrency.** "Once per customer" is only true if the check and the write are atomic; fire the request in parallel to find out.
- **Check-then-write is the classic TOCTOU shape.** The fix is a single atomic step – a conditional `UPDATE ... WHERE voucher_claimed = 0`, a row lock, or a unique constraint – not a prior `SELECT`.
- **Distrust stale UI.** The dashboard lagged the database; always re-read authoritative state (here, by re-authenticating) before concluding an attempt failed.
- **Races are probabilistic – give yourself margin.** 30 requests to clear an 18-request threshold absorbs the requests that lose the race.

## Reproduce

```bash
cd solve
python3 exploit.py                                  # recipe only, no network
python3 exploit.py http://web.secleaf.xyz:8880      # live run (target offline after the event)
python3 exploit.py http://web.secleaf.xyz:8880 40   # with N parallel requests
```

Manual version with curl (fire in parallel, then open the valve):

```bash
for i in $(seq 1 30); do
  curl -s -b jar.txt -c jar.txt -X POST http://web.secleaf.xyz:8880/api/voucher/redeem &
done; wait
curl -s -b jar.txt -X POST http://web.secleaf.xyz:8880/api/valve/open
```

The endpoint paths are placeholders – the source did not record the exact
routes; adjust them to the captured requests. Full exploit:
[`solve/exploit.py`](solve/exploit.py)

---

[← Back to Web](../README.md) · [Challenge overview](README.md)
