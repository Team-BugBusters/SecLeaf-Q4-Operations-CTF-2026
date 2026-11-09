# Signing Shadow: Redshift – full writeup

[← Back to Cryptography](../README.md) · [Challenge overview](README.md)

**Category:** Cryptography · **Points:** 500 · **Flag:** `SecLeaf{cl0ck_drift_c4nt_h1de_a_shad0w}`

**Author:** [Rutwik](https://github.com/Rutwik-712) · **Team:** Bug Busters

## TL;DR

1. Every signature is valid, so the leak has to be in the nonces. Each record also has a 24-bit "stamp".
2. The stamps span almost exactly `q >> 136`, so a stamp is the **top 24 bits of the nonce, plus a constant offset**.
3. Subtracting one record from another cancels the offset. What remains is a Hidden Number Problem in the private key `x`, which lattice reduction (LLL) solves.
4. Four decoy records each use a different offset. Attacking random 9-record subsets avoids them. `g^x == pub` confirms the key, and AES-GCM reveals the flag.

## The challenge

The brief says it straight out: "every signature checks out" (don't attack the scheme) and "clocks are supposed to tell the truth" (the timestamps are the leak). In astronomy, *Redshift* is a shift that pushes every value the same way, which hints at the constant offset. The data contained:

| Item | Contents |
| --- | --- |
| `p, q, g` | Schnorr group; `q` is a 160-bit prime |
| `pub` | `g^x mod p` |
| 23 records | `msg`, `R`, `s`, and a 24-bit `stamp` |
| `sealed` | AES-GCM nonce and ciphertext |

The scheme is:

```text
c = SHA-256("SecLeaf/redshift/v3/nonce|" + msg + R) mod q
s = k + c·x mod q                      k = fresh secret nonce, x = private key
AES key = SHA-256("SecLeaf/shadow-redshift/v3/secret|" + x as 20 bytes)
```

All 23 signatures verified. In Schnorr (as in ECDSA), knowing even part of each `k` is enough to recover `x`, and the stamp is the only extra field.

## Step 1 – What is the stamp? (Read the data, not the formula)

We first tried the obvious models, and none of them produced a key:

- stamp = the top or bottom 24 bits of `k`, used directly;
- stamp at other bit positions, shifted or scaled;
- stamp as a counter drifting from record to record;
- nonces from a PRNG seeded with a 24-bit time (we brute-forced all 2²⁴ seeds).

The breakthrough came from the **range** of the stamps. They don't fill 0 – 16.7 M; they sit between about 1.5 M and 11.1 M, a width of about **10.19 M**. That is exactly the size of the top 24 bits of a number below `q`:

```text
q >> 136  ≈ 10.19 M
```

So the stamps are the top bits of `k`, moved up by some unknown constant:

```text
stamp = (k >> 136) + offset
```

## Step 2 – Cancel the lying clock

Write each nonce as `k_i = (stamp_i − offset)·2¹³⁶ + e_i`, where `e_i < 2¹³⁶` is the unknown low part. The offset is the same for every honest record, so subtracting a reference record removes it:

```text
k_i − k_0 = (stamp_i − stamp_0)·2^136 + (e_i − e_0)
```

Substituting `k = s − c·x` gives one equation per record:

```text
(s_i − s_0 − (stamp_i − stamp_0)·2^136) + (c_0 − c_i)·x  ≡  e_i − e_0   (mod q)
```

The left side is known apart from `x`, and the right side is **small** (below 2¹³⁷ against a 160-bit modulus). This is the textbook **Hidden Number Problem**. Each equation leaks about 24 bits of `x`, so 8 differences (9 records) give about 192 bits, enough for a 160-bit key.

## Step 3 – Let LLL find the small vector

Stack the equations into a lattice: one `q` per equation on the diagonal, one row for the coefficients of `x`, and one row for the constants. Weight them so that the vector `(e_1−e_0, …, e_8−e_0, x·scale, scale)` is unusually short. LLL finds short vectors, so `x` appears in one of the reduced rows. We checked every candidate with

```text
g^x mod p == pub
```

## Step 4 – Dodge the decoys

Running on all 23 records **failed**. Four records (`/02`, `/07`, `/11`, `/20`) were stamped with *different* offsets: 1421399, 1399888, 1488932 and 1633628 respectively, against the honest 1366043. For those records the right-hand side isn't small, and one bad row is enough to break the whole lattice.

We didn't know which rows were bad, so we sampled. With 19 honest records out of 23, a random 9-record subset is entirely honest with probability

```text
C(19,9) / C(23,9) ≈ 11%
```

That means about one success every ten tries. One subset gave an `x` with `g^x == pub`. With the key known, every record's offset can be computed directly: the honest one is **1366043**, and the four decoys don't match it.

## Step 5 – Open the sealed blob

```text
key = SHA-256("SecLeaf/shadow-redshift/v3/secret|" || x.to_bytes(20, "big"))
```

AES-GCM with the provided nonce decrypted the blob, **and the tag verified**:

```text
SecLeaf{cl0ck_drift_c4nt_h1de_a_shad0w}
```

## Flag

```text
SecLeaf{cl0ck_drift_c4nt_h1de_a_shad0w}
```

## Why this is the right answer

- **The key is checkable.** `g^x mod p == pub` cannot hold for a wrong `x`.
- **The decoys are explained.** Once we had `x`, the four rejected records turned out to carry their own, different offsets, which accounts for why the full-set lattice failed.
- **The ciphertext authenticated.** A successful GCM tag check confirms the key derivation and the decryption.
- **We ruled out the tempting fake.** Early on, `SecLeaf{t1m3_1s_r3l4t1v3_y0ur_suff3r1ng_1nt}`, a leetspeak version of "Time is relative. Your suffering isn't.", was suggested as the flag. It was rejected. It was never in the data.

## What we learned

- **"Valid signatures" says nothing about nonce quality.** A 24-bit partial leak per nonce is enough to recover the whole key with a lattice.
- **Look at the distribution before guessing formulas.** The stamps' range matched `q >> 136`, which told us the model faster than four failed hypotheses had.
- **Differences remove shared unknowns.** Subtracting a reference record cancels any constant offset.
- **Lattices are fragile, so sample.** When some rows may be poisoned, random subsets with a cheap success check (`g^x == pub`) beat trying to fix the whole dataset.

## Reproduce

```bash
cd solve
python3 solve.py --selftest
python3 -m pip install -r requirements.txt
python3 solve.py          # with the original data.json in ../attachments/
```

On the archived `data.json` the solver recovers `x = 0xa13f9648f4f4e416a02f1f0ced932692aca4701` after 23 random subsets (3–10 minutes, depending on the random subsets and the machine) and decrypts the flag. The self-test builds a 160-bit Schnorr-style instance with the same leak (`stamp = (k >> 136) + 1366043`) and four decoy records at indices 2, 7, 11 and 20, then recovers the planted key with the same subset-plus-LLL loop.

Full solver: [`solve/solve.py`](solve/solve.py)

---

[← Back to Cryptography](../README.md) · [Challenge overview](README.md)
