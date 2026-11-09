# Fault Atlas – full writeup

[← Back to Cryptography](../README.md) · [Challenge overview](README.md)

**Category:** Cryptography · **Points:** 500 · **Flag:** `SecLeaf{f4ult5_d0nt_n33d_t0_b3_h0n35t}`

**Author:** [Rutwik](https://github.com/Rutwik-712) · **Team:** Bug Busters

## TL;DR

1. Each of 110 records has a plaintext, the correct ciphertext, and a "disturbed" ciphertext. Some disturbed ones are real round-9 fault outputs; the rest are forged.
2. A real fault changes exactly four ciphertext bytes, in a known pattern, **and** those four bytes satisfy a MixColumns equation. Forgeries can copy the pattern but not the equation.
3. For each column we let every record vote for the key bytes that explain its fault. The genuine traces all agree (13 votes); forgeries scatter (1–2 votes).
4. Round-10 key → invert the key schedule → master key, which reproduces all 110 pairs. Then SHA-256 with the hint label gives the capsule key, and AES-256-GCM (AAD `round10-key`) gives the flag.

## The challenge

`model.py` is a byte-level AES-128 with one twist: a **single byte of the state is changed in round 9, just before MixColumns**. `data.json` (archive name `repair-shift-9`) holds 110 records of `{pt, ct, disturbed}`, one verification pair, and an encrypted capsule.

The brief has two parts: "someone **injected faults**" (this is a differential fault analysis) and "someone else **forged the logs**" (not every disturbed ciphertext is a real fault). The job is to tell them apart.

## Step 1 – What a real fault looks like

Follow one faulty byte through the end of AES:

```text
round 9:  one byte changes  →  MixColumns spreads it across its whole column (4 bytes)
round 10: SubBytes + ShiftRows (no MixColumns)  →  those 4 bytes land in 4 fixed ciphertext positions
```

So a genuine fault changes **exactly four** ciphertext bytes, and which four depends only on the column:

| Column | Ciphertext positions (row order) |
| ---: | --- |
| 0 | 0, 13, 10, 7 |
| 1 | 4, 1, 14, 11 |
| 2 | 8, 5, 2, 15 |
| 3 | 12, 9, 6, 3 |

Sorting the 110 records by which bytes differ gave **four groups of 24**, one per column, plus **14** records that matched none of the patterns. Those 14 are forgeries on sight.

## Step 2 – The test a forger can't pass

A matching pattern is necessary but easy to fake. The real test is algebraic. Guess the last-round key byte `k` at a position and peel off the final round:

```text
D(k) = S⁻¹(C ⊕ k) ⊕ S⁻¹(F ⊕ k)          C = correct byte, F = faulty byte
```

If the trace is genuine and `k` is right, the four `D` values of a column must equal one fault value `e` (1–255) multiplied by a MixColumns column, for example `(2·e, 1·e, 1·e, 3·e)` in GF(2⁸). There are four possible columns depending on which row was hit: `(2,1,1,3)`, `(3,2,1,1)`, `(1,3,2,1)`, `(1,1,3,2)`.

For each record, we listed every 4-byte key tuple consistent with *some* row and *some* `e`. Random bytes rarely satisfy four linked equations at once, so forgeries produce few or junk candidates. Genuine traces always include the true key.

## Step 3 – Vote, one record at a time

One record proves little because it allows several tuples. Many genuine records, though, all contain the *same* true tuple. So we counted, for every tuple, how many **distinct records** support it. Each record votes once, so a forgery can't stuff the ballot, and we don't need every record to agree. That matters because intersecting all records would come out empty as soon as one forgery slipped in.

| Column | Positions | Winning key bytes | Votes | Runner-up |
| ---: | --- | --- | ---: | ---: |
| 0 | 0, 13, 10, 7 | `e1 16 6f 81` | 13 | 1–2 |
| 1 | 4, 1, 14, 11 | `34 db 9d 72` | 13 | 1–2 |
| 2 | 8, 5, 2, 15 | `7c 4b 89 52` | 13 | 1–2 |
| 3 | 12, 9, 6, 3 | `84 cb 4c a2` | 13 | 1–2 |

In total: **52** genuine traces (13 × 4), **44** forgeries that copied the pattern but failed the algebra, and **14** that failed the pattern. Only the disturbed partners were forged; every original `(pt, ct)` pair was still good.

## Step 4 – From the last round key to the master key

Putting each byte back in its position gives the **round-10** key:

```text
e1db89a2344b4c817ccb6f7284169d52
```

That is the last key of the schedule, not the AES key itself. The AES-128 key schedule can be run backwards because each word is the XOR of the word four places earlier and a function of the previous word:

```text
w[i-4] = w[i] XOR T(w[i-1])        T = RotWord → SubWord → ⊕Rcon when i % 4 == 0, identity otherwise
```

Unwinding from `w[43]` down to `w[0]`:

```text
master key = ef06894cdda41099d17786e51911ce45
```

**Check:** AES-128 of the verification plaintext `7a6dd388c6738ac381afd680323b9912` gives `b212b9bb3c09e65d9475eeb55a57df1a`, as expected. The same key reproduces **110 / 110** `(pt, ct)` pairs.

## Step 5 – The capsule key

The hint gave the label:

```text
Secleaf/fault-atlas/record-seal/v1\x00
```

Two traps are hidden in it. `\x00` is **one** NUL byte, not the four characters `\`, `x`, `0`, `0`. And the spelling that works is `SecLeaf` with a capital L. The label is 35 bytes, and SHA-256 runs over the label followed by the **raw** 16-byte key (51 bytes in total):

```text
capsule_key = SHA-256(label || master_key)
            = 92d087267875ed5b12f78221242dddad97e953981e4ae2265c556391720c41cb
```

## Step 6 – Open and authenticate the capsule

| Parameter | Value |
| --- | --- |
| Cipher | AES-256-GCM |
| Nonce | `2fa4591f9cc72843e1c6bc93` |
| Ciphertext | 38 bytes |
| Tag | `206f23b52947bbdde091fbd048078e91` |

GCM's keystream doesn't depend on the AAD, so the plaintext was already readable. The tag, however, failed with empty AAD. Since we held the key, we could work out what AAD the tag expected:

```text
H  = AES_K(0^128)                    GHASH subkey
J0 = nonce || 00000001
S  = tag ⊕ AES_K(J0)                 the GHASH output the tag commits to
```

GHASH is a chain of `state = (state ⊕ block) · H`. Starting from `S`, we peeled off the length block and the three ciphertext blocks with `state = state · H⁻¹ ⊕ block`. What remained was the padded AAD block. Trying each AAD length from 1 to 16 bytes, only one gave readable text followed by zero padding: **`round10-key`**.

Decrypting with that AAD **passes** authentication.

## Flag

```text
SecLeaf{f4ult5_d0nt_n33d_t0_b3_h0n35t}
```

## Why this is the right answer

- **The key is overdetermined.** Four independent columns each had 13 agreeing traces against a runner-up of 1–2.
- **It reproduces all 110 pairs**, which no partially correct key could do.
- **The GCM tag verifies** with the derived key, nonce, ciphertext and AAD. Any mistake in the label, its capitalisation, the NUL byte or the AAD would make it fail.

## What we learned

- **Check a fault's algebra, not just its shape.** The 4-byte pattern filtered out 14 forgeries; the MixColumns relation filtered out the other 44.
- **Vote when the data is partly hostile.** Counting distinct supporting records is robust to forgeries, and intersecting candidate sets is not.
- **A round key is not the key.** For AES-128 the schedule is invertible, so the last round key gives the master key.
- **Labels are bytes.** Capitalisation, a literal NUL, and hashing raw bytes instead of hex each change the derived key.

## Reproduce

```bash
cd solve
python3 -m pip install -r requirements.txt
python3 solve.py --selftest
python3 solve.py
```

`--selftest` builds 110 traces under a random key with a pure-Python AES: half are genuine round-9 faults, half are forged in the right 4-byte patterns or as junk. The vote still recovers the planted key.

Full solver: [`solve/solve.py`](solve/solve.py)

---

[← Back to Cryptography](../README.md) · [Challenge overview](README.md)
