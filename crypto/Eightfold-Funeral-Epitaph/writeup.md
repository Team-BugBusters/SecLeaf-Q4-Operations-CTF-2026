# Eightfold Funeral: Epitaph – full writeup

[← Back to Cryptography](../README.md) · [Challenge overview](README.md)

**Category:** Cryptography · **Points:** 500 · **Flag:** `SecLeaf{m0dular_c4rr13s_d0nt_r3st_1n_p34c3}`

**Author:** [Rutwik](https://github.com/Rutwik-712) · **Team:** Bug Busters

## TL;DR

1. Values are disguised by a "stamp": an affine map modulo 2⁸⁴ followed by a bit rotation. Calibration rows reveal it, but some rows are forged, so we voted. Rotation 35 wins with 15 of 25 rows.
2. Un-stamping gives eight lane seeds and a target `T`. Each lane defines a virtual catalog of 2²¹ labels.
3. We need one index per lane with `Σ labels ≡ T (mod 2⁸⁴)`. A Wagner k-tree solves this by cancelling 21 bits per level: 84 = 21 + 21 + 42.
4. The eight (index, label) pairs form a 139-byte receipt. SHA-256 of it is the AES-256 key, and the GCM keystream reveals the flag.

## The challenge

The brief maps onto the attack one line at a time:

- **"forged the autopsy reports"**: some calibration rows lie.
- **"eight million guests"**: 8 lanes × 2²¹ ≈ 16.7 million labels.
- **"the checksum is still there"**: the goal is a modular sum.
- **"rest in complexity"**: brute force (2¹⁶⁸ combinations) is out.
- The flag itself, "modular carries don't rest in peace", warns that this is **addition** modulo 2⁸⁴ with carries. It is not XOR.

`model.py` defines the 84-bit stamp, how lane labels are derived, the modular receipt and the key serialisation. `data.json` has 25 calibration records, eight lane stamps, a target stamp, and the capsule (`nonce`, `ct_tag`).

## Step 1 – Recover the honest stamp map by voting

The stamp is

```text
stamp(x) = rotl_r( a·x + b  mod 2^84 )        a odd (so it is invertible)
```

For each of the 84 possible rotations `r`, we rotated every calibration output back by `r` and treated the result as `y = a·x + b`. Any two rows then give a candidate multiplier:

```text
a = (y_i − y_j) · (x_i − x_j)⁻¹   mod 2^84      only when x_i − x_j is odd
b = y_i − a·x_i
```

Only odd differences are invertible modulo a power of two, so even pairs were skipped. Every candidate `(r, a, b)` was then scored by how many of the 25 **whole rows** it reproduces:

| Map | Rotation | Rows reproduced |
| --- | ---: | ---: |
| **honest** | **35** | **15** (56 votes from valid pairs) |
| decoy | 71 | 7 |
| none | – | 3 outliers (rows 3, 14, 25) |

| Parameter | Value |
| --- | --- |
| `r` | 35 |
| `a` | `0x750e59bef1f0e6b385693` |
| `b` | `0x67cd6060c7616d28d7c34` |
| `a⁻¹ mod 2⁸⁴` | `0xe23edb8d6f1a270ce379b` |

A single pair can be forged to give a plausible `a`. Fifteen independent rows agreeing on one map cannot.

## Step 2 – Un-stamp the seeds and the target

```text
x = a⁻¹ · ( rotr_35(z) − b )   mod 2^84
```

| Lane | Seed |
| ---: | --- |
| 0 | `0xd10e12dd1a92b568095cc` |
| 1 | `0x83b12bcf6e5c7d0238d18` |
| 2 | `0x9f6907f41f632026feb73` |
| 3 | `0x4314ec950d28d71e802d0` |
| 4 | `0xefb8201ea98c16be80e9e` |
| 5 | `0x1866ea8c6bef1710ba967` |
| 6 | `0xdd923a4a9bf987baec4f2` |
| 7 | `0xd805b3695a44f501eadfb` |

```text
T = 0x1b59868b301e63f23871f
```

Re-stamping these values gave back the published stamps exactly, so the inverse is right.

Each lane's catalog entry `i` (0 ≤ i < 2²¹) has a label computed from a 27-byte message:

| Field | Encoding |
| --- | --- |
| domain | 11 ASCII bytes `Epitaph/v7\|` |
| lane | 1 byte (0–7) |
| seed | 11 bytes, little-endian |
| index | 4 bytes, little-endian |

```text
label = int_le( SHA-256(message)[:11] ) mod 2^84      (88 bits → drop the top 4)
```

## Step 3 – Why brute force is hopeless and Wagner isn't

Trying every combination is (2²¹)⁸ = 2¹⁶⁸. Even "meet in the middle" with two halves of four lanes needs lists of 2⁸⁴.

Wagner's trick is to solve the problem **a few bits at a time** while keeping each list at its original size. When two lists of 2²¹ random values are added pairwise, about 2²¹ × 2²¹ / 2²¹ = **2²¹** pairs have their low 21 bits summing to zero. The list size stays the same while 21 bits are fixed. With eight lists, that is three levels:

```text
level 1:  (0,1) (2,3) (4,5) (6,7)   keep pairs with low 21 bits = 0  → store the remaining 63 bits
level 2:  (01,23) (45,67)            next 21 bits = 0                  → store the remaining 42 bits
level 3:  (0123,4567)                all 42 remaining bits must cancel → a full solution
```

To aim at `T` instead of 0, we subtracted `T` from every lane-7 search value. That is only a temporary shift. The receipt later uses the **original** lane-7 label.

Because this is integer addition, the carries out of the low block flow into the next one. That is why each level stores `(sum mod 2^width) >> 21` rather than XOR-ing blocks independently. The flag text makes the same point.

Records kept at each level:

| Merge | Kept |
| --- | ---: |
| lanes 0+1 | 2,098,083 |
| lanes 2+3 | 2,097,014 |
| lanes 4+5 | 2,096,744 |
| lanes 6+7 | 2,098,533 |
| group 0–3 | 2,099,416 |
| group 4–7 | 2,096,046 |
| **full-width match** | **1** |

Each list stays at about 2²¹, as the theory predicts. Every entry carries its original indices, so the single final match unrolls back into eight catalog indices.

## Step 4 – The eight indices

| Lane | Index | Label |
| ---: | ---: | --- |
| 0 | 1924587 | `0x1f41dfd2e4b4c5688399b` |
| 1 | 2031184 | `0xd1a64010db0acf0d7c665` |
| 2 | 29597 | `0xf81c5ca8a66c59e70dc2c` |
| 3 | 785188 | `0x0a2750d86d9411a2f23d4` |
| 4 | 676753 | `0xead24d962b64c4c7f8c54` |
| 5 | 560734 | `0xd14a40b069726a72073ac` |
| 6 | 264902 | `0xdefe3d85a83e2ba87b18c` |
| 7 | 1161509 | `0x8d12ed5a1f49090fbd593` |

Their sum modulo 2⁸⁴ is `0x1b59868b301e63f23871f`, which is exactly `T`.

## Step 5 – Receipt → key → capsule

The key depends on the whole receipt, not just the checksum:

| Part | Bytes |
| --- | --- |
| `Epitaph/v7/capsule` + `0x00` | 19 |
| for each lane: index (4 B LE) + label (11 B LE) | 8 × 15 = 120 |
| **total** | **139** |

```text
key = SHA-256(receipt) = 3d4d888000202e2db8c6f12732fbccb8afb9992b442ce555089fc49a2d892cf7
```

The capsule has a 12-byte nonce and `ct_tag` = 43 bytes of ciphertext followed by a 16-byte tag. Standard AES-GCM verification **with no AAD failed**, and the public files don't specify an AAD. GCM's encryption half is plain AES-CTR, though: for a 96-bit nonce the first data block uses counter `nonce ‖ 00000002`. So we generated that keystream directly:

```bash
openssl enc -d -aes-256-ctr \
  -K 3d4d888000202e2db8c6f12732fbccb8afb9992b442ce555089fc49a2d892cf7 \
  -iv f829357dfebda4d8bd3b749500000002 \
  -in capsule.ct -out capsule_plaintext.txt
```

Note that the counter suffix is big-endian, unlike the little-endian receipt fields.

## Flag

```text
SecLeaf{m0dular_c4rr13s_d0nt_r3st_1n_p34c3}
```

## Why this is the right answer

- **The checksum holds.** Eight labels, rebuilt independently from the seeds, sum to `T` modulo 2⁸⁴. The search found exactly one such combination.
- **The search reproduces.** Our Python port (`solve.py --search`, 22 s) returned the same eight indices *and* the same six per-level counts as the C++ run above.
- **The map is consistent.** Re-stamping the recovered seeds and target reproduces every published stamp.
- **The plaintext fits the key.** A wrong receipt (wrong byte order, missing NUL, adjusted lane-7 label) would give random bytes, not 43 bytes of on-theme flag.
- **Caveat:** the GCM tag never verified (no AAD was published), so this decrypt is unauthenticated. We say so rather than claim more.

## What we learned

- **Consensus beats single samples.** One calibration pair can be forged; fifteen agreeing rows can't.
- **Only odd numbers are invertible modulo 2ⁿ.** Filter for odd differences before dividing.
- **Carries are the point.** Modular addition is not XOR. Each Wagner level has to carry its high bits forward.
- **Keep witnesses.** The receipt needs the indices, so every merged record must remember where it came from.
- **GCM = CTR + GHASH.** When authentication can't be completed, the keystream still decrypts. Report that honestly.

## Reproduce

```bash
cd solve
python3 solve.py
python3 solve.py --search
```

References: D. Wagner, *A Generalized Birthday Problem* (CRYPTO 2002); NIST SP 800-38D (GCM counter construction).

Full solver: [`solve/solve.py`](solve/solve.py)

---

[← Back to Cryptography](../README.md) · [Challenge overview](README.md)
