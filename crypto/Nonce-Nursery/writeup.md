# Nonce Nursery – full writeup

[← Back to Cryptography](../README.md) · [Challenge overview](README.md)

**Category:** Cryptography · **Points:** 250 · **Flag:** `SecLeaf{4ff1n3_n0nc3s_b3nd_th3_curv3}`

**Author:** [Rutwik](https://github.com/Rutwik-712) · **Team:** Bug Busters

## TL;DR

1. Every ECDSA signature gives the nonce as a linear function of the private key: `k = u + v·d (mod N)`.
2. Five consecutive nonces follow `k_(i+1) = A·k_i + B`. Taking differences removes `B`, and the ratios of those differences remove `A`.
3. That leaves two polynomials in `d` that must share a root. Their GCD is linear only in the one window where the relationship holds: **leaf 03 – 07**.
4. The root is `d`. We confirm `d·G` equals the public key, derive the AES key, and decrypt the flag.

## The challenge

The brief is a wink: "eleven *different* nonces". The classic ECDSA break is a **reused** nonce, and the author is telling us that is not the bug here. "Uses `random` for passwords" hints that the generator is predictable. The name and the flag both point at **affine** structure.

`data.json` holds 11 secp256k1 signatures over the messages `SecLeaf telemetry leaf 00` … `leaf 10`, a public key, and an AES-GCM capsule. The public description says that one run of **five consecutive** nonces satisfies

```text
k_(i+1) ≡ A·k_i + B  (mod N)      A, B unknown
```

All ECDSA arithmetic here is modulo the **group order** `N`, not the curve's field prime:

```text
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
```

## Step 1 – Hash the messages

Each `h` is SHA-256 of the exact message line. The spacing and the two-digit suffix matter, and each line is hashed on its own. For example:

```text
SHA-256("SecLeaf telemetry leaf 03")
  = cb9f4f790d28475b3d107db0078386869cafbc48ea0943985ddb8358b43fd7dd
```

## Step 2 – Write every nonce as a line in `d`

The ECDSA signing equation is `s·k ≡ h + r·d (mod N)`. Dividing by `s`:

```text
k ≡ u + v·d   where   u = h·s⁻¹,  v = r·s⁻¹   (mod N)
```

We know `u` and `v` for every signature. So each of the 11 nonces is a known straight line in the single unknown `d`. In code, a "line" is just the pair `(u, v)`.

## Step 3 – Eliminate `A` and `B`

Take a window of five consecutive nonces `k0 … k4` and their differences:

```text
t_i = k_(i+1) − k_i
```

If the window is affine, then `t_(i+1) = A·t_i`: subtracting consecutive terms cancels `B`. Consecutive ratios are therefore equal, `t1/t0 = t2/t1 = t3/t2 = A`, and cross-multiplying gets rid of `A` as well:

```text
P(d) = t0·t2 − t1²  = 0
Q(d) = t1·t3 − t2²  = 0
```

Each `t_i` is linear in `d`, so `P` and `Q` are quadratics in `d`. The true key is a root of **both**, so it is a root of `gcd(P, Q)`. In a window where the nonces aren't related, the two quadratics share no root and the GCD is just a constant.

## Step 4 – Scan all seven windows

Eleven signatures give seven windows of five:

| Window | `gcd(P, Q)` |
| --- | --- |
| 00 – 04 | 1 |
| 01 – 05 | 1 |
| 02 – 06 | 1 |
| **03 – 07** | **linear** |
| 04 – 08 | 1 |
| 05 – 09 | 1 |
| 06 – 10 | 1 |

Only one window works. The root of the linear GCD is the private key:

```text
d = f833e0b49cd9652c84292c5097b7dbdfd4005fdd2d1cfa7c975cce14a34616de
```

We used SageMathCell for this (`F = GF(N)`, `R.<x> = PolynomialRing(F)`, `gcd(P, Q).roots()`). The solver does the same with a 40-line polynomial GCD in pure Python.

## Step 5 – Check, then open the capsule

Before trusting `d` we ran three checks:

- rebuilt all 11 nonces with `k = u + v·d`: all distinct, as the brief promised;
- recomputed `A` and `B` from the 03–07 window: all four recurrence equations hold;
- computed `d·G` on secp256k1: it equals the public key in `data.json`.

Key derivation hashes the ASCII prefix and the raw 32-byte scalar:

```text
SHA-256("SecLeaf/nonce-nursery/v2/" || d)
  = 8dc6d74f2ac0fda28c069a762e4d17c658f707d2409804d999484c2c6c1fee5a
```

The `ct` field is 53 bytes: 37 bytes of ciphertext followed by a 16-byte tag. There is no AAD.

| Field | Value |
| --- | --- |
| nonce | `293913b75cab1570ef4929fb` |
| ciphertext (37 B) | `05d4c88968ff68b107b8886f395e9392357144c514b978c128c272e637b64426ef4e28f76f` |
| tag (16 B) | `37754ef632553357c963b0323b7a6a21` |

## Flag

```text
SecLeaf{4ff1n3_n0nc3s_b3nd_th3_curv3}
```

## Why this is the right answer

- **Only one window gave a root.** The other six windows returned a constant GCD, so the window wasn't chosen by hand.
- **The key matches the public key.** `d·G` equals the published point, which a wrong root could not do.
- **The recurrence holds.** The recovered nonces satisfy `k_(i+1) = A·k_i + B` across the whole window.
- **AES-GCM authenticated.** The tag check passed, which confirms the key, the KDF and the ciphertext/tag split.

## What we learned

- **Unique is not the same as independent.** ECDSA nonces must be unpredictable, not just non-repeating. Any known relationship between nonces can leak the key.
- **Turn unknowns into polynomials and let a GCD do the work.** Differencing removes the additive constant and cross-multiplying removes the multiplier. This pattern works for many "related nonce" bugs.
- **Use N, not p.** Signature algebra is modulo the group order. Using the curve's field prime silently gives garbage.
- **Order matters.** The relationship only exists between *consecutive* records. Sorting the signatures by anything else would hide it.

## Reproduce

```bash
cd solve
python3 -m pip install -r requirements.txt
python3 solve.py --selftest
python3 solve.py
```

Full solver: [`solve/solve.py`](solve/solve.py)

---

[← Back to Cryptography](../README.md) · [Challenge overview](README.md)
