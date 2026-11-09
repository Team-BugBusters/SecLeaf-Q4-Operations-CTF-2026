# Hensel Garden – full writeup

[← Back to Cryptography](../README.md) · [Challenge overview](README.md)

**Category:** Cryptography · **Points:** 100 · **Flag:** `SecLeaf{r00ts_gr0w_through_pr1me_p0w3rs}`

**Author:** [Rutwik](https://github.com/Rutwik-712) · **Team:** Bug Busters

## TL;DR

1. The challenge hides a 128-bit seed `s` behind two shifted squares: `A = (s+87)² mod 2⁷²` and `B = (s+143)² mod 3⁵¹`.
2. Square roots modulo a prime power can be built up one power at a time (Hensel lifting). We get 4 roots for `A` and 2 for `B`.
3. Subtract the shifts and combine each pair with the Chinese Remainder Theorem: 8 candidates, but only one is below 2¹²⁸.
4. `SHA-256("SecLeaf/hensel/v2/" ‖ seed)` is the AES-GCM key, and the capsule decrypts to the flag.

## The challenge

The name says what to do: **Hensel** is the lemma for lifting roots modulo prime powers, and a **garden** is where roots grow. The brief ("finding your roots", "roots have trust issues") hints that there will be several roots and only some of them can be trusted.

`data.json` gives two observations of the same secret seed:

```text
A = 2090995815874869393993      = (s + 87)^2  mod 2^72
B = 246419994095244398264902    = (s + 143)^2 mod 3^51
```

It also gives an AES-GCM capsule (nonce + ciphertext + tag). The seed is a non-negative integer below 2¹²⁸.

## Step 1 – Why a square mod a prime power is not a dead end

Over the integers you would just take a square root. Modulo `2⁷²` that doesn't work: `A` is the *reduced* square, and `√A` over the integers is meaningless. What we need are all `r` with `r² ≡ A (mod 2⁷²)`.

Hensel's idea is to solve the equation for a small modulus and grow the answer one digit at a time:

```text
if r_k² ≡ A (mod p^k), every root mod p^(k+1) has the form
    r_(k+1) = r_k + t·p^k,   0 ≤ t < p
keep the t values for which r_(k+1)² ≡ A (mod p^(k+1))
```

Each step tries only `p` extensions (2 for `p = 2`, 3 for `p = 3`), so 72 or 51 steps are instant. The important part is to **keep every surviving branch**. Dropping one root could throw away the real seed.

Roots of `A` modulo `2⁷²` (4 of them):

```text
311693314961566273123
2049489926473256333725
2672876556396388879971
4410673167908078940573
```

Roots of `B` modulo `3⁵¹` (2 of them):

```text
143629324417692064196608
2010064638657865702114139
```

## Step 2 – Undo the shifts

These roots are values of `s + 87` and `s + 143`, not of `s` itself. Subtracting the shift turns each root into a congruence on the seed:

```text
s ≡ r_A − 87   (mod 2^72 = 4722366482869645213696)
s ≡ r_B − 143  (mod 3^51 = 2153693963075557766310747)
```

For the pair that turns out to be correct:

```text
a = 311693314961566273036
b = 143629324417692064196465
```

## Step 3 – Glue the two moduli together with CRT

`2⁷²` and `3⁵¹` share no factors, so each (root A, root B) pair gives exactly one residue modulo their product, which is about 1.0 × 10⁴⁶. That is much larger than 2¹²⁸ ≈ 3.4 × 10³⁸. The inverse used in the combination step is:

```text
u = (2^72)^(-1) mod 3^51 = 2005783915697921746635103
```

Running CRT on all 4 × 2 = 8 pairs and comparing each result with the seed bound:

| Pair | CRT result | < 2¹²⁸? |
| --- | --- | :---: |
| r_A[0], r_B[0] | `282779946134366997745983790016833981964` | **yes** |
| the other 7 | ≈ 10⁴⁵ – 10⁴⁶ | no |

Only one candidate fits:

```text
s = 282779946134366997745983790016833981964
```

As a check, `(s+87)² mod 2⁷² = A` and `(s+143)² mod 3⁵¹ = B`.

## Step 4 – Derive the key and open the capsule

The seed as 16 big-endian bytes:

```text
d4bd6fc49311dd10e59d1a891c1b0e0c
```

The key is SHA-256 over the ASCII prefix followed by those raw bytes:

```text
SHA-256( "SecLeaf/hensel/v2/" || d4bd6fc4...1c1b0e0c )
  = c17e6cb58287b5d26bfc10183101fdfcd583ded77134de67fc4818d4659e0974
```

The `ct` field is 56 bytes: 40 bytes of ciphertext followed by a 16-byte tag. There is no AAD.

| Field | Value |
| --- | --- |
| nonce | `47058b956d0949a8d2e0c83d` |
| ciphertext (40 B) | `455e7863f10096e5984ed4c341c580eeb492ad737893e0873dfe495aca47a0fb01b086a10df02ddb` |
| tag (16 B) | `2f85dec7aa6048ca320b82ee0dcae6b1` |

```python
key = hashlib.sha256(b"SecLeaf/hensel/v2/" + seed.to_bytes(16, "big")).digest()
print(AESGCM(key).decrypt(nonce, ciphertext + tag, None).decode())
```

## Flag

```text
SecLeaf{r00ts_gr0w_through_pr1me_p0w3rs}
```

## Why this is the right answer

- **The algebra checks out.** The recovered seed reproduces both published squares exactly.
- **It is unique.** Seven of the eight CRT candidates are about 10⁷ times too large to be a 128-bit seed, so nothing was guessed.
- **AES-GCM authenticates.** A wrong seed, wrong byte order, missing slash in the prefix, or wrong tag split would raise an authentication error instead of returning text. The successful decrypt confirms the whole chain.

## What we learned

- **Squaring is not hiding.** Modulo a prime power, a square has only a few roots, and Hensel lifting finds all of them in linear time.
- **Keep every branch.** The power of 2 gave four roots and the power of 3 gave two. Picking "the" root on either side has a good chance of losing the seed.
- **Size constraints are information.** The CRT modulus is far larger than the seed space, so the 128-bit bound acts as a filter that picks one candidate out of eight.
- **KDF inputs are byte-exact.** The prefix's trailing slash, the 16-byte big-endian encoding, and hashing raw bytes instead of hex all matter.

## Reproduce

```bash
cd solve
python3 -m pip install -r requirements.txt
python3 solve.py
```

Full solver: [`solve/solve.py`](solve/solve.py)

---

[← Back to Cryptography](../README.md) · [Challenge overview](README.md)
