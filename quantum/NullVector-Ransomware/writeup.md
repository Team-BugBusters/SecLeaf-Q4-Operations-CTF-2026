# NullVector Ransomware – full writeup

[← Back to Quantum Security](../README.md) · [Challenge overview](README.md)

**Category:** Quantum Security · **Points:** 150 · **Flag:** `SecLeaf{e4d90b218a754f1c93206e58b1f4a7c2}`

**Author:** [Rutwik](https://github.com/Rutwik-712) · **Team:** Bug Busters

## TL;DR

1. `Quantum_factory.json` gave the RSA modulus **and its factors** (`N`, `p`, `q`, `e`). We checked `p*q == N` and computed the private exponent `d`.
2. `classified_report.locked` = magic + length + 256-byte RSA-wrapped key + 16-byte IV + 608-byte AES-CBC body.
3. Raw RSA unwrapped a 32-byte AES-256 key. AES-CBC decrypted with valid padding, but the result was still unreadable.
4. A known `=` banner exposed the extra layer: rotate each byte left by 3, then XOR with `K_i = (13*i + 122) mod 256`.
5. The recovered report contains the master asset key, which is the flag.

## The challenge

| File | What it contained |
| --- | --- |
| `Quantum_factory.json` | RSA parameters `N`, `p`, `q`, `e` (all hex) |
| `classified_report.locked` | 886-byte ransomware-locked report |

The RSA key arrives already factored (fitting for a "quantum factory" in a Quantum Security category: factoring is exactly what a large quantum computer would break). So RSA is not the obstacle. The warning about an additional scrambling layer is the real hint: decrypting AES will not be the last step.

## Step 1 – Rebuild the RSA private key

With the factors in hand, RSA is textbook. We checked the factorisation first, then computed the totient and the modular inverse (PARI/GP; `Mod` is modular arithmetic, `lift` turns it back into an integer):

```text
p*q == N                      \\ -> 1
phi = (p-1)*(q-1);
d   = lift(1/Mod(e, phi));    \\ e = 0x10001 = 65537
(e*d) % phi                   \\ -> 1
```

Both checks returned 1. `(N, d)` is the private key.

## Step 2 – Parse the locked file before decrypting anything

The file is 886 bytes. Its first six bytes:

```bash
xxd -g 1 -l 6 classified_report.locked
89 52 57 01 01 00
```

`89 52 57 01` is a custom magic. The next two bytes, `01 00`, read as an integer, are `0x0100` = 256: the size of an RSA-2048 block. That gives the layout (zero-based offsets):

| Offsets | Field |
| --- | --- |
| 0–3 | magic `89 52 57 01` |
| 4–5 | RSA block length `01 00` (256) |
| 6–261 | 256-byte RSA-wrapped key |
| 262–277 | 16-byte AES IV |
| 278–885 | 608-byte AES-CBC body |

The sizes add up exactly: 4 + 2 + 256 + 16 + 608 = 886.

## Step 3 – Unwrap the AES key

```bash
xxd -p -s 6 -l 256 classified_report.locked     # RSA block as hex
```

We loaded the block as an integer `c` and applied raw RSA:

```text
m = lift(Mod(c, N)^d);
printf("%064x\n", m)
078440dd9f8c28d0a8e90f37efd987f736e67023762a2bfbe32cbac9d7afa8d7
```

The 256-byte output is zeros followed by these 32 bytes: an AES-256 key. It starts with `07`, so printing it zero-padded to 64 hex digits matters; dropping a leading zero would shorten the key. OpenSSL confirmed the key.

IV (16 bytes from offset 262):

```text
570d8115917ada6efd6e9cf0f5a90025
```

## Step 4 – AES works, but the output is still scrambled

We decrypted the body (from offset 278) with AES-256-CBC, key and IV as above. PKCS#7 stripping removed eleven `0x0b` bytes, leaving **597 bytes**; OpenSSL produced the same 597 bytes.

Valid padding proves the key, IV and structure are right. But the 597 bytes were not readable. That matches the warning: something was applied to the plaintext before AES.

Two observations narrowed it down:

- **The mask repeats every 256 positions.** XOR-ing two bytes 256 positions apart (after undoing any rotation) cancels the mask and leaves the XOR of two plaintext bytes. That signals a position-dependent mask with period 256.
- **There is a known banner.** At body position 38 we expected a banner line made of `=` characters (`0x3d`).

So we took the 50 bytes starting at position 38 and, for each rotation 0–7, rotated each byte left and XOR-ed with `3d`. If the guess is right, what is left is the mask itself. Only **rotation 3** gave a mask with a clean pattern:

```text
68 75 82 8f 9c a9 b6 c3
```

Each byte is the previous one plus `0x0d` (13), mod 256: a linear mask. Since it starts at position 38, we walked it back to position 0:

```text
(0x68 - 13*38) % 256 = 122 = 0x7a
```

So the mask is `K_i = (13*i + 0x7a) mod 256`, counted from byte 0 of the AES-decrypted body. We worked in bytes, not displayed characters, because the report's punctuation is UTF-8.

## Step 5 – Undo the scrambler

```text
K_i = (13*i + 122) mod 256
S_i = ROTR8(P_i XOR K_i, 3)        (scramble)
P_i = ROTL8(S_i, 3) XOR K_i        (unscramble)
```

The order matters: rotate first, then XOR. The first four bytes show it working:

| | Bytes |
| --- | --- |
| scrambled `S` | `27 79 ba 5e` |
| `ROTL8(S, 3)` | `39 cb d5 f2` |
| XOR `K` (`7a 87 94 a1`) | `43 4c 41 53` = `CLAS` |

Because `13*256 ≡ 0 (mod 256)`, one 256-byte cycle of the mask is the whole key. In offline CyberChef the recipe was **AES Decrypt** (CBC, key/IV hex, input hex, output raw) → **Rotate left** (amount 3, carry off) → **XOR** (scheme Standard, null-preserving off) with this 256-byte hex key (concatenate the lines):

```text
7a8794a1aebbc8d5e2effc091623303d4a5764717e8b98a5b2bfccd9e6f3000d
1a2734414e5b6875828f9ca9b6c3d0ddeaf704111e2b3845525f6c798693a0ad
bac7d4e1eefb0815222f3c495663707d8a97a4b1becbd8e5f2ff0c192633404d
5a6774818e9ba8b5c2cfdce9f603101d2a3744515e6b7885929facb9c6d3e0ed
fa0714212e3b4855626f7c8996a3b0bdcad7e4f1fe0b1825323f4c596673808d
9aa7b4c1cedbe8f5020f1c293643505d6a7784919eabb8c5d2dfecf90613202d
3a4754616e7b8895a2afbcc9d6e3f0fd0a1724313e4b5865727f8c99a6b3c0cd
dae7f4010e1b2835424f5c697683909daab7c4d1deebf805121f2c394653606d
```

The output is a readable document beginning `CLASSIFIED INTEL REPORT – EYES ONLY`. In the middle:

```text
RECOVERED MASTER ASSET KEY:
SecLeaf{e4d90b218a754f1c93206e58b1f4a7c2}
```

## Flag

```text
SecLeaf{e4d90b218a754f1c93206e58b1f4a7c2}
```

## Why this is the right answer

- **Every layer has its own check.** `p*q == N` and `e*d ≡ 1 (mod φ)` for RSA; the RSA output is 224 zero bytes plus a 32-byte key; AES-CBC padding is valid (eleven `0x0b`), in OpenSSL and CyberChef alike.
- **The scrambler was derived, not guessed.** Only one of the eight rotations produced a mask with a constant step, and that formula reproduces the whole 256-byte mask and turns the first bytes into `CLAS`.
- **The whole 597-byte report becomes readable**, not just the banner, which a wrong mask could not do by chance.
- **Format match.** The asset key is the `SecLeaf{…}` value under "RECOVERED MASTER ASSET KEY".

## What we learned

- **Verify given factors.** Check `p*q == N` and the inverse before trusting a "factored" key.
- **Parse before you decrypt.** Splitting header, wrapped key, IV and body first made every later step a one-liner.
- **Keep keys at full byte length.** A leading `0x07` (or `0x00`) byte is part of a 32-byte AES key; print it zero-padded.
- **Valid padding is not success.** It proves the AES layer only; an unreadable result means there is another transform. A known plaintext (here a `=` banner) is the fastest way to recover a simple byte-wise one.

## Reproduce

```bash
cd solve
python3 solve.py      # needs both attachments in ../attachments/
```

The stdlib solver does RSA, pure-Python AES-256-CBC and the un-rotate/un-XOR, and checks the scrambler against the values above before decrypting the archived file. Full solver: [`solve/solve.py`](solve/solve.py)

---

[← Back to Quantum Security](../README.md) · [Challenge overview](README.md)
