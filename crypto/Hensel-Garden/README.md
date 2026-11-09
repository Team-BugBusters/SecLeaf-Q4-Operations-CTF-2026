# Hensel Garden

![Event](https://img.shields.io/badge/SecLeaf_CTF-2026-101518?style=flat-square)
![Category](https://img.shields.io/badge/Category-Cryptography-B4441F?style=flat-square)
![Points](https://img.shields.io/badge/Points-100-2F5D3A?style=flat-square)

> **Solved by** [Rutwik](https://github.com/Rutwik-712) · **Team** Bug Busters · **Solved** 31 October 2026, 2:58 pm
> **Challenge author:** 5h1kh4r

## Challenge description

> They say mathematics is all about finding your roots. Well, we planted a few, added some questionable soil, and now even the roots have trust issues.
>
> Go touch grass. Mathematically, of course.

**Flag format:** `SecLeaf{...}`

**Attachments:** [`Hensel_Garden.zip`](attachments/Hensel_Garden.zip) · [`chall.py`](attachments/chall.py) · [`data.json`](attachments/data.json)

## Flag

```text
SecLeaf{r00ts_gr0w_through_pr1me_p0w3rs}
```

## Writeup

Read the full solve: **[writeup.md](writeup.md)**

**In one line:** squaring a seed modulo a prime power hides it only up to a handful of square roots; lift them with Hensel's lemma, combine the two moduli with CRT, and the 128-bit size limit leaves exactly one seed.

- `A = (s + 87)² mod 2⁷²` has **4** square roots; `B = (s + 143)² mod 3⁵¹` has **2**.
- 4 × 2 = **8** CRT candidates, and only **one** of them fits in 128 bits.
- Key = `SHA-256("SecLeaf/hensel/v2/" ‖ seed as 16 big-endian bytes)`.
- The AES-GCM tag verifies, which independently confirms the seed.

## Files

| Path | What it is |
| --- | --- |
| [`writeup.md`](writeup.md) | Full solve |
| [`solve/solve.py`](solve/solve.py) | Hensel lifting → CRT → seed filter → SHA-256 → AES-GCM |
| [`solve/requirements.txt`](solve/requirements.txt) | `cryptography` (for AES-GCM) |

## Run the solver

```bash
cd solve
python3 -m pip install -r requirements.txt
python3 solve.py
```

Expected output ends with:

```text
[+] FLAG: SecLeaf{r00ts_gr0w_through_pr1me_p0w3rs}
```

## Notes

- The solver embeds the values from `data.json` and, when `attachments/data.json` is present, re-reads the file and requires every value to match.
- During the event we used SageMathCell (`Mod(A, 2^72).sqrt(all=True)`, `CRT(...)`) and CyberChef. The solver does the same in pure Python, with a hand-written Hensel lift.
- The KDF hashes the **raw** seed bytes. Hashing the hex string gives a different key.

---

[← Back to Cryptography](../README.md) · [All writeups](../../README.md)
