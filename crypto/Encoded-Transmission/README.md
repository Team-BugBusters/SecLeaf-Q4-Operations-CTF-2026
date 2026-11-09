# Encoded Transmission

![Event](https://img.shields.io/badge/SecLeaf_CTF-2026-101518?style=flat-square)
![Category](https://img.shields.io/badge/Category-Cryptography-B4441F?style=flat-square)
![Points](https://img.shields.io/badge/Points-175-2F5D3A?style=flat-square)

> **Solved by** [Rutwik](https://github.com/Rutwik-712) · **Team** Bug Busters · **Solved** 1 November 2026, 10:38 am

## Challenge description

> We were successfully able to intercept their transmission and capture vital data from their location. But it is encrypted in latest format in some way. You need to decrypt and decode data to find what they used for infiltration.
>
> **Hint:** Use 2 numbers they were talking about as key to decrypt the message they recieved during their stay.

**Flag format:** `CRY{...}`

**Attachments:** none – the intercepted Base64 text was given in the challenge and is embedded in the solver.

## Flag

```text
CRY{ok_password_was_the_building_code_and_cost_in_yen_with_2underscore}
```

## Writeup

Read the full solve: **[writeup.md](writeup.md)**

**In one line:** the "two numbers" from Riddled Code – building code `01000144` and parking cost `984720` yen – joined by two underscores make exactly 16 bytes, a raw AES-128 key for the Base64-wrapped ECB ciphertext.

- 300 Base64 characters → 224 bytes = 14 AES blocks.
- Key `01000144__984720` (hex `30313030303134345f5f393834373230`), AES-128-ECB, PKCS#7 padding `03 03 03`.
- The plaintext holds the flag and a 24-code-point Unicode password for the next stage ([Final Tools](../Final-Tools/README.md)).
- That password is Base65536 for `this_has_all_the_tools_required_to_do_infiltrate`.

## Files

| Path | What it is |
| --- | --- |
| [`writeup.md`](writeup.md) | Full solve |
| [`solve/solve.py`](solve/solve.py) | Base64 → AES-128-ECB (pure-Python AES) → flag, with re-encryption and Base65536 consistency checks |

## Run the solver

```bash
cd solve
python3 solve.py
```

Expected output ends with:

```text
[+] FLAG: CRY{ok_password_was_the_building_code_and_cost_in_yen_with_2underscore}
```

## Notes

- Part of a chain: **Riddled Code** (supplies the two numbers) → **Encoded Transmission** → **[Final Tools](../Final-Tools/README.md)** (uses both forms of the password).
- The leading zero of `01000144` and *both* underscores are part of the key; one underscore gives only 15 bytes. The flag text itself ("with 2underscore") confirms the construction.
- The solver is stdlib-only: AES is implemented in pure Python and checked against the FIPS-197 test vector. The Base65536 step is checked for consistency (low bytes and block mapping) rather than fully decoded, because qntm's block table is not vendored.

---

[← Back to Cryptography](../README.md) · [All writeups](../../README.md)
