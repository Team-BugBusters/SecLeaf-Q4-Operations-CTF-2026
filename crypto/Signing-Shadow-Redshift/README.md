# Signing Shadow: Redshift

![Event](https://img.shields.io/badge/SecLeaf_CTF-2026-101518?style=flat-square)
![Category](https://img.shields.io/badge/Category-Cryptography-B4441F?style=flat-square)
![Points](https://img.shields.io/badge/Points-500-2F5D3A?style=flat-square)

> **Solved by** [Rutwik](https://github.com/Rutwik-712) · **Team** Bug Busters · **Solved** 1 November 2026, 12:50 am
> **Challenge author:** 5h1kh4r

## Challenge description

> Every signature checks out. Every record looks legitimate. Unfortunately, somebody forgot that clocks are supposed to tell the truth.
>
> Time is relative. Your suffering isn't.

**Flag format:** `SecLeaf{...}`

**Attachments:** [`Signing_Shadow_Redshift.zip`](attachments/Signing_Shadow_Redshift.zip) · [`data.json`](attachments/data.json) · [`model.py`](attachments/model.py)

## Flag

```text
SecLeaf{cl0ck_drift_c4nt_h1de_a_shad0w}
```

## Writeup

Read the full solve: **[writeup.md](writeup.md)**

**In one line:** each record's 24-bit "clock" stamp is the top 24 bits of the secret nonce plus a constant offset. Subtracting two records cancels the offset, which leaves a Hidden Number Problem that LLL solves for the private key.

- All 23 Schnorr signatures verify; the bug is in the nonces, not in the scheme.
- The stamps span ≈ 10.19 M values, which is exactly `q >> 136`. That is the giveaway that stamp = `(k >> 136) + offset`.
- 4 records (`/02`, `/07`, `/11`, `/20`) use a different offset and poison the lattice, so we attacked random 9-record subsets.
- The honest offset is `1366043`. `g^x == pub` confirms the key, and the AES-GCM tag confirms the flag.

## Files

| Path | What it is |
| --- | --- |
| [`writeup.md`](writeup.md) | Full solve |
| [`solve/solve.py`](solve/solve.py) | Pure-Python LLL + HNP over random subsets, with a planted-instance self-test |
| [`solve/requirements.txt`](solve/requirements.txt) | `cryptography` (only for the final AES-GCM step) |

## Run the solver

```bash
cd solve
python3 solve.py --selftest   # ~2 min: plants the same leak and 4 decoys, recovers the key
python3 -m pip install -r requirements.txt
python3 solve.py              # 3-10 min on the archived data.json (random subsets, pure Python)
```

Expected output on the real data:

```text
[+] all 23 signatures verify (R serialised as bytes-plen)
[+] x = 0xa13f9648f4f4e416a02f1f0ced932692aca4701   (g^x == pub, found after 23 subsets)
[+] clock offsets seen: [1366043, 1399888, 1421399, 1488932, 1633628]  (honest one: 1366043)
[+] FLAG: SecLeaf{cl0ck_drift_c4nt_h1de_a_shad0w}
```

## Notes

- Verified on the original `data.json`: all 23 signatures verify, the subset attack recovers `x = 0xa13f9648f4f4e416a02f1f0ced932692aca4701` (`g^x == pub`), the decoys are `/02`, `/07`, `/11`, `/20` (each with its own offset), and the GCM tag authenticates. The run takes about 3–4 minutes in pure Python.
- `model.py` serialises `R` as `len(p)` big-endian bytes inside the challenge hash. The solver also confirms this on its own: it keeps the encoding under which all 23 signatures verify.
- `SecLeaf{t1m3_1s_r3l4t1v3_y0ur_suff3r1ng_1nt}` is **not** a flag. It was a leetspeak guess built from the brief's second line, and the platform rejected it.
- We used `fpylll` during the event. The solver ships a small exact-rational LLL so it runs with no dependencies.

---

[← Back to Cryptography](../README.md) · [All writeups](../../README.md)
