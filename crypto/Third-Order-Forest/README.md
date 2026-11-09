# Third-Order Forest

![Event](https://img.shields.io/badge/SecLeaf_CTF-2026-101518?style=flat-square)
![Category](https://img.shields.io/badge/Category-Cryptography-B4441F?style=flat-square)
![Points](https://img.shields.io/badge/Points-500-2F5D3A?style=flat-square)

> **Solved by** [Shreya](https://github.com/doodleP) · **Team** Bug Busters · **Solved** 1 November 2026, 7:36 am
> **Challenge author:** 5h1kh4r

## Challenge description

> "We masked the secrets. We scrambled the wiring. We added enough noise to make your laptop reconsider its career choices."
>
> "The trees are hiding something. Unfortunately, the trees have a PhD in cryptography. Good luck. You'll need more than numpy and divine intervention."

**Flag format:** `SecLeaf{...}`

**Attachments:** [`acquisition.py`](attachments/acquisition.py) · [`capsule.json`](attachments/capsule.json) · [`capture.npz`](attachments/capture.npz)

## Flag

```text
SecLeaf{wal5h_sp3ctra_outgr0w_th3_m4sked_f0r3st}
```

## Writeup

Read the full solve: **[writeup.md](writeup.md)**

**In one line:** the Hamming weight of an unknown linear map of the S-box output is a sum of exactly 8 Walsh characters, so the Walsh–Hadamard spectrum of third-order class means ranks key guesses without ever recovering the secret wiring.

- 60,000 power traces of a masked AES; a value `110` in samples 0–2 marks a random delay ("phase"), which we realigned on.
- Three-share Boolean masking ("Third-Order") means only the product of three samples leaks; a third-order F-test over sample triples found the three share points for each of the 16 key bytes.
- A Walsh–Hadamard transform of the class means, re-indexed by each key guess, gave 8 same-sign spikes for the right guess (score ≈ 2.1 vs ≈ 1.35 runner-up on every byte).
- Key `2f1aa90f9774de5a29ef06a881d5ee68` decrypted the AES-GCM capsule with a valid tag.

## Files

| Path | What it is |
| --- | --- |
| [`writeup.md`](writeup.md) | Full solve |
| [`solve/solve.py`](solve/solve.py) | Realign → third-order products → Walsh ranking → AES-GCM (plus a synthetic self-test of the scorer) |
| [`solve/requirements.txt`](solve/requirements.txt) | `numpy`, `cryptography` |

## Run the solver

```bash
cd solve
python3 -m pip install -r requirements.txt
python3 solve.py
```

Expected output ends with:

```text
[+] FLAG: SecLeaf{wal5h_sp3ctra_outgr0w_th3_m4sked_f0r3st}
```

## Notes

- Verified on the original `capture.npz` / `capsule.json`: every key byte wins with a Walsh score of about 2.1 against a runner-up of about 1.35, and the AES-GCM tag authenticates. `capture.npz` is 9.7 MB.
- The solver uses the share-sample table found during the event rather than repeating the full F-test over all triples.
- The exact score normalisation used during the event was not recorded. The solver divides the 8 largest same-sign coefficients by the spectrum's L2 norm (maximum √8 ≈ 2.83 for a noiseless correct guess).
- The recovered key is cross-checked against `2f1aa90f9774de5a29ef06a881d5ee68`; the GCM tag check is the final proof.

---

[← Back to Cryptography](../README.md) · [All writeups](../../README.md)
