# Eightfold Funeral: Epitaph

![Event](https://img.shields.io/badge/SecLeaf_CTF-2026-101518?style=flat-square)
![Category](https://img.shields.io/badge/Category-Cryptography-B4441F?style=flat-square)
![Points](https://img.shields.io/badge/Points-500-2F5D3A?style=flat-square)

> **Solved by** [Rutwik](https://github.com/Rutwik-712) · **Team** Bug Busters · **Solved** 1 November 2026, 12:13 am
> **Challenge author:** 5h1kh4r

## Challenge description

> The funeral was supposed to be over.
>
> Unfortunately, somebody dug up the corpse, replaced the evidence, forged the autopsy reports, and invited another eight million guests.
>
> The checksum is still there. The mathematics is considerably less friendly.
>
> Rest in peace? Nah. Rest in complexity.

**Flag format:** `SecLeaf{...}`

**Attachments:** [`Eightfold_Epitaph.zip`](attachments/Eightfold_Epitaph.zip) · [`data.json`](attachments/data.json) · [`model.py`](attachments/model.py)

## Flag

```text
SecLeaf{m0dular_c4rr13s_d0nt_r3st_1n_p34c3}
```

## Writeup

Read the full solve: **[writeup.md](writeup.md)**

**In one line:** pick one entry from each of eight lists of 2²¹ so the sum hits a target modulo 2⁸⁴. That is impossible by brute force, but Wagner's k-tree cancels 21 bits per merge level and finds it with lists that never grow past about 2 million entries.

- Calibration rows vote for the honest stamp map: rotation **35**, backed by 15 of 25 rows; a decoy map (rotation 71) matches 7, and 3 are outliers.
- Inverting the map gives the eight lane seeds and the target `T = 0x1b59868b301e63f23871f`.
- 8 × 2²¹ = 16.7 M labels, 3 merge levels, **exactly one** full-width match.
- The 139-byte receipt is hashed to the AES-256 key; the capsule is decrypted with the GCM keystream (AES-CTR from `nonce ‖ 00000002`).

## Files

| Path | What it is |
| --- | --- |
| [`writeup.md`](writeup.md) | Full solve |
| [`solve/solve.py`](solve/solve.py) | Calibration vote, unstamping, labels, checksum, receipt key, capsule; `--search` reruns the full Wagner tree |
| [`solve/requirements.txt`](solve/requirements.txt) | `cryptography` (only for the final CTR decrypt) |

## Run the solver

```bash
cd solve
python3 -m pip install -r requirements.txt
python3 solve.py            # < 1 s: map vote, unstamp, labels, checksum, receipt key, capsule
python3 solve.py --search   # ~25 s, ~2.2 GB RAM: rebuilds all 16.7M labels and finds the same 8 indices
```

Expected output (default run, lane lines trimmed):

```text
[+] honest stamp map: rotation 35, a = 0x750e59bef1f0e6b385693, b = 0x67cd6060c7616d28d7c34  (15/25 rows)
    decoy map on the other rows: rotation 71 (7 rows); 3 rows fit neither
[+] unstamped 8 lane seeds and target T = 0x1b59868b301e63f23871f
[+] sum of labels mod 2^84 = 0x1b59868b301e63f23871f = target
[+] receipt key = 3d4d888000202e2db8c6f12732fbccb8afb9992b442ce555089fc49a2d892cf7
[+] FLAG: SecLeaf{m0dular_c4rr13s_d0nt_r3st_1n_p34c3}
```

## Notes

- Verified on the original `data.json`: the calibration vote recovers the honest map (rotation 35, 15/25 rows), the decoy map (rotation 71, 7 rows) and 3 outliers, the seeds and target are unstamped from the published stamps, and the capsule decrypts. `Eightfold_Epitaph.zip` is the original download.
- The capsule decrypted with the CTR keystream, but GCM verification without AAD **failed**, so we never had an authenticated decrypt. The readable flag and the passing checksum are the evidence.
- During the event the merge ran in C++. `--search` is a CPython port: it took 22 s and 2.2 GB of RAM in our test, and it reproduces the same per-level counts and the same eight indices.

---

[← Back to Cryptography](../README.md) · [All writeups](../../README.md)
