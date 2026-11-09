# Fault Atlas

![Event](https://img.shields.io/badge/SecLeaf_CTF-2026-101518?style=flat-square)
![Category](https://img.shields.io/badge/Category-Cryptography-B4441F?style=flat-square)
![Points](https://img.shields.io/badge/Points-500-2F5D3A?style=flat-square)

> **Solved by** [Rutwik](https://github.com/Rutwik-712) · **Team** Bug Busters · **Solved** 1 November 2026, 2:03 pm
> **Challenge author:** 5h1kh4r

## Challenge description

> Someone injected faults into production. Someone else forged the logs. Apparently this counts as teamwork.

Objective: identify the genuine AES fault traces, recover the encryption key, and open the encrypted capsule.

**Flag format:** `SecLeaf{...}`

**Attachments:** [`Fault_Atlas.zip`](attachments/Fault_Atlas.zip) · [`data.json`](attachments/data.json) · [`model.py`](attachments/model.py)

## Flag

```text
SecLeaf{f4ult5_d0nt_n33d_t0_b3_h0n35t}
```

## Writeup

Read the full solve: **[writeup.md](writeup.md)**

**In one line:** a single-byte fault before round 9's MixColumns leaves a fixed algebraic fingerprint on four ciphertext bytes. Forged traces can copy the *pattern* but not the *algebra*, so voting across records recovers the last round key.

- 110 traces: 4 groups of 24 hit the right 4-byte patterns, and 14 are obviously wrong.
- Per column, the winning key quadruple had **13** supporting records; the runner-up had 1 or 2.
- Round-10 key `e1db89a2…9d52` → inverted key schedule → master key `ef06894cdda41099d17786e51911ce45`, which reproduces all 110 (pt, ct) pairs.
- Capsule key = `SHA-256("SecLeaf/fault-atlas/record-seal/v1\x00" ‖ master)`. AES-256-GCM with AAD `round10-key` authenticates.

## Files

| Path | What it is |
| --- | --- |
| [`writeup.md`](writeup.md) | Full solve |
| [`solve/solve.py`](solve/solve.py) | Fault voting, key-schedule inversion, KDF, GCM, and a synthetic self-test |
| [`solve/requirements.txt`](solve/requirements.txt) | `cryptography` |

## Run the solver

```bash
cd solve
python3 -m pip install -r requirements.txt
python3 solve.py --selftest   # plants genuine + forged faults under a random key and recovers it
python3 solve.py
```

Expected output (on the archived `data.json`, under a second):

```text
[*] 110 trace records; voting on round-10 key bytes
    column 0: positions [0, 13, 10, 7] -> e1 16 6f 81  (13 votes; runner-up 2)
    column 1: positions [4, 1, 14, 11] -> 34 db 9d 72  (13 votes; runner-up 1)
    column 2: positions [8, 5, 2, 15] -> 7c 4b 89 52  (13 votes; runner-up 2)
    column 3: positions [12, 9, 6, 3] -> 84 cb 4c a2  (13 votes; runner-up 1)
[+] master key reproduces 110/110 (pt, ct) pairs
[+] master key   = ef06894cdda41099d17786e51911ce45
[+] FLAG: SecLeaf{f4ult5_d0nt_n33d_t0_b3_h0n35t}
```

## Notes

- Verified on the original `data.json`: the vote gives 13 supporting records per column (runner-up 1–2), the master key reproduces 110/110 pairs, and the capsule authenticates with AAD `round10-key`. `Fault_Atlas.zip` is the original download; `model.py` and `data.json` are its contents.
- The hint label is printed as `Secleaf/…` with a lowercase *l*, but the label that works is `SecLeaf/…`. `\x00` is one real NUL byte, not four characters.
- The original notes call the AAD "10 bytes long", but `round10-key` is 11 bytes. The 11-byte string is the one that authenticates.

---

[← Back to Cryptography](../README.md) · [All writeups](../../README.md)
