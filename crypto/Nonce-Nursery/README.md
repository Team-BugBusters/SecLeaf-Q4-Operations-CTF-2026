# Nonce Nursery

![Event](https://img.shields.io/badge/SecLeaf_CTF-2026-101518?style=flat-square)
![Category](https://img.shields.io/badge/Category-Cryptography-B4441F?style=flat-square)
![Points](https://img.shields.io/badge/Points-250-2F5D3A?style=flat-square)

> **Solved by** [Rutwik](https://github.com/Rutwik-712) · **Team** Bug Busters · **Solved** 31 October 2026, 3:03 pm
> **Challenge author:** 5h1kh4r

## Challenge description

> Eleven signatures. Eleven different nonces. Surely nothing could go wrong, right?
>
> The developer said the nonce generator was perfectly secure. The developer also uses random for passwords.

**Flag format:** `SecLeaf{...}`

**Attachments:** [`Nonce_Nursery.zip`](attachments/Nonce_Nursery.zip) · [`chall.py`](attachments/chall.py) · [`data.json`](attachments/data.json)

## Flag

```text
SecLeaf{4ff1n3_n0nc3s_b3nd_th3_curv3}
```

## Writeup

Read the full solve: **[writeup.md](writeup.md)**

**In one line:** the nonces are all different but five consecutive ones follow `k_(i+1) = A·k_i + B`, and that relationship, combined with ECDSA's linear signing equation, turns the private key into the shared root of two polynomials.

- 11 secp256k1 signatures (`leaf 00` … `leaf 10`) give 7 windows of 5 consecutive signatures.
- Only the window **leaf 03 – leaf 07** gives a non-trivial polynomial GCD.
- Its single root is the private key `d`, and `d·G` matches the published public key.
- `SHA-256("SecLeaf/nonce-nursery/v2/" ‖ d)` decrypts the AES-GCM capsule.

## Files

| Path | What it is |
| --- | --- |
| [`writeup.md`](writeup.md) | Full solve |
| [`solve/solve.py`](solve/solve.py) | Window scan with polynomial GCD over GF(N), `d·G` check, capsule decryption, and a self-test |
| [`solve/requirements.txt`](solve/requirements.txt) | `cryptography` (for AES-GCM) |

## Run the solver

```bash
cd solve
python3 -m pip install -r requirements.txt
python3 solve.py --selftest   # plants the same weakness in fake signatures and recovers it
python3 solve.py              # recovers the flag
```

Expected output ends with:

```text
[+] FLAG: SecLeaf{4ff1n3_n0nc3s_b3nd_th3_curv3}
```

## Notes

- Verified on the original `data.json`: the window scan finds 03–07, `d·G` equals the published public key, and the capsule decrypts. `Nonce_Nursery.zip` is the original download.
- `--selftest` shows the attack end to end on synthetic signatures with an affine window planted at 03–07.
- The source notes disagree on the count ("ten consecutive" vs eleven). Eleven is correct: the messages run from `leaf 00` to `leaf 10`.

---

[← Back to Cryptography](../README.md) · [All writeups](../../README.md)
