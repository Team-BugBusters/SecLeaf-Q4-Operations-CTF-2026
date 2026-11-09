# NullVector Ransomware

![Event](https://img.shields.io/badge/SecLeaf_CTF-2026-101518?style=flat-square)
![Category](https://img.shields.io/badge/Category-Quantum_Security-B4441F?style=flat-square)
![Points](https://img.shields.io/badge/Points-150-2F5D3A?style=flat-square)

> **Solved by** [Rutwik](https://github.com/Rutwik-712) · **Team** Bug Busters · **Solved** 31 October 2026, 7:42 pm

## Challenge description

An archived ransomware-encrypted file was supplied together with an already-factored RSA key and a warning about an additional scrambling layer. The objective was to recover the asset key.

*Brief reconstructed from the solve notes; the original text was not archived.*

**Flag format:** `SecLeaf{...}`

**Attachments:** [`Quantum_factory.json`](attachments/Quantum_factory.json) · [`classified_report.locked`](attachments/classified_report.locked)

## Flag

```text
SecLeaf{e4d90b218a754f1c93206e58b1f4a7c2}
```

## Writeup

Read the full solve: **[writeup.md](writeup.md)**

**In one line:** with `p` and `q` handed over, RSA unwraps the AES key, but valid CBC padding only proves the AES layer; the plaintext is still a 3-bit rotation plus a position-dependent XOR mask `(13*i + 0x7a) mod 256`, recovered from a known `=` banner.

- `p*q == N` and `e*d ≡ 1 (mod φ)` checked; raw RSA on the 256-byte block gives AES-256 key `078440dd…a8d7`.
- File layout: 4-byte magic `89 52 57 01`, 2-byte length `0x0100`, 256-byte RSA block, 16-byte IV, 608-byte AES-CBC body.
- AES-256-CBC strips 11 bytes of `0x0b` padding → 597 unreadable bytes.
- `P_i = ROTL8(S_i, 3) XOR K_i` with `K_i = (13*i + 122) mod 256` reveals the report and the master asset key.

## Files

| Path | What it is |
| --- | --- |
| [`writeup.md`](writeup.md) | Full solve |
| [`solve/solve.py`](solve/solve.py) | Stdlib solver: RSA → AES-256-CBC (pure-Python AES) → un-rotate + un-XOR |

## Run the solver

```bash
cd solve
python3 solve.py
```

Expected output ends with:

```text
[+] FLAG: SecLeaf{e4d90b218a754f1c93206e58b1f4a7c2}
```

## Notes

- Verified on the original files: RSA unwraps the AES key from `Quantum_factory.json`'s `p` and `q`, and the ROTL3 + XOR layer gives the flag. The JSON's note blames a "custom S-Box post-processing layer", but the layer is only a rotate and an XOR.
- Before the real run, the solver self-tests: AES-256 known-answer test, the mask formula reproducing the 256-byte XOR key from our CyberChef recipe, the `27 79 ba 5e` → `CLAS` example, and the banner masks at offset 38. All pass.
- The original solve used PARI/GP, offline CyberChef, OpenSSL and `xxd`; the Python solver does the same arithmetic with no dependencies.
- The challenge hint mentioned an S-box layer, but the extra layer was only rotation + XOR; AES itself was standard.

---

[← Back to Quantum Security](../README.md) · [All writeups](../../README.md)
