# Layers

![Event](https://img.shields.io/badge/SecLeaf_CTF-2026-101518?style=flat-square)
![Category](https://img.shields.io/badge/Category-Miscellaneous-B4441F?style=flat-square)
![Points](https://img.shields.io/badge/Points-150-2F5D3A?style=flat-square)

> **Solved by** [Rutwik](https://github.com/Rutwik-712) · **Team** Bug Busters · **Solved** 31 October 2026, 11:42 pm

## Challenge description

A single attachment named `Binary_Data` with no extension, hiding a flag behind
several stacked encodings and one password-protected archive.

> "Layer by layer, we build a strong foundation, adding each step carefully to create something complete and meaningful."

**Flag format:** no wrapper – the recovered value is the raw string (the brief specifies no prefix).

**Attachments:** [`Binary_Data`](attachments/Binary_Data)

## Flag

```text
F1n4lLy_YOu_G0t_1T_!^!
```

## Writeup

Read the full solve: **[writeup.md](writeup.md)**

**In one line:** peel the layers in order – binary → ROT13 (letters only, which
turns `n..s` into `a..f`) → hex → a RAR5 archive opened with `stormstorm` →
ROT47 of the one extracted file.

- `Binary_Data` is 4320 `0`/`1` characters = 540 bytes; decoded as 8-bit bytes it reads like hex with letters shifted to `n..s`.
- ROT13 maps `n,o,p,q,r,s → a,b,c,d,e,f`, producing 540 valid hex chars; hex-decoding gives 270 bytes starting `52 61 72 21 1A 07 01 00` – a RAR5 archive.
- The password `stormstorm` (a wordlist base `storm` + Hashcat's duplicate rule `d`, mode 13000) opens it; `unar` extracts the 22-byte file `Text`.
- ROT47 of `Text` yields the flag; ROT47 is self-inverse, so re-applying it returns the ciphertext – a built-in check.

## Files

| Path | What it is |
| --- | --- |
| [`writeup.md`](writeup.md) | Full solve |
| [`solve/solve.py`](solve/solve.py) | Runs the full chain from `../attachments/Binary_Data`; falls back to verifying the final ROT47 stage from the archived ciphertext |

## Run the solver

```bash
cd solve
python3 solve.py
```

Expected output ends with:

```text
[+] FLAG: F1n4lLy_YOu_G0t_1T_!^!
```

## Notes

- **Category:** the SecLeaf scoreboard showed **no category** for this challenge; we file it under Miscellaneous (encoding / archive analysis).
- Verified on the original `Binary_Data`: the solver runs the whole chain (binary → ROT13 → hex → RAR5 with `stormstorm` → ROT47). It needs `unar` or `7z` on PATH for the RAR step.
- Running the **full** chain needs a RAR5 extractor – `unar` (used during the event), or `7z`, or the Python `rarfile` library with an `unrar` backend. Some `p7zip` builds list the archive but fail extraction with "Unsupported Method"; `unar` handles it.
- The flag has **no wrapper**: the capitalisation, digits, underscores and trailing `!^!` are all part of the recovered value.

---

[← Back to Miscellaneous](../README.md) · [All writeups](../../README.md)
