# Tomb Translation

![Event](https://img.shields.io/badge/SecLeaf_CTF-2026-101518?style=flat-square)
![Category](https://img.shields.io/badge/Category-Cryptography-B4441F?style=flat-square)
![Points](https://img.shields.io/badge/Points-100-2F5D3A?style=flat-square)

> **Solved by** [Rutwik](https://github.com/Rutwik-712) · **Team** Bug Busters · **Solved** 1 November 2026, 11:12 am

## Challenge description

> "Something was written on the walls of an old tomb."
>
> "You just need to figure out what it says."

**Flag format:** `SecLeaf{...}`

**Attachments:** five inscription panels – [`panel_1.png`](attachments/panel_1.png) · [`panel_2.png`](attachments/panel_2.png) · [`panel_3.png`](attachments/panel_3.png) · [`panel_4.png`](attachments/panel_4.png) · [`panel_5.png`](attachments/panel_5.png) (recovered from our writeup document; original filenames not recorded)

## Flag

```text
SecLeaf{l1nk_1s_st1ll_l00k1ng_f0r_z3ld4}
```

## Writeup

Read the full solve: **[writeup.md](writeup.md)**

**In one line:** the glyphs are Sheikah *numerals*, and the 124-digit number they spell is the flag in disguise – written in base 36 it uses only `0–9a–f`, i.e. it is hex for `SecLeaf{…}`.

- Five panels of Sheikah numerals (25 + 25 + 25 + 25 + 24 = 124 digits), read left-to-right, top-to-bottom, in panel order.
- Panel 3 starts with `0`; joining as text keeps it.
- Decimal → base 36 gives 80 characters, all hex digits, starting `5365634c6561667b` (`SecLeaf{`).
- Hex → 40 ASCII bytes: the flag. Every conversion was checked in reverse.

## Files

| Path | What it is |
| --- | --- |
| [`writeup.md`](writeup.md) | Full solve |
| [`attachments/`](attachments/) | The five inscription panels |
| [`solve/solve.py`](solve/solve.py) | Transcribed digits → base 36 → hex → ASCII, with inverse checks |

## Run the solver

```bash
cd solve
python3 solve.py
```

Expected output ends with:

```text
[+] FLAG: SecLeaf{l1nk_1s_st1ll_l00k1ng_f0r_z3ld4}
```

## Notes

- The glyph reading is a manual step (dCode's Sheikah chart); the solver starts from our transcribed digits.
- Panel order follows the order the images were provided (and embedded in our notes). It is consistent with the transcription: `panel_5.png` is the only panel with a shorter third row (24 glyphs), and `panel_4.png` opens with two identical glyphs (`55…`).
- Use arbitrary-precision integers. A 124-digit number does not survive a float conversion.

---

[← Back to Cryptography](../README.md) · [All writeups](../../README.md)
