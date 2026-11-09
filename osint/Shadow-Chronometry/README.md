# Shadow Chronometry

![Event](https://img.shields.io/badge/SecLeaf_CTF-2026-101518?style=flat-square)
![Category](https://img.shields.io/badge/Category-OSINT-B4441F?style=flat-square)
![Points](https://img.shields.io/badge/Points-100-2F5D3A?style=flat-square)

> **Solved by** [Rutwik](https://github.com/Rutwik-712) · **Team** Bug Busters · **Solved** 31 October 2026, 4:24 pm

## Challenge description

We were given a photograph of a landmark and asked for its geographic coordinates, written as latitude and longitude to four decimal places.

*Brief reconstructed from the solve notes; the original text was not archived.*

**Flag format:** `SecLeaf{latitude,longitude}` (4 decimal places)

**Attachments:** [`shadow_chronometry.jpg`](attachments/shadow_chronometry.jpg)

## Flag

```text
SecLeaf{-34.6038,-58.3817}
```

## Writeup

Read the full solve: **[writeup.md](writeup.md)**

**In one line:** a famous landmark is a solved problem for reverse image search, so the real work is the last step – truncating, not rounding, the published coordinates to four decimals.

- Reverse image search (Google Lens) identified the landmark as the **Obelisk of Buenos Aires**, Argentina.
- Published coordinates: `-34.603851`, `-58.381775`.
- Truncated to 4 dp: `-34.6038`, `-58.3817`. Rounding would give `-34.6039`, `-58.3818` – both digits differ.
- Southern and western hemispheres → both values negative.

## Files

| Path | What it is |
| --- | --- |
| [`writeup.md`](writeup.md) | Full solve |
| [`solve/solve.py`](solve/solve.py) | Formats the coordinates: truncation vs. rounding, prints the flag |

## Run the solver

```bash
cd solve
python3 solve.py
```

Expected output ends with:

```text
[+] FLAG: SecLeaf{-34.6038,-58.3817}
```

## Notes

- The landmark identification is a manual step; the solver only reproduces the formatting.
- `SecLeaf{-34.6039,-58.3818}` (rounded) is the obvious wrong answer – 4 decimal places here means "cut", not "round".
- The photo (4320 × 3240 JPEG) carries no EXIF or GPS data, so the identification has to come from the picture itself: a tall obelisk, an Argentine flag, and Itaú and Panamericana signs on the buildings around it.

---

[← Back to OSINT](../README.md) · [All writeups](../../README.md)
