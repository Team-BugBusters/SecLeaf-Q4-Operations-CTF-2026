# Shadow Chronometry – full writeup

[← Back to OSINT](../README.md) · [Challenge overview](README.md)

**Category:** OSINT · **Points:** 100 · **Flag:** `SecLeaf{-34.6038,-58.3817}`

**Author:** [Rutwik](https://github.com/Rutwik-712) · **Team:** Bug Busters

## TL;DR

1. The challenge is a single landmark photo; the flag is its coordinates to 4 decimal places.
2. Reverse image search identifies it as the **Obelisk of Buenos Aires**, Argentina.
3. Its published coordinates are `-34.603851, -58.381775`.
4. **Truncate** (don't round) to four decimals: `SecLeaf{-34.6038,-58.3817}`.

## The challenge

We were given an image of a landmark and had to find its geographic coordinates. Format: `SecLeaf{latitude,longitude}`, four decimal places.

The name is the hint. *Shadow chronometry* is telling time by shadows – a sundial. An obelisk is the classic sundial pointer (gnomon): tall, thin and freestanding, the shape whose shadow marks the hour. So the name points at the kind of monument before you even open the image. (We did not need this to solve it, but it is a useful sanity check on the identification.)

## Step 1 – Identify the landmark

We ran the image through Google Lens.

**Why reverse image search works here.** Services like Lens do not match pixels; they turn the image into a compact visual "fingerprint" (an embedding) and look for the nearest fingerprints among billions of indexed photos. A world-famous monument has been photographed from every angle and in every light, so a new photo of it lands right next to thousands of labelled ones – and the label wins by majority. That is why landmark identification is the easiest kind of reverse image search, and why a 100-point challenge can rely on it.

Lens returned the **Obelisk of Buenos Aires** (Obelisco de Buenos Aires), in Buenos Aires, Argentina.

The photo (`attachments/shadow_chronometry.jpg`) has no EXIF or GPS data, so the picture is the only evidence. It shows a tall, plain obelisk with a pointed tip, an Argentine flag on a pole beside it, and Itaú and Panamericana signs on the buildings along the avenue, all consistent with the Obelisco on Avenida 9 de Julio.

## Step 2 – Confirm it independently

One search engine's top hit is a lead, not proof. Ways to confirm without trusting Lens:

- **Compare against reference photos.** Search the name directly and compare the challenge image with known photographs of the monument – overall form, proportions, surroundings – rather than relying on Lens's label.
- **Check the type against the name hint.** The result is an obelisk, which is exactly what "shadow chronometry" (a sundial's gnomon) suggests.
- **Check the coordinates land on it.** Paste the coordinates from Step 3 into a map and confirm the pin sits on the monument itself (the Obelisco stands in Plaza de la República, at the crossing of Avenida 9 de Julio and Avenida Corrientes), not somewhere nearby.

## Step 3 – Get the coordinates

Searching for the Obelisk's coordinates gave:

| | Value |
| --- | --- |
| Latitude | `-34.603851` |
| Longitude | `-58.381775` |

Both are negative: Buenos Aires is south of the equator (negative latitude) and west of Greenwich (negative longitude). Dropping a sign would put the answer in the wrong hemisphere.

## Step 4 – Four decimal places: truncate, not round

The flag needs exactly four decimals. There are two ways to get there, and they disagree **on both coordinates**:

| Value | Truncated (drop digits) | Rounded (half-up) |
| --- | --- | --- |
| `-34.603851` | `-34.6038` | `-34.6039` (5th digit is 5) |
| `-58.381775` | `-58.3817` | `-58.3818` (5th digit is 7) |

So the format detail decides the flag:

```text
truncated: SecLeaf{-34.6038,-58.3817}   <- accepted
rounded:   SecLeaf{-34.6039,-58.3818}   <- different string, both values off by one in the last digit
```

We truncated – kept the first four decimals and dropped the rest. For negative numbers that means cutting *toward zero* (`-34.603851` → `-34.6038`), not flooring (which would give `-34.6039`).

Why truncation is the natural reading: "four decimal places" with coordinates usually means "the first four digits after the point", the way a reference value is copied, not re-rounded. Four decimals is about 11 m of latitude – finer than the size of the plaza – so either choice points at the same spot on the ground, but only one gives the exact flag string.

A tiny script shows both:

```python
from decimal import Decimal, ROUND_DOWN, ROUND_HALF_UP
q = Decimal("0.0001")
for v in (Decimal("-34.603851"), Decimal("-58.381775")):
    print(v.quantize(q, ROUND_DOWN), v.quantize(q, ROUND_HALF_UP))
# -34.6038 -34.6039
# -58.3817 -58.3818
```

(`ROUND_DOWN` in Python's `decimal` means "toward zero", which is truncation.)

## Flag

```text
SecLeaf{-34.6038,-58.3817}
```

## Why this is the right answer

- **Identification:** reverse image search named the Obelisk of Buenos Aires, consistent with the "shadow / sundial" hint in the challenge name.
- **Coordinates:** the published values `-34.603851, -58.381775` place it in Buenos Aires (southern, western hemispheres → both negative).
- **Formatting:** truncated to exactly four decimals, comma-separated, no spaces, inside `SecLeaf{}`.
- **Decoy ruled out:** the rounded version `-34.6039,-58.3818` is the tempting wrong string; it differs in the last digit of both values.

## What we learned

- **Famous landmarks are easy for reverse image search** – the effort belongs in verifying the hit and getting the format exactly right.
- **Truncation and rounding are different answers.** Whenever the next digit is 5 or more, they disagree; check both and read the format note carefully.
- **Signs carry the hemisphere.** South and west are negative in decimal degrees.
- **Challenge names are hints.** "Shadow chronometry" → sundial → obelisk.

## Reproduce

1. Reverse image search the challenge photo → Obelisk of Buenos Aires.
2. Look up its coordinates → `-34.603851, -58.381775`.
3. Truncate to four decimals and format:

```bash
cd solve
python3 solve.py
```

Full script: [`solve/solve.py`](solve/solve.py)

---

[← Back to OSINT](../README.md) · [Challenge overview](README.md)
