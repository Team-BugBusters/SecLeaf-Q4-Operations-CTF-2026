# Riddled Code

![Event](https://img.shields.io/badge/SecLeaf_CTF-2026-101518?style=flat-square)
![Category](https://img.shields.io/badge/Category-OSINT-B4441F?style=flat-square)
![Points](https://img.shields.io/badge/Points-200-2F5D3A?style=flat-square)

> **Solved by** [Rutwik](https://github.com/Rutwik-712) · **Team** Bug Busters · **Solved** 1 November 2026, 10:29 am

## Challenge description

> After successfully locating the building - noted for its single-tenant floors overlooking Park - you retrieved a hidden configuration file.
>
> The file was locked, but the hint read: "The key is our sanctuary's unique building code followed by the bleed we paid to the lot for our two shadows in yen in this month of the Harvest Moon." The "sanctuary code" is the building's code where they were staying. To unlock the "Hidden Ruth," you must analyze the riddle and find the key.
>
> Note: Do not use a comma like 10,000. Flag format: CRY{number_number}.

**Flag format:** `CRY{number_number}`

**Attachments:** none

## Flag

```text
CRY{01000144_984720}
```

## Writeup

Read the full solve: **[writeup.md](writeup.md)**

**In one line:** the riddle asks for two numbers – the building's listing code and a whole month of parking for two cars – and the parking total is only right if every date is priced by the 2022 rate sign *and* the Japanese holiday calendar.

- **First number, `01000144`:** the building code of River Rise Utsubo Honmachi Building on Office Navi (the building found in *Trip to Foreign*).
- **Second number, `984720`:** two vehicles × September 2022 at Times Utsubohonmachi No. 8, the lot across the street, priced from its September 2022 Street View rate sign.
- September 2022 = 24 ordinary dates (20,130 yen/day) + 4 Sundays + 2 public holidays (1,540 yen/day) → 492,360 yen per car.
- 2 × 492,360 = **984,720**, written without the comma.

## Files

| Path | What it is |
| --- | --- |
| [`writeup.md`](writeup.md) | Full solve |
| [`solve/solve.py`](solve/solve.py) | Classifies the dates of September 2022 and recomputes the parking total from the recorded rates |

## Run the solver

```bash
cd solve
python3 solve.py
```

Expected output ends with:

```text
[+] FLAG: CRY{01000144_984720}
```

## Notes

- The OSINT inputs (building code, rate sign, holidays) are embedded in the solver as constants; only the calendar check and arithmetic are automated.
- Keep the leading zero in `01000144` – it is an identifier, not a number.
- Saturdays are ordinary-rate days; only Sundays and public holidays get the 1,210 yen daytime cap. Treating Saturdays as discounted, or applying the cap to every date, gives a wrong total.
- The two numbers are reused downstream: *Encoded Transmission* uses `01000144__984720` as its AES key.
- "Hidden Ruth" is quoted verbatim from the brief (presumably "Hidden Truth").

---

[← Back to OSINT](../README.md) · [All writeups](../../README.md)
