# Riddled Code – full writeup

[← Back to OSINT](../README.md) · [Challenge overview](README.md)

**Category:** OSINT · **Points:** 200 · **Flag:** `CRY{01000144_984720}`

**Author:** [Rutwik](https://github.com/Rutwik-712) · **Team:** Bug Busters

## TL;DR

1. The riddle wants two numbers: the building's **unique building code** and the **parking cost for two cars** for **September 2022**.
2. The building is River Rise Utsubo Honmachi Building (from *Trip to Foreign*); its Office Navi building code is `01000144`.
3. The lot across the street is Times Utsubohonmachi No. 8. Its September 2022 Street View rate sign gives day and night rates.
4. September 2022 has 24 ordinary dates and 6 Sunday/holiday dates. One car costs 492,360 yen for the month; two cost **984,720**.
5. Flag: `CRY{01000144_984720}`.

## The challenge

> After successfully locating the building - noted for its single-tenant floors overlooking Park - you retrieved a hidden configuration file.
>
> The file was locked, but the hint read: "The key is our sanctuary's unique building code followed by the bleed we paid to the lot for our two shadows in yen in this month of the Harvest Moon." The "sanctuary code" is the building's code where they were staying. To unlock the "Hidden Ruth," you must analyze the riddle and find the key.
>
> Note: Do not use a comma like 10,000. Flag format: CRY{number_number}.

This is a direct sequel to *Trip to Foreign*. Decoding the riddle phrase by phrase:

| Phrase | Meaning | Gives |
| --- | --- | --- |
| "our sanctuary" | the hideout building from *Trip to Foreign* | River Rise Utsubo Honmachi Building |
| "unique building code" | the building's listing identifier | first number |
| "the bleed we paid to the lot" | money paid to the parking lot | parking charges |
| "our two shadows" | the two luxury vehicles parked "directly across the street" | × 2 |
| "in yen" | currency, no comma | integer yen |
| "this month of the Harvest Moon" | the stay – "the entirety of September 2022" – and the Harvest Moon, the full moon nearest the September equinox | September 2022, all 30 days |

"Entirety" matters: the cars are parked for the whole month, so every date contributes a full daytime and a full nighttime period.

Sources we used:

| Source | Purpose |
| --- | --- |
| Office Navi listing | Building name, location, description, building code |
| Google Maps + historical Street View | The lot across the street and its September 2022 rate sign |
| NAOJ 2022 calendar | Sundays and Japanese national holidays in September 2022 |

## Step 1 – The first number: building code `01000144`

The Office Navi record for River Rise Utsubo Honmachi Building (1-15-1 Utsubohonmachi, Nishi-ku, Osaka) describes one tenant per floor and rooms overlooking Utsubo Park – matching "single-tenant floors overlooking Park" in the brief. The listing shows:

```text
Building Code: 01000144
```

It is also the ID in the listing's URL (`en.office-navi.jp/building/01000144/`). We keep it as the string `01000144`: the leading zero is part of an identifier.

## Step 2 – Find the lot and its 2022 prices

In Google Maps we walked the streets around the building in Street View and found the car park across from it: **Times Utsubohonmachi No. 8**.

Parking prices change, and the question is about September 2022. So we did not read today's sign – we switched Street View to its **historical September 2022 capture** and read the rate board from that date.

| Period and day type | Rate / maximum per vehicle |
| --- | --- |
| 07:00–22:00, ordinary Monday–Saturday | 220 yen per 10 minutes, **no daytime maximum** |
| 07:00–22:00, Sundays and public holidays | daytime maximum **1,210 yen** |
| 22:00–07:00, every date | nighttime maximum **330 yen** |

## Step 3 – Classify the 30 days

Which rate applies depends on the day type, so the calendar is part of the answer. From the NAOJ 2022 calendar:

| Day category | Dates | Count |
| --- | --- | ---: |
| Sundays | 4, 11, 18, 25 | 4 |
| Public holidays | 19 (Respect for the Aged Day, Monday), 23 (Autumnal Equinox Day, Friday) | 2 |
| **Sunday or holiday** | | **6** |
| Ordinary (incl. the four Saturdays) | | 30 − 6 = **24** |

Neither holiday fell on a Sunday, so there is no double-counting.

## Step 4 – The second number: parking for two cars

**One ordinary day.** 07:00–22:00 is 15 hours = 900 minutes = 90 ten-minute units, with no cap:

```text
ordinary daytime   = (15 × 60 / 10) × 220 = 90 × 220 = 19800 yen
ordinary full day  = 19800 + 330 (night max)       = 20130 yen
```

**One Sunday/holiday.** The daytime cap of 1,210 yen applies instead of the uncapped 19,800:

```text
Sunday/holiday full day = 1210 + 330 = 1540 yen
```

**The month, per vehicle:**

| Calculation | Yen |
| --- | ---: |
| Ordinary dates: 24 × 20130 | 483120 |
| Sundays and holidays: 6 × 1540 | 9240 |
| One vehicle, full month | 492360 |
| **Two vehicles: 2 × 492360** | **984720** |

**Cross-check** by summing daytime and nighttime separately for one car:

```text
24 × 19800 + 6 × 1210 + 30 × 330 = 475200 + 7260 + 9900 = 492360
```

Same total. In one line:

```text
2 × [24 × (90 × 220 + 330) + 6 × (1210 + 330)] = 984720
```

## Flag

```text
CRY{01000144_984720}
```

## Why this is the right answer

- **Where each number comes from:** `01000144` is the Office Navi building code of the building identified in *Trip to Foreign*; `984720` is the full-month September 2022 parking cost for two vehicles at the lot across the street, at the rates on the September 2022 sign.
- **Two independent sums agree** (per-day totals vs. day/night totals).
- **Format:** `CRY{number_number}`, no thousands separator, leading zero preserved.
- **Downstream confirmation:** these exact two numbers form the key `01000144__984720` that decrypts the message in *Encoded Transmission* – a wrong parking total would have broken that challenge too.
- **Traps avoided:** today's prices instead of 2022's; discounting Saturdays; applying the Sunday cap to every day; forgetting the nightly 330 yen; dropping the leading zero.

## What we learned

- **Preserve identifiers exactly.** `01000144` is a code, not a quantity.
- **Match the evidence to the period.** Historical Street View turns "what did it cost in September 2022?" into something you can read off a sign.
- **The local calendar is data.** Two Japanese public holidays changed the rate on 19 and 23 September; a generic weekday/weekend split misses them.
- **Do the arithmetic two ways.** A second decomposition of the same total catches unit and counting mistakes.

## Reproduce

```bash
cd solve
python3 solve.py
```

The solver embeds the recovered facts (building code, rates, holidays), counts Sundays with Python's `calendar` module, and recomputes both totals. Full script: [`solve/solve.py`](solve/solve.py)

---

[← Back to OSINT](../README.md) · [Challenge overview](README.md)
