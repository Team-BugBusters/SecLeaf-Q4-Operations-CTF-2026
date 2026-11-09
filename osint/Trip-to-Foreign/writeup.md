# Trip to Foreign – full writeup

[← Back to OSINT](../README.md) · [Challenge overview](README.md)

**Category:** OSINT · **Points:** 200 · **Flag:** `CRY{34°41'05.9"N_135°29'45.3"E}`

**Author:** [Shreya](https://github.com/doodleP) · **Team:** Bug Busters

## TL;DR

1. Translate the hideout's nickname 川の上昇: "the rising of (the) river" – i.e. **River Rise**.
2. Combine with the other hard constraints: Osaka, single-tenant office floors, 4 minutes on foot from Honmachi Station.
3. Only **River Rise Utsubo Honmachi Building** fits all of them.
4. Read the coordinates from its Office Navi listing – `34°41'05.9"N`, `135°29'45.3"E` – and drop them into the flag format.

## The challenge

> Intelligence gathered from the raided safehouse reveals that the syndicate highcommand spent the entirety of September 2022 lying low in Osaka, Japan. A recovered travel log indicates they leased a single-tenant office floor. The local operatives nicknamed their hideout "川の上昇".
>
> The location was strategically chosen for its tactical advantages. The rental unit occupies an entire floor and overlooks Parking, providing a panoramic vantage point to monitor for incoming threats.
>
> Furthermore, the building is situated just a 4-minute walk from Honmachi Station, ensuring the high-command had an immediate escape route into Osaka's massive subway network.
>
> For their private transport, they kept two luxury vehicles parked at the lot directly across the street. You need to find the exact location of the building.
>
> Note:- Official Website location data only!

Flag format: `CRY{xx°xx'xx.x"N_xxx°xx'xx.x"E}` – degrees, minutes and seconds to one decimal.

Each sentence is a filter. Pulled out:

| Clue | What it constrains |
| --- | --- |
| Osaka, Japan | City |
| "川の上昇" | The building's name |
| Single-tenant office floor, entire floor | Building type – one tenant per floor |
| Overlooks a park/parking, panoramic view | Open space in front of the building |
| 4-minute walk from Honmachi Station | Neighbourhood |
| Two vehicles in the lot across the street | Not needed here – it is the hook for the follow-up challenge *Riddled Code* |
| "Official Website location data only!" | Where the coordinates must come from |
| September 2022 | Not needed here – used in *Riddled Code* |

Because the brief over-supplies details (the cars, the month), we read Trip to Foreign and Riddled Code together from the start.

## Step 1 – Decode the nickname

川 is "river"; 上昇 is "rise / ascent". Translated, the nickname reads **"The Rising of River"**. That is an awkward phrase in both languages – which is the point: it is a word-for-word Japanese rendering of an English building name, **River Rise**. Japanese office buildings frequently carry English names, so the nickname is really a name lookup in disguise.

## Step 2 – Find the building

We searched with the combined keywords – Osaka, "River Rise", single-tenant office building – which returned a handful of candidates. The Honmachi Station constraint ("4-minute walk") cut the list down to one:

**River Rise Utsubo Honmachi Building** – 1-15-1 Utsubohonmachi, Nishi-ku, Osaka.

Every clue now lines up:

- the name contains "River Rise",
- the listing describes one tenant per floor,
- rooms overlook Utsubo Park (the open view from the brief),
- it sits a few minutes from Honmachi Station.

## Step 3 – Take the coordinates from the listing

The note "Official Website location data only!" rules out dropping a pin on a map: at this precision (tenths of an arc-second, roughly 3 m) a pin placed by hand would almost certainly change a digit. We used the coordinates published on the building's listing page on Office Navi:

```text
https://en.office-navi.jp/building/01000144/
```

| | Value |
| --- | --- |
| Latitude | `34°41'05.9"N` |
| Longitude | `135°29'45.3"E` |

These drop straight into the template `xx°xx'xx.x"N_xxx°xx'xx.x"E` with no conversion. (For cross-checking on a map: 34°41'05.9" ≈ 34.68497° and 135°29'45.3" ≈ 135.49592°.)

The listing URL's ID, `01000144`, is the building code – the first half of the Riddled Code flag.

## Flag

```text
CRY{34°41'05.9"N_135°29'45.3"E}
```

## Why this is the right answer

- **Every clue is satisfied by one building**: name (River Rise), type (single tenant per floor), view (Utsubo Park), access (Honmachi Station).
- **Format match:** two-digit latitude degrees, three-digit longitude degrees, seconds to one decimal, `N` / `E`, joined with `_` – exactly the template's shape.
- **The data source matches the note**: coordinates copied from the listing, not estimated from a map.
- **The chain holds**: the same listing supplies building code `01000144`, and the lot across the street supplies the parking rates, which together produce the accepted Riddled Code flag `CRY{01000144_984720}`.

## What we learned

- **Literal translations are disguised names.** An awkward machine-style phrase like "The Rising of River" usually means "reverse it into the English proper noun".
- **Stack constraints, don't search one at a time.** Name + building type + station distance together reduce a city to one building.
- **Respect the stated data source.** At tenth-of-a-second precision, the source of the coordinates *is* the answer.
- **Read linked challenges together.** Details irrelevant here (two cars, September 2022) were exactly what the next challenge needed.

## Reproduce

No solver – the steps are lookups:

1. Translate 川の上昇 → "River Rise".
2. Search Osaka office buildings named River Rise near Honmachi Station → River Rise Utsubo Honmachi Building.
3. Open `https://en.office-navi.jp/building/01000144/` and read the published coordinates.
4. Format as `CRY{34°41'05.9"N_135°29'45.3"E}`.

---

[← Back to OSINT](../README.md) · [Challenge overview](README.md)
