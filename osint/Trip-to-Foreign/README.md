# Trip to Foreign

![Event](https://img.shields.io/badge/SecLeaf_CTF-2026-101518?style=flat-square)
![Category](https://img.shields.io/badge/Category-OSINT-B4441F?style=flat-square)
![Points](https://img.shields.io/badge/Points-200-2F5D3A?style=flat-square)

> **Solved by** [Shreya](https://github.com/doodleP) · **Team** Bug Busters · **Solved** 1 November 2026, 8:21 am

## Challenge description

> Intelligence gathered from the raided safehouse reveals that the syndicate highcommand spent the entirety of September 2022 lying low in Osaka, Japan. A recovered travel log indicates they leased a single-tenant office floor. The local operatives nicknamed their hideout "川の上昇".
>
> The location was strategically chosen for its tactical advantages. The rental unit occupies an entire floor and overlooks Parking, providing a panoramic vantage point to monitor for incoming threats.
>
> Furthermore, the building is situated just a 4-minute walk from Honmachi Station, ensuring the high-command had an immediate escape route into Osaka's massive subway network.
>
> For their private transport, they kept two luxury vehicles parked at the lot directly across the street. You need to find the exact location of the building.
>
> Note:- Official Website location data only!

**Flag format:** `CRY{xx°xx'xx.x"N_xxx°xx'xx.x"E}`

**Attachments:** none

## Flag

```text
CRY{34°41'05.9"N_135°29'45.3"E}
```

## Writeup

Read the full solve: **[writeup.md](writeup.md)**

**In one line:** the nickname 川の上昇 is a literal Japanese rendering of "River Rise", which, filtered by Osaka + single-tenant floors + Honmachi Station, points to River Rise Utsubo Honmachi Building, whose listing gives the coordinates.

- 川の上昇 → "the rising of (the) river" → building name **River Rise**.
- Narrowed by "single-tenant office floor" and "4-minute walk from Honmachi Station" → River Rise Utsubo Honmachi Building, 1-15-1 Utsubohonmachi, Nishi-ku, Osaka.
- Coordinates taken from the building's listing on Office Navi (`en.office-navi.jp/building/01000144/`), as the "Official Website location data only!" note demands.
- First of a chain: the same building feeds **Riddled Code** (building code `01000144` + parking cost).

## Files

| Path | What it is |
| --- | --- |
| [`writeup.md`](writeup.md) | Full solve |

## Notes

- No offline solver: the solve is search and lookup only.
- Office Navi is a property-listing site rather than the building owner's own page; it is the source we used for "official website location data", and the coordinates were accepted.
- The coordinates must be copied from the listing, not from a map pin: a dropped pin a few metres off changes the tenth-of-a-second digit.
- The brief says the floor "overlooks Parking"; the Office Navi listing and the follow-up challenge describe rooms overlooking **Utsubo Park**. The parking clue is the lot across the street (used in Riddled Code).

---

[← Back to OSINT](../README.md) · [All writeups](../../README.md)
