# Web

Parameter pollution, race conditions and headers that drip secrets. All targets were live and are now offline.

**Team result:** 3 solved · **Points:** 250 · **Published writeups:** 3

## Published writeups

| Challenge | Solved by | Points | Solved | Writeup |
| --- | --- | ---: | --- | --- |
| [Ledger](Ledger/) | [Rutwik](https://github.com/Rutwik-712) | 100 | 1 Nov, 12:48 pm | [read](Ledger/writeup.md) |
| [Water Hammer](Water-Hammer/) | [Shreya](https://github.com/doodleP) | 100 | 1 Nov, 12:17 am | [read](Water-Hammer/writeup.md) |
| [Slow Leak](Slow-Leak/) | [Ria](https://github.com/ri-Ria-ri) | 50 | 31 Oct, 11:26 pm | [read](Slow-Leak/writeup.md) |

## Notes

- `Ledger`: nginx authorises on the first `view` value while Flask renders the last, so view=public&view=restricted slips through (HPP).
- `Water Hammer`: The voucher check and quota write aren't atomic, so ~30 parallel redemptions all pass and burst the 1000 L valve (TOCTOU).
- `Slow Leak`: The body is a decoy; each response leaks one flag char in X-Drip indexed by X-Drip-Serial n/40.

---

[← All writeups](../README.md)
