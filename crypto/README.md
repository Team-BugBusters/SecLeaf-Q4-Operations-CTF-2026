# Cryptography

Lattices, fault attacks, Hensel lifts, birthday trees and the odd encoding chain. The maths is the exploit.

**Team result:** 9 solved · **Points:** 2,725 · **Published writeups:** 9

## Published writeups

| Challenge | Solved by | Points | Solved | Writeup |
| --- | --- | ---: | --- | --- |
| [Fault Atlas](Fault-Atlas/) | [Rutwik](https://github.com/Rutwik-712) | 500 | 1 Nov, 2:03 pm | [read](Fault-Atlas/writeup.md) |
| [Third-Order Forest](Third-Order-Forest/) | [Shreya](https://github.com/doodleP) | 500 | 1 Nov, 7:36 am | [read](Third-Order-Forest/writeup.md) |
| [Eightfold Funeral: Epitaph](Eightfold-Funeral-Epitaph/) | [Rutwik](https://github.com/Rutwik-712) | 500 | 1 Nov, 12:13 am | [read](Eightfold-Funeral-Epitaph/writeup.md) |
| [Signing Shadow: Redshift](Signing-Shadow-Redshift/) | [Rutwik](https://github.com/Rutwik-712) | 500 | 1 Nov, 12:50 am | [read](Signing-Shadow-Redshift/writeup.md) |
| [Nonce Nursery](Nonce-Nursery/) | [Rutwik](https://github.com/Rutwik-712) | 250 | 31 Oct, 3:03 pm | [read](Nonce-Nursery/writeup.md) |
| [Encoded Transmission](Encoded-Transmission/) | [Rutwik](https://github.com/Rutwik-712) | 175 | 1 Nov, 10:38 am | [read](Encoded-Transmission/writeup.md) |
| [Hensel Garden](Hensel-Garden/) | [Rutwik](https://github.com/Rutwik-712) | 100 | 31 Oct, 2:58 pm | [read](Hensel-Garden/writeup.md) |
| [Final Tools](Final-Tools/) | [Ria](https://github.com/ri-Ria-ri) | 100 | 1 Nov, 1:57 pm | [read](Final-Tools/writeup.md) |
| [Tomb Translation](Tomb-Translation/) | [Rutwik](https://github.com/Rutwik-712) | 100 | 1 Nov, 11:12 am | [read](Tomb-Translation/writeup.md) |

## Notes

- `Fault Atlas`: Round-9 single-byte faults leave a MixColumns fingerprint forgeries can't fake; voting recovers the round-10 key, which unwinds to the master key.
- `Third-Order Forest`: HW of an unknown linear map of the S-box output is a sum of 8 Walsh characters, so the Walsh spectrum of third-order class means ranks key guesses without knowing the wiring.
- `Eightfold Funeral: Epitaph`: Wagner's 8-list k-tree cancels 21 bits per level to hit a modular checksum over 16.7M labels.
- `Signing Shadow: Redshift`: The 24-bit stamp is the nonce's top bits plus a constant offset; differences cancel it into a Hidden Number Problem that LLL solves, sampling subsets to dodge 4 decoys.
- `Nonce Nursery`: Five affinely related ECDSA nonces make the private key the common root of two polynomials.
- `Encoded Transmission`: Riddled Code's two numbers joined by two underscores make a 16-byte AES-128-ECB key.
- `Hensel Garden`: Hensel-lift the square roots mod 2^72 and 3^51, CRT them, and the 128-bit bound leaves one seed.
- `Final Tools`: One password in two forms: raw Base65536 opens the outer 7z, its decoded ASCII opens the inner FLAG.zip.
- `Tomb Translation`: Sheikah numerals spell a 124-digit number whose base-36 form is pure hex.

---

[← All writeups](../README.md)
