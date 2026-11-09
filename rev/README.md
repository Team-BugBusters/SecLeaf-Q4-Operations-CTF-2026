# Reverse Engineering

Custom VMs, custom ISAs and checkers that leak one byte at a time.

**Team result:** 5 solved · **Points:** 1,850 · **Published writeups:** 5

## Published writeups

| Challenge | Solved by | Points | Solved | Writeup |
| --- | --- | ---: | --- | --- |
| [Maintainer of None](Maintainer-of-None/) | [Vaidik](https://github.com/Vaidik-Makhasana) | 500 | 1 Nov, 9:39 am | [read](Maintainer-of-None/writeup.md) |
| [Blackout Protocol](Blackout-Protocol/) | [Vaidik](https://github.com/Vaidik-Makhasana) | 500 | 31 Oct, 10:50 pm | [read](Blackout-Protocol/writeup.md) |
| [Null Choir](Null-Choir/) | [Vaidik](https://github.com/Vaidik-Makhasana) | 500 | 31 Oct, 4:34 pm | [read](Null-Choir/writeup.md) |
| [Dead Letter Office](Dead-Letter-Office/) | [Vaidik](https://github.com/Vaidik-Makhasana) | 250 | 31 Oct, 4:09 pm | [read](Dead-Letter-Office/writeup.md) |
| [Sugar Glass](Sugar-Glass/) | [Vaidik](https://github.com/Vaidik-Makhasana) | 100 | 31 Oct, 3:15 pm | [read](Sugar-Glass/writeup.md) |

## Notes

- `Maintainer of None`: Three chained verifiers each accept a witness extending the previous one; history picks the DB rows and Gaussian elimination mod 65521 solves the blinded systems.
- `Blackout Protocol`: Memory gives the seeds, the FNV-1a-checked journal and checksum-filtered PCAP give the 384-byte table; together they rebuild the verifier's 52-round transform.
- `Null Choir`: The target state is input-independent, so dump the decoded program and final state with GDB and run the reversible VM backwards.
- `Dead Letter Office`: The binary hides the postcard's key seed and walk parameters behind a DLO2 marker; invert its 14-round byte-pair Feistel and walk the records in order.
- `Sugar Glass`: The checker compares one byte per round and each round adds one unknown character, so the password falls out byte by byte (7,424 tries, not 256^29).

---

[← All writeups](../README.md)
