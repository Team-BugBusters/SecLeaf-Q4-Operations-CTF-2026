# Dead Letter Office

![Event](https://img.shields.io/badge/SecLeaf_CTF-2026-101518?style=flat-square)
![Category](https://img.shields.io/badge/Category-Reverse_Engineering-B4441F?style=flat-square)
![Points](https://img.shields.io/badge/Points-250-2F5D3A?style=flat-square)

> **Solved by** [Vaidik](https://github.com/Vaidik-Makhasana) · **Team** Bug Busters · **Solved** 31 October 2026, 4:09 pm

## Challenge description

> "I sent a very important letter. It never arrived. Typical."
>
> "Anyways, you're the post office now. Go find it. No refunds btw."

**Flag format:** `SecLeaf{...}`

**Attachments:** [`dead_letter_office`](attachments/dead_letter_office) · [`postcard.grid`](attachments/postcard.grid)

## Flag

```text
SecLeaf{th3_p0st0ff1c3_h4s_4_d4rk_s1d3!}
```

## Writeup

Read the full solve: **[writeup.md](writeup.md)**

**In one line:** the binary carries everything needed to open the postcard – a key seed and walk parameters behind a `DLO2` marker in `.rodata` – so we re-implemented its 14-round byte-pair cipher, walked the 20 records in its scrambled order and undid each pair.

- `postcard.grid` is a custom `HPL2` file: 40-byte message, 20 four-byte records, FNV-1a checksum `0x41cbd9ec`, initial state `0x39c6`.
- `DLO2` is followed by an 8-byte seed (key `20 2f 57 4d bc 50 10 a4` after derivation) and `07 07 0e` = start 7, step 7, 14 rounds.
- Records are read in the order 7, 14, 1, 8, … 13, 0, not sequentially.
- The binary confirmed the recovered message with `Delivered.`

## Files

| Path | What it is |
| --- | --- |
| [`writeup.md`](writeup.md) | Full solve |
| [`solve/solve.py`](solve/solve.py) | Parses `HPL2`, checks FNV-1a, derives the key from the ELF, walks and decodes all 20 records |
| [`solve/verify.sh`](solve/verify.sh) | Feeds the recovered flag to the original binary (expects `Delivered.`) |

## Run the solver

```bash
cd solve
python3 solve.py
```

Expected output ends with:

```text
[+] FLAG: SecLeaf{th3_p0st0ff1c3_h4s_4_d4rk_s1d3!}
```

## Notes

- Verified on the original `postcard.grid` (checksum OK, key `20 2f 57 4d bc 50 10 a4`, record order 7, 14, 1, …). The Python solver doesn't run the ELF, so it works on any OS.
- **Cross-checked with the original binary:** `bash solve/verify.sh` prints `Returned to sender.` for a wrong flag and `Delivered.` for the recovered one (in Docker on non-Linux hosts).
- The solver is **reconstructed from the disassembly** of `dead_letter_office`; it is not the challenge author's source.
- During the event each pair was brute-forced over 65,536 candidates. The cleaned-up solver inverts the Feistel-style rounds directly and checks every pair by re-running the forward transform.

---

[← Back to Reverse Engineering](../README.md) · [All writeups](../../README.md)
