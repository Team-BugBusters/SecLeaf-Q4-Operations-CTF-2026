# Sugar Glass

![Event](https://img.shields.io/badge/SecLeaf_CTF-2026-101518?style=flat-square)
![Category](https://img.shields.io/badge/Category-Reverse_Engineering-B4441F?style=flat-square)
![Points](https://img.shields.io/badge/Points-100-2F5D3A?style=flat-square)

> **Solved by** [Vaidik](https://github.com/Vaidik-Makhasana) · **Team** Bug Busters · **Solved** 31 October 2026, 3:15 pm

## Challenge description

> "It's glass. How hard could it possibly be to break?"
>
> "Famous last words, probably."

**Flag format:** `SecLeaf{...}`

**Attachments:** [`sugar_glass`](attachments/sugar_glass)

## Flag

```text
SecLeaf{gl455_h0ld5_4_53cr3t}
```

## Writeup

Read the full solve: **[writeup.md](writeup.md)**

**In one line:** the checker compares one target byte per round and each round adds exactly one unknown character to a known state, so the 29-character password falls out one byte at a time: 29 × 256 trials instead of 256^29.

- `sugar_glass` is a stripped x86-64 ELF password checker; all of its constants sit in `.rodata`.
- The password must be 29 characters. Each round reads input position `(5 + 11*i) mod 29` and checks a running total against `array2[i]`.
- With the state carried over from earlier rounds, every round has exactly one matching character.
- Gotcha: `Filed.` is the success message and `Rejected.` the failure message.

## Files

| Path | What it is |
| --- | --- |
| [`writeup.md`](writeup.md) | Full solve |
| [`solve/solve.py`](solve/solve.py) | Re-implements the checker with the extracted constants and recovers the password one character per round |
| [`solve/verify.sh`](solve/verify.sh) | Feeds the flag to the original `sugar_glass` binary (Linux x86-64, or Docker) |

## Run the solver

```bash
cd solve
python3 solve.py
```

Expected output ends with:

```text
[+] FLAG: SecLeaf{gl455_h0ld5_4_53cr3t}
```

## Notes

- The solver needs no attachments: the 29-byte `array1` / `array2` tables and the start constants are embedded. Both tables were found byte-for-byte in `attachments/sugar_glass` (`.rodata`).
- `solve/verify.sh` feeds the recovered flag to the original binary: it prints `Filed.`, and a wrong flag prints `Rejected.`.
- The checker's registers are 32-bit and only the low byte is rotated. Truncating to 8 bits too early breaks the carry into the next round.

---

[← Back to Reverse Engineering](../README.md) · [All writeups](../../README.md)
