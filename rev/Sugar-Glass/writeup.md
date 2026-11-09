# Sugar Glass – full writeup

[← Back to Reverse Engineering](../README.md) · [Challenge overview](README.md)

**Category:** Reverse Engineering · **Points:** 100 · **Flag:** `SecLeaf{gl455_h0ld5_4_53cr3t}`

**Author:** [Vaidik](https://github.com/Vaidik-Makhasana) · **Team:** Bug Busters

## TL;DR

1. `sugar_glass` reads a password, scrambles it through 29 chained rounds and compares one byte per round against a secret table.
2. All constants (length 29, step 11, start 5, initial state 0x42, two 29-byte tables) are in `.rodata`.
3. Each round consumes exactly one input character. Once earlier rounds are solved, that character is the only unknown, so we try all 256 values.
4. 29 rounds × 256 candidates = 7,424 trials, and each round has exactly one hit. The result is the flag.

## The challenge

One file, `sugar_glass`:

```text
$ file sugar_glass
sugar_glass: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,
BuildID[sha1]=dee7ff69228fa259d6c5d2b258e900534ace34e4, stripped
```

Stripped, so no function names. `strings` gives only the line-reading helpers (`strncpy`, `strlen`, `strcspn`) and two messages: `Filed.` and `Rejected.`

The brief teases that glass is easy to break. The name fits the solve: the checker looks solid, but it shatters into 29 independent one-byte pieces.

## Step 1 – Read the result logic first

The disassembly has three parts: read a line, run the check, print a verdict. Tracing the verdict branch shows that **`Filed.` means success** and `Rejected.` means failure. The two words read as if they could mean either, and we nearly discarded a correct attempt because of it. Always trace which message belongs to which branch.

## Step 2 – Recover the checker

The constants in `.rodata`:

| Name | Value | Role |
| --- | --- | --- |
| `SECLEN` | `29` | required password length |
| `K1` | `11` | step between input positions |
| `K2` | `5` | first input position |
| `K3` | `0x42` (66) | initial value of the carried state `edi` |
| `array1` | 29 bytes | secret byte mixed into each round |
| `array2` | 29 bytes | target byte for each round |

```text
array1 = e5 5f b1 5d df ad 9b b9 6e 3f 15 f1 43 dc 40 a5 cd d3 d9 6b 04 21 48 46 52 a4 89 b1 cb
array2 = 7b 7d 34 f7 74 78 b2 56 83 11 29 cb e1 a6 35 40 e5 91 50 29 30 48 47 24 b9 5d 8b 19 b2
```

After checking the length is exactly 29, the loop does this (translated from the assembly; the counters `r9` and `r8` start at `0x39` and `0x5d`):

```c
idx   = esi % SECLEN;          // which input character this round uses
esi  += K1;

value = array1[i] ^ input[idx];
value += edi;                  // carry from the previous round
edi   = rotate_low_byte(value, 3);

mixed = edi ^ counter;         // counter (r9) starts at 0x39
mixed = rotate_low_byte(mixed, 1);
running_total += mixed;        // r8, starts at 0x5d
counter += 17;

passed = (array2[i] == (running_total & 0xff));
```

Three details matter:

- **Scrambled read order.** Round `i` reads position `(5 + 11*i) mod 29`, so the characters are consumed out of order: 5, 16, 27, 9, 20, …
- **Chaining.** `edi` and the running total carry into the next round, so round 5 can only be computed after rounds 1–4 are correct.
- **32-bit registers.** Only the low byte is rotated. The upper bits and the carry from the addition survive into the next round. Our first attempts truncated to 8 bits too early and produced wrong results.

## Step 3 – Why one byte at a time works

Algebraically undoing the rounds is possible (XOR, add and rotate are all reversible), but the 32-bit carries make the formulas messy. There is a simpler route.

Each round checks **its own** target byte `array2[i]`, and each round adds **only one** new unknown: the character at `idx`. Everything else in the round (`edi`, `r8`, `r9`, `array1[i]`) is already fixed by the earlier rounds. So the per-round comparison works like an oracle for one character:

```text
whole password at once:   256^29 ≈ 2^232 candidates   (hopeless)
one character per round:  29 × 256 = 7,424 trials     (instant)
```

The answer is also unique. For a fixed state, the low byte of the running total is a bijection of the input byte (XOR, add, rotate, XOR, rotate and add are each one-to-one on 8 bits), so exactly one of the 256 candidates matches each round. Our solver asserts this.

## Step 4 – Run it

```python
for i in range(SECLEN):
    idx = esi % SECLEN
    esi = (esi + K1) & MASK32
    for x in range(256):
        new_edi, new_r8 = round_step(x, array1[i], edi, r9, r8)
        if new_r8 & 0xff == array2[i]:
            edi, r8 = new_edi, new_r8
            r9 = (r9 + 0x11) & MASK32
            result[idx] = x
            break
```

```text
$ python3 solve.py
...
[+] FLAG: SecLeaf{gl455_h0ld5_4_53cr3t}
```

## Flag

```text
SecLeaf{gl455_h0ld5_4_53cr3t}
```

## Why this is the right answer

- **Every round has exactly one match**, so there was no choice to make and no ambiguity in the result.
- **All 29 positions are filled**: the step 11 is coprime to 29, so `(5 + 11*i) mod 29` visits every index exactly once.
- **Format and meaning**: the output is printable, 29 characters, `SecLeaf{...}`, and reads as leetspeak for "glass holds a secret", matching the challenge theme.

## What we learned

- **Trace the verdict, not the wording.** `Filed.` sounded like a failure; the branch said otherwise.
- **Per-step comparisons leak per-step answers.** If a checker compares an intermediate value every round, each round can be solved on its own and the search becomes additive instead of multiplicative.
- **Respect register widths.** Rotating only the low byte of a 32-bit register keeps the carry alive; emulate exactly, then truncate.
- **Check where input is read from.** The read order was `(5 + 11*i) mod 29`, not left to right.

## Reproduce

```bash
cd solve
python3 solve.py
```

Full solver: [`solve/solve.py`](solve/solve.py)

---

[← Back to Reverse Engineering](../README.md) · [Challenge overview](README.md)
