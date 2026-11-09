# Null Choir – full writeup

[← Back to Reverse Engineering](../README.md) · [Challenge overview](README.md)

**Category:** Reverse Engineering · **Points:** 500 · **Flag:** `SecLeaf{th3_ch01r_s1ng5_1n_5h4d0w_m4ch1n35!!!!!}`

**Author:** [Vaidik](https://github.com/Vaidik-Makhasana) · **Team:** Bug Busters

## TL;DR

1. `null_choir` is a stripped VM interpreter. `canticle.score` holds 4,096 encrypted, shuffled instructions plus the target state; `echoes.trace` feeds the key derivation.
2. The 48-character input becomes six 64-bit words, is scrambled with the key, run through the VM (with a diffusion step every 64 instructions) and compared to a target.
3. The target state does **not** depend on the input. So the problem is not "find an input" but "run the machine backwards from a known end state".
4. GDB dumped the decoded instructions, the final state and the key `0x866a952e86bb7d8b` from one run on a dummy input; every VM operation is reversible.
5. Running the program in reverse and undoing the scrambler gave the flag; the binary prints `Harmony.`.

## The challenge

> "I wanted to make a difficult reversing challenge."
>
> "I think I may have overdone it a little (again :<). Anyways, enjoy the concert. The screaming is complimentary :)"

The theme carries through every file name: a *choir* (the VM) sings a *canticle* (the instruction score) shaped by *echoes* (the key trace). The author warning that it is "overdone" is a hint that brute force is not the intended path.

Three files:

| File | Magic | What it turned out to be |
| --- | --- | --- |
| `null_choir` | ELF | Stripped, dynamically linked x86-64 interpreter |
| `canticle.score` | `NCS2` | Encrypted VM program + target state |
| `echoes.trace` | `ECH8` | 16-byte records used to derive the key |

`strings null_choir` showed the plumbing immediately:

```text
canticle.score
echoes.trace
Harmony.
Dissonance.
NCH2
```

`Harmony.` / `Dissonance.` are the success and failure messages. The binary also checks the score's size: `0x100 + 0x30 × 4096 = 0x30100` bytes – a 0x100-byte header followed by 4,096 slots of 0x30 bytes – and the real file is exactly 196,864 bytes (`0x30100`). Finally, a **24-entry jump table** in the disassembly said this was a bytecode VM with 24 opcodes, not a password compare.

## Step 1 – Recovering the program's shape

With no symbols, we read the disassembly (`objdump -d -M intel null_choir`) and used GDB. The program does five things:

1. Read and validate `canticle.score` and `echoes.trace`.
2. Derive a key from `echoes.trace`.
3. Mask (scramble) the input.
4. Execute 4,096 encrypted VM instructions.
5. Compare the final state with a target.

The input must be **exactly 48 characters**. They are loaded as six little-endian 64-bit words – the VM's entire state.

## Step 2 – How the key is made

`echoes.trace` contains 16-byte records beginning with `EC`. A record is accepted only if:

- its third byte matches a specific byte in the score header,
- its fourth byte is an unused slot number in `0..31`,
- the FNV-1a hash of the record equals its last four bytes.

Accepted records fill a 32-slot array. SplitMix-style mixing over that array, combined with constants from the file headers, produces the 64-bit runtime key held in `rbp`:

```text
rbp = 0x866a952e86bb7d8b
```

Records that fail the header-byte, slot or hash checks never reach the array, so junk in the trace cannot influence the key. None of this depends on the user's input – which becomes important in Step 5.

## Step 3 – How the VM runs

**Input scrambling.** Each of the six input words is XORed with key material, passed through the SplitMix64 finaliser and rotated; the rotation amount depends on the word's position.

**Instruction fetch.** For each of the 4,096 steps the VM:

- picks the next instruction slot through a Feistel-like permutation (so execution order is shuffled relative to file order),
- decrypts it with a generated keystream,
- validates its fields,
- extracts opcode selector, destination register, source register, rotation amount and immediate,
- dispatches to one of **24 handlers** – add, subtract, XOR, rotate, byte permutation, bit permutation, register permutation and SplitMix-based mixes.

**Diffusion.** After every 64 instructions, a diffusion step mixes all six words together, so every instruction's effect spreads to the whole state.

**Check.** After 4,096 steps the state is compared to a target computed from `canticle.score`, the key and other constants.

## Step 4 – The insight: the target ignores the input

Searching 48 characters through 4,096 instructions with periodic diffusion is hopeless. But the target in the final comparison is built only from the score file, the key and constants – **never from the input**. That turns the problem around:

- the end state is fixed and observable,
- the program (once decrypted) is fixed and observable,
- each operation is a bijection on the state.

Every handler type has an exact inverse:

| Forward | Inverse |
| --- | --- |
| `x ^= v` | `x ^= v` |
| `x += v` | `x -= v` |
| `rotl(x, r)` | `rotr(x, r)` |
| byte / bit / register permutation | the inverse permutation |
| diffusion every 64 steps | inverse diffusion at the same points |
| input scrambler (XOR → SplitMix64 finaliser → rotate) | rotate back → inverse finaliser → XOR |

So the input is simply: start from the target, run the decoded program backwards (undoing diffusion at each 64-instruction boundary), then undo the scrambler.

## Step 5 – Letting GDB do the decryption

Re-implementing the key derivation, Feistel shuffle and keystream would be a lot of code to get exactly right. The binary already does all of it, and – crucially – none of it depends on the input being correct. So we let the binary decrypt its own program and recorded the results.

With ASLR disabled the PIE base is `0x555555554000`. Two breakpoints:

| Offset | Captures |
| --- | --- |
| `0x179b` | each decoded VM instruction (16 bytes at `rsp+0x50`, plus `r8`) |
| `0x1cc6` | the final 48-byte state at `rsp+0x60`, and `rbp` |

The core of the GDB Python script ([`solve/gdb_extract.py`](solve/gdb_extract.py)):

```python
class BP(gdb.Breakpoint):
    def stop(s):
        r = lambda n: int(gdb.parse_and_eval('$' + n)) & (2**64 - 1)
        if s.tag == 'rec':
            m = bytes(inf.read_memory(r('rsp') + 0x50, 16))
            recs.append((r('r8'), m.hex()))
        elif s.tag == 'end':
            st = bytes(inf.read_memory(r('rsp') + 0x60, 48))
            # write state.txt, recs.txt, regs.txt (rbp)
        return False

BP(0x179b, 'rec')
BP(0x1cc6, 'end')
```

The input was a dummy of 48 `A`s:

```bash
printf 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n' > in.txt
```

Outputs:

| File | Contents |
| --- | --- |
| `state.txt` | final 48-byte VM state |
| `recs.txt` | decoded VM instructions |
| `regs.txt` | runtime key from `rbp` |

One trap: reading `rbp` at an earlier breakpoint gave a **wrong** key. The correct value, read after execution, is `0x866a952e86bb7d8b`.

## Step 6 – Running the choir backwards

With the decoded instructions, the key and the target state, we walked the 4,096 instructions from last to first, applying each handler's inverse and reversing the diffusion at every 64-instruction boundary. Undoing the input scrambler on the resulting six words gave the 48 input bytes.

Before trusting the reverse, we tested it on the dummy run: forward-executing 48 `A`s and then running the result backwards must return exactly 48 `A`s. It did, which validated the forward model and every inverse handler.

## Flag

```text
SecLeaf{th3_ch01r_s1ng5_1n_5h4d0w_m4ch1n35!!!!!}
```

## Why this is the right answer

- **The original binary accepts it:**

  ```bash
  printf '%s\n' "SecLeaf{th3_ch01r_s1ng5_1n_5h4d0w_m4ch1n35!!!!!}" | ./null_choir
  ```

  ```text
  Harmony.
  ```

- **Length:** exactly 48 characters – six 64-bit words, as the VM requires.
- **Round trip:** the reverse executor was validated on the known dummy input before it was used on the target.
- **Readable plaintext:** "the choir sings in shadow machines" – a clean leetspeak sentence is a strong signal that the inversion was exact; one wrong handler would produce noise.

## What we learned

- **Read the final check first.** Learning that the target is independent of the input changed the problem from search to inversion.
- **Let the binary decrypt itself.** Breakpoints after decryption give you decoded instructions and keys for free, as long as those values don't depend on the input.
- **Don't forget the global steps.** Inverting single instructions is not enough; the diffusion every 64 instructions must be undone at exactly the right points.
- **Watch when you read registers.** `rbp` read too early gave a wrong key – capture values at the point where they are actually used.

## Reproduce

The backward-execution code and the dumped data were not kept, so there is no offline re-implementation. [`solve/verify.sh`](solve/verify.sh) checks the flag against the original binary (in Docker if needed). It printed `Dissonance.` for a wrong flag and `Harmony.` for ours. With the original files, by hand:

```bash
cd attachments                       # null_choir, canticle.score, echoes.trace
printf 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n' > in.txt
NC_WORKDIR="$PWD" gdb -q -batch -x ../solve/gdb_extract.py ./null_choir
# -> state.txt, recs.txt, regs.txt; invert the 4,096 instructions as in Step 6
printf '%s\n' "SecLeaf{th3_ch01r_s1ng5_1n_5h4d0w_m4ch1n35!!!!!}" | ./null_choir   # Harmony.
```

Script: [`solve/gdb_extract.py`](solve/gdb_extract.py)

---

[← Back to Reverse Engineering](../README.md) · [Challenge overview](README.md)
