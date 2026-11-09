# Null Choir

![Event](https://img.shields.io/badge/SecLeaf_CTF-2026-101518?style=flat-square)
![Category](https://img.shields.io/badge/Category-Reverse_Engineering-B4441F?style=flat-square)
![Points](https://img.shields.io/badge/Points-500-2F5D3A?style=flat-square)

> **Solved by** [Vaidik](https://github.com/Vaidik-Makhasana) · **Team** Bug Busters · **Solved** 31 October 2026, 4:34 pm

## Challenge description

> "I wanted to make a difficult reversing challenge."
>
> "I think I may have overdone it a little (again :<). Anyways, enjoy the concert. The screaming is complimentary :)"

**Flag format:** `SecLeaf{...}`

**Attachments:** [`canticle.score`](attachments/canticle.score) · [`echoes.trace`](attachments/echoes.trace) · [`null_choir`](attachments/null_choir)

## Flag

```text
SecLeaf{th3_ch01r_s1ng5_1n_5h4d0w_m4ch1n35!!!!!}
```

## Writeup

Read the full solve: **[writeup.md](writeup.md)**

**In one line:** the VM's target state is computed without looking at the input, so instead of searching for a 48-byte input we dumped the target state and the decoded program from a live run and executed the reversible VM backwards.

- Stripped x86-64 ELF with a 24-entry jump table: a custom VM running 4,096 encrypted, shuffled instructions from `canticle.score`.
- `echoes.trace` (FNV-1a-validated `EC` records) derives the runtime key `rbp = 0x866a952e86bb7d8b`.
- GDB breakpoints at `PIE+0x179b` (decoded instruction) and `PIE+0x1cc6` (final state) captured everything using a dummy `AAAA…` input.
- Reverse order: undo each instruction, undo the diffusion every 64 steps, undo the input scrambler → the flag; the binary answers `Harmony.`.

## Files

| Path | What it is |
| --- | --- |
| [`writeup.md`](writeup.md) | Full solve |
| [`solve/verify.sh`](solve/verify.sh) | Runs the original binary on a wrong flag and on the recovered flag |
| [`solve/gdb_extract.py`](solve/gdb_extract.py) | GDB Python script that dumps decoded VM instructions, final state and key (runs inside GDB, needs the binary) |

## Run the verifier

```bash
cd solve
bash verify.sh      # Linux x86-64 runs it directly; anywhere else it re-runs itself in Docker (linux/amd64, no network)
```

Expected output:

```text
[*] wrong flag  -> Dissonance.
[*] real flag   -> Harmony.
[+] FLAG: SecLeaf{th3_ch01r_s1ng5_1n_5h4d0w_m4ch1n35!!!!!}
```

## Notes

- **Checked against the original binary:** with the archived `canticle.score` and `echoes.trace`, `null_choir` prints `Harmony.` (exit 0) for the flag and `Dissonance.` (exit 1) for a wrong one, via argv or stdin.
- `gdb_extract.py` runs inside GDB on Linux x86-64 against the original binary and data files, which are now in `attachments/`.
- `rbp` must be read at the end breakpoint – reading it earlier gave a wrong key during the solve.
- Sanity check on the input length: the flag is exactly 48 characters = six 64-bit words, matching the VM's input requirement.

---

[← Back to Reverse Engineering](../README.md) · [All writeups](../../README.md)
