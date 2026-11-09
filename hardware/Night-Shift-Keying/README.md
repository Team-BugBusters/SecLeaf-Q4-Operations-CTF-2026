# Night Shift Keying

![Event](https://img.shields.io/badge/SecLeaf_CTF-2026-101518?style=flat-square)
![Category](https://img.shields.io/badge/Category-Hardware-B4441F?style=flat-square)
![Points](https://img.shields.io/badge/Points-80-2F5D3A?style=flat-square)

> **Solved by** [Rutwik](https://github.com/Rutwik-712) · **Team** Bug Busters · **Solved** 31 October 2026, 4:27 pm

## Challenge description

A noisy radio recording, `signal.wav`, conceals a short data transmission. Isolate the burst and recover its message.

*Brief reconstructed from the solve notes; the original text was not archived.*

**Flag format:** `SecLeaf{...}`

**Attachments:** [`signal.wav`](attachments/signal.wav)

## Flag

```text
SecLeaf{R4d10_W4v35}
```

## Writeup

Read the full solve: **[writeup.md](writeup.md)**

**In one line:** the title is a pun on *Frequency Shift Keying*; the last 0.178 s of a 30 s noise recording is a 1200-baud Bell 202 AFSK burst (1200 Hz = 1, 2200 Hz = 0) carrying plain 8N1 ASCII.

- `signal.wav`: mono, 44,100 Hz, 16-bit PCM, 1,330,864 samples (~30.18 s).
- RMS 0.026966 for the first 30 s vs 0.707093 for the final 0.178322 s (7,864 samples): the burst is ~26x louder.
- `minimodem --rx 1200 --mark 1200 --space 2200`, 8N1 framing, decodes the cropped burst to the flag (measured rate 1198.37 bps).

## Files

| Path | What it is |
| --- | --- |
| [`writeup.md`](writeup.md) | Full solve |
| [`solve/solve.py`](solve/solve.py) | Stdlib re-implementation of the SoX + minimodem steps: finds the burst by RMS, demodulates Bell 202 AFSK, frames 8N1, prints the flag |

## Run the solver

```bash
cd solve
python3 solve.py
```

Expected output ends with:

```text
[+] FLAG: SecLeaf{R4d10_W4v35}
```

## Notes

- Verified on the original `signal.wav`: the burst sits at 29.990–30.178 s, and the stdlib-only demodulator prints the flag (with a leading `M` byte from the preamble).
- The original solve used SoX 14.4.2 and minimodem 0.24; the exact commands are in the writeup.
- Decoding the whole file (without cropping) also yields the flag, but preceded by junk characters that the modem "hears" in the noise.
- We filed this under Hardware (radio/signals); our notes labelled it Forensics / Audio.

---

[← Back to Hardware](../README.md) · [All writeups](../../README.md)
