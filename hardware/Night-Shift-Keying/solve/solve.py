#!/usr/bin/env python3
"""Night Shift Keying (SecLeaf CTF 2026, Hardware) - solver.

A stdlib re-implementation of what SoX + minimodem did in the writeup:

  1. read signal.wav (mono, 16-bit PCM, 44.1 kHz)
  2. find the loud burst after ~30 s of noise using a windowed RMS
  3. demodulate it as Bell 202 AFSK: 1200 baud, mark 1200 Hz (=1), space 2200 Hz (=0)
  4. UART-frame the bit stream as 8N1 (start 0, 8 data bits LSB first, stop 1)

Equivalent tool commands (from the writeup):
    sox signal.wav burst.wav trim 30
    minimodem --rx 1200 --mark 1200 --space 2200 --ascii \
              --startbits 1 --stopbits 1 -f burst.wav

Usage:  python3 solve.py [path/to/signal.wav]
Needs the original recording in ../attachments/.
Stdlib only.
"""
import cmath
import math
import re
import sys
import wave
from array import array
from pathlib import Path

HERE = Path(__file__).resolve().parent
WAV = HERE.parent / "attachments" / "signal.wav"

BAUD = 1200
MARK_HZ = 1200      # logical 1 (also the idle line state)
SPACE_HZ = 2200     # logical 0


def load_wav(path: Path) -> tuple[list[float], int]:
    with wave.open(str(path), "rb") as w:
        if w.getsampwidth() != 2:
            sys.exit("[-] expected 16-bit PCM")
        ch, rate, n = w.getnchannels(), w.getframerate(), w.getnframes()
        pcm = array("h", w.readframes(n))
    if sys.byteorder == "big":
        pcm.byteswap()
    samples = [s / 32768.0 for s in pcm[::ch]]          # first channel only
    print(f"[*] {path.name}: {ch} ch, {rate} Hz, {len(samples)} samples "
          f"({len(samples) / rate:.2f} s)")
    return samples, rate


def rms(xs) -> float:
    return math.sqrt(sum(x * x for x in xs) / len(xs)) if xs else 0.0


def find_burst(x: list[float], rate: int) -> tuple[int, int]:
    """Return [start, end) of the loud region, using 10 ms RMS windows."""
    win = rate // 100
    levels = [rms(x[i:i + win]) for i in range(0, len(x), win)]
    threshold = max(levels) / 4
    loud = [i for i, lv in enumerate(levels) if lv >= threshold]
    start = max(0, (loud[0] - 1) * win)
    end = min(len(x), (loud[-1] + 2) * win)
    print(f"[*] burst: {start / rate:.3f}-{end / rate:.3f} s "
          f"(RMS {rms(x[start:end]):.6f} vs {rms(x[:start]):.6f} before it)")
    return start, end


def tone_power(x: list[float], rate: int, freq: float, width: int) -> list[float]:
    """|sum x[k] e^{-j w k}| over a centred sliding window of `width` samples."""
    w = 2 * math.pi * freq / rate
    prod = [v * cmath.exp(-1j * w * k) for k, v in enumerate(x)]
    csum = [0j]
    for p in prod:
        csum.append(csum[-1] + p)
    half = width // 2
    out = []
    for n in range(len(x)):
        a, b = max(0, n - half), min(len(x), n - half + width)
        out.append(abs(csum[b] - csum[a]))
    return out


def demodulate(x: list[float], rate: int) -> str:
    spb = rate / BAUD                                    # 36.75 samples per bit at 44.1 kHz
    width = int(round(spb))
    mark = tone_power(x, rate, MARK_HZ, width)
    space = tone_power(x, rate, SPACE_HZ, width)
    bit = [1 if m >= s else 0 for m, s in zip(mark, space)]

    out, n = bytearray(), 1
    while n < len(bit) - int(10 * spb):
        if not (bit[n - 1] == 1 and bit[n] == 0):        # falling edge = start bit
            n += 1
            continue
        centre = lambda k: int(n + (k + 0.5) * spb)     # middle of bit k of the frame
        if bit[centre(0)] != 0:                          # glitch, not a start bit
            n += 1
            continue
        data = [bit[centre(k)] for k in range(1, 9)]
        if bit[centre(9)] != 1:                          # framing error
            n += 1
            continue
        out.append(sum(b << i for i, b in enumerate(data)))   # LSB first
        n = centre(9)                                    # resume inside the stop bit
    return out.decode("latin-1")


def main() -> None:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else WAV
    if not path.exists():
        sys.exit(f"[-] {path} not found. Place signal.wav in attachments/ to run.")
    x, rate = load_wav(path)
    start, end = find_burst(x, rate)
    print(f"[*] demodulating Bell 202 AFSK, {BAUD} baud, mark {MARK_HZ} Hz / "
          f"space {SPACE_HZ} Hz, 8N1")
    text = demodulate(x[start:end], rate)
    print(f"[*] decoded text: {text!r}")
    m = re.search(r"SecLeaf\{[^}]*\}", text)
    if not m:
        sys.exit("[-] no SecLeaf{...} in the decoded text")
    print(f"[+] FLAG: {m.group(0)}")


if __name__ == "__main__":
    main()
