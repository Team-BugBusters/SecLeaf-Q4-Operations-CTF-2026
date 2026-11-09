#!/usr/bin/env python3
"""Sugar Glass – invert a chained password checker one character at a time.

The checker in the `sugar_glass` ELF runs 29 rounds. Each round mixes exactly
one input character into a carried state and compares one byte against a
target. With the state from earlier rounds known, the only unknown is that one
character, so we try all 256 values per round (29 x 256 = 7,424 trials).

All constants below were read from the binary's .rodata (they appear byte-for-byte in
../attachments/sugar_glass), so this script needs no attachments. ./verify.sh feeds the
result to the original binary.

Run:
    python3 solve.py
"""
from __future__ import annotations

SECLEN = 0x1D            # 29: required password length
K1, K2, K3 = 0x0B, 0x05, 0x42   # index step, index start, initial edi

ARRAY1 = bytes([         # per-round secret byte mixed into the character
    0xE5, 0x5F, 0xB1, 0x5D, 0xDF, 0xAD, 0x9B, 0xB9, 0x6E, 0x3F, 0x15, 0xF1, 0x43, 0xDC, 0x40, 0xA5,
    0xCD, 0xD3, 0xD9, 0x6B, 0x04, 0x21, 0x48, 0x46, 0x52, 0xA4, 0x89, 0xB1, 0xCB,
])
ARRAY2 = bytes([         # per-round target for the low byte of the running total
    0x7B, 0x7D, 0x34, 0xF7, 0x74, 0x78, 0xB2, 0x56, 0x83, 0x11, 0x29, 0xCB, 0xE1, 0xA6, 0x35, 0x40,
    0xE5, 0x91, 0x50, 0x29, 0x30, 0x48, 0x47, 0x24, 0xB9, 0x5D, 0x8B, 0x19, 0xB2,
])

MASK32 = 0xFFFFFFFF


def rol8(v: int, n: int) -> int:
    v &= 0xFF
    return ((v << n) | (v >> (8 - n))) & 0xFF


def round_step(x: int, s1: int, edi: int, r9: int, r8: int) -> tuple[int, int]:
    """One checker round for candidate character x. Returns (new_edi, new_r8).

    Registers are 32-bit; only the low byte (AL) is rotated, so the upper bits
    and carries survive into the next round. Truncating early gives wrong answers.
    """
    r14 = (((s1 ^ x) & 0xFF) + edi) & MASK32
    new_edi = (r14 & 0xFFFFFF00) | rol8(r14, 3)
    eax = new_edi ^ r9
    eax2 = (eax & 0xFFFFFF00) | rol8(eax, 1)
    new_r8 = (r8 + eax2) & MASK32
    return new_edi, new_r8


def main() -> None:
    result: list[int | None] = [None] * SECLEN
    edi, r9, r8, esi = K3, 0x39, 0x5D, K2

    print("round  idx  char")
    for i in range(SECLEN):
        idx = esi % SECLEN               # (5 + 11*i) mod 29: scrambled read order
        esi = (esi + K1) & MASK32
        hits = []
        for x in range(256):
            new_edi, new_r8 = round_step(x, ARRAY1[i], edi, r9, r8)
            if (new_r8 & 0xFF) == ARRAY2[i]:
                hits.append((x, new_edi, new_r8))
        if len(hits) != 1:
            raise SystemExit(f"[-] round {i}: expected exactly one candidate, got {len(hits)}")
        x, edi, r8 = hits[0]
        r9 = (r9 + 0x11) & MASK32
        result[idx] = x
        print(f"{i:5d}  {idx:3d}  {chr(x)!r}")

    flag = bytes(result).decode()  # type: ignore[arg-type]
    print(f"[+] FLAG: {flag}")


if __name__ == "__main__":
    main()
