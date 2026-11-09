#!/usr/bin/env python3
"""Tomb Translation (SecLeaf CTF 2026) - offline solver.

The five panels in ../attachments/panel_1.png ... panel_5.png are Sheikah
numerals. Reading each panel left-to-right, top-to-bottom gives the digit
strings below (transcribed by hand against the dCode Sheikah chart; the
glyph reading itself is a visual step and is not automated here).

decimal digits  ->  one big integer  ->  base 36  ->  hex pairs  ->  ASCII
"""
import string

PANELS = [
    "4512850624708810755782579",  # panel_1.png (25 glyphs)
    "4509536482336411038819437",  # panel_2.png (25 glyphs)
    "0809101818732879793065419",  # panel_3.png (25 glyphs, leading zero matters)
    "5536138714068480877382878",  # panel_4.png (25 glyphs)
    "837658921334372170847241",   # panel_5.png (24 glyphs)
]

ALPHABET = string.digits + string.ascii_lowercase  # base-36 digits


def to_base(n: int, base: int) -> str:
    out = []
    while n:
        n, r = divmod(n, base)
        out.append(ALPHABET[r])
    return "".join(reversed(out)) or "0"


def main():
    for i, p in enumerate(PANELS, 1):
        print(f"[*] panel {i}: {p}  ({len(p)} digits)")
    digits = "".join(PANELS)  # concatenate as text so panel 3's leading 0 survives
    print(f"[*] joined: {len(digits)} decimal digits")

    n = int(digits)  # Python ints are arbitrary precision - no float rounding
    b36 = to_base(n, 36)
    print(f"[*] base 36 ({len(b36)} chars): {b36}")
    assert set(b36) <= set(string.hexdigits.lower()), "base-36 output is not hex-only"

    flag_bytes = bytes.fromhex(b36)
    flag = flag_bytes.decode("ascii")
    print(f"[*] hex -> {len(flag_bytes)} ASCII bytes")

    # Inverse checks: bytes -> hex -> base-36 integer -> decimal must give back the input.
    assert flag_bytes.hex() == b36
    assert str(int(b36, 36)) == digits
    print("[*] inverse conversion restores the exact 124-digit input")

    print(f"[+] FLAG: {flag}")


if __name__ == "__main__":
    main()
