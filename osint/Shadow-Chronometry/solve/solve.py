#!/usr/bin/env python3
"""Shadow Chronometry (SecLeaf CTF 2026, OSINT) - format the landmark coordinates.

The landmark (Obelisk of Buenos Aires) was identified by reverse image search;
that step is not reproducible offline. This script only shows why the flag uses
truncation to 4 decimal places, and what rounding would have produced instead.
"""
from decimal import Decimal, ROUND_DOWN, ROUND_HALF_UP

LAT = Decimal("-34.603851")   # Obelisk of Buenos Aires
LON = Decimal("-58.381775")
Q = Decimal("0.0001")


def truncate(x: Decimal) -> Decimal:
    # ROUND_DOWN in decimal means "toward zero", i.e. drop the extra digits.
    return x.quantize(Q, rounding=ROUND_DOWN)


def rounded(x: Decimal) -> Decimal:
    return x.quantize(Q, rounding=ROUND_HALF_UP)


for name, v in (("lat", LAT), ("lon", LON)):
    print(f"[*] {name}: {v}  truncated -> {truncate(v)}  rounded -> {rounded(v)}")

print(f"[*] Rounded (wrong) candidate: SecLeaf{{{rounded(LAT)},{rounded(LON)}}}")
print(f"[+] FLAG: SecLeaf{{{truncate(LAT)},{truncate(LON)}}}")
