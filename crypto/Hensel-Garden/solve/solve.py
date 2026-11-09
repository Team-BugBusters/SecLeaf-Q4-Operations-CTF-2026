#!/usr/bin/env python3
"""Hensel Garden: lift square roots modulo 2^72 and 3^51, undo the shifts,
CRT the candidates, keep the one 128-bit seed, then derive the AES-GCM key.

The inputs below are copied from the challenge's data.json. If ../attachments/data.json is
present the script re-reads it and requires every value to match the embedded copy.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Public observations: A = (s + 87)^2 mod 2^72, B = (s + 143)^2 mod 3^51
A, SHIFT_A, M1 = 2090995815874869393993, 87, 2**72
B, SHIFT_B, M2 = 246419994095244398264902, 143, 3**51
SEED_BITS = 128

PREFIX = b"SecLeaf/hensel/v2/"
NONCE = bytes.fromhex("47058b956d0949a8d2e0c83d")
CT_AND_TAG = bytes.fromhex(
    "455e7863f10096e5984ed4c341c580eeb492ad737"
    "893e0873dfe495aca47a0fb01b086a10df02ddb"
    "2f85dec7aa6048ca320b82ee0dcae6b1"
)


DATA = Path(__file__).resolve().parent.parent / "attachments" / "data.json"


def crosscheck_data() -> None:
    if not DATA.exists():
        print(f"[*] ({DATA.name} not present - using the embedded values)")
        return
    d = json.loads(DATA.read_text())
    assert [int(x) for x in d["moduli"]] == [M1, M2], "moduli differ from the embedded values"
    assert d["shifts"] == [SHIFT_A, SHIFT_B], "shifts differ from the embedded values"
    assert [int(x) for x in d["squares"]] == [A, B], "squares differ from the embedded values"
    assert d["bits"] == SEED_BITS, "seed size differs"
    assert bytes.fromhex(d["sealed"]["nonce"]) == NONCE, "nonce differs"
    assert bytes.fromhex(d["sealed"]["ct"]) == CT_AND_TAG, "ciphertext differs"
    print(f"[*] {DATA.name} matches the embedded values")


def hensel_sqrt(a: int, p: int, e: int) -> list[int]:
    """Every r in [0, p^e) with r^2 = a (mod p^e), lifted one power of p at a time."""
    roots = [r for r in range(p) if (r * r - a) % p == 0]
    mod = p
    for _ in range(1, e):
        nxt = mod * p
        # each root mod p^k has p possible extensions r + t*p^k; keep the ones that still work
        roots = sorted({r + t * mod for r in roots for t in range(p) if ((r + t * mod) ** 2 - a) % nxt == 0})
        mod = nxt
    return roots


def crt(a: int, m1: int, b: int, m2: int) -> int:
    u = pow(m1, -1, m2)
    return (a + m1 * ((b - a) * u % m2)) % (m1 * m2)


def main() -> None:
    crosscheck_data()
    roots_a = hensel_sqrt(A, 2, 72)
    roots_b = hensel_sqrt(B, 3, 51)
    print(f"[*] {len(roots_a)} roots mod 2^72: {roots_a}")
    print(f"[*] {len(roots_b)} roots mod 3^51: {roots_b}")

    candidates = []
    for ra in roots_a:
        for rb in roots_b:
            s = crt((ra - SHIFT_A) % M1, M1, (rb - SHIFT_B) % M2, M2)
            ok = s < 2**SEED_BITS
            print(f"    CRT -> {s}  {'<-- fits 128 bits' if ok else ''}")
            if ok:
                candidates.append(s)

    assert len(candidates) == 1, "expected exactly one 128-bit seed"
    seed = candidates[0]
    assert (seed + SHIFT_A) ** 2 % M1 == A and (seed + SHIFT_B) ** 2 % M2 == B
    print(f"[+] seed = {seed}")

    seed_bytes = seed.to_bytes(16, "big")
    key = hashlib.sha256(PREFIX + seed_bytes).digest()
    print(f"[+] seed hex = {seed_bytes.hex()}")
    print(f"[+] AES key  = {key.hex()}")

    # AES-GCM checks the tag, so a successful decrypt also proves the seed and key are right.
    flag = AESGCM(key).decrypt(NONCE, CT_AND_TAG, None).decode()
    print(f"[+] FLAG: {flag}")


if __name__ == "__main__":
    main()
