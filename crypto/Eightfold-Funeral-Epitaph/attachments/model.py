#!/usr/bin/env python3
"""Eightfold Funeral: Epitaph. Public arithmetic and receipt format.

The printed stamps are images under one odd affine automorphism of Z/2^84Z.
Calibration records are not guaranteed honest. The eight catalogs are virtual:
each is indexed from 0 to 2^21-1, and sampled deterministically from an
unknown eleven-byte lane seed. A valid receipt sums one label from every lane in
Z/2^84Z. It is NOT a bitwise-XOR receipt.
"""
from hashlib import sha256
MOD = 1 << 84
SIZE = 1 << 21

def _rol84(x, r):
    r %= 84
    x %= MOD
    return ((x << r) | (x >> (84 - r))) % MOD if r else x

def stamp(x, multiplier, offset, rotation):
    """One secret odd affine map, followed by a secret 84-bit rotation."""
    return _rol84((multiplier * x + offset) % MOD, rotation)

def label(seed, lane, index):
    assert 0 <= seed < MOD and 0 <= lane < 8 and 0 <= index < SIZE
    msg = b'Epitaph/v7|' + bytes([lane]) + seed.to_bytes(11, 'little') + index.to_bytes(4, 'little')
    return int.from_bytes(sha256(msg).digest()[:11], 'little') % MOD

def receipt(indices, seeds):
    assert len(indices) == len(seeds) == 8
    return sum(label(seeds[g], g, indices[g]) for g in range(8)) % MOD

def receipt_key(indices, seeds):
    assert len(indices) == len(seeds) == 8
    b = b'Epitaph/v7/capsule\0'
    for g in range(8):
        b += indices[g].to_bytes(4, 'little') + label(seeds[g], g, indices[g]).to_bytes(11, 'little')
    return sha256(b).digest()
