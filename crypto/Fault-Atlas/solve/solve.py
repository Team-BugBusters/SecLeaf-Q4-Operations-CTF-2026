#!/usr/bin/env python3
"""Fault Atlas: AES-128 differential fault analysis with forged traces.

Pipeline
  1. (needs data.json) classify each faulty ciphertext by which 4 bytes changed, test every
     candidate key quadruple against the round-9 single-byte fault model, and vote – one vote
     per record – so forged traces can't drown out the genuine ones;
  2. invert the AES-128 key schedule: round-10 key -> master key;
  3. check the master key against the verification pair;
  4. capsule key = SHA-256("SecLeaf/fault-atlas/record-seal/v1\\x00" || master key);
  5. (needs data.json) AES-256-GCM decrypt with AAD "round10-key".

Steps 2-4 run on the values quoted in the writeup; 1 and 5 run when attachments/data.json exists.
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ATT = Path(__file__).resolve().parents[1] / "attachments"

ROUND10_KEY = bytes.fromhex("e1db89a2344b4c817ccb6f7284169d52")  # recovered in the writeup
VERIFY_PT = bytes.fromhex("7a6dd388c6738ac381afd680323b9912")
VERIFY_CT = bytes.fromhex("b212b9bb3c09e65d9475eeb55a57df1a")
LABEL = b"SecLeaf/fault-atlas/record-seal/v1\x00"  # capital L, one real NUL byte
EXPECTED_CAPSULE_KEY = "92d087267875ed5b12f78221242dddad97e953981e4ae2265c556391720c41cb"
AAD = b"round10-key"


# ---------- AES building blocks ----------
def xtime(a: int) -> int:
    a <<= 1
    return (a ^ 0x11B) & 0xFF if a & 0x100 else a


def gmul(a: int, b: int) -> int:
    r = 0
    while b:
        if b & 1:
            r ^= a
        a, b = xtime(a), b >> 1
    return r


def build_sbox() -> list[int]:
    inv = [0] * 256
    for x in range(1, 256):
        inv[x] = next(y for y in range(1, 256) if gmul(x, y) == 1)
    sbox = []
    for x in range(256):
        b, s = inv[x], inv[x]
        for _ in range(4):
            b = ((b << 1) | (b >> 7)) & 0xFF
            s ^= b
        sbox.append(s ^ 0x63)
    return sbox


SBOX = build_sbox()
INV_SBOX = [0] * 256
for i, v in enumerate(SBOX):
    INV_SBOX[v] = i
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]
# A fault in row j of a column, after MixColumns, multiplies the fault value by column j of the matrix
MIX_COLS = [(2, 1, 1, 3), (3, 2, 1, 1), (1, 3, 2, 1), (1, 1, 3, 2)]


def invert_key_schedule(k10: bytes) -> bytes:
    """w[i-4] = w[i] XOR T(w[i-1]); T = RotWord+SubWord+Rcon when i % 4 == 0."""
    w = [None] * 44
    for j in range(4):
        w[40 + j] = list(k10[4 * j:4 * j + 4])
    for i in range(43, 3, -1):
        t = w[i - 1][:]
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [SBOX[b] for b in t]
            t[0] ^= RCON[i // 4 - 1]
        w[i - 4] = [a ^ b for a, b in zip(w[i], t)]
    return bytes(sum(w[:4], []))


def aes128_block(key: bytes, pt: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(pt) + enc.finalize()


# ---------- step 1: the fault analysis (only with data.json) ----------
def column_positions(col: int) -> list[int]:
    """Ciphertext positions hit by a round-9 fault in state column `col`, in row order.
    Row r of column c lands in column (c - r) mod 4 after the last ShiftRows."""
    return [4 * ((col - r) % 4) + r for r in range(4)]


def recover_round10_key(records) -> bytes:
    groups = {tuple(sorted(column_positions(c))): c for c in range(4)}
    key = [None] * 16
    for col in range(4):
        pos = column_positions(col)
        votes = Counter()
        for rec in records:
            c, f = bytes.fromhex(rec["ct"]), bytes.fromhex(rec["disturbed"])
            diff = tuple(i for i in range(16) if c[i] != f[i])
            if groups.get(diff) != col:
                continue
            # for each byte: map "inverse-S-box difference" -> list of key bytes producing it
            tables = []
            for p in pos:
                t = {}
                for k in range(256):
                    t.setdefault(INV_SBOX[c[p] ^ k] ^ INV_SBOX[f[p] ^ k], []).append(k)
                tables.append(t)
            cands = set()
            for coeffs in MIX_COLS:
                for e in range(1, 256):
                    lists = [tables[r].get(gmul(coeffs[r], e)) for r in range(4)]
                    if all(lists):
                        for a in lists[0]:
                            for b in lists[1]:
                                for c2 in lists[2]:
                                    for d in lists[3]:
                                        cands.add((a, b, c2, d))
            votes.update(cands)  # a record votes at most once per tuple
        (best, n), *rest = votes.most_common(2)
        print(f"    column {col}: positions {pos} -> {bytes(best).hex(' ')}  ({n} votes; runner-up {rest[0][1] if rest else 0})")
        for p, k in zip(pos, best):
            key[p] = k
    return bytes(key)


def load_data():
    path = ATT / "data.json"
    if not path.exists():
        return None
    data = json.loads(path.read_text())
    records = next(v for v in (data.values() if isinstance(data, dict) else [data])
                   if isinstance(v, list) and v and {"pt", "ct", "disturbed"} <= set(v[0]))
    return data, records


# ---------- self-test: a pure-Python AES with an optional round-9 fault ----------
def expand_key(key: bytes) -> list[list[int]]:
    w = [list(key[4 * i:4 * i + 4]) for i in range(4)]
    for i in range(4, 44):
        t = w[i - 1][:]
        if i % 4 == 0:
            t = [SBOX[b] for b in t[1:] + t[:1]]
            t[0] ^= RCON[i // 4 - 1]
        w.append([a ^ b for a, b in zip(w[i - 4], t)])
    return [sum(w[4 * r:4 * r + 4], []) for r in range(11)]


def encrypt(key: bytes, pt: bytes, fault=None) -> bytes:
    """fault = (byte_index, value): XORed into the state just before round 9's MixColumns."""
    rk = expand_key(key)
    s = [a ^ b for a, b in zip(pt, rk[0])]
    for rnd in range(1, 11):
        s = [SBOX[b] for b in s]
        s = [s[(i + 4 * (i % 4)) % 16] for i in range(16)]  # ShiftRows (column-major state)
        if rnd == 9 and fault:
            s[fault[0]] ^= fault[1]
        if rnd != 10:
            out = []
            for c in range(4):
                a = s[4 * c:4 * c + 4]
                out += [gmul(a[0], 2) ^ gmul(a[1], 3) ^ a[2] ^ a[3],
                        a[0] ^ gmul(a[1], 2) ^ gmul(a[2], 3) ^ a[3],
                        a[0] ^ a[1] ^ gmul(a[2], 2) ^ gmul(a[3], 3),
                        gmul(a[0], 3) ^ a[1] ^ a[2] ^ gmul(a[3], 2)]
            s = out
        s = [a ^ b for a, b in zip(s, rk[rnd])]
    return bytes(s)


def selftest() -> None:
    import random
    rng = random.Random(7)
    key = bytes(rng.randrange(256) for _ in range(16))
    assert encrypt(key, VERIFY_PT) == aes128_block(key, VERIFY_PT), "pure-Python AES mismatch"
    records = []
    for i in range(110):
        pt = bytes(rng.randrange(256) for _ in range(16))
        ct = encrypt(key, pt)
        if i % 2 == 0:   # genuine single-byte round-9 fault
            bad = encrypt(key, pt, (rng.randrange(16), rng.randrange(1, 256)))
        else:            # forged: random bytes in a plausible 4-byte pattern, or junk
            col = rng.randrange(4)
            bad = bytearray(ct)
            for p_ in column_positions(col) if i % 3 else rng.sample(range(16), 5):
                bad[p_] ^= rng.randrange(1, 256)
            bad = bytes(bad)
        records.append({"pt": pt.hex(), "ct": ct.hex(), "disturbed": bad.hex()})
    print("[*] self-test: 110 synthetic traces, half genuine faults, half forged")
    k10 = recover_round10_key(records)
    assert invert_key_schedule(k10) == key
    print("[+] self-test passed: voting recovered the planted key despite the forgeries")


def main() -> None:
    import sys
    if "--selftest" in sys.argv:
        selftest()
        return
    loaded = load_data()
    k10 = ROUND10_KEY
    if loaded:
        data, records = loaded
        print(f"[*] {len(records)} trace records; voting on round-10 key bytes")
        k10 = recover_round10_key(records)
        ok = sum(aes128_block(invert_key_schedule(k10), bytes.fromhex(r["pt"])).hex() == r["ct"] for r in records)
        print(f"[+] master key reproduces {ok}/{len(records)} (pt, ct) pairs")
    else:
        print("[*] attachments/data.json not found; starting from the round-10 key in the writeup")

    print(f"[+] round-10 key = {k10.hex()}")
    master = invert_key_schedule(k10)
    print(f"[+] master key   = {master.hex()}")
    assert aes128_block(master, VERIFY_PT) == VERIFY_CT
    print("[+] verification pair: AES-128(master, pt) == ct  OK")

    capsule_key = hashlib.sha256(LABEL + master).digest()
    print(f"[+] capsule key  = {capsule_key.hex()}  (label {len(LABEL)} B + key 16 B = {len(LABEL) + 16} B hashed)")
    assert capsule_key.hex() == EXPECTED_CAPSULE_KEY

    if not loaded:
        print("[!] attachments/data.json not found; stopping before decryption.")
        print("[i] flag as recorded in the writeup (NOT recomputed): SecLeaf{f4ult5_d0nt_n33d_t0_b3_h0n35t}")
        return
    cap = data["capsule"]  # field names per the writeup: nonce + ct_tag
    flag = AESGCM(capsule_key).decrypt(bytes.fromhex(cap["nonce"]), bytes.fromhex(cap["ct_tag"]), AAD)
    print(f"[+] FLAG: {flag.decode()}")


if __name__ == "__main__":
    main()
