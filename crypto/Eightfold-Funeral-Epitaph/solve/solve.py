#!/usr/bin/env python3
"""Eightfold Funeral: Epitaph: eight-list generalized birthday (Wagner) over Z/2^84.

Default run (seconds): rebuild the 8 labels for the indices we found, check the
modular checksum, and derive the AES key from the 139-byte receipt.

  --search   rerun the full Wagner k-tree over 8 x 2^21 virtual catalogs from the
             recovered seeds (16.7M SHA-256 labels; ~25 s and ~2.2 GB RAM
             in CPython. We ran it in C++ during the event; this port finds the same indices).

The 84-bit stamps and the capsule ciphertext live in ../attachments/data.json.
With data.json present the capsule is decrypted too; without it the script stops after
reproducing the receipt key and prints the flag recorded in the writeup, clearly labelled.
"""
from __future__ import annotations

import hashlib
import json
import sys
import time
from pathlib import Path

ATT = Path(__file__).resolve().parents[1] / "attachments"

BITS = 84
M = 1 << BITS
LANE_SIZE = 1 << 21
BLOCK = 21

# Honest stamp map recovered by consensus over the calibration rows (15 of 25 rows agree)
ROT, A_MUL, B_OFF = 35, 0x750E59BEF1F0E6B385693, 0x67CD6060C7616D28D7C34

SEEDS = [
    0xD10E12DD1A92B568095CC, 0x83B12BCF6E5C7D0238D18, 0x9F6907F41F632026FEB73, 0x4314EC950D28D71E802D0,
    0xEFB8201EA98C16BE80E9E, 0x1866EA8C6BEF1710BA967, 0xDD923A4A9BF987BAEC4F2, 0xD805B3695A44F501EADFB,
]
TARGET = 0x1B59868B301E63F23871F
FOUND = [1924587, 2031184, 29597, 785188, 676753, 560734, 264902, 1161509]
EXPECTED_KEY = "3d4d888000202e2db8c6f12732fbccb8afb9992b442ce555089fc49a2d892cf7"


def rotl(x: int, r: int) -> int:
    r %= BITS
    return ((x << r) | (x >> (BITS - r))) % M if r else x % M


def stamp(x: int, a: int = A_MUL, b: int = B_OFF, r: int = ROT) -> int:
    """Forward map from model.py: affine mod 2^84, then rotate left by r."""
    return rotl((a * x + b) % M, r)


def unstamp(z: int, a: int = A_MUL, b: int = B_OFF, r: int = ROT) -> int:
    return (rotl(z, -r) - b) * pow(a, -1, M) % M


def recover_map(calibration):
    """Vote over every rotation and every row pair with an odd input difference.
    Each candidate (r, a, b) is scored by how many whole rows it reproduces."""
    rows = [(int(c["input"], 16), int(c["stamp"], 16)) for c in calibration]
    best = {}
    for r in range(BITS):
        ys = [rotl(z, -r) for _, z in rows]
        for i in range(len(rows)):
            for j in range(i + 1, len(rows)):
                dx = (rows[i][0] - rows[j][0]) % M
                if dx % 2 == 0:
                    continue  # only odd numbers are invertible mod 2^84
                a = (ys[i] - ys[j]) * pow(dx, -1, M) % M
                b = (ys[i] - a * rows[i][0]) % M
                key = (r, a, b)
                if key not in best:
                    best[key] = frozenset(k for k, (x, z) in enumerate(rows) if stamp(x, a, b, r) == z)
    return sorted(best.items(), key=lambda kv: -len(kv[1]))


def label(lane: int, index: int) -> int:
    msg = b"Epitaph/v7|" + bytes([lane]) + SEEDS[lane].to_bytes(11, "little") + index.to_bytes(4, "little")
    return int.from_bytes(hashlib.sha256(msg).digest()[:11], "little") % M  # 88 bits -> 84


def receipt_key(indices: list[int], labels: list[int]) -> bytes:
    blob = b"Epitaph/v7/capsule\x00" + b"".join(
        i.to_bytes(4, "little") + l.to_bytes(11, "little") for i, l in zip(indices, labels))
    assert len(blob) == 139
    return hashlib.sha256(blob).digest()


# ---------- Wagner k-tree ----------
def merge(va, vb, width):
    """Pair entries whose sum is 0 in the low BLOCK bits; keep (sum mod 2^width) >> BLOCK."""
    mask = (1 << BLOCK) - 1
    buckets: dict[int, list[int]] = {}
    for j, v in enumerate(vb):
        buckets.setdefault(v & mask, []).append(j)
    out_v, out_a, out_b = [], [], []
    wmask = (1 << width) - 1
    for i, v in enumerate(va):
        for j in buckets.get(-v & mask, ()):
            out_v.append(((v + vb[j]) & wmask) >> BLOCK)
            out_a.append(i)
            out_b.append(j)
    return out_v, out_a, out_b


def wagner_search() -> list[int]:
    t0 = time.time()
    lanes = []
    for lane in range(8):
        vals = [label(lane, i) for i in range(LANE_SIZE)]
        if lane == 7:  # shift the target into lane 7 so the goal becomes "sum == 0"
            vals = [(v - TARGET) % M for v in vals]
        lanes.append(vals)
        print(f"    lane {lane}: {LANE_SIZE} labels  ({time.time() - t0:.0f}s)", flush=True)

    level1 = [merge(lanes[2 * p], lanes[2 * p + 1], BITS) for p in range(4)]
    for p, (v, _, _) in enumerate(level1):
        print(f"    lanes {2 * p}+{2 * p + 1}: {len(v)} kept", flush=True)
    del lanes
    level2 = [merge(level1[2 * q][0], level1[2 * q + 1][0], BITS - BLOCK) for q in range(2)]
    for q, (v, _, _) in enumerate(level2):
        print(f"    group {4 * q}-{4 * q + 3}: {len(v)} kept", flush=True)
    # final: the remaining 42 bits must cancel exactly
    final_v, fa, fb = merge(level2[0][0], level2[1][0], BITS - 2 * BLOCK)
    hits = [(a, b) for v, a, b in zip(final_v, fa, fb) if v == 0]
    full = []
    for a, b in hits:
        # the last merge only zeroes 21 more bits; demand the full 42
        va, vb = level2[0][0][a], level2[1][0][b]
        if (va + vb) % (1 << (BITS - 2 * BLOCK)) != 0:
            continue
        idx = []
        for q, top in ((0, a), (1, b)):
            l2 = level2[q]
            for half, p1 in ((l2[1][top], 2 * q), (l2[2][top], 2 * q + 1)):
                idx += [level1[p1][1][half], level1[p1][2][half]]
        full.append(idx)
    print(f"    full-width matches: {len(full)}  ({time.time() - t0:.0f}s)")
    return full[0]


def main() -> None:
    global SEEDS, TARGET
    indices = FOUND
    path = ATT / "data.json"
    data = json.loads(path.read_text()) if path.exists() else None
    if data:
        ranked = recover_map(data["calibration"])
        (r, a, b), honest = ranked[0]
        decoy = next(((k, v) for k, v in ranked if not (v & honest)), None)
        n_rows = len(data["calibration"])
        print(f"[+] honest stamp map: rotation {r}, a = {a:#x}, b = {b:#x}  ({len(honest)}/{n_rows} rows)")
        if decoy:
            rest = n_rows - len(honest) - len(decoy[1] - honest)
            print(f"    decoy map on the other rows: rotation {decoy[0][0]} ({len(decoy[1])} rows); {rest} rows fit neither")
        assert (r, a, b) == (ROT, A_MUL, B_OFF)
        SEEDS = [unstamp(int(z, 16), a, b, r) for z in data["lane_stamps"]]
        TARGET = unstamp(int(data["target_stamp"], 16), a, b, r)
        print(f"[+] unstamped 8 lane seeds and target T = 0x{TARGET:021x}")
    if "--search" in sys.argv:
        print("[*] running the 8-list Wagner search from the recovered seeds")
        indices = wagner_search()
        print(f"[+] indices = {indices}")

    labels = [label(lane, i) for lane, i in enumerate(indices)]
    for lane, (i, l) in enumerate(zip(indices, labels)):
        print(f"    lane {lane}: index {i:>7}  label 0x{l:021x}")
    total = sum(labels) % M
    assert total == TARGET, "labels do not sum to the target"
    print(f"[+] sum of labels mod 2^84 = 0x{total:021x} = target")
    assert unstamp(stamp(TARGET)) == TARGET

    key = receipt_key(indices, labels)
    print(f"[+] receipt key = {key.hex()}")
    assert key.hex() == EXPECTED_KEY

    if not data:
        print("[!] attachments/data.json not found; stopping before decryption.")
        print("[i] flag as recorded in the writeup (NOT recomputed): SecLeaf{m0dular_c4rr13s_d0nt_r3st_1n_p34c3}")
        return
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    cap = data["capsule"]  # nonce + ct_tag, per the writeup
    nonce, ct = bytes.fromhex(cap["nonce"]), bytes.fromhex(cap["ct_tag"])[:-16]
    # GCM's keystream is AES-CTR starting at nonce || 00000002
    dec = Cipher(algorithms.AES(key), modes.CTR(nonce + b"\x00\x00\x00\x02")).decryptor()
    print(f"[+] FLAG: {(dec.update(ct) + dec.finalize()).decode()}")


if __name__ == "__main__":
    main()
