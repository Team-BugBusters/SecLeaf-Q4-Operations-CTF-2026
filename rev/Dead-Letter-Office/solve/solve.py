#!/usr/bin/env python3
"""Dead Letter Office – decode the HPL2 postcard with the key hidden in the ELF.

Reconstructed from the disassembly of `dead_letter_office` (this is our
re-implementation, not the challenge author's source).

Pipeline:
  1. Parse the HPL2 header of postcard.grid and verify its FNV-1a checksum.
  2. Find the `DLO2` marker in the ELF; the next 8 bytes are a key seed and
     the 3 bytes after that are (start, step, rounds) = (7, 7, 14).
  3. Derive the key: key[i] = seed[i] ^ ((31*i - 0x5B) & 0xFF).
  4. Walk the 20 records in the scrambled order 7, 14, 1, 8, ... and undo the
     14-round byte-pair transform for each, then strip the chaining XOR.

During the event we recovered each pair by brute force (256 x 256 = 65,536
candidates per record). The transform is a Feistel network, so this cleaned-up
version inverts it directly and confirms every pair by re-running it forward.

Inputs:
    ../attachments/postcard.grid
    ../attachments/dead_letter_office

Run:
    python3 solve.py
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

ATT = Path(__file__).resolve().parents[1] / "attachments"
GRID_FILE = ATT / "postcard.grid"
ELF_FILE = ATT / "dead_letter_office"

PAYLOAD_OFFSET = 0x80
FNV_OFFSET_BASIS = 0x811C9DC5
FNV_PRIME = 0x01000193
MASK16 = 0xFFFF


def rol8(value: int, count: int) -> int:
    value &= 0xFF
    count %= 8
    return ((value << count) | (value >> (8 - count))) & 0xFF if count else value


def rol16(value: int, count: int) -> int:
    value &= MASK16
    count %= 16
    return ((value << count) | (value >> (16 - count))) & MASK16 if count else value


def fnv1a(data: bytes) -> int:
    value = FNV_OFFSET_BASIS
    for byte in data:
        value = ((value ^ byte) * FNV_PRIME) & 0xFFFFFFFF
    return value


def round_keys(pair_index: int, round_index: int, key: bytes) -> tuple[int, int]:
    key_a = (key[(pair_index + round_index) & 7] ^ (13 * pair_index)) & 0xFF
    key_b = rol8(key[(5 + 3 * round_index) & 7], (pair_index % 7) + 1)
    return key_a, key_b


def transform_pair(a: int, b: int, pair_index: int, key: bytes, rounds: int) -> tuple[int, int]:
    """The binary's forward transform: (a, b) -> (b, F(b) ^ a), `rounds` times."""
    for r in range(rounds):
        key_a, key_b = round_keys(pair_index, r, key)
        f = rol8((key_a + b) & 0xFF, (r % 7) + 1) ^ key_b
        a, b = b, f ^ a
    return a, b


def invert_pair(a: int, b: int, pair_index: int, key: bytes, rounds: int) -> tuple[int, int]:
    """Undo transform_pair: each Feistel round is reversed as (a', b') -> (b' ^ F(a'), a')."""
    for r in reversed(range(rounds)):
        key_a, key_b = round_keys(pair_index, r, key)
        f = rol8((key_a + a) & 0xFF, (r % 7) + 1) ^ key_b
        a, b = b ^ f, a
    return a, b


def main() -> None:
    missing = [p.name for p in (GRID_FILE, ELF_FILE) if not p.is_file()]
    if missing:
        sys.exit(
            f"[-] missing {', '.join(missing)} in {ATT}\n"
            "    Place postcard.grid and dead_letter_office in attachments/ to run."
        )

    grid = GRID_FILE.read_bytes()
    elf = ELF_FILE.read_bytes()

    # --- HPL2 header -------------------------------------------------------
    if len(grid) < PAYLOAD_OFFSET or grid[:4] != b"HPL2":
        sys.exit("[-] postcard.grid does not start with HPL2")
    message_length, record_count = struct.unpack_from("<HH", grid, 4)
    (expected_checksum,) = struct.unpack_from("<I", grid, 8)
    (initial_state,) = struct.unpack_from("<H", grid, 12)
    payload = grid[PAYLOAD_OFFSET:]
    print(f"[*] HPL2: length={message_length} records={record_count} "
          f"checksum={expected_checksum:#010x} state={initial_state:#06x}")

    if len(payload) != record_count * 4:
        sys.exit("[-] payload size does not match record count")
    actual_checksum = fnv1a(payload)
    if actual_checksum != expected_checksum:
        sys.exit(f"[-] FNV-1a mismatch: expected {expected_checksum:08x}, got {actual_checksum:08x}")
    print("[*] FNV-1a checksum OK")

    # --- DLO2 parameters from .rodata -------------------------------------
    marker = elf.find(b"DLO2")
    if marker < 0 or marker + 15 > len(elf):
        sys.exit("[-] DLO2 marker missing or truncated")
    seed = elf[marker + 4:marker + 12]
    start, step, rounds = elf[marker + 12:marker + 15]
    key = bytes(seed[i] ^ ((31 * i - 0x5B) & 0xFF) for i in range(8))
    print(f"[*] DLO2 seed={seed.hex(' ')} start={start} step={step} rounds={rounds}")
    print(f"[*] derived key: {key.hex(' ')}")

    # --- Walk and decode the records --------------------------------------
    cursor = step
    state = initial_state
    recovered = bytearray()
    order = []
    for pair_index in range(record_count):
        record_index = cursor % record_count
        order.append(record_index)
        (record_value,) = struct.unpack_from("<H", payload, record_index * 4)

        target = (rol16(state, 3) ^ (((pair_index + 1) * 0x9E37) & MASK16) ^ record_value) & MASK16
        wanted = (target & 0xFF, target >> 8)

        first, second = invert_pair(*wanted, pair_index, key, rounds)
        if transform_pair(first, second, pair_index, key, rounds) != wanted:
            sys.exit(f"[-] pair {pair_index}: inversion failed forward check")

        recovered.append(first ^ (state & 0xFF))
        recovered.append(second ^ (state >> 8))
        state = record_value                      # chain on the raw record value
        cursor = (cursor + start) & 0xFFFFFFFF

    print(f"[*] record order: {', '.join(map(str, order))}")
    if len(recovered) != message_length:
        sys.exit("[-] recovered length does not match header")
    print(f"[+] FLAG: {recovered.decode('ascii')}")


if __name__ == "__main__":
    main()
