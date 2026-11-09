#!/usr/bin/env python3
"""Maintainer of None – re-check the accepted dossier and replay the verifiers.

What this does (mirrors the team's reconstructed `reproduce_chain.py`):
  1. Split the accepted 2,784-byte dossier into its nested sections.
  2. Stage 2 (arbiter): read the 48 `trust_reconciliation` rows for epoch
     0xa8a713f6, solve the 48x48 system over GF(65521), undo the V4 recurrence
     and compare the result with the 48 raw values stored in the dossier.
  3. Stage 3 (conclave): same for the 64 `attestation` rows (epoch 0x1f381262)
     with the V5 recurrence.
  4. On Linux x86-64, run custodian / arbiter / conclave with LD_PRELOAD unset
     and print the receipt each binary returns.

Limits, stated honestly:
  * The stage-1 witness, route4/route5 words and chapter digests are taken from
    the accepted dossier. They were captured from the live verifiers with
    temporary instrumentation that was not kept, so they are not regenerated.
  * The writeup gives the blind formulas but does not define `stage1_digest`
    (V4) or `ancestor` (V5), nor the SQLite column names. We ASSUME
    stage1_digest = SHA-256(stage-1 witness) and ancestor = SHA-256(stage-2
    witness) and locate columns by name. If the assumption is wrong the solved
    vector will not match the dossier and the script says so.

Inputs in ../attachments/ (the accepted dossier is NOT archived; the other files are):
    dossier_v5_route_captured.bin, chancery.sqlite, attestor.sqlite,
    custodian, arbiter, conclave, libisa.so, libpolicy.so, libstamp.so
    plus the remaining challenge files the binaries read at runtime.

Run:
    python3 solve.py
"""
from __future__ import annotations

import hashlib
import os
import platform
import sqlite3
import struct
import subprocess
import sys
from pathlib import Path

ATT = Path(__file__).resolve().parents[1] / "attachments"
DOSSIER = ATT / "dossier_v5_route_captured.bin"
P = 65521

DOSSIER_SHA256 = "d960ca8169bdae653203b5a24d21c133c743becfe9befe64a74bdaf936e8761e"
EPOCH_V4 = 0xA8A713F6
EPOCH_V5 = 0x1F381262

# (start, end) offsets inside the dossier
SECTIONS = {
    "stage1_witness": (0x000, 0x240),   # 32 u16 arithmetic values + 128 u32 continuity selectors
    "v4_raw":         (0x240, 0x2A0),   # 48 u16
    "route4":         (0x2A0, 0x6A0),   # 256 u32
    "v5_raw":         (0x6A0, 0x720),   # 64 u16
    "route5":         (0x720, 0xA20),   # 192 u32 (24 chapters x 8 words)
    "chapters":       (0xA20, 0xAE0),   # 24 x 8-byte chapter-state digests
}


# ---------------------------------------------------------------- GF(p) maths
def solve_mod(rows: list[list[int]], rhs: list[int], p: int = P) -> list[int]:
    """Gauss-Jordan elimination over GF(p). Raises if the system is singular."""
    n = len(rows)
    m = [[c % p for c in row] + [r % p] for row, r in zip(rows, rhs)]
    for col in range(n):
        pivot = next((r for r in range(col, n) if m[r][col]), None)
        if pivot is None:
            raise ValueError(f"singular system at column {col}")
        m[col], m[pivot] = m[pivot], m[col]
        inv = pow(m[col][col], -1, p)
        m[col] = [v * inv % p for v in m[col]]
        for r in range(n):
            if r != col and m[r][col]:
                f = m[r][col]
                m[r] = [(a - f * b) % p for a, b in zip(m[r], m[col])]
    return [m[r][n] for r in range(n)]


def v4_forward(x: list[int]) -> list[int]:
    """z0=x0, z1=x1, z2=x2+x1*x0, zi=xi+x(i-1)*x(i-2)+x(i-3)  (mod p)."""
    z = []
    for i, xi in enumerate(x):
        if i < 2:
            z.append(xi % P)
        elif i == 2:
            z.append((xi + x[1] * x[0]) % P)
        else:
            z.append((xi + x[i - 1] * x[i - 2] + x[i - 3]) % P)
    return z


def v4_inverse(z: list[int]) -> list[int]:
    x: list[int] = []
    for i, zi in enumerate(z):
        if i < 2:
            x.append(zi % P)
        elif i == 2:
            x.append((zi - x[1] * x[0]) % P)
        else:
            x.append((zi - x[i - 1] * x[i - 2] - x[i - 3]) % P)
    return x


def v5_forward(x: list[int]) -> list[int]:
    """z0=x0, z1=x1+x0^2, z2=x2+x1^2, zi=xi+x(i-1)^2+x(i-3). Uses RAW x(i-1), not z."""
    z = []
    for i, xi in enumerate(x):
        if i == 0:
            z.append(xi % P)
        elif i < 3:
            z.append((xi + x[i - 1] ** 2) % P)
        else:
            z.append((xi + x[i - 1] ** 2 + x[i - 3]) % P)
    return z


def v5_inverse(z: list[int]) -> list[int]:
    x: list[int] = []
    for i, zi in enumerate(z):
        if i == 0:
            x.append(zi % P)
        elif i < 3:
            x.append((zi - x[i - 1] ** 2) % P)
        else:
            x.append((zi - x[i - 1] ** 2 - x[i - 3]) % P)
    return x


def blind(tag: bytes, context: bytes, epoch: int, index: int) -> int:
    h = hashlib.sha256(tag + context + struct.pack("<IH", epoch, index)).digest()
    return struct.unpack("<H", h[:2])[0] % P


# ---------------------------------------------------------------- SQLite rows
def load_rows(db: Path, table: str, n: int, epoch: int) -> list[tuple[int, list[int], int]]:
    """Return n rows as (index, coefficients, syndrome), locating columns by name."""
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    cols = [r[1] for r in con.execute(f"PRAGMA table_info({table})")]

    def find(*keys: str) -> str | None:
        return next((c for c in cols if any(k in c.lower() for k in keys)), None)

    c_idx, c_coef = find("row", "slot", "idx"), find("coef", "blob")
    c_syn, c_epoch = find("syndrome"), find("epoch", "lane")
    if not (c_idx and c_coef and c_syn):
        sys.exit(f"[-] {db.name}:{table} columns {cols} - could not identify index/coeff/syndrome")
    sql = f"SELECT {c_idx}, {c_coef}, {c_syn} FROM {table}"
    args: tuple = ()
    if c_epoch:
        sql += f" WHERE {c_epoch} = ?"
        args = (epoch,)
    rows = [
        (int(i), list(struct.unpack(f"<{n}H", bytes(blob))), int(s))
        for i, blob, s in con.execute(sql + f" ORDER BY {c_idx}", args)
    ]
    if len(rows) != n:
        sys.exit(f"[-] {db.name}:{table}: expected {n} rows for epoch {epoch:#x}, got {len(rows)}")
    return rows


def solve_stage(name, db, table, n, epoch, tag, context, inverse, forward, expected):
    rows = load_rows(ATT / db, table, n, epoch)
    coeffs = [c for _, c, _ in rows]
    rhs = [(s - blind(tag, context, epoch, i)) % P for i, _, s in rows]
    z = solve_mod(coeffs, rhs)
    x = inverse(z)
    ok_eq = all(
        (sum(a * b for a, b in zip(c, forward(x))) + blind(tag, context, epoch, i)) % P == s
        for i, c, s in rows
    )
    match = x == expected
    print(f"[*] {name}: solved {n} values, {n} equations hold={ok_eq}, matches dossier={match}")
    print(f"    first values: {x[:8]}")
    if not match:
        print("    (mismatch: the blind-context assumption in the docstring is likely wrong)")
    return match


# ---------------------------------------------------------------- main
def main() -> None:
    if not DOSSIER.is_file():
        sys.exit(
            f"[-] {DOSSIER.name} not found in {ATT}\n"
            "    The accepted dossier is not archived in this repository; place it in "
            "attachments/ (next to the challenge files) to run."
        )
    dossier = DOSSIER.read_bytes()
    digest = hashlib.sha256(dossier).hexdigest()
    print(f"[*] dossier: {len(dossier)} bytes, sha256 {digest}")
    if len(dossier) != 0xAE0:
        sys.exit("[-] dossier must be 2,784 (0xae0) bytes")
    if digest != DOSSIER_SHA256:
        print("[!] sha256 differs from the accepted dossier recorded in the writeup")

    sec = {k: dossier[a:b] for k, (a, b) in SECTIONS.items()}
    v4_raw = list(struct.unpack("<48H", sec["v4_raw"]))
    v5_raw = list(struct.unpack("<64H", sec["v5_raw"]))
    stage1 = dossier[:0x240]
    stage2 = dossier[:0x6A0]
    print(f"[*] route4: {len(sec['route4']) // 4} words, route5: {len(sec['route5']) // 4} words, "
          f"chapters: {len(sec['chapters']) // 8} digests")

    solve_stage("V4 / arbiter", "chancery.sqlite", "trust_reconciliation", 48, EPOCH_V4,
                b"V4/BLIND", hashlib.sha256(stage1).digest(), v4_inverse, v4_forward, v4_raw)
    solve_stage("V5 / conclave", "attestor.sqlite", "attestation", 64, EPOCH_V5,
                b"V5/AUDIT/BLIND", hashlib.sha256(stage2).digest(), v5_inverse, v5_forward, v5_raw)

    if platform.system() != "Linux" or platform.machine() not in ("x86_64", "AMD64"):
        sys.exit("[-] the verifier binaries are Linux x86-64 ELF; run this on Linux to get the receipts")

    work = ATT
    (work / "stage1_witness.bin").write_bytes(stage1)
    (work / "stage2_witness.bin").write_bytes(stage2)
    env = {k: v for k, v in os.environ.items() if k != "LD_PRELOAD"}
    receipts = []
    for binary, flag, inp in (("custodian", "--reconcile", "stage1_witness.bin"),
                              ("arbiter", "--adjudicate", "stage2_witness.bin"),
                              ("conclave", "--attest", DOSSIER.name)):
        exe = work / binary
        exe.chmod(exe.stat().st_mode | 0o111)
        r = subprocess.run([str(exe), flag, inp], cwd=work, env=env,
                           capture_output=True, text=True, timeout=120)
        out = r.stdout.strip().splitlines()[-1] if r.stdout.strip() else ""
        print(f"[*] {binary}: exit={r.returncode} -> {out}")
        if r.returncode != 0:
            sys.exit(f"[-] {binary} rejected its input")
        receipts.append(out)

    print("[*] custodian and arbiter outputs are intermediate receipts; conclave's is the flag")
    print(f"[+] FLAG: {receipts[-1]}")


if __name__ == "__main__":
    main()
