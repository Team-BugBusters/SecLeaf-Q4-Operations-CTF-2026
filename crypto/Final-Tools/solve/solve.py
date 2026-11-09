#!/usr/bin/env python3
"""Final Tools (SecLeaf CTF 2026) - offline helper/solver.

Two nested archives, two forms of the same password (from Encoded Transmission):
    Payload.7z  <- original 24-code-point Unicode (Base65536) field
    FLAG.zip        <- its Base65536-decoded ASCII text
    FLAG.txt        -> flag (82 ASCII bytes, no newline)

The Unicode password is awkward to type, so this script builds it from the
code points and drives the `7z` binary. Needs ../attachments/Payload.7z
and 7-Zip on PATH. No Python dependencies.
"""
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ATT = Path(__file__).resolve().parent.parent / "attachments"
PAYLOAD = ATT / "Payload.7z"

OUTER_PASSWORD = "".join(chr(cp) for cp in [
    0x9D74, 0x13169, 0x9D5F, 0x13161, 0x965F, 0xA36C,
    0x1325F, 0x9A68, 0x1325F, 0x1206F, 0x1316C, 0x1305F,
    0x12265, 0x9E75, 0x9A72, 0x9464, 0x12074, 0x995F,
    0x946F, 0x10669, 0x9E66, 0x1326C, 0x9672, 0x9A74,
])
INNER_PASSWORD = "this_has_all_the_tools_required_to_do_infiltrate"


def check_password_forms():
    # Base65536: low byte of each code point = 1st byte of the pair; the code
    # point's 256-block encodes the 2nd byte. Check the two forms agree.
    assert len(INNER_PASSWORD) == 2 * len(OUTER_PASSWORD) == 48
    blocks = {}
    for i, ch in enumerate(OUTER_PASSWORD):
        assert ord(ch) & 0xFF == ord(INNER_PASSWORD[2 * i])
        assert blocks.setdefault(ord(ch) >> 8, INNER_PASSWORD[2 * i + 1]) == INNER_PASSWORD[2 * i + 1]
    print(f"[*] outer (7z) password : {OUTER_PASSWORD}  ({len(OUTER_PASSWORD)} code points)")
    print(f"[*] inner (zip) password: {INNER_PASSWORD}  ({len(INNER_PASSWORD)} bytes)")


def sevenzip(*args):
    return subprocess.run(["7z", *args], capture_output=True, text=True)


def main():
    check_password_forms()
    if not PAYLOAD.exists():
        sys.exit(f"[-] {PAYLOAD.name} not found; place it in attachments/ to run.")
    if not shutil.which("7z"):
        sys.exit("[-] 7z not found on PATH (install p7zip / 7-Zip).")

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        r = sevenzip("x", f"-p{OUTER_PASSWORD}", f"-o{tmp/'outer'}", "-y", str(PAYLOAD))
        assert r.returncode == 0, r.stdout + r.stderr
        inner = tmp / "outer" / "FLAG.zip"
        print(f"[*] Payload.7z -> FLAG.zip ({inner.stat().st_size} bytes)")
        r = sevenzip("x", f"-p{INNER_PASSWORD}", f"-o{tmp/'final'}", "-y", str(inner))
        assert r.returncode == 0, r.stdout + r.stderr
        flag = (tmp / "final" / "FLAG.txt").read_bytes()
        print(f"[*] FLAG.zip -> FLAG.txt ({len(flag)} bytes)")
        print(f"[+] FLAG: {flag.decode().strip()}")


if __name__ == "__main__":
    main()
