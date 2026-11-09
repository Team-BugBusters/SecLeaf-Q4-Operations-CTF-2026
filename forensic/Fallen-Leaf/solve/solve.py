#!/usr/bin/env python3
"""Fallen Leaf: the whole chain from leafdisk.img.xz.

  1. decompress the ext4 image (stdlib lzma);
  2. read notes.txt (SHA-256 of the active key) and its user.leaf xattr with debugfs;
  3. list deleted inodes and dump them: the four gzip'd key backups are still there;
  4. pick the backup whose key hashes to the value in notes.txt;
  5. decrypt Documents/harvest.enc (openssl enc -aes-256-cbc -pbkdf2 -iter 100000) -> piece 1;
  6. Base32-decode the xattr -> piece 2.

Needs `debugfs` from e2fsprogs (Linux: preinstalled; macOS: `brew install e2fsprogs`)
and the `cryptography` package.
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import lzma
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ATT = Path(__file__).resolve().parents[1] / "attachments"
IMAGE_XZ = ATT / "leafdisk.img.xz"


def find_debugfs() -> str:
    for cand in ("debugfs", "/sbin/debugfs", "/usr/sbin/debugfs",
                 "/opt/homebrew/opt/e2fsprogs/sbin/debugfs", "/usr/local/opt/e2fsprogs/sbin/debugfs"):
        path = shutil.which(cand) or (cand if Path(cand).exists() else None)
        if path:
            return path
    sys.exit("[-] debugfs not found: install e2fsprogs (macOS: brew install e2fsprogs)")


def debugfs(tool: str, img: Path, request: str) -> str:
    return subprocess.run([tool, "-R", request, str(img)], capture_output=True, text=True).stdout


def openssl_pbkdf2_decrypt(blob: bytes, password: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    assert blob[:8] == b"Salted__", "not an `openssl enc -salt` file"
    kiv = hashlib.pbkdf2_hmac("sha256", password, blob[8:16], 100_000, 48)
    dec = Cipher(algorithms.AES(kiv[:32]), modes.CBC(kiv[32:])).decryptor()
    pt = dec.update(blob[16:]) + dec.finalize()
    if not 1 <= pt[-1] <= 16 or pt[-pt[-1]:] != bytes([pt[-1]]) * pt[-1]:
        raise ValueError("bad padding (wrong password)")
    return pt[:-pt[-1]]


def main() -> None:
    if not IMAGE_XZ.exists():
        sys.exit(f"[-] {IMAGE_XZ.name} not found in attachments/")
    tool = find_debugfs()
    with tempfile.TemporaryDirectory() as tmp:
        img = Path(tmp) / "leafdisk.img"
        img.write_bytes(lzma.decompress(IMAGE_XZ.read_bytes()))
        print(f"[*] leafdisk.img: {img.stat().st_size} bytes (ext4)")

        notes = debugfs(tool, img, "cat /home/leaf/Documents/notes.txt")
        target = re.search(r"\b[0-9a-f]{64}\b", notes).group(0)
        print(f"[*] notes.txt: active key has sha256 {target}")

        xattr = re.search(r'user\.leaf \(\d+\) = "([^"]+)"', debugfs(tool, img, "ea_list /home/leaf/Documents/notes.txt")).group(1)
        print(f"[*] notes.txt xattr user.leaf = {xattr}")

        deleted = [int(m) for m in re.findall(r"^\s*(\d+)\s+\d+\s+100644", debugfs(tool, img, "lsdel"), re.M)]
        print(f"[*] deleted inodes still holding data: {deleted}")
        password = None
        for ino in deleted:
            out = Path(tmp) / f"inode{ino}"
            debugfs(tool, img, f"dump <{ino}> {out}")
            raw = out.read_bytes()
            if raw[:2] != b"\x1f\x8b":
                continue
            name = raw[10:raw.index(b"\0", 10)].decode() if raw[3] & 8 else "?"
            text = gzip.decompress(raw).decode().strip()
            key = text.split(":", 1)[-1]
            ok = hashlib.sha256(key.encode()).hexdigest() == target
            print(f"    inode {ino}: {name}.gz -> {text!r}  {'<-- sha256 matches notes.txt' if ok else ''}")
            if ok:
                password = key.encode()
        assert password, "no backup matched the hash in notes.txt"

        harvest = Path(tmp) / "harvest.enc"
        debugfs(tool, img, f"dump /home/leaf/Documents/harvest.enc {harvest}")
        plain = openssl_pbkdf2_decrypt(harvest.read_bytes(), password).decode()
        print(f"[*] harvest.txt:\n{plain.rstrip()}")

    # harvest.txt carries its own decoy (a full FLAG=SecLeaf{...} line); the real piece is labelled
    decoy = re.search(r"FLAG=(\S+)", plain)
    if decoy:
        print(f"[*] ignoring the decoy inside harvest.txt: {decoy.group(1)}")
    part1 = re.search(r"Part one of the real flag:\s*(\S+)", plain).group(1)
    part2 = base64.b32decode(xattr).decode()
    print(f"[*] piece 1 (harvest): {part1}")
    print(f"[*] piece 2 (xattr):   {part2}")
    print(f"[+] FLAG: SecLeaf{{{part1}{part2}}}")


if __name__ == "__main__":
    main()
