#!/usr/bin/env python3
"""
At Their House (SecLeaf CTF 2026) - offline solver.

Reproduces lock.exe's three-layer AES-256-CBC unlock:
  * PIN 1 / PIN 2 come from the photo ZIP entry timestamp 2022-07-15 10:04:52
    (YYMMDD and HHMMSS).
  * Each layer derives key/IV with OpenSSL EVP_BytesToKey(SHA-256, count=1)
    from a PIN and an 8-byte salt (one byte 0..10 followed by seven zeros).
  * Layer 2's IV is overwritten with PIN 2 (zero-padded to 16 bytes).
  * Layer 3 keeps PKCS#7 padding on, but lock.exe ignores the failed
    EVP_DecryptFinal_ex and uses the bytes EVP_DecryptUpdate returned.
  * All 11*11*11 = 1331 salt combinations are tried; success = "CRY{" in output.

The 112-byte ciphertext (lock.exe .data, raw offset 0x2600, RVA 0x3000) and the
timestamp are embedded below, so the script runs without the attachments. When
../attachments/ holds photooflock.zip (and, with the optional `py7zr` package,
Box-1234.7z, password 1234) the script also reads the timestamp from the ZIP entry
and the ciphertext from lock.exe and requires them to match the embedded values.
"""
from __future__ import annotations

import hashlib
import tempfile
import zipfile
from pathlib import Path

try:
    from Crypto.Cipher import AES  # pycryptodome

    def aes_cbc_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
        return AES.new(key, AES.MODE_CBC, iv).decrypt(data)
except ImportError:  # fall back to the `cryptography` package
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    def aes_cbc_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
        d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        return d.update(data) + d.finalize()


TIMESTAMP = (2022, 7, 15, 10, 4, 52)  # ZIP entry mtime of OIP-3595450325.jpg

CIPHERTEXT = bytes.fromhex(
    "e6fac39c4d4e249fff261038c112c965"
    "b1481be2323342a0239cc79c845d4ba4"
    "2d3d30fe977808ad6cbf668f092c8eef"
    "cea6cc3bc412cbc61e392cc8b3560697"
    "bd7cdca9ff7ab6f8f3a41debc1c46fff"
    "3b4ce5f332f2bb1b598098c9f5faa6f1"
    "57fa52424cacf97a5eef7470a58b424d"
)


def evp_bytes_to_key_sha256(password: str, salt8: bytes) -> tuple[bytes, bytes]:
    """D1 = SHA256(P||S) -> key; D2 = SHA256(D1||P||S) -> IV = D2[:16]."""
    pw = password.encode("ascii")
    d1 = hashlib.sha256(pw + salt8).digest()
    d2 = hashlib.sha256(d1 + pw + salt8).digest()
    return d1, d2[:16]


def decrypt_layer(data, password, salt_value, iv_override=None, padding=False):
    salt8 = bytes([salt_value]) + b"\x00" * 7
    key, iv = evp_bytes_to_key_sha256(password, salt8)
    if iv_override is not None:
        # memset(iv, 0, 16); memcpy(iv, second_pin, strlen(second_pin));
        iv = iv_override.encode("ascii")[:16].ljust(16, b"\x00")
    raw = aes_cbc_decrypt(data, key, iv)
    if not padding:
        return raw, key, iv
    # EVP_DecryptUpdate holds back the final block; Final only appends it if
    # PKCS#7 is valid. lock.exe ignores Final's status.
    pad = raw[-1]
    if 1 <= pad <= 16 and raw[-pad:] == bytes([pad]) * pad:
        return raw[:-pad], key, iv
    return raw[:-16], key, iv


ATT = Path(__file__).resolve().parent.parent / "attachments"


def crosscheck_attachments() -> None:
    photo_zip = ATT / "photooflock.zip"
    if photo_zip.exists():
        with zipfile.ZipFile(photo_zip) as z:
            stamp = z.infolist()[0].date_time
        assert stamp == TIMESTAMP, f"ZIP timestamp {stamp} differs from the embedded {TIMESTAMP}"
        print(f"[*] photooflock.zip entry time {stamp} matches the embedded timestamp")
    box = ATT / "Box-1234.7z"
    if box.exists():
        try:
            import py7zr
        except ImportError:
            print("[*] (py7zr not installed - skipped reading lock.exe from Box-1234.7z)")
            return
        with tempfile.TemporaryDirectory() as tmp:
            with py7zr.SevenZipFile(box, password="1234") as z:
                z.extractall(tmp)
            exe = (Path(tmp) / "lock.exe").read_bytes()
        assert exe[0x2600:0x2600 + len(CIPHERTEXT)] == CIPHERTEXT, "lock.exe .data differs from the embedded ciphertext"
        print(f"[*] lock.exe ({len(exe)} bytes) holds the embedded ciphertext at raw offset 0x2600")


def main() -> int:
    crosscheck_attachments()
    y, mo, d, hh, mm, ss = TIMESTAMP
    pin1 = f"{y % 100:02d}{mo:02d}{d:02d}"
    pin2 = f"{hh:02d}{mm:02d}{ss:02d}"
    print(f"[*] PIN 1 (YYMMDD): {pin1}")
    print(f"[*] PIN 2 (HHMMSS): {pin2}")
    print(f"[*] Ciphertext: {len(CIPHERTEXT)} bytes")

    attempts = 0
    for s1 in range(11):
        l1, k1, iv1 = decrypt_layer(CIPHERTEXT, pin1, s1)
        for s2 in range(11):
            l2, k2, iv2 = decrypt_layer(l1, pin1, s2, iv_override=pin2)
            for s3 in range(11):
                attempts += 1
                l3, k3, iv3 = decrypt_layer(l2, pin2, s3, padding=True)
                i = l3.find(b"CRY{")
                if i < 0:
                    continue
                j = l3.find(b"}", i)
                if j < 0:
                    continue
                print(f"[*] Hit after {attempts}/1331 combinations: salts {s1}-{s2}-{s3}")
                print(f"[*] Layer 1 key {k1.hex()}  IV {iv1.hex()}")
                print(f"[*] Layer 2 key {k2.hex()}  IV {iv2.hex()} (PIN 2 override)")
                print(f"[*] Layer 3 key {k3.hex()}  IV {iv3.hex()}")
                print(f"[*] Layer 1 output: {l1.hex()}")
                print(f"[*] Layer 2 output: {l2.hex()}")
                print(f"[*] Layer 3 output ({len(l3)} bytes): {l3.hex()}")
                print(f"[+] FLAG: {l3[i:j + 1].decode()}")
                return 0
    print(f"[-] No flag after {attempts} combinations")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
