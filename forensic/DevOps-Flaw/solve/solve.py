#!/usr/bin/env python3
"""
DevOps Flaw (SecLeaf CTF 2026) - offline solver for the final decode.

Inputs recovered from the disk image and embedded here:
  * acme-infrastructure/.env.example:          DB_PASSWORD=KEY_15_00f
  * acme-infrastructure/logs/deploy-2026-09-18.log: the 38-byte value after
    the Error label and tab.
`00f` read as hex with a leading zero -> two-byte key 00 0f (decimal 15 for
the second byte). Repeating XOR with that key yields the flag.
The archive (attachments/Archive.7z, password 299792458rocks) and the disk image inside
it are not needed for this step; both values were checked against them by hand.
"""

ENV_MARKER = "KEY_15_00f"
LOG_VALUE = "SjcCenftl<g;cV_}eh1|T}YPm>g}a[1`nP274r"


def main() -> None:
    _, dec, hexpart = ENV_MARKER.split("_")
    key = bytes.fromhex(hexpart.rjust(4, "0"))  # "00f" -> "000f" -> 00 0f
    assert key[-1] == int(dec), "decimal and hex parts of the marker disagree"
    print(f"[*] Key marker {ENV_MARKER} -> key bytes {key.hex(' ')}")

    ct = LOG_VALUE.encode()
    print(f"[*] Log ciphertext: {len(ct)} bytes")
    pt = bytes(b ^ key[i % len(key)] for i, b in enumerate(ct)).decode()
    print(f"[+] FLAG: {pt}")


if __name__ == "__main__":
    main()
