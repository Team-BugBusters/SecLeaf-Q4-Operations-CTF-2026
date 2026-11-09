#!/usr/bin/env python3
"""
Layers – SecLeaf CTF 2026 (Miscellaneous / encoding + archive analysis)

Peels the challenge chain:

    Binary_Data  ->  binary (8-bit bytes)  ->  ROT13 (letters only)
                 ->  hex decode  ->  RAR5 archive  ->  (password: stormstorm)
                 ->  file "Text"  ->  ROT47  ->  flag

The original attachment is ../attachments/Binary_Data. With it present the script runs
the whole chain (it extracts the RAR with `unar`/`7z`, or the `rarfile` library if one
of those is installed). With no attachment, or no RAR extractor, it falls back to the
ROT47 ciphertext recorded in the writeup, so it prints the exact flag either way.

Python 3.10+, standard library only (archive extraction shells out to tools that
may or may not be present).  No network.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ATT = HERE.parent / "attachments"
BINARY_DATA = ATT / "Binary_Data"

RAR_PASSWORD = "stormstorm"

# The 22-byte file "Text" that was extracted from the RAR during the event.
# The writeup quotes it verbatim; ROT47 of it is the flag.
ROT47_CIPHERTEXT = "u`?c={J0*~F0v_E0`%0P/P"

EXPECTED_FLAG = "F1n4lLy_YOu_G0t_1T_!^!"


def rot13_letters(s: str) -> str:
    """ROT13 on A-Z / a-z only; digits and punctuation untouched.

    Maps the n..s that fall out of the binary decode onto a..f, turning the
    substituted text into valid hexadecimal.
    """
    out = []
    for ch in s:
        o = ord(ch)
        if 65 <= o <= 90:        # A-Z
            out.append(chr((o - 65 + 13) % 26 + 65))
        elif 97 <= o <= 122:     # a-z
            out.append(chr((o - 97 + 13) % 26 + 97))
        else:
            out.append(ch)
    return "".join(out)


def rot47(s: str) -> str:
    """ROT47 over the printable ASCII band 33..126."""
    out = []
    for ch in s:
        o = ord(ch)
        if 33 <= o <= 126:
            out.append(chr(33 + (o - 33 + 47) % 94))
        else:
            out.append(ch)
    return "".join(out)


def bits_to_text(bits: str) -> str:
    """Decode a continuous bitstring as 8-bit bytes into a string."""
    bits = "".join(bits.split())  # drop any whitespace / newlines
    if len(bits) % 8 != 0:
        raise ValueError(f"bit length {len(bits)} is not a multiple of 8")
    return "".join(
        chr(int(bits[i:i + 8], 2)) for i in range(0, len(bits), 8)
    )


def extract_rar_text(rar_bytes: bytes) -> str | None:
    """Write the RAR5 archive to a temp dir and extract the single file 'Text'.

    Tries `unar`, then `7z`, then the optional `rarfile` library. Returns the
    extracted contents as text, or None if no extractor is available/works.
    """
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        rar_path = tmp / "layer3.rar"
        rar_path.write_bytes(rar_bytes)

        # 1) unar (handles RAR5, the extractor that worked during the event)
        if shutil.which("unar"):
            out_dir = tmp / "unpacked"
            rc = subprocess.run(
                ["unar", "-p", RAR_PASSWORD, "-o", str(out_dir),
                 "-f", str(rar_path)],
                capture_output=True,
            )
            text = out_dir / "Text"
            if rc.returncode == 0 and text.exists():
                return text.read_text(errors="replace")

        # 2) 7z (may report "Unsupported Method" on some builds)
        if shutil.which("7z"):
            out_dir = tmp / "unpacked7z"
            rc = subprocess.run(
                ["7z", "x", f"-p{RAR_PASSWORD}", f"-o{out_dir}",
                 "-y", str(rar_path)],
                capture_output=True,
            )
            text = out_dir / "Text"
            if rc.returncode == 0 and text.exists():
                return text.read_text(errors="replace")

        # 3) rarfile library (needs an unrar backend)
        try:
            import rarfile  # type: ignore
            with rarfile.RarFile(str(rar_path)) as rf:
                rf.setpassword(RAR_PASSWORD)
                data = rf.read("Text")
            return data.decode(errors="replace")
        except Exception:
            pass

    return None


def run_full_chain() -> str | None:
    """Full chain from the archived Binary_Data attachment, if present."""
    if not BINARY_DATA.exists():
        return None

    bits = BINARY_DATA.read_text()
    print(f"[*] read {BINARY_DATA.name}: {len(''.join(bits.split()))} bits")

    substituted = bits_to_text(bits)
    print(f"[*] binary -> text (first 48): {substituted[:48]}")

    hexstr = rot13_letters(substituted)
    print(f"[*] ROT13   -> hex  (first 48): {hexstr[:48]}")

    rar_bytes = bytes.fromhex(hexstr)
    print(f"[*] hex     -> {len(rar_bytes)} bytes, signature "
          f"{rar_bytes[:8].hex(' ').upper()}")
    if rar_bytes[:4] != b"Rar!":
        print("[!] not a RAR archive; aborting full chain")
        return None

    text = extract_rar_text(rar_bytes)
    if text is None:
        print("[!] no working RAR extractor found (install `unar`); "
              "falling back to the archived ciphertext")
        return None
    print(f"[*] extracted Text ({len(text)} bytes): {text!r}")

    return rot47(text)


def main() -> None:
    flag = run_full_chain()

    if flag is None:
        # No attachment (or no extractor): reproduce from the quoted ciphertext.
        print("[*] no attachment or no RAR extractor - verifying the final ROT47 stage "
              "from the ciphertext recorded in the writeup")
        print(f"[*] Text ciphertext: {ROT47_CIPHERTEXT!r}")
        flag = rot47(ROT47_CIPHERTEXT)

    # Self-check: ROT47 is its own inverse, so it must map the flag back to the
    # ciphertext the writeup recorded.
    assert rot47(flag) == ROT47_CIPHERTEXT, "ROT47 round-trip failed"
    assert flag == EXPECTED_FLAG, f"unexpected result: {flag!r}"

    print(f"[+] FLAG: {flag}")


if __name__ == "__main__":
    main()
