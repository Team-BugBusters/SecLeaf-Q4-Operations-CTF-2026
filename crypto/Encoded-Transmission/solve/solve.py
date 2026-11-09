#!/usr/bin/env python3
"""Encoded Transmission (SecLeaf CTF 2026) - offline solver.

Layers:
  1. Base64 (outer transport encoding)        -> 224 ciphertext bytes
  2. AES-128-ECB, PKCS#7, raw key 01000144__984720 -> plaintext with the flag
  3. Base65536 password field (24 code points)  -> 48-byte ASCII password

Everything needed is embedded below (taken from the team writeup), so the
script needs no attachments and no third-party packages: AES is implemented
in pure Python.
"""
import base64

# ---------------------------------------------------------------------------
# Inputs (from the writeup)
# ---------------------------------------------------------------------------
TRANSMISSION = """
ykt4faVZ2qGkcdWkMnDES8HXjpwvrTYiCVO65dg/1Vv/7R2+0KRe0XGDhfdw
B0U2UyMzvb5ZqskJG4wlz9dXKUHcFqXTpF09hg2uAUJI0NASWuPw1h/H4Zi/
1rRGmqnUJkdZzbW58HI2d81iUdS+XePbaQJ+bGwABg35WaJBizKXgQgtI3pt
vQRGuZlZNv6TFHmvpVRyf/TWulZVJPkrE25z1Yu3C+XnqHcqn7ZByHC/SAOf
Ojj6gvFo7MaKw7yOai0IwmdcLwByJAG8fyounsNL7mjMr4nTo4+0C69Raic=
"""

BUILDING_CODE = "01000144"   # from Riddled Code - keep the leading zero
PARKING_COST_YEN = "984720"  # from Riddled Code

# The 24-code-point password field, as recorded in the writeup.
PASSWORD_CODEPOINTS = [
    0x9D74, 0x13169, 0x9D5F, 0x13161, 0x965F, 0xA36C,
    0x1325F, 0x9A68, 0x1325F, 0x1206F, 0x1316C, 0x1305F,
    0x12265, 0x9E75, 0x9A72, 0x9464, 0x12074, 0x995F,
    0x946F, 0x10669, 0x9E66, 0x1326C, 0x9672, 0x9A74,
]
# Base65536-decoded value reported by the team (qntm decoder).
PASSWORD_ASCII = "this_has_all_the_tools_required_to_do_infiltrate"

# ---------------------------------------------------------------------------
# Minimal pure-Python AES (encrypt + decrypt, 128/192/256-bit keys)
# ---------------------------------------------------------------------------
def _xtime(a):
    a <<= 1
    return (a ^ 0x11B) & 0xFF if a & 0x100 else a


def _gmul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = _xtime(a)
        b >>= 1
    return r


def _build_sbox():
    sbox = [0] * 256
    for x in range(256):
        inv = 0 if x == 0 else next(y for y in range(1, 256) if _gmul(x, y) == 1)
        s = inv
        for shift in range(1, 5):
            s ^= ((inv << shift) | (inv >> (8 - shift))) & 0xFF
        sbox[x] = s ^ 0x63
    inv_sbox = [0] * 256
    for i, v in enumerate(sbox):
        inv_sbox[v] = i
    return sbox, inv_sbox


SBOX, INV_SBOX = _build_sbox()


def _expand_key(key):
    nk = len(key) // 4
    nr = nk + 6
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    rcon = 1
    for i in range(nk, 4 * (nr + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = t[1:] + t[:1]
            t = [SBOX[b] for b in t]
            t[0] ^= rcon
            rcon = _xtime(rcon)
        elif nk > 6 and i % nk == 4:
            t = [SBOX[b] for b in t]
        w.append([a ^ b for a, b in zip(w[i - nk], t)])
    return [sum(w[4 * r:4 * r + 4], []) for r in range(nr + 1)]


def _shift_rows(s, inv=False):
    out = [0] * 16
    for c in range(4):
        for r in range(4):
            src = (c + r) % 4 if not inv else (c - r) % 4
            out[4 * c + r] = s[4 * src + r]
    return out


def _mix(s, m):
    out = []
    for c in range(4):
        col = s[4 * c:4 * c + 4]
        for r in range(4):
            out.append(_gmul(col[0], m[r][0]) ^ _gmul(col[1], m[r][1])
                       ^ _gmul(col[2], m[r][2]) ^ _gmul(col[3], m[r][3]))
    return out


_MIX = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]
_INV_MIX = [[14, 11, 13, 9], [9, 14, 11, 13], [13, 9, 14, 11], [11, 13, 9, 14]]


def aes_encrypt_block(rk, block):
    s = [b ^ k for b, k in zip(block, rk[0])]
    for rnd in range(1, len(rk)):
        s = [SBOX[b] for b in s]
        s = _shift_rows(s)
        if rnd != len(rk) - 1:
            s = _mix(s, _MIX)
        s = [b ^ k for b, k in zip(s, rk[rnd])]
    return bytes(s)


def aes_decrypt_block(rk, block):
    s = [b ^ k for b, k in zip(block, rk[-1])]
    for rnd in range(len(rk) - 2, -1, -1):
        s = _shift_rows(s, inv=True)
        s = [INV_SBOX[b] for b in s]
        s = [b ^ k for b, k in zip(s, rk[rnd])]
        if rnd != 0:
            s = _mix(s, _INV_MIX)
    return bytes(s)


def ecb(func, key, data):
    rk = _expand_key(key)
    return b"".join(func(rk, data[i:i + 16]) for i in range(0, len(data), 16))


# ---------------------------------------------------------------------------
def main():
    # FIPS-197 Appendix C.1 known-answer test for the AES implementation.
    kat_key = bytes(range(16))
    kat_pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    assert ecb(aes_encrypt_block, kat_key, kat_pt).hex() == "69c4e0d86a7b0430d8cdb78070b4c55a"
    print("[*] AES self-test (FIPS-197 C.1) passed")

    # Layer 1: Base64
    b64 = "".join(TRANSMISSION.split())
    ct = base64.b64decode(b64)
    print(f"[*] Base64 characters: {len(b64)}  ->  ciphertext bytes: {len(ct)} ({len(ct) // 16} blocks)")

    # Layer 2: AES-128-ECB with the literal 16-byte key
    key = f"{BUILDING_CODE}__{PARKING_COST_YEN}".encode()
    assert len(key) == 16
    print(f"[*] Key: {key.decode()}  (hex {key.hex()})")
    padded = ecb(aes_decrypt_block, key, ct)
    pad = padded[-1]
    assert 1 <= pad <= 16 and padded[-pad:] == bytes([pad]) * pad, "bad PKCS#7 padding"
    print(f"[*] PKCS#7 padding: {padded[-pad:].hex(' ')}")
    pt = padded[:-pad]
    print(f"[*] Plaintext: {len(pt)} bytes UTF-8")
    text = pt.decode("utf-8")
    print("[*] --- decrypted message ---")
    print(text)
    print("[*] --- end ---")

    # Round-trip check: re-encrypt and compare with the original ciphertext.
    assert ecb(aes_encrypt_block, key, padded) == ct
    print("[*] Re-encryption reproduces all 224 ciphertext bytes")

    # Layer 3: Base65536 password field
    field = "".join(chr(cp) for cp in PASSWORD_CODEPOINTS)
    if field in text:
        print("[*] The 24-code-point password field appears verbatim in the plaintext")
    # In Base65536 every code point carries two bytes: its low 8 bits are the
    # first byte, and the 256-code-point block it sits in encodes the second.
    # Without vendoring qntm's block table we can still check the reported
    # ASCII value: low bytes must equal the even-position characters, and the
    # block -> second-byte mapping must be consistent and one-to-one.
    assert len(PASSWORD_ASCII) == 2 * len(PASSWORD_CODEPOINTS)
    block_to_byte = {}
    for i, cp in enumerate(PASSWORD_CODEPOINTS):
        assert cp & 0xFF == ord(PASSWORD_ASCII[2 * i])
        hi = PASSWORD_ASCII[2 * i + 1]
        assert block_to_byte.setdefault(cp >> 8, hi) == hi
    assert len(set(block_to_byte.values())) == len(block_to_byte)
    print(f"[*] Base65536 field is consistent with: {PASSWORD_ASCII}")

    flag = next(w for w in text.split() if w.startswith("CRY{"))
    flag = flag[: flag.index("}") + 1]
    print(f"[+] FLAG: {flag}")


if __name__ == "__main__":
    main()
