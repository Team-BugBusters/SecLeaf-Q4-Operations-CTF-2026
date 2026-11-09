#!/usr/bin/env python3
"""NullVector Ransomware (SecLeaf CTF 2026) - offline solver.

classified_report.locked layout (886 bytes):
    0-3     magic 89 52 57 01
    4-5     RSA block length, big-endian (0x0100 = 256)
    6-261   RSA-2048 wrapped AES-256 key (raw RSA, key = last 32 bytes)
    262-277 AES IV
    278-885 AES-256-CBC body (608 bytes, PKCS#7)

After AES the body is still scrambled:
    K_i = (13*i + 0x7a) mod 256
    P_i = ROTL8(S_i, 3) XOR K_i

Inputs: ../attachments/Quantum_factory.json (N, p, q, e) and
        ../attachments/classified_report.locked
Stdlib only (AES is implemented in pure Python below).
"""
import json
import sys
from pathlib import Path

ATT = Path(__file__).resolve().parent.parent / "attachments"
FACTORY = ATT / "Quantum_factory.json"
LOCKED = ATT / "classified_report.locked"

# Values recorded in the writeup, used as cross-checks.
EXPECTED_AES_KEY = "078440dd9f8c28d0a8e90f37efd987f736e67023762a2bfbe32cbac9d7afa8d7"
EXPECTED_IV = "570d8115917ada6efd6e9cf0f5a90025"
WRITEUP_XOR_KEY = (
    "7a8794a1aebbc8d5e2effc091623303d4a5764717e8b98a5b2bfccd9e6f3000d"
    "1a2734414e5b6875828f9ca9b6c3d0ddeaf704111e2b3845525f6c798693a0ad"
    "bac7d4e1eefb0815222f3c495663707d8a97a4b1becbd8e5f2ff0c192633404d"
    "5a6774818e9ba8b5c2cfdce9f603101d2a3744515e6b7885929facb9c6d3e0ed"
    "fa0714212e3b4855626f7c8996a3b0bdcad7e4f1fe0b1825323f4c596673808d"
    "9aa7b4c1cedbe8f5020f1c293643505d6a7784919eabb8c5d2dfecf90613202d"
    "3a4754616e7b8895a2afbcc9d6e3f0fd0a1724313e4b5865727f8c99a6b3c0cd"
    "dae7f4010e1b2835424f5c697683909daab7c4d1deebf805121f2c394653606d"
)

# ---------------------------------------------------------------------------
# Minimal pure-Python AES (128/192/256-bit keys)
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



def aes_cbc_decrypt(key, iv, data):
    rk = _expand_key(key)
    out, prev = bytearray(), iv
    for i in range(0, len(data), 16):
        blk = data[i:i + 16]
        out += bytes(a ^ b for a, b in zip(aes_decrypt_block(rk, blk), prev))
        prev = blk
    return bytes(out)


# ---------------------------------------------------------------------------
# Scrambler
# ---------------------------------------------------------------------------
def mask(i):
    return (13 * i + 0x7A) % 256


def rotl8(x, r):
    return ((x << r) | (x >> (8 - r))) & 0xFF


def unscramble(body):
    return bytes(rotl8(s, 3) ^ mask(i) for i, s in enumerate(body))


def self_test():
    # FIPS-197 C.3 (AES-256) known-answer test
    k = bytes(range(32))
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    assert aes_encrypt_block(_expand_key(k), pt).hex() == "8ea2b7ca516745bfeafc49904b496089"
    assert aes_decrypt_block(_expand_key(k), bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")) == pt
    # The mask formula reproduces the 256-byte XOR key used in CyberChef
    assert bytes(mask(i) for i in range(256)).hex() == WRITEUP_XOR_KEY
    # Mask period is 256 (13*256 = 0 mod 256)
    assert all(mask(i) == mask(i + 256) for i in range(256))
    # Worked example from the writeup: 27 79 ba 5e -> rotl3 39 cb d5 f2 -> xor "CLAS"
    s = bytes.fromhex("2779ba5e")
    assert bytes(rotl8(b, 3) for b in s).hex() == "39cbd5f2"
    assert unscramble(s) == b"CLAS"
    # Banner check: rotation 3 + XOR '=' gives masks 68 75 82 ... at offset 38
    assert [mask(38 + j) for j in range(8)] == [0x68, 0x75, 0x82, 0x8F, 0x9C, 0xA9, 0xB6, 0xC3]
    print("[*] self-tests passed (AES-256 KAT, mask table, CLAS example, banner masks)")


# ---------------------------------------------------------------------------
# RSA parameter loading (field names in the JSON were not recorded, so search)
# ---------------------------------------------------------------------------
def _walk(o):
    if isinstance(o, dict):
        for k, v in o.items():
            yield k, v
            yield from _walk(v)
    elif isinstance(o, list):
        for v in o:
            yield from _walk(v)


def _cands(v):
    if isinstance(v, int):
        return [v]
    if isinstance(v, str):
        s = v.strip().lower()
        out = []
        if s.startswith("0x"):
            s = s[2:]
        try:
            out.append(int(s, 16))
        except ValueError:
            pass
        if s.isdigit():
            out.append(int(s, 10))
        return out
    return []


def load_rsa(path):
    data = json.loads(path.read_text())
    names = {"n": ("n", "modulus"), "p": ("p", "prime1"), "q": ("q", "prime2"),
             "e": ("e", "public_exponent", "exponent")}
    found = {k: [] for k in names}
    for key, val in _walk(data):
        for slot, aliases in names.items():
            if str(key).lower() in aliases:
                found[slot] += _cands(val)
    for N in found["n"]:
        for p in found["p"]:
            for q in found["q"]:
                if p * q == N:
                    e = next((x for x in found["e"] if x in (65537, 0x10001)), None)
                    e = e or (found["e"][0] if found["e"] else 65537)
                    return N, p, q, e
    sys.exit(f"[-] could not find N, p, q with p*q == N in {path.name}; adjust load_rsa()")


def main():
    self_test()
    missing = [p.name for p in (FACTORY, LOCKED) if not p.exists()]
    if missing:
        sys.exit("[-] Missing attachment(s): " + " and ".join(missing)
                 + ". Place them in attachments/ to run the full recovery.")

    N, p, q, e = load_rsa(FACTORY)
    assert p * q == N
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    assert (e * d) % phi == 1
    print(f"[*] p*q == N, e = {e:#x}, d recovered ({d.bit_length()} bits)")

    blob = LOCKED.read_bytes()
    print(f"[*] locked file: {len(blob)} bytes, header {blob[:6].hex(' ')}")
    assert blob[:4] == bytes.fromhex("89525701")
    rsa_len = int.from_bytes(blob[4:6], "big")
    off = 6
    c = int.from_bytes(blob[off:off + rsa_len], "big"); off += rsa_len
    iv = blob[off:off + 16]; off += 16
    body = blob[off:]
    print(f"[*] RSA block {rsa_len} bytes, IV {iv.hex()}, body {len(body)} bytes")

    m = pow(c, d, N)
    aes_key = m.to_bytes(rsa_len, "big")[-32:]
    print(f"[*] AES-256 key: {aes_key.hex()}")
    if aes_key.hex() != EXPECTED_AES_KEY or iv.hex() != EXPECTED_IV:
        print("[!] key/IV differ from the values recorded in the writeup")

    padded = aes_cbc_decrypt(aes_key, iv, body)
    pad = padded[-1]
    assert 1 <= pad <= 16 and padded[-pad:] == bytes([pad]) * pad, "bad PKCS#7 padding"
    scrambled = padded[:-pad]
    print(f"[*] AES-CBC ok, padding {pad:#04x} x {pad}, {len(scrambled)} bytes (still scrambled)")

    report = unscramble(scrambled).decode("utf-8", errors="replace")
    print("[*] --- report ---")
    print(report)
    print("[*] --- end ---")
    start = report.index("SecLeaf{")
    flag = report[start:report.index("}", start) + 1]
    print(f"[+] FLAG: {flag}")


if __name__ == "__main__":
    main()
