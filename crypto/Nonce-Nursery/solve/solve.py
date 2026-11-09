#!/usr/bin/env python3
"""Nonce Nursery: ECDSA private key from affinely related nonces.

Two modes:
  * full attack: if ../attachments/data.json is present, hash the 11 messages, express
    every nonce as k = u + v*d, scan every 5-signature window with a polynomial GCD over
    GF(N), and recover d;
  * capsule only (default when the attachment isn't archived): take the recovered d
    quoted in the writeup and derive the key, then decrypt the flag.

A built-in self-test (--selftest) plants the same weakness in synthetic signatures and
shows the GCD attack finds the planted key and the planted window.
"""
from __future__ import annotations

import hashlib
import json
import random
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ATT = Path(__file__).resolve().parents[1] / "attachments"

# secp256k1 group order: ECDSA arithmetic is mod N, not mod the field prime
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Values quoted in the writeup
D_RECOVERED = 0xF833E0B49CD9652C84292C5097B7DBDFD4005FDD2D1CFA7C975CCE14A34616DE
KDF_PREFIX = b"SecLeaf/nonce-nursery/v2/"
NONCE = bytes.fromhex("293913b75cab1570ef4929fb")
CT_AND_TAG = bytes.fromhex(
    "05d4c88968ff68b107b8886f395e9392357144c514"
    "b978c128c272e637b64426ef4e28f76f"
    "37754ef632553357c963b0323b7a6a21"
)


# ---------- tiny polynomial arithmetic over GF(N): coefficient lists, lowest degree first ----------
def p_trim(a):
    while len(a) > 1 and a[-1] % N == 0:
        a = a[:-1]
    return [c % N for c in a]


def p_mul(a, b):
    out = [0] * (len(a) + len(b) - 1)
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            out[i + j] = (out[i + j] + x * y) % N
    return p_trim(out)


def p_sub(a, b):
    n = max(len(a), len(b))
    a, b = a + [0] * (n - len(a)), b + [0] * (n - len(b))
    return p_trim([(x - y) % N for x, y in zip(a, b)])


def p_mod(a, b):
    a = p_trim(a)
    inv = pow(b[-1], -1, N)
    while len(a) >= len(b) and a != [0]:
        f = a[-1] * inv % N
        shift = len(a) - len(b)
        a = p_sub(a, [0] * shift + [c * f % N for c in b])
    return a


def p_gcd(a, b):
    a, b = p_trim(a), p_trim(b)
    while b != [0]:
        a, b = b, p_mod(a, b)
    return a


# ---------- the attack ----------
def nonce_lines(sigs):
    """k_i = u_i + v_i*d, with u = h/s and v = r/s (mod N)."""
    out = []
    for h, r, s in sigs:
        si = pow(s, -1, N)
        out.append([h * si % N, r * si % N])
    return out


def window_root(lines):
    """For 5 consecutive nonces with k_{i+1} = A*k_i + B, differences t_i satisfy t_{i+1} = A*t_i,
    so t0*t2 - t1^2 = 0 and t1*t3 - t2^2 = 0. Their GCD is linear only if the window is affine."""
    t = [p_sub(lines[i + 1], lines[i]) for i in range(4)]
    P = p_sub(p_mul(t[0], t[2]), p_mul(t[1], t[1]))
    Q = p_sub(p_mul(t[1], t[3]), p_mul(t[2], t[2]))
    g = p_gcd(P, Q)
    if len(g) == 2:  # c0 + c1*x  ->  root x = -c0/c1
        return (-g[0]) * pow(g[1], -1, N) % N
    return None


def recover_d(sigs, labels):
    lines = nonce_lines(sigs)
    found = None
    for start in range(len(lines) - 4):
        root = window_root(lines[start:start + 5])
        tag = "linear GCD -> root" if root is not None else "GCD = 1"
        print(f"    window {labels[start]}-{labels[start + 4]}: {tag}")
        if root is not None:
            found = (start, root)
    return found


# ---------- secp256k1 point check (d*G == public key) ----------
P_FIELD = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def ec_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % P_FIELD == 0:
        return None
    if p == q:
        lam = 3 * p[0] * p[0] * pow(2 * p[1], -1, P_FIELD) % P_FIELD
    else:
        lam = (q[1] - p[1]) * pow(q[0] - p[0], -1, P_FIELD) % P_FIELD
    x = (lam * lam - p[0] - q[0]) % P_FIELD
    return x, (lam * (p[0] - x) - p[1]) % P_FIELD


def ec_mul(k, p=G):
    r = None
    while k:
        if k & 1:
            r = ec_add(r, p)
        p, k = ec_add(p, p), k >> 1
    return r


# ---------- capsule ----------
def open_capsule(d: int) -> str:
    key = hashlib.sha256(KDF_PREFIX + d.to_bytes(32, "big")).digest()
    print(f"[+] AES key = {key.hex()}")
    return AESGCM(key).decrypt(NONCE, CT_AND_TAG, None).decode()


def load_attachment():
    """data.json: {curve, public_key: [x, y], records: [{message, r, s}, ...], sealed: {nonce, ct}}"""
    data = json.loads((ATT / "data.json").read_text())
    rows = data["records"]
    to_int = lambda v: int(v, 16) if isinstance(v, str) else int(v)
    sigs, labels = [], []
    for i, row in enumerate(rows):
        msg = row.get("message", row.get("msg"))
        h = int.from_bytes(hashlib.sha256(msg.encode()).digest(), "big")
        sigs.append((h, to_int(row["r"]), to_int(row["s"])))
        labels.append(f"{i:02d}")
    return sigs, labels


def selftest() -> None:
    print("[*] self-test: 11 synthetic signatures, affine nonces planted in window 03-07")
    rng = random.Random(1337)
    d = rng.randrange(1, N)
    ks = [rng.randrange(1, N) for _ in range(11)]
    A, B = rng.randrange(1, N), rng.randrange(1, N)
    for i in range(4, 8):
        ks[i] = (A * ks[i - 1] + B) % N
    sigs = []
    for k in ks:
        h, r = rng.randrange(N), rng.randrange(1, N)  # r's curve origin is irrelevant to the algebra
        s = pow(k, -1, N) * (h + r * d) % N
        sigs.append((h, r, s))
    start, root = recover_d(sigs, [f"{i:02d}" for i in range(11)])
    assert root == d and start == 3
    print("[+] self-test passed: recovered the planted key from the only affine window")


def main() -> None:
    if "--selftest" in sys.argv:
        selftest()
        return
    d = D_RECOVERED
    if (ATT / "data.json").exists():
        sigs, labels = load_attachment()
        print(f"[*] {len(sigs)} signatures loaded; scanning 5-signature windows")
        start, d = recover_d(sigs, labels)
        print(f"[+] affine window starts at leaf {labels[start]}")
        pub_json = tuple(int(v, 16) if isinstance(v, str) else int(v) for v in json.loads((ATT / "data.json").read_text())["public_key"])
        assert ec_mul(d) == pub_json, "d*G does not match data.json public_key"
        print("[+] d*G matches data.json public_key")
    else:
        print("[*] attachments/data.json not found; using the d recovered in the writeup")
    print(f"[+] d = {d:064x}")
    pub = ec_mul(d)
    print(f"[+] d*G = ({pub[0]:064x},\n          {pub[1]:064x})")
    print(f"[+] FLAG: {open_capsule(d)}")


if __name__ == "__main__":
    main()
