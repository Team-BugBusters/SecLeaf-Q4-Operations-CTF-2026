#!/usr/bin/env python3
"""Signing Shadow: Redshift: Schnorr private key from a lying 24-bit clock.

Model found during the event:  stamp = (k >> 136) + offset   (one constant offset;
4 decoy records use a different one). Subtracting a reference record cancels the offset
and leaves a Hidden Number Problem in x, solved here with a small pure-Python LLL over
random 9-record subsets (any subset containing a decoy simply fails the g^x == pub check).

  python3 solve.py --selftest   plant the same leak + decoys in a synthetic instance and recover x
  python3 solve.py              run on ../attachments/data.json (3-10 minutes in pure Python; random subsets)
"""
from __future__ import annotations

import hashlib
import json
import random
import sys
from fractions import Fraction
from pathlib import Path

ATT = Path(__file__).resolve().parents[1] / "attachments"
SHIFT = 136          # stamp carries the top 24 bits of a 160-bit nonce
SUBSET = 9           # 8 differences x ~24 bits > 160 bits of key


# ---------- textbook LLL (exact rationals; dimension ~10 so speed is fine) ----------
def lll(basis: list[list[int]], delta: Fraction = Fraction(3, 4)) -> list[list[int]]:
    b = [row[:] for row in basis]
    n = len(b)
    dot = lambda u, v: sum(x * y for x, y in zip(u, v))

    def gram_schmidt():
        bstar, mu = [], [[Fraction(0)] * n for _ in range(n)]
        for i in range(n):
            v = [Fraction(x) for x in b[i]]
            for j in range(i):
                mu[i][j] = dot(b[i], bstar[j]) / dot(bstar[j], bstar[j])
                v = [a - mu[i][j] * c for a, c in zip(v, bstar[j])]
            bstar.append(v)
        return bstar, mu

    bstar, mu = gram_schmidt()
    norms = [dot(v, v) for v in bstar]
    k = 1
    while k < n:
        for j in range(k - 1, -1, -1):  # size-reduce b[k]; only row k of mu changes
            q = round(mu[k][j])
            if q:
                b[k] = [x - q * y for x, y in zip(b[k], b[j])]
                for l in range(j):
                    mu[k][l] -= q * mu[j][l]
                mu[k][j] -= q
        if norms[k] >= (delta - mu[k][k - 1] ** 2) * norms[k - 1]:
            k += 1
        else:
            b[k], b[k - 1] = b[k - 1], b[k]
            bstar, mu = gram_schmidt()
            norms = [dot(v, v) for v in bstar]
            k = max(k - 1, 1)
    return b


# ---------- the HNP ----------
def hnp_candidates(rows, q: int):
    """rows: list of (c, s, stamp). With k = s - c*x and k = stamp*2^136 + e (minus offset):
         (s_i - s_0 - (stamp_i - stamp_0)*2^136) + (c_0 - c_i)*x  =  e_i - e_0   (mod q)
    and |e_i - e_0| < 2^137 is small: a Hidden Number Problem."""
    c0, s0, t0 = rows[0]
    a = [(c0 - c) % q for c, _, _ in rows[1:]]
    b = [(s - s0 - (t - t0) * (1 << SHIFT)) % q for _, s, t in rows[1:]]
    m, K = len(a), 1 << (SHIFT + 1)
    # Kannan embedding, scaled by q to stay integral; the short vector is (q*delta_i..., x*K, q*K)
    basis = [[q * q if j == i else 0 for j in range(m + 2)] for i in range(m)]
    basis.append([q * ai for ai in a] + [K, 0])
    basis.append([q * bi for bi in b] + [0, q * K])
    for vec in lll(basis):
        if abs(vec[-1]) == q * K and vec[-2] % K == 0:
            x = (vec[-2] // K) * (1 if vec[-1] > 0 else -1)
            yield x % q
            yield (-x) % q


def attack(records, q: int, is_key, tries: int = 200, seed: int = 0):
    rng = random.Random(seed)
    for t in range(1, tries + 1):
        subset = rng.sample(records, SUBSET)
        for x in hnp_candidates(subset, q):
            if is_key(x):
                return x, t
    raise RuntimeError("no subset produced the key")


# ---------- self-test on a planted instance ----------
def is_probable_prime(n: int) -> bool:
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29):
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d, r = d // 2, r + 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        y = pow(a, d, n)
        if y in (1, n - 1):
            continue
        for _ in range(r - 1):
            y = y * y % n
            if y == n - 1:
                break
        else:
            return False
    return True


def selftest() -> None:
    rng = random.Random(2026)
    q = rng.getrandbits(160) | (1 << 159) | 1
    while not is_probable_prime(q):
        q += 2
    x = rng.randrange(1, q)
    honest, decoy = 1366043, 4242424  # the event's honest offset, plus an arbitrary decoy one
    decoys = {2, 7, 11, 20}
    records = []
    for i in range(23):
        k, c = rng.randrange(1, q), rng.randrange(q)
        s = (k + c * x) % q
        stamp = (k >> SHIFT) + (decoy if i in decoys else honest)
        records.append((c, s, stamp))
    print(f"[*] self-test: 160-bit q, 23 records, decoys at {sorted(decoys)}")
    found, tries = attack(records, q, lambda cand: cand == x)
    print(f"[+] recovered the planted key after {tries} random subset(s)")
    assert found == x


# ---------- real data ----------
def challenge_variants(msg: str, R: int, p: int):
    """The writeup gives c = SHA256("SecLeaf/redshift/v3/nonce|" + msg + R) mod q, but not how R
    is serialised. Try the usual encodings; the right one is the one under which every
    signature verifies (g^s == R * pub^c mod p)."""
    pre, mb = b"SecLeaf/redshift/v3/nonce|", msg.encode()
    plen = (p.bit_length() + 7) // 8
    yield "decimal", pre + mb + str(R).encode()
    yield "hex", pre + mb + format(R, "x").encode()
    yield "bytes", pre + mb + R.to_bytes((R.bit_length() + 7) // 8, "big")
    yield "bytes-plen", pre + mb + R.to_bytes(plen, "big")


def main() -> None:
    if "--selftest" in sys.argv:
        selftest()
        return
    path = ATT / "data.json"
    if not path.exists():
        print("[!] attachments/data.json not found. Run `python3 solve.py --selftest` to see the")
        print("    attack work on a planted instance, or place the original data.json in attachments/.")
        print("[i] flag as recorded in the writeup (NOT recomputed): SecLeaf{cl0ck_drift_c4nt_h1de_a_shad0w}")
        return
    D = json.loads(path.read_text())
    num = lambda v: int(v, 0) if isinstance(v, str) else int(v)
    p, q, g, pub = (num(D[k]) for k in ("p", "q", "g", "pub"))
    raw = [(r["msg"], num(r["R"]), num(r["s"]), num(r["stamp"])) for r in D["records"]]

    for name, _ in challenge_variants("", 1, p):
        cs = [int.from_bytes(hashlib.sha256(dict(challenge_variants(m, R, p))[name]).digest(), "big") % q
              for m, R, _, _ in raw]
        if all(pow(g, s, p) == R * pow(pub, c, p) % p for (_, R, s, _), c in zip(raw, cs)):
            print(f"[+] all {len(raw)} signatures verify (R serialised as {name})")
            break
    else:
        raise SystemExit("[!] no R encoding made the signatures verify; adjust challenge_variants()")

    records = [(c, s, t) for c, (_, _, s, t) in zip(cs, raw)]
    x, tries = attack(records, q, lambda cand: pow(g, cand, p) == pub)
    print(f"[+] x = {x:#x}   (g^x == pub, found after {tries} subsets)")
    offsets = sorted({t - ((s - c * x) % q >> SHIFT) for c, s, t in records})
    print(f"[+] clock offsets seen: {offsets}  (honest one: 1366043)")

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = hashlib.sha256(b"SecLeaf/shadow-redshift/v3/secret|" + x.to_bytes(20, "big")).digest()
    sealed = D["sealed"]
    flag = AESGCM(key).decrypt(bytes.fromhex(sealed["nonce"]), bytes.fromhex(sealed["ct"]), None)
    print(f"[+] FLAG: {flag.decode()}")


if __name__ == "__main__":
    main()
