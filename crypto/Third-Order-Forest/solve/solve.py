#!/usr/bin/env python3
"""Third-Order Forest (SecLeaf CTF 2026) - offline solver.

Pipeline (see ../writeup.md):
  1. phase = position of the value 110 in samples 0..2; drop those 3 samples
     and standardise every sample within each phase group.
  2. For key byte j, combine its three share samples (table below, + phase)
     with a centred product x_a * x_b * x_c (third-order combination).
  3. Mean of that product per plaintext-byte value (256 classes).
  4. For each key guess k, re-index the means by y = S(p ^ k) and take a
     256-point Walsh-Hadamard transform. The correct k concentrates the energy
     in 8 same-sign coefficients (one per row of the secret wiring matrix L).
  5. AES-GCM-decrypt capsule.json with the 16-byte key.

Inputs: ../attachments/capture.npz and ../attachments/capsule.json
Without them the script runs a self-test of the Walsh
scorer on noiseless synthetic class means and stops.

Deps: numpy, cryptography (see requirements.txt).
"""
import json
import sys
from pathlib import Path

import numpy as np

ATT = Path(__file__).resolve().parent.parent / "attachments"
CAPTURE = ATT / "capture.npz"
CAPSULE = ATT / "capsule.json"

EXPECTED_KEY = "2f1aa90f9774de5a29ef06a881d5ee68"  # recorded in the writeup
MARKER = 110

# Share triples per key byte (indices after dropping the 3 marker samples;
# add the trace's phase). Found by the third-order F-test over all triples.
TRIPLES = [
    (4, 6, 8), (19, 20, 21), (26, 28, 30), (37, 39, 42),
    (51, 53, 57), (62, 64, 65), (79, 80, 81), (89, 90, 92),
    (99, 100, 101), (109, 111, 112), (122, 123, 129), (132, 140, 141),
    (144, 146, 148), (156, 161, 164), (168, 173, 176), (181, 182, 185),
]


# --------------------------------------------------------------------------
# AES S-box (computed, not pasted)
# --------------------------------------------------------------------------
def _sbox():
    def gmul(a, b):
        r = 0
        while b:
            if b & 1:
                r ^= a
            a = ((a << 1) ^ 0x11B) if a & 0x80 else a << 1
            b >>= 1
        return r
    s = []
    for x in range(256):
        inv = 0 if x == 0 else next(y for y in range(1, 256) if gmul(x, y) == 1)
        v = inv
        for sh in range(1, 5):
            v ^= ((inv << sh) | (inv >> (8 - sh))) & 0xFF
        s.append(v ^ 0x63)
    return np.array(s, dtype=np.uint8)


SBOX = _sbox()
INV_SBOX = np.argsort(SBOX).astype(np.uint8)
assert SBOX[0x00] == 0x63 and SBOX[0x53] == 0xED


def wht(v):
    """Fast Walsh-Hadamard transform (Sylvester/natural order, same as scipy.linalg.hadamard)."""
    v = np.array(v, dtype=float)
    h = 1
    while h < len(v):
        v = v.reshape(-1, 2, h)
        v = np.stack([v[:, 0] + v[:, 1], v[:, 0] - v[:, 1]], axis=1).reshape(-1)
        h *= 2
    return v


def score_guess(means_by_p, k):
    """8 largest same-sign Walsh coefficients relative to spectrum energy."""
    p_of_y = INV_SBOX ^ np.uint8(k)          # p such that S(p ^ k) = y
    spec = wht(means_by_p[p_of_y])[1:]       # drop the constant coefficient
    energy = np.sqrt(np.sum(spec ** 2)) + 1e-30
    pos = np.sort(spec[spec > 0])[::-1][:8].sum() if np.any(spec > 0) else 0.0
    neg = np.sort(-spec[spec < 0])[::-1][:8].sum() if np.any(spec < 0) else 0.0
    return max(pos, neg) / energy


def rank_byte(means_by_p):
    scores = np.array([score_guess(means_by_p, k) for k in range(256)])
    order = np.argsort(scores)[::-1]
    return int(order[0]), scores[order[0]], scores[order[1]]


def self_test():
    """Noiseless check: means = HW(L * S(p ^ k)) for a random invertible L."""
    rng = np.random.default_rng(1)
    while True:
        L = rng.integers(0, 2, size=(8, 8), dtype=np.uint8)
        if round(abs(np.linalg.det(L))) % 2 == 1:
            break
    bits = ((np.arange(256)[:, None] >> np.arange(8)) & 1).astype(np.uint8)
    hw_l = ((bits @ L.T) % 2).sum(axis=1)    # HW(L*y) for every y
    k_true = 0xA7
    means = hw_l[SBOX[np.arange(256) ^ k_true]].astype(float)
    k, s1, s2 = rank_byte(means)
    assert k == k_true, (k, s1, s2)
    print(f"[*] self-test: Walsh scorer recovers synthetic key byte {k:#04x} "
          f"(score {s1:.2f} vs runner-up {s2:.2f})")


def load_capture(path):
    z = np.load(path)
    arrays = {name: z[name] for name in z.files}
    traces = next(a for a in arrays.values() if a.ndim == 2 and a.shape[1] > 16)
    pts = next(a for a in arrays.values()
               if a.ndim == 2 and a.shape == (traces.shape[0], 16))
    return traces.astype(np.float64), pts.astype(np.uint8)


def main():
    self_test()
    missing = [p.name for p in (CAPTURE, CAPSULE) if not p.exists()]
    if missing:
        sys.exit("[-] Missing attachment(s): " + " and ".join(missing)
                 + ". Place them in attachments/ to run the key recovery.")

    traces, pts = load_capture(CAPTURE)
    print(f"[*] {traces.shape[0]} traces x {traces.shape[1]} samples")

    head = traces[:, :3]
    assert np.all((head == MARKER).sum(axis=1) == 1), "expected exactly one 110 in samples 0..2"
    phase = np.argmax(head == MARKER, axis=1)
    print("[*] phase groups:", {int(ph): int((phase == ph).sum()) for ph in range(3)})

    x = traces[:, 3:].copy()
    for ph in range(3):
        g = phase == ph
        x[g] = (x[g] - x[g].mean(axis=0)) / (x[g].std(axis=0) + 1e-12)

    rows = np.arange(len(x))
    key = bytearray()
    for j, (a, b, c) in enumerate(TRIPLES):
        prod = x[rows, a + phase] * x[rows, b + phase] * x[rows, c + phase]
        cnt = np.bincount(pts[:, j], minlength=256)
        means = np.bincount(pts[:, j], weights=prod, minlength=256) / np.maximum(cnt, 1)
        k, s1, s2 = rank_byte(means)
        key.append(k)
        print(f"[*] byte {j:2d}: {k:02x}  score {s1:.2f}  runner-up {s2:.2f}")
    print(f"[*] AES-128 key: {key.hex()}")
    if key.hex() != EXPECTED_KEY:
        print(f"[!] differs from the key recorded in the writeup ({EXPECTED_KEY})")

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    cap = json.loads(CAPSULE.read_text())

    def field(*names):
        for n in names:
            if n in cap:
                v = cap[n]
                return bytes.fromhex(v) if all(ch in "0123456789abcdefABCDEF" for ch in v) \
                    else __import__("base64").b64decode(v)
        return b""
    nonce = field("nonce", "iv", "n")
    ct = field("ciphertext", "ct", "c") + field("tag", "t")
    aad = field("aad", "a") or None
    pt = AESGCM(bytes(key)).decrypt(nonce, ct, aad)  # raises InvalidTag if any byte is wrong
    print("[*] GCM tag verified")
    print(f"[+] FLAG: {pt.decode()}")


if __name__ == "__main__":
    main()
