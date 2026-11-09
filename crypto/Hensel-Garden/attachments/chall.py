#!/usr/bin/env python3
"""Public mathematical construction. Secret seed and flag are NOT embedded."""
from hashlib import sha256
from secrets import randbits,token_bytes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SEED_BITS=128
MODULI=(2**72,3**51)
SHIFTS=(87,143)

def public_observations(seed):
    return [pow(seed + a,2,m) for a,m in zip(SHIFTS,MODULI)]

def derive_key(seed):
    assert 0 <= seed < 1<<SEED_BITS
    return sha256(b'SecLeaf/hensel/v2/'+seed.to_bytes(16,'big')).digest()

def seal(flag,seed):
    key=derive_key(seed)
    nonce=token_bytes(12)
    return {'nonce':nonce.hex(),'ct':AESGCM(key).encrypt(nonce,flag.encode(),None).hex()}

# The released data.json was produced with an unpublished random seed.
# Only public_observations(seed) and seal(flag,seed) are needed to solve.
