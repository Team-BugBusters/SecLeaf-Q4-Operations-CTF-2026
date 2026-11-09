#!/usr/bin/env python3
"""Public vulnerability model. The secret scalar, nonce seeds, run location and flag are omitted."""
from secrets import randbelow,token_bytes
from hashlib import sha256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# secp256k1 signing-group order, NOT its coordinate field prime
N=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def digest(msg):
    return int.from_bytes(sha256(msg.encode()).digest(),'big')%N

def ecdsa_signing_scalar(k,r,d,h):
    return (pow(k,-1,N)*(h+r*d))%N

def make_nonces(count):
    # For one secret consecutive length-5 interval, the nonce source used
    # an affine recursion in Z/NZ. Elsewhere it produced fresh independent k.
    start=randbelow(count-4)
    A=1+randbelow(N-1)
    B=1+randbelow(N-1)
    k=1+randbelow(N-1)
    nonces=[1+randbelow(N-1) for _ in range(count)]
    for j in range(start,start+5):
        if j!=start:k=(A*k+B)%N
        nonces[j]=k
    return nonces

def derive_key(private_scalar):
    return sha256(b'SecLeaf/nonce-nursery/v2/'+private_scalar.to_bytes(32,'big')).digest()

def seal(flag,private_scalar):
    nonce=token_bytes(12)
    return {'nonce':nonce.hex(),'ct':AESGCM(derive_key(private_scalar)).encrypt(nonce,flag.encode(),None).hex()}

# Standard ECDSA has r = x([k]G) mod N, s = (h+r*d)/k mod N.
# The released observations are all valid signatures in chronological order.
