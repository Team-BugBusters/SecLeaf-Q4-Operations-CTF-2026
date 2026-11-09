#!/usr/bin/env python3
"""Public verification and key derivation for the Redshift signing audit."""
from hashlib import sha256

def challenge(p,q,msg,R):
    rb=int(R).to_bytes((int(p).bit_length()+7)//8,'big')
    return int.from_bytes(sha256(b'SecLeaf/redshift/v3/nonce|'+msg.encode()+rb).digest(),'big')%q

def valid_record(p,q,g,pub,r):
    R=int(r['R'],16);s=int(r['s'],16)
    return pow(g,s,p)==(R*pow(pub,challenge(p,q,r['msg'],R),p))%p

def derive_key(q,private_scalar):
    return sha256(b'SecLeaf/shadow-redshift/v3/secret|'+int(private_scalar).to_bytes(20,'big')).digest()
