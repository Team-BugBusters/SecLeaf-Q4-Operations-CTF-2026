#!/usr/bin/env python3
"""Public acquisition equations. Device wiring, layout and secrets are absent."""

def hw(x):
    return int(x).bit_count()

def linear_wire(byte, rows):
    """An unknown invertible binary wiring transform (eight 8-bit rows)."""
    return sum(((int(byte)&int(row)).bit_count()&1)<<j for j,row in enumerate(rows))

def three_shares(plaintext, key, mask_a, mask_b, secret_rows, aes_sbox):
    z=linear_wire(aes_sbox[plaintext^key],secret_rows)
    return (hw(mask_a)-4, hw(mask_b)-4, hw(z^mask_a^mask_b)-4)

# Acquisitions contain independent background samples, including samples
# statistically indistinguishable (marginally) from these three shares.
# The phase and three site locations must be inferred from the traces.
