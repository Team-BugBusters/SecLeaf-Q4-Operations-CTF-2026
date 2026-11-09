# Maintainer of None – full writeup

[← Back to Reverse Engineering](../README.md) · [Challenge overview](README.md)

**Category:** Reverse Engineering · **Points:** 500 · **Flag:** `SecLeaf{r15cv_cu57om_1sa_th3_f0rg3_f0rg0t_84f1a936}`

**Author:** [Vaidik](https://github.com/Vaidik-Makhasana) · **Team:** Bug Busters

## TL;DR

1. Three verifiers – `custodian`, `arbiter`, `conclave` – each take a binary witness. Each witness is the previous one plus new sections: 576 → 1,696 → 2,784 bytes.
2. **Custodian:** release receipt + Git history give reconciliation lane `0xc4c0045a`, which selects the right rows from `forge.sqlite`. Accepted with an audit receipt, not the flag.
3. **Arbiter:** a 48-variable linear system over GF(65521), hidden behind a V4 recurrence and SHA-256 blinds, plus 256 route4 words captured from the verifier. Accepted with a second receipt.
4. **Conclave:** a 64-variable system over GF(65521) with a V5 recurrence, plus 192 route5 words and 24 chapter-state digests from the custom-ISA check. Accepted with the final flag.

## The challenge

The brief has three hints: a **signed release**, an **audit of the audit** (verification nested in verification), and a **new instruction set** (a custom ISA in the last stage).

The archive held three 64-bit Linux ELF verifiers, their libraries and a pile of evidence:

| Stage | Verifier | Evidence it consumes |
| --- | --- | --- |
| Release | – | `release.tar.xz`, `history.bundle` |
| 1 | `custodian` | `journal.vlg`, `forge.sqlite`, `fragments.dat`, `seal.bin`, `relay.cache`, `libstamp.so` |
| 2 | `arbiter` | `chancery.sqlite`, `palinode.bin`, `recovery.tape`, `verdict.seal`, `route4.cache`, `libpolicy.so` |
| 3 | `conclave` | `attestor.sqlite`, `clerk.tape`, `closure.seal`, `riscv.rom`, `route5.cache`, `libisa.so`, `libpolicy.so` |

`strings` on the binaries gave the usage lines, which set the whole direction of the solve: every stage wants a binary file, not text.

```text
./custodian --reconcile witness.bin
./arbiter   --adjudicate witness_v4.bin
./conclave  --attest dossier.bin
```

## Step 1 – Find the right lane in the release history

The release receipt in `release.tar.xz` identifies the project:

```text
Project: verdantsh
Version: 4.2.1
Release: rv-2026-1042
```

It reports a valid signature, and the build trace requires reproducibility against the archived toolchain stamp. Cross-referencing the release with the Git history in `history.bundle` (`git clone history.bundle`, `git log`) gave the first-stage **reconciliation lane**:

```text
0xc4c0045a
```

This matters because the SQLite databases are full of rows that are not part of the real reconciliation. The lane is the filter that separates the relevant entries from the noise.

## Step 2 – Custodian: the 576-byte witness

`journal.vlg` is a structured binary journal: magic `VLOG9C`, `0x6000` (24,576) records of `0x60` bytes each. `forge.sqlite` has two relevant tables: `reconciliation_ledger` (arithmetic records) and `continuity_checks`.

| Offset | Length | Contents |
| --- | --- | --- |
| `0x000–0x03f` | 64 | 32 little-endian u16 arithmetic values from `reconciliation_ledger` (lane `0xc4c0045a`) |
| `0x040–0x23f` | 512 | 128 four-byte continuity selectors tied to `journal.vlg` + `continuity_checks`, in order |

The values have to satisfy the verifier's arithmetic constraints, so picking 32 arbitrary rows fails. The custodian also checks stamp evidence through `libstamp.so` (`stamp_restore`, `stamp_sequence`), `relay.cache`, `fragments.dat` and `seal.bin`, so solving the arithmetic alone is not enough.

```text
$ env -u LD_PRELOAD ./custodian --reconcile stage1_witness.bin
SecLeaf{this_is_only_the_audit_receipt_keep_going}
```

The string says it: an **audit receipt**, not the flag. Stage 1 passed.

## Step 3 – Arbiter: a 48-variable system over GF(65521)

The 1,696-byte witness is the full stage-1 witness followed by:

| Offset | Length | Contents |
| --- | --- | --- |
| `0x240–0x29f` | 96 | 48 little-endian u16 raw values `x` |
| `0x2a0–0x69f` | 1,024 | 256 little-endian u32 route4 words |

`chancery.sqlite` table `trust_reconciliation` has 48 equations for the stage-2 epoch `0xa8a713f6` (derived from the stage-1 witness and release data). Each row has an index, a 96-byte coefficient blob (48 u16) and a syndrome.

The verifier does not use `x` directly. It first applies the **V4 recurrence** (mod 65521):

```text
z0 = x0
z1 = x1
z2 = x2 + x1*x0
zi = xi + x(i-1)*x(i-2) + x(i-3)        for i >= 3
```

and adds a per-row blind:

```text
blind_i = LE16( SHA256("V4/BLIND" || stage1_digest || LE32(epoch) || LE16(row_i))[:2] ) mod 65521
(sum_j coeff_ij * z_j + blind_i) mod 65521 = syndrome_i
```

**Why it is solvable:** the blinds depend only on known data, so moving them to the right-hand side leaves an ordinary linear system `A·z = syndrome - blind` in a prime field. Gaussian elimination mod 65521 gives `z`. The recurrence only ever uses *raw* earlier values, so it unwinds front to back: `x_i = z_i - x(i-1)*x(i-2) - x(i-3)`.

```python
def solve_mod(rows, rhs, p=65521):          # Gauss-Jordan over GF(p)
    n = len(rows)
    m = [[c % p for c in r] + [b % p] for r, b in zip(rows, rhs)]
    for col in range(n):
        piv = next(r for r in range(col, n) if m[r][col])
        m[col], m[piv] = m[piv], m[col]
        inv = pow(m[col][col], -1, p)
        m[col] = [v * inv % p for v in m[col]]
        for r in range(n):
            if r != col and m[r][col]:
                f = m[r][col]
                m[r] = [(a - f * b) % p for a, b in zip(m[r], m[col])]
    return [m[r][n] for r in range(n)]
```

We then recomputed all 48 equations from the recovered `x` to confirm them.

**Route4.** The 256 route words were not derivable from the databases. We instrumented the verifier's lookup/compare routine and captured the values it expected. The first capture failed because we read the channel selector from the wrong place; reading the comparison routine again showed where it really lives, and the second capture produced the full table.

```text
$ env -u LD_PRELOAD ./arbiter --adjudicate stage2_witness.bin
SecLeaf{m41nt41n3r_0f_n0n3_f0rg3d_th3_tru5t_ch41n_4c7f63ab}
```

Trust reconciliation and routing both validated. This is still an intermediate receipt; there is one more verifier.

## Step 4 – Conclave: 64 variables, a V5 recurrence and the custom ISA

The final 2,784-byte (`0xae0`) dossier:

| Offset | Length | Contents |
| --- | --- | --- |
| `0x000–0x69f` | 1,696 | complete stage-2 witness |
| `0x6a0–0x71f` | 128 | 64 u16 audit values |
| `0x720–0xa1f` | 768 | 192 u32 route5 words (24 chapters × 8) |
| `0xa20–0xadf` | 192 | 24 chapter-state digests, 8 bytes each |

`attestor.sqlite` table `attestation`: 64 rows, each a 128-byte blob of 64 u16 coefficients, epoch `0x1f381262`. Same shape as stage 2, new recurrence:

```text
z0 = x0
z1 = x1 + x0^2
z2 = x2 + x1^2
zi = xi + x(i-1)^2 + x(i-3)             for i >= 3     (all mod 65521)

blind_i = LE16( SHA256("V5/AUDIT/BLIND" || ancestor || LE32(epoch) || LE16(slot_i))[:2] ) mod 65521
(sum_j coeff_ij * z_j + blind_i) mod 65521 = syndrome_i
```

The trap: `x(i-1)^2` uses the previous **raw** value, not the previous transformed `z`. Our first inversion used the wrong state and produced an invalid vector. With raw values the inversion is again a simple forward pass, and all 64 equations checked out.

**Custom ISA.** `riscv.rom` and `libisa.so` implement the "new instruction set" from the brief; `libpolicy.so`, `clerk.tape`, `route5.cache` and `closure.seal` feed the final route and state check. As in stage 2, we analysed the verifier's route-comparison and state-processing logic and used instrumentation to extract the 192 route5 words and 24 chapter-state digests, then wrote them into the dossier.

```text
$ env -u LD_PRELOAD ./conclave --attest dossier_v5_route_captured.bin
SecLeaf{r15cv_cu57om_1sa_th3_f0rg3_f0rg0t_84f1a936}
Exit Status: 0
```

## Flag

```text
SecLeaf{r15cv_cu57om_1sa_th3_f0rg3_f0rg0t_84f1a936}
```

## Why this is the right answer

- **It comes from the last verifier.** The challenge is a chain of three verifiers; `conclave` is the final attestation and its output is the flag. The other two strings are receipts: the first literally says `this_is_only_the_audit_receipt_keep_going`, and the second is printed by the middle stage.
- **The original binaries accept it, uninstrumented.** All three verifiers were run with `LD_PRELOAD` unset on the nested prefixes of one dossier and all exited 0.
- **The maths re-checks.** Our reproduction re-solved both systems and confirmed all 112 database equations (48 + 64).
- **Artifact hashes** were recorded so the replay is pinned to the original files:

  | Artifact | SHA-256 |
  | --- | --- |
  | `custodian` | `025315690fd61380e898ede369622f499053486489f8eeb6226932f8a714c888` |
  | `arbiter` | `814f1519b0fd1150282d8ad07fc7a2c66af9e84715b7ca797087fcbb88821ee6` |
  | `conclave` | `f4d135211c98190ea325bbf185886cef51f27a249ea84683f2333e84aafab66a` |
  | `libisa.so` | `c16ecdb721c146ab2645fea5697606eadb38fb2761a79ab2c7e6b3ec46ac83f5` |
  | `libpolicy.so` | `46c7311de4de0a016d4e2ea2b970e2dcfe4d2d4189e5168c98dfd91806244d0a` |
  | `libstamp.so` | `8928454dfdce3e540384253576bf2078452b0031953094b0a69222a516cca309` |
  | `dossier_v5_route_captured.bin` | `d960ca8169bdae653203b5a24d21c133c743becfe9befe64a74bdaf936e8761e` |

- **Format and meaning:** `SecLeaf{...}`, leetspeak for "RISC-V custom ISA: the forge forgot", matching the brief.

## What we learned

- **A chain of verifiers means a chain of flags.** When the first output says "keep going", believe it; only the last verifier's output is the answer.
- **History selects the data.** The lane from the release and Git history was what turned a noisy database into 32 usable rows.
- **Blinded linear systems are still linear.** Hash-derived offsets depend only on known data; move them to the right-hand side and Gaussian elimination mod p does the rest.
- **Check which state a recurrence reads.** V5 squares the previous *raw* value; using the transformed value gave a wrong answer. Keep your capture scripts too: losing ours made a clean-room rebuild impossible.

## Reproduce

The team's reproduction (`reproduce_chain.py`) worked from the accepted dossier: it hashed the artifacts, split the nested witnesses, re-solved both GF(65521) systems, checked all 112 equations, exported the route and digest sections and ran the three verifiers. It was too large to include in the original writeup.

[`solve/solve.py`](solve/solve.py) is a compact equivalent. Put the challenge files and `dossier_v5_route_captured.bin` in `../attachments/`, then on Linux x86-64:

```bash
cd solve
python3 solve.py
```

It does **not** regenerate the stage-1 witness, the route words or the chapter digests; those were captured with one-shot instrumentation that was not kept, so they are read from the accepted dossier.

---

[← Back to Reverse Engineering](../README.md) · [Challenge overview](README.md)
