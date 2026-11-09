# Maintainer of None

![Event](https://img.shields.io/badge/SecLeaf_CTF-2026-101518?style=flat-square)
![Category](https://img.shields.io/badge/Category-Reverse_Engineering-B4441F?style=flat-square)
![Points](https://img.shields.io/badge/Points-500-2F5D3A?style=flat-square)

> **Solved by** [Vaidik](https://github.com/Vaidik-Makhasana) · **Team** Bug Busters · **Solved** 1 November 2026, 9:39 am

## Challenge description

> "The release was signed. The audit was signed. Even the audit of the audit was signed."
>
> "Apparently the maintainers have invented a new instruction set to explain who approved it."
>
> "Seems reasonable. Surely nothing else can go wrong :)"

**Flag format:** `SecLeaf{...}`

**Attachments:** [`arbiter`](attachments/arbiter) · [`attestor.sqlite`](attachments/attestor.sqlite) · [`chancery.sqlite`](attachments/chancery.sqlite) · [`clerk.tape`](attachments/clerk.tape) · [`closure.seal`](attachments/closure.seal) · [`conclave`](attachments/conclave) · [`custodian`](attachments/custodian) · [`forge.sqlite`](attachments/forge.sqlite) · [`fragments.dat`](attachments/fragments.dat) · [`history.bundle`](attachments/history.bundle) · [`journal.vlg`](attachments/journal.vlg) · [`libisa.so`](attachments/libisa.so) · [`libpolicy.so`](attachments/libpolicy.so) · [`libstamp.so`](attachments/libstamp.so) · [`palinode.bin`](attachments/palinode.bin) · [`recovery.tape`](attachments/recovery.tape) · [`relay.cache`](attachments/relay.cache) · [`release.tar.xz`](attachments/release.tar.xz) · [`riscv.rom`](attachments/riscv.rom) · [`route4.cache`](attachments/route4.cache) · [`route5.cache`](attachments/route5.cache) · [`seal.bin`](attachments/seal.bin) · [`verdict.seal`](attachments/verdict.seal)

## Flag

```text
SecLeaf{r15cv_cu57om_1sa_th3_f0rg3_f0rg0t_84f1a936}
```

This is the output of the third and final verifier, `conclave`. The two other `SecLeaf{...}` strings in the writeup are receipts printed by the first two verifiers; see [Notes](#notes).

## Writeup

Read the full solve: **[writeup.md](writeup.md)**

**In one line:** three verifiers each accept a binary witness that extends the previous one, so we rebuilt the 576 → 1,696 → 2,784-byte nested dossier stage by stage – release history picks the right database rows, modular Gaussian elimination over GF(65521) solves the 48- and 64-variable systems, and instrumentation of the verifiers captured the route tables and chapter digests.

- **Custodian** (576 bytes): 32 arithmetic values + 128 continuity selectors, using lane `0xc4c0045a` from the release / Git history.
- **Arbiter** (1,696 bytes): 48 values from a GF(65521) system (epoch `0xa8a713f6`) + 256 route4 words.
- **Conclave** (2,784 bytes): 64 values from a second GF(65521) system (epoch `0x1f381262`) + 192 route5 words + 24 chapter-state digests.
- All three original binaries accepted the final dossier with `LD_PRELOAD` unset, exit status 0.

## Files

| Path | What it is |
| --- | --- |
| [`writeup.md`](writeup.md) | Full solve |
| [`solve/solve.py`](solve/solve.py) | Splits the accepted dossier, re-solves both GF(65521) systems against the SQLite rows, and replays the three verifiers on Linux |

## Run the solver

```bash
cd solve
python3 solve.py
```

Expected output ends with:

```text
[+] FLAG: SecLeaf{r15cv_cu57om_1sa_th3_f0rg3_f0rg0t_84f1a936}
```

## Notes

- **Three flags, one answer.** Each verifier prints a receipt:

  | Verifier | Output | Role |
  | --- | --- | --- |
  | `custodian` | `SecLeaf{this_is_only_the_audit_receipt_keep_going}` | stage-1 receipt (the text itself says keep going) |
  | `arbiter` | `SecLeaf{m41nt41n3r_0f_n0n3_f0rg3d_th3_tru5t_ch41n_4c7f63ab}` | stage-2 receipt, intermediate |
  | `conclave` | `SecLeaf{r15cv_cu57om_1sa_th3_f0rg3_f0rg0t_84f1a936}` | **final flag** |

- The challenge files are archived, but the replay also needs our accepted `dossier_v5_route_captured.bin` (SHA-256 `d960ca81…936e8761e`), which wasn't kept with the notes. The verifiers take witness files, not a flag (`arbiter --adjudicate witness_v4.bin`, `conclave --attest dossier.bin`), so the flag can't be checked by feeding it in directly.
- The verifiers are Linux x86-64 ELFs: run them with `LD_LIBRARY_PATH=.` from `attachments/`. `custodian` also links `libarchive.so.13` (Debian/Ubuntu package `libarchive13`).
- **Not a clean-room solver.** The stage-1 witness generator and the route-capture instrumentation were one-shot scripts that were not kept. The solver therefore takes the stage-1 witness, route4/route5 words and chapter digests from the accepted dossier and re-derives only the two modular systems. The team's original `reproduce_chain.py` was too large to include in the writeup.
- The writeup does not define the `stage1_digest` / `ancestor` inputs to the blind hashes or the SQLite column names. The solver assumes SHA-256 of the previous witness and finds columns by name; it reports a mismatch if that assumption is wrong.

---

[← Back to Reverse Engineering](../README.md) · [All writeups](../../README.md)
