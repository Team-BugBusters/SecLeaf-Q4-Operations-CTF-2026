# Blackout Protocol – full writeup

[← Back to Reverse Engineering](../README.md) · [Challenge overview](README.md)

**Category:** Reverse Engineering · **Points:** 500 · **Flag:** `SecLeaf{n01s3_1n_th3_w1r35_4nd_4ft3r1m4g3s!!!!!}`

**Author:** [Vaidik](https://github.com/Vaidik-Makhasana) · **Team:** Bug Busters

## TL;DR

1. Four files: a verifier (`blackout_protocol`) and three evidence sources. The verifier is the judge; the evidence supplies the parameters of its transform.
2. `retained.mem` has an `M16B` header and two 64-bit seeds: `0x72f23b4a1c67cd00` and `0xabfedf0984f04e18`.
3. `incident.journal` contains forged records; FNV-1a integrity checks plus unique indices leave 48 authentic ones. `transmission.pcap` has 290 packets; protocol fields and checksums leave 32 genuine ones, which rebuild a 384-byte lookup table.
4. With seeds, records and table, the verifier's 52-round transform (S-box → permutation → forward/reverse diffusion → periodic ops) could be reconstructed, which yielded the candidate flag.
5. The original binary answers `Authenticated.` with exit code 0 for the recovered flag.

## The challenge

We were given four files and no obvious place to start:

| File | Role in the investigation |
| --- | --- |
| `blackout_protocol` | Verification executable – final authentication logic |
| `retained.mem` | Memory evidence – header and seed material |
| `incident.journal` | Incident records – some authentic, some not |
| `transmission.pcap` | Network capture – protocol data mixed with unrelated traffic |

The name sets the tone: after a "blackout", what survives is what was *retained* in memory and what was *transmitted* on the wire – exactly the two filenames that carry the key material. The flag later confirms this reading ("noise in the wires and afterimages").

The important framing decision: these are not four independent puzzles. The executable is the only authority on whether an answer is correct, and every other file exists to feed it. So the job is to find out what the verifier needs, and which file supplies each piece.

First-pass triage was the usual:

```bash
file blackout_protocol retained.mem incident.journal transmission.pcap
strings blackout_protocol
readelf -h blackout_protocol
capinfos transmission.pcap
```

## Step 1 – Seeds from the memory image

Memory images hold state that never reaches disk, which makes them a natural place to hide runtime parameters. `retained.mem` was not random bytes: it contained an `M16B` header, which gave a fixed anchor for parsing the structure that follows instead of guessing at offsets.

Behind that structure sat two 64-bit values:

```text
0x72f23b4a1c67cd00
0xabfedf0984f04e18
```

These are the seeds for the verifier's transformation. It matters *where* they came from: they were read out of the provided evidence, not back-derived from a guessed flag, so they are an independent input to the reconstruction. Without them the rest of the transform cannot be rebuilt.

## Step 2 – Filtering the journal with its own checksums

`incident.journal` mixes genuine records with erroneous or misleading ones. Feeding forged records into the reconstruction would silently corrupt it, so each record had to prove itself.

The integrity check is FNV-1a – a small, non-cryptographic hash that XORs in each byte and then multiplies by a fixed prime, modulo the word size:

```python
def fnv1a_32(data):
    h = 0x811c9dc5
    for byte in data:
        h ^= byte
        h = (h * 0x01000193) & 0xffffffff
    return h
```

A record was accepted only if its stored hash matched the FNV-1a of its contents **and** its index was unique. That left **48 authentic, uniquely indexed records**.

Why this works: forged records can copy the shape of a real one, but unless the forger also recomputes the hash (and avoids index collisions) they fail the check. The data effectively tells you which of its own rows to trust.

> Our parsing script and the individual record values were not preserved in the solve notes, so they are not reproduced here.

## Step 3 – Picking the real conversation out of the capture

`transmission.pcap` holds **290 packets**. Most are unrelated to the application's protocol. We inspected the capture with:

```bash
capinfos transmission.pcap
tshark -r transmission.pcap
tshark -r transmission.pcap -V
tshark -r transmission.pcap -q -z io,phs
```

Rather than pulling payloads from whatever looked interesting, we kept only packets whose protocol fields were consistent with the application's format **and** whose checksums verified. **32 packets** passed.

Those 32 payloads were used to reconstruct a **384-byte lookup table** – a core component of the verifier's transform. As with the journal, the selection script and the reconstructed table were not saved in the notes, so this writeup records the result rather than the bytes.

## Step 4 – The verifier's transform

The verifier does not compare the input against a string in plain sight. It runs the input through a custom, block-cipher-like transform:

| Stage | What it does |
| --- | --- |
| 256-byte S-box | Substitutes every byte value `0x00`–`0xff` through a table – non-linear, so no simple arithmetic inverse |
| Byte permutation | Moves bytes to new positions by a fixed mapping |
| Forward diffusion | Propagates each byte's influence to the bytes after it |
| Reverse diffusion | Propagates influence back the other way, so every byte depends on every other |
| Periodic operations | Extra steps applied at intervals during the run, not just at the start or end |
| 52 rounds | The whole sequence repeated, each round feeding the next |

Two consequences shaped the approach:

- Because of the two-way diffusion and the rounds, no output byte can be solved independently. The transform has to be rebuilt **as a whole process**.
- Each stage type is invertible in principle once its parameters are known (a substitution table can be inverted, a permutation reversed, a diffusion chain unwound). The difficulty is in recovering the parameters – which is what Steps 1–3 were for. Our notes record the stage structure but not the exact constants or the inversion code.

## Step 5 – Putting the evidence together

| Evidence source | Recovered | Role |
| --- | --- | --- |
| `retained.mem` | `M16B` header, two 64-bit seeds | Seed material for the transform |
| `incident.journal` | 48 authentic, uniquely indexed records | Validated incident data |
| `transmission.pcap` | 32 genuine packets out of 290 | Lookup-table reconstruction |
| Reconstructed data | 384-byte lookup table | Parameters of the transform |
| `blackout_protocol` | Authentication logic | Final judge |

None of the evidence files alone gives the answer; the combination yields the transform the verifier expects, and from it the candidate:

```text
SecLeaf{n01s3_1n_th3_w1r35_4nd_4ft3r1m4g3s!!!!!}
```

## Flag

```text
SecLeaf{n01s3_1n_th3_w1r35_4nd_4ft3r1m4g3s!!!!!}
```

## Why this is the right answer

- **The original verifier accepts it.** This is the only check that matters for a reconstructed multi-round transform – a plausible-looking string or a self-consistent re-implementation proves nothing on its own.

  ```bash
  ./blackout_protocol 'SecLeaf{n01s3_1n_th3_w1r35_4nd_4ft3r1m4g3s!!!!!}'
  ```

  ```text
  Authenticated.
  ```

  Exit code: `0`.
- **Format match:** `SecLeaf{...}` wrapper, 48 characters total.
- **The plaintext explains the challenge:** "noise in the wires and afterimages" – the network noise we filtered and the memory afterimage we mined.

## What we learned

- **Map each evidence file to what the verifier needs.** Treating the files as one system ("who supplies the seeds, who supplies the table?") is faster than solving each in isolation.
- **Let the data authenticate itself.** FNV-1a hashes in the journal and checksums in the capture were the filters; using records blindly would have poisoned the reconstruction.
- **Rebuild multi-round transforms as a process.** With two-way diffusion over 52 rounds, per-byte reasoning fails; recover the parameters, then invert stage by stage.
- **Save intermediates.** Seeds, the accepted record set, the packet selection and the lookup table are what make a solve reproducible – we lost ours, and this writeup is thinner for it.

## Reproduce

The team's reconstruction script and constants were not kept, so there is no re-implementation. The flag is checked against the original binary instead: [`solve/verify.sh`](solve/verify.sh) runs it on a wrong flag and on the recovered one (in Docker if the host isn't Linux x86-64). In our run it printed `Blackout.` and then `Authenticated.`. The manual equivalent:

```bash
mkdir -p attachments && cp /path/to/blackout_protocol attachments/
bash solve/verify.sh
```

Expected output:

```text
Authenticated.
[+] FLAG: SecLeaf{n01s3_1n_th3_w1r35_4nd_4ft3r1m4g3s!!!!!}
```

Script: [`solve/verify.sh`](solve/verify.sh)

---

[← Back to Reverse Engineering](../README.md) · [Challenge overview](README.md)
