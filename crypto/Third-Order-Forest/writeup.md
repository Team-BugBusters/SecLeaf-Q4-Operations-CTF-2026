# Third-Order Forest – full writeup

[← Back to Cryptography](../README.md) · [Challenge overview](README.md)

**Category:** Cryptography (side-channel analysis) · **Points:** 500 · **Flag:** `SecLeaf{wal5h_sp3ctra_outgr0w_th3_m4sked_f0r3st}`

**Author:** [Shreya](https://github.com/doodleP) · **Team:** Bug Busters

## TL;DR

1. We had 60,000 power traces of a protected AES-128 and an AES-GCM "capsule" holding the flag. The job was to pull the 16-byte key out of the traces.
2. A marker value `110` in samples 0–2 gave each trace's random delay. We realigned on it.
3. The masking uses three shares ("Third-Order"), so only the product of three samples leaks. A third-order F-test over sample triples found the three share points for each key byte.
4. The S-box output passes through a secret 8×8 bit matrix ("scrambled wiring") before it leaks. The Hamming weight of a linear map is a sum of 8 Walsh characters, so for the correct key guess a Walsh–Hadamard transform of the class means shows exactly 8 same-sign spikes. This ranked every byte without recovering the matrix.
5. Key `2f1aa90f9774de5a29ef06a881d5ee68` decrypted the capsule and the GCM tag verified.

## The challenge

| File | What it contained |
| --- | --- |
| `capture.npz` | 60,000 power traces, plus the plaintext used for each trace |
| `acquisition.py` | How the traces were recorded |
| `capsule.json` | AES-GCM nonce and ciphertext holding the flag |

The brief names three countermeasures, and each one maps to a step of the attack:

| Hint in the brief | Countermeasure | What breaks it |
| --- | --- | --- |
| "We masked the secrets" + the name **Third-Order** | three-share Boolean masking | a third-order (three-sample) combination |
| "We scrambled the wiring" | a secret linear map `L` on the S-box output | Walsh–Hadamard spectrum |
| "enough noise" | heavy noise | 60,000 traces + per-phase standardisation |

"Third-Order" is the most useful word in the title: it tells you the number of shares, and so the order of the statistic you need. The numpy jab in the brief is fair: the whole attack is numpy matrix work, but only with the right statistics on top.

## Step 1 – Realign on the phase marker

Two things stood out when we loaded the traces:

- In every trace, exactly one of the first three samples had the value `110`.
- Because the secrets are masked, a normal first-order attack (CPA on the S-box output) cannot work: no single sample depends on the secret.

The position of `110` (0, 1 or 2) splits the traces into three groups. Once we found the leakage points (Step 2), they sat exactly one sample further right for each step of the marker. So the marker is a **phase**: a random delay inserted to desynchronise the traces.

```text
phase           = position of 110 in samples [0, 1, 2]
leakage sample  = base sample + phase
```

To undo it, we dropped the three marker samples and standardised every sample (subtract the mean, divide by the standard deviation) separately within each phase group. When reading a leakage point we always added the trace's phase to the base index. After this, all 60,000 traces lined up.

Alignment had to come first. A third-order statistic multiplies three samples; if each of them is in the wrong place a third of the time, the signal is ruined.

## Step 2 – Find the three shares with a third-order F-test

With three-share Boolean masking, every sensitive byte `v` is split into random shares:

```text
v = share1 XOR share2 XOR share3
```

Any one share, or any two, is uniformly random and independent of `v`. Only all three together carry information. That is why first- and second-order analysis show nothing, and why the challenge is called **Third-Order** Forest.

The standard answer is the **centred product**: centre three samples and multiply them. Each share leaks a little at its own sample; the product of the three centred samples has an average that depends on `v`, even though no single sample does.

We did not know which three samples held the shares, so we tested triples:

- For each sample triple `(a, b, c)`, compute `x_a * x_b * x_c` for every trace (after centring).
- Group the products by the value of one plaintext byte (256 classes).
- Run a one-way ANOVA F-test across the 256 classes (the same statistic as `scipy.stats.f_oneway`). If the class means differ, the triple leaks.

This is leakage *detection*: it needs no model of what leaks, only whether something depends on the plaintext. The real triples stood out clearly from the noise, in a regular layout: key byte `j` leaks inside samples `12j` to `12j+11` (indices after removing the marker samples), plus the phase.

| Byte | Sample triple | Byte | Sample triple |
| ---: | --- | ---: | --- |
| 0 | 4, 6, 8 | 8 | 99, 100, 101 |
| 1 | 19, 20, 21 | 9 | 109, 111, 112 |
| 2 | 26, 28, 30 | 10 | 122, 123, 129 |
| 3 | 37, 39, 42 | 11 | 132, 140, 141 |
| 4 | 51, 53, 57 | 12 | 144, 146, 148 |
| 5 | 62, 64, 65 | 13 | 156, 161, 164 |
| 6 | 79, 80, 81 | 14 | 168, 173, 176 |
| 7 | 89, 90, 92 | 15 | 181, 182, 185 |

So byte 0, for example, leaks at samples 4, 6 and 8 (plus the phase). Tools such as Lascar and eshard's SCAred offer the same higher-order centred-product preprocessing; we did it directly with numpy matrix operations.

## Step 3 – Why the usual key-recovery model fails

Normally the next step is to correlate the combined leakage with a model such as `HW(S(p XOR k))` for each of the 256 key guesses `k`. That does not work here because of the "scrambled wiring": the S-box output `y` goes through a secret 8×8 binary matrix `L` before it leaks.

```text
leakage ≈ HW(L * S(p XOR k))
```

We cannot compute this model without `L`, and guessing `L` (2^64 possible matrices) is out of the question.

## Step 4 – The Walsh spectrum sees through the wiring

The trick is to stop thinking of `L` as a matrix and think of its output bits one at a time.

Each output bit of `L * y` is a parity: row `r` of `L` (call it `l_r`) dotted with `y`, mod 2. A single bit `b` can be written with a ±1 sign as `b = (1 - (-1)^b) / 2`. Adding up the 8 output bits:

```text
HW(L * y) - 4 = -1/2 * sum over the 8 rows r of (-1)^(l_r · y)
```

Each term `(-1)^(l_r · y)` is a **Walsh character**: one of the 256 basic ±1 patterns over the byte `y`. So whatever `L` is, `HW(L * y)` is made of exactly **8** Walsh patterns (one per row), all with the same weight and the same sign.

A Walsh–Hadamard transform measures how much of each of the 256 patterns a function contains. Apply it to the leakage-as-a-function-of-`y` and the correct key gives 8 equal spikes and almost nothing else. A wrong key scrambles the relationship between `p` and `y`, and the energy smears across the spectrum. We never need to find `L`; the positions of the spikes *are* its rows.

For each key byte:

- Compute the mean of the triple product for each of the 256 plaintext values.
- For each key guess `k`, re-index those means by `y = S(p XOR k)` (using the inverse S-box: `p = S⁻¹(y) XOR k`).
- Apply a 256-point Walsh–Hadamard transform (`scipy.linalg.hadamard` gives the matrix) and drop the constant coefficient.
- Score the guess by the size of its 8 largest same-sign coefficients relative to the total energy of the spectrum.

```python
p_of_y = INV_SBOX ^ k                 # p such that S(p ^ k) = y
spec   = wht(means_by_p[p_of_y])[1:]  # drop the constant term
score  = top8_same_sign(spec) / sqrt(sum(spec ** 2))
```

The correct guess showed exactly 8 sharp spikes of the same sign. It won clearly on all 16 bytes, with a score of about **2.1** against about **1.35** for the runner-up. The recovered AES-128 key:

```text
2f1aa90f9774de5a29ef06a881d5ee68
```

## Step 5 – Open the capsule

We decrypted `capsule.json` with AES-GCM, using its nonce and ciphertext and the recovered key (the `cryptography` library; pycryptodome's `AES.MODE_GCM` works the same way). The authentication tag verified. GCM rejects the ciphertext if even one key bit is wrong, so a valid tag confirms all 16 key bytes at once.

```text
SecLeaf{wal5h_sp3ctra_outgr0w_th3_m4sked_f0r3st}
```

## Flag

```text
SecLeaf{wal5h_sp3ctra_outgr0w_th3_m4sked_f0r3st}
```

## Why this is the right answer

- **Authenticated decryption.** The AES-GCM tag verified under the recovered key. A wrong key raises an error rather than producing plausible text.
- **Every byte won clearly.** Each of the 16 bytes had the expected 8-spike Walsh signature, scoring about 2.1 against about 1.35 for the next guess.
- **The structure matches the brief.** The leakage needed exactly three samples (three shares), a per-trace delay (the phase marker) and a linear-map-aware model (Walsh), which is everything the brief warned about.
- **The flag says so too:** "walsh spectra outgrow the masked forest".

## What we learned

- **Align before you analyse.** Desynchronised traces ruin every statistic, especially higher-order products, so finding the phase marker came first.
- **Masking order sets attack order.** With three shares, only a third-order combination of three samples leaks; first- and second-order tests will look clean.
- **Detect leakage before you model it.** An F-test (ANOVA) over sample triples finds the points of interest without needing to know what leaks.
- **Walsh analysis handles unknown linear maps.** The Hamming weight of any linear function is a fixed-size sum of Walsh characters, so a spectrum exposes the hidden structure without solving for the map.

## Reproduce


```bash
cd solve
python3 -m pip install -r requirements.txt
python3 solve.py
```

On the archived capture, every key byte wins with a score of about 2.1 against a runner-up of about 1.35, giving key `2f1aa90f9774de5a29ef06a881d5ee68`, and the GCM tag authenticates. Full solver: [`solve/solve.py`](solve/solve.py)

---

[← Back to Cryptography](../README.md) · [Challenge overview](README.md)
