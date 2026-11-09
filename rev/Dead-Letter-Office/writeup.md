# Dead Letter Office – full writeup

[← Back to Reverse Engineering](../README.md) · [Challenge overview](README.md)

**Category:** Reverse Engineering · **Points:** 250 · **Flag:** `SecLeaf{th3_p0st0ff1c3_h4s_4_d4rk_s1d3!}`

**Author:** [Vaidik](https://github.com/Vaidik-Makhasana) · **Team:** Bug Busters

## TL;DR

1. `postcard.grid` is an encrypted `HPL2` file with 20 four-byte records; `dead_letter_office` is the ELF that checks the message.
2. The ELF's `.rodata` holds a `DLO2` marker followed by an 8-byte key seed and three parameters: start 7, step 7, 14 rounds.
3. The key is `seed[i] ^ ((31*i - 0x5B) & 0xff)` = `20 2f 57 4d bc 50 10 a4`.
4. Each record hides two message bytes behind a 14-round transform plus a chaining XOR. Undoing all 20 records, in the order 7, 14, 1, 8, …, gives the 40-character flag.

## The challenge

| File | Purpose |
| --- | --- |
| `dead_letter_office` | Linux ELF 64-bit executable that verifies the recovered message |
| `postcard.grid` | Binary file containing the encrypted data |

The brief says "you're the post office now": the program that delivers the mail already knows how to read it. Our job is to read the binary closely enough to do the delivery ourselves.

## Step 1 – What the binary talks about

```bash
strings -a dead_letter_office
```

```text
Delivered.
Returned to sender.
postcard.grid
No mail.
DLO2
```

So the program reads `postcard.grid`, checks a supplied message, and prints `Delivered.` on success. `DLO2` is not a message; it looks like a marker for embedded data. Dumping `.rodata` (`objdump -s -j .rodata`) and following the disassembly (`objdump -d -M intel`) confirmed that the decoding constants live right after it.

## Step 2 – The HPL2 file format

The postcard starts with `48 50 4c 32` = `HPL2`. Matching the binary's parsing code against `xxd` output gave this header:

| Offset | Contents | Value |
| --- | --- | --- |
| `0x00` | Magic | `HPL2` |
| `0x04` | Expected message length (u16) | `40` |
| `0x06` | Number of records (u16) | `20` |
| `0x08` | FNV-1a checksum of the payload (u32) | `0x41cbd9ec` |
| `0x0C` | Initial chaining state (u16) | `0x39c6` |
| `0x80` | Encrypted records | 20 × 4 bytes |

The checksum is standard 32-bit FNV-1a over the 80-byte payload, so we can tell immediately if we parsed the payload boundaries correctly. Each record contributes its first two bytes (a little-endian u16) to the decoding.

## Step 3 – The key behind `DLO2`

The 11 bytes after the marker:

```text
85 eb b4 4f 9d 10 4f da   07 07 0e
└──────── seed ───────┘   start step rounds
```

The binary turns the seed into the working key:

```text
key[i] = seed[i] ^ ((31*i - 0x5B) & 0xff)
key    = 20 2f 57 4d bc 50 10 a4
```

The last three bytes set the record walk and cipher strength:

| Parameter | Value |
| --- | --- |
| Record starting position | 7 |
| Record step | 7 |
| Transformation rounds | 14 |

The cursor starts at 7 and adds 7 each time, modulo 20. Because 7 and 20 are coprime, every record is visited exactly once:

```text
7, 14, 1, 8, 15, 2, 9, 16, 3, 10, 17, 4, 11, 18, 5, 12, 19, 6, 13, 0
```

Reading the records sequentially produces garbage; message pair 0 lives in record 7.

## Step 4 – The cipher, and how to undo it

For message pair `i`, with chaining state `s` (initially `0x39c6`), the binary:

1. XORs the two plaintext bytes with `s` (low byte, high byte).
2. Runs 14 rounds over the pair `(a, b)`:

   ```text
   key_a = key[(i + r) & 7] ^ (13*i)
   key_b = rol8(key[(5 + 3r) & 7], (i % 7) + 1)
   (a, b) -> (b, rol8(key_a + b, (r % 7) + 1) ^ key_b ^ a)
   ```

3. Mixes the result into the record: `record = pair ^ rol16(s, 3) ^ ((i + 1) * 0x9E37)`.
4. Sets `s = record` for the next pair.

To decode, we compute the transformed pair from the record (`rol16(s, 3) ^ ((i+1)*0x9E37) ^ record`), undo the 14 rounds, and XOR with `s`.

During the event we undid the rounds by brute force: only two unknown bytes per record means 256 × 256 = 65,536 candidates, which is instant. The round function is a Feistel network, though, so it can also be inverted directly. Each round maps `(a, b)` to `(b, F(b) ^ a)`; given `(a', b')` the previous pair is `(b' ^ F(a'), a')`. The cleaned-up solver does that and re-runs the forward transform to check every pair.

## Step 5 – Decode everything

The solver ([`solve/solve.py`](solve/solve.py), reconstructed from the disassembly, not the author's source) parses the header, checks FNV-1a, pulls the `DLO2` bytes out of the ELF, derives the key and walks the records:

```text
Derived key: 20 2f 57 4d bc 50 10 a4
Record order: 7, 14, 1, 8, 15, 2, 9, 16, 3, 10, 17, 4, 11, 18, 5, 12, 19, 6, 13, 0
Recovered message: SecLeaf{th3_p0st0ff1c3_h4s_4_d4rk_s1d3!}
```

The recovered message is 40 bytes, matching the header.

## Flag

```text
SecLeaf{th3_p0st0ff1c3_h4s_4_d4rk_s1d3!}
```

## Why this is the right answer

- **The binary accepts it:**

  ```text
  $ ./dead_letter_office 'SecLeaf{th3_p0st0ff1c3_h4s_4_d4rk_s1d3!}'
  Delivered.
  ```

- **Integrity checks pass along the way:** the FNV-1a checksum matches `0x41cbd9ec`, and the recovered length equals the header's 40.
- **Format:** printable ASCII, `SecLeaf{...}`, and leetspeak for "the post office has a dark side".

## What we learned

- **Look for markers in `.rodata`.** A short tag like `DLO2` next to unexplained bytes is often the config block for the whole algorithm.
- **Validate the parser before the cipher.** The FNV-1a checksum told us the payload offsets were right before we touched the decryption.
- **Don't assume sequential order.** A start/step pair over a coprime modulus is a common way to shuffle records.
- **Two unknown bytes is a small search.** 65,536 candidates per block is trivially brute-forceable; spotting the Feistel structure is a bonus, not a requirement.

## Reproduce

Put `postcard.grid` and `dead_letter_office` in `../attachments/`, then:

```bash
cd solve
python3 solve.py
```

Full solver: [`solve/solve.py`](solve/solve.py)

---

[← Back to Reverse Engineering](../README.md) · [Challenge overview](README.md)
