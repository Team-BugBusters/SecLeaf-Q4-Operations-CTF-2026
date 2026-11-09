# At Their House – full writeup

[← Back to Forensics](../README.md) · [Challenge overview](README.md)

**Category:** Forensics · **Points:** 150 · **Flag:** `CRY{7im3_1n_phO70_u5ed_45_p1n_w45_54mE_45_d473_r34d_1n_jAp4n_8f2b}`

**Author:** [Vaidik](https://github.com/Vaidik-Makhasana) · **Team:** Bug Busters

## TL;DR

1. The photo ZIP's entry timestamp, `2022-07-15 10:04:52`, splits into two six-digit PINs: `220715` (YYMMDD) and `100452` (HHMMSS).
2. The 7z (password `1234`) contains `lock.exe`, a PE32+ that uses OpenSSL to decrypt a 112-byte blob through three AES-256-CBC layers.
3. PIN 1 keys layers 1 and 2. PIN 2 overwrites layer 2's IV and keys layer 3. That is the "state-dependent" lock: one PIN preps it, the other opens it.
4. The program tries all 1331 salt triples; `7-2-5` produces `CRY{…}` even though layer 3's padding check fails.

## The challenge

We got two files:

| File | Contents |
| --- | --- |
| `Box-1234.7z` | Encrypted 7z (password `1234`, given in the brief), encrypted headers, holds `lock.exe` |
| `photooflock.zip` | One image, `OIP-3595450325.jpg` |

The brief is full of hints:

- **"6-digit locks"**, **"could never open their doors on the first try"**, **"must be prepped"** – two PINs, used in order.
- **"photo was captured on the day lock was installed"** and **"looked at this photo and then tried to open"** – the PINs come from the photo's time.
- **"went to Japan"** – Japanese dates are written year-month-day, so YYMMDD. The flag itself confirms it: *"time in photo used as pin was same as date read in Japan"*.

## Step 1 – Get the PINs from the photo's timestamp

The JPEG's EXIF had no capture time. The ZIP entry's modification time did:

```text
OIP-3595450325.jpg   2022-07-15 10:04:52
```

Split it into date and time, read the date the Japanese way:

| PIN | Source | Value | Role |
| --- | --- | --- | --- |
| PIN 1 | date, YYMMDD | `220715` | Preps the lock (layers 1 and 2) |
| PIN 2 | time, HHMMSS | `100452` | Opens it (IV of layer 2, key of layer 3) |

## Step 2 – Unpack `lock.exe` from the 7z

The archive encrypts its headers, so we decrypted them ourselves. 7z's AES coder (method ID `06 F1 07 01`) derives its key by hashing the UTF-16LE password plus a 64-bit counter with SHA-256, 2^19 times (cycles power 19, empty salt):

| Value | |
| --- | --- |
| 7z AES key | `1e7a2dd184530fb98daa8ceb3a42a7a3f96b4efbe5d867ea601317722f769ef5` |
| Header IV | `47c2f09ceb7e977e730421717ee3d46e` |
| Decrypted header CRC32 | `de720b8b` (expected `de720b8b`) |
| Main stream IV | `68eb5216a10f1ea478fcf01703c12594` |
| Main stream | offset 32, 14,384 bytes, AES-256-CBC → x86 BCJ → LZMA2 |

The matching CRC proves the key is right. The main stream unpacks to `lock.exe`: 58,796 bytes, PE32+.

## Step 3 – Read what the lock does

`lock.exe` imports `EVP_BytesToKey`, `EVP_aes_256_cbc`, `EVP_sha256`, `EVP_DecryptInit_ex/Update/Final_ex` and `EVP_CIPHER_CTX_set_padding`. Its strings include:

```text
SYNDICATE TERMINAL v4.2.4-BRUTE
Enter 6 digit pin:
[!] HANDSHAKE SUCCESSFUL (Salt Combo: %d-%d-%d)
RECOVERED: %s
```

Reversing `main()` and `decrypt_layer()` gave the chain:

| Layer | Password | Salt | IV | Padding |
| --- | --- | --- | --- | --- |
| 1 | PIN 1 `220715` | s1 | derived | off |
| 2 | PIN 1 `220715` | s2 | **replaced by PIN 2** | off |
| 3 | PIN 2 `100452` | s3 | derived | PKCS#7 on |

Each layer derives its key and IV with `EVP_BytesToKey` (SHA-256, count 1). The salt is 8 bytes: the salt number, then seven zeros (salt 7 = `07 00 00 00 00 00 00 00`):

```text
D1 = SHA256(PIN || salt)          -> AES key (32 bytes)
D2 = SHA256(D1 || PIN || salt)    -> IV = first 16 bytes
```

In layer 2 the code throws the derived IV away and puts PIN 2 in its place:

```c
memset(iv, 0, 16);
memcpy(iv, second_pin, strlen(second_pin));   // IV = "100452" + 10 zero bytes
```

So PIN 2 is not just a second password. It changes the IV of the middle layer *and* keys the last one. That is the state dependency.

## Step 4 – Search the salts

Three nested loops try salts 0–10 for each layer: 11 × 11 × 11 = 1331 combinations. A combination wins when the output contains `CRY{`. The ciphertext is 112 bytes in `.data` (RVA `0x3000`, raw offset `0x2600`):

```text
e6fac39c4d4e249fff261038c112c965 b1481be2323342a0239cc79c845d4ba4
2d3d30fe977808ad6cbf668f092c8eef cea6cc3bc412cbc61e392cc8b3560697
bd7cdca9ff7ab6f8f3a41debc1c46fff 3b4ce5f332f2bb1b598098c9f5faa6f1
57fa52424cacf97a5eef7470a58b424d
```

The hit is **7-2-5**, on try 875. The derived values:

| Layer | Key | IV used |
| --- | --- | --- |
| 1 (salt 7) | `ff2e9e8f…6e6861c4` | `d8d67f809dd53c0ead6dceea2f26aa21` |
| 2 (salt 2) | `590e829c…5468a724` | `31303034353200000000000000000000` (derived `fcc21860a55e1845e0d4f08926bf66e0` discarded) |
| 3 (salt 5) | `5153e65c…70c4b768` | `8e32142e2af104153fc2d9eefe97521a` |

Full keys are printed by the solver.

## Step 5 – Handle the broken padding the way the lock does

Layers 1 and 2 disable padding, so they return all 112 bytes. Layer 3 leaves PKCS#7 on. `EVP_DecryptUpdate` returns 96 bytes and holds back the last block; `EVP_DecryptFinal_ex` then fails the padding check and returns 0 bytes. The program ignores that failure and searches the 96 bytes it has:

| Call | Status | Output |
| --- | --- | --- |
| `EVP_DecryptUpdate` | 1 | 96 bytes |
| `EVP_DecryptFinal_ex` | 0 | 0 bytes |

The 96 bytes start with:

```text
4352597b37696d335f316e5f70684f37305f753565645f34355f70316e5f7734355f
35346d455f34355f643437335f723334645f316e5f6a4170346e5f386632627d...
```

which is the flag in ASCII. This matters for anyone re-implementing it: a decryptor that insists on valid padding throws away the correct combination.

## Flag

```text
CRY{7im3_1n_phO70_u5ed_45_p1n_w45_54mE_45_d473_r34d_1n_jAp4n_8f2b}
```

## Why this is the right answer

- **Every step self-checks.** The 7z header CRC matched, the unpacked file is the expected 58,796-byte PE, and only one of 1331 salt triples yields `CRY{…}`.
- **The flag explains the puzzle.** Leetspeak aside, it reads "time in photo used as pin was same as date read in Japan" – exactly the PIN derivation we used.
- **The program's own success check matches.** Our reimplementation uses the same test as `lock.exe` (look for `CRY{`), whose success message is `HANDSHAKE SUCCESSFUL (Salt Combo: %d-%d-%d)`.
- **Our solver reproduces it.** `solve.py` matches every key, IV and intermediate output recorded during the solve.

## What we learned

- **Container metadata counts as evidence.** The image itself had no capture time; the ZIP entry's mtime did.
- **Read brief hints literally.** "Japan" picked the date order, "prepped" meant two PINs in sequence.
- **An IV override is a second key.** Find where each input is actually used, not just where it is read.
- **Copy the target's bugs.** The lock ignores `EVP_DecryptFinal_ex`; a "correct" decryptor would miss the flag.

## Reproduce

```bash
cd solve
python3 -m pip install -r requirements.txt
python3 solve.py
```

Full solver: [`solve/solve.py`](solve/solve.py). It embeds the 112-byte ciphertext and PIN timestamp from our notes, so the original archives are not needed.

---

[← Back to Forensics](../README.md) · [Challenge overview](README.md)
