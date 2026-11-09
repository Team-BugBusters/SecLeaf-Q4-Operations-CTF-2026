# Layers – full writeup

[← Back to Miscellaneous](../README.md) · [Challenge overview](README.md)

**Category:** Miscellaneous · **Points:** 150 · **Flag:** `F1n4lLy_YOu_G0t_1T_!^!`

**Author:** [Rutwik](https://github.com/Rutwik-712) · **Team:** Bug Busters

## TL;DR

1. `Binary_Data` is 4320 `0`/`1` characters. Decoded as 8-bit bytes it becomes 540 characters that look like hex with the letters shifted into `n..s`.
2. ROT13 maps `n,o,p,q,r,s → a,b,c,d,e,f`, leaving digits alone, giving 540 valid hex characters.
3. Hex-decoding gives 270 bytes beginning `52 61 72 21 1A 07 01 00` – a RAR5 archive.
4. The archive password `stormstorm` opens it; `unar` extracts the 22-byte file `Text`; ROT47 of `Text` is the flag.

## The challenge

The attachment `Binary_Data` has no extension. The flavour text – "layer by
layer… adding each step carefully" – says this is a nested-encoding puzzle: each
decode reveals the format of the next layer. The whole approach is to let the
**character set and length** of each output tell us which transform comes next.

The tools the workflow leaned on:

| Task | Tool |
| --- | --- |
| Decode | CyberChef |
| Hash extraction | `rar2john` |
| Password | Hashcat |
| Archive | 7-Zip / `unar` |

## Step 1 – Binary → text

The file is one continuous bitstring; all 4320 characters are `0` or `1`, and
4320 is divisible by 8, so byte-wise decoding is the obvious first step. The
opening bytes are:

```text
00110101 00110010 00110110 00110001 00110111 00110010 00110010 00110001
```

Decoding 8-bit groups (CyberChef *From Binary*, byte length 8), the 4320 bits
become **540 characters** beginning:

```text
526172211n070100rs8s8r0321040000010snpr6qs82p7s519n378q44213qssq28p
```

The output is only digits plus the letters `n` through `s`. That narrow letter
range is the clue: it looks like hexadecimal with its `a..f` letters pushed up by
13 places.

## Step 2 – ROT13 → hexadecimal

Applying ROT13 to the letters only (digits untouched) maps:

```text
n o p q r s  ->  a b c d e f
```

so the string becomes valid hex. The result begins:

```text
526172211a070100ef8f8e0321040000010face6df82c7f519a378d44213dffd28c
```

All 540 characters are now valid hexadecimal – a clear signal to decode to bytes.

## Step 3 – Hex → RAR5 archive

Hex-decoding (CyberChef *From Hex*) yields a **270-byte** binary object whose
first eight bytes are:

```text
52 61 72 21 1A 07 01 00
```

`52 61 72 21` is ASCII `Rar!`, and the `1A 07 01 00` continuation identifies a
**RAR version 5** archive. We save it as `layer3.rar`:

```bash
file layer3.rar
7z l layer3.rar
```

Listing requires a password before the encrypted headers can be read, so the
remaining obstacle is archive access.

## Step 4 – Recover the archive password

Hashcat is the password-recovery tool for this step. First export the archive's
password verifier and strip the filename prefix so Hashcat gets a bare hash line:

```bash
rar2john layer3.rar > archive.hash
cut -d: -f2- archive.hash > rar5.hash
```

The verifier is RAR5, whose Hashcat mode is **13000**. The password is a repeated
word, so a dictionary attack (`-a 0`) with the duplicate rule `d` (which doubles
each candidate, e.g. `storm → stormstorm`) recovers it:

```bash
printf '%s\n' d > duplicate.rule
hashcat -m 13000 -a 0 rar5.hash words.txt -r duplicate.rule --potfile-path rar5.pot
hashcat -m 13000 rar5.hash --show --potfile-path rar5.pot
```

The working password is:

```text
stormstorm
```

> The Hashcat run is a reproducible workflow rather than a captured session –
> the hash output was not archived. The password itself was confirmed
> independently by decrypting the archive headers and successfully extracting
> the file below.

## Step 5 – Extract the archive

With the password, 7-Zip lists one encrypted file, `Text`, 22 bytes
uncompressed:

```bash
7z l -pstormstorm layer3.rar
```

The installed `p7zip` build could list but returned "Unsupported Method" on
extraction, so we switched to `unar`, which extracted it cleanly:

```bash
unar -p stormstorm -o unpacked -f layer3.rar
cat unpacked/Text
```

The 22-character contents of `Text`:

```text
u`?c={J0*~F0v_E0`%0P/P
```

## Step 6 – ROT47 → flag

`Text` is still encoded. Applying ROT47 (rotate printable ASCII 33–126 by 47,
so punctuation and digits move too) gives:

```text
F1n4lLy_YOu_G0t_1T_!^!
```

ROT47 is its own inverse, so applying it again restores the exact ciphertext –
confirming the transform preserved the character sequence.

## Flag

```text
F1n4lLy_YOu_G0t_1T_!^!
```

## Why this is the right answer

- **Each layer validated the next:** the `n..s` letter set pointed at ROT13-obscured hex; the decoded `Rar!` signature confirmed a RAR5 container; a successful decrypt+extract confirmed the password.
- **ROT47 round-trip:** re-applying ROT47 to `F1n4lLy_YOu_G0t_1T_!^!` reproduces `u`?c={J0*~F0v_E0`%0P/P` exactly, so the final decode is self-checking. The archived `solve.py` asserts this.
- **No wrapper, intentionally:** the brief specifies no flag prefix, so the recovered value stands as-is – the capitalisation, digits, underscores and trailing `!^!` are all part of it.

## What we learned

- **Let the output shape pick the next tool.** Digits plus only `n..s` was the tell for ROT13-obscured hex; the `Rar!` magic identified the container without an extension.
- **Check binary signatures after every decode.** A magic number names the next layer even when the file has no extension.
- **Be precise with Hashcat modes and rules.** A dictionary + duplicate-word rule (`d`) is a targeted attack, quite different from brute-forcing every combination; RAR5 is mode 13000.
- **A wrong password and an unsupported extractor look different.** When one tool fails mid-extract, try a second compatible extractor (`unar`) before doubting the password.
- **Keep decoding extracted content.** A successful archive extraction was not the end – the extracted `Text` still needed a separate ROT47 pass.

## Reproduce

```bash
cd solve
python3 solve.py
```

With no `Binary_Data` attachment present, `solve.py` reproduces the final ROT47
stage from the recorded `Text` ciphertext and prints the flag. Drop the original
`Binary_Data` into `attachments/` (and have `unar`, `7z`, or `rarfile`
available) to run the full binary → ROT13 → hex → RAR5 → ROT47 chain.

Full solver: [`solve/solve.py`](solve/solve.py)

---

[← Back to Miscellaneous](../README.md) · [Challenge overview](README.md)
