# Final Tools – full writeup

[← Back to Cryptography](../README.md) · [Challenge overview](README.md)

**Category:** Cryptography (with forensics) · **Points:** 100 · **Flag:** `CRY{Johnny_4nD_M1Cha3L_w3re_tHe_3neMy_Wh0_st4yed_and_tried_to_lnf1itrAt3_the_base}`

**Author:** [Ria](https://github.com/ri-Ria-ri) · **Team:** Bug Busters

## TL;DR

1. `Payload.7z` is not a zip: it is a 465-byte encrypted 7z archive containing an encrypted `FLAG.zip`.
2. [Encoded Transmission](../Encoded-Transmission/README.md) gave us one password in two forms: a 24-code-point Unicode (Base65536) string and its decoded ASCII text.
3. The original Unicode string opens the outer 7z. The decoded ASCII opens the inner `FLAG.zip`.
4. `FLAG.txt` inside holds the flag. Both archives pass integrity tests.

## The challenge

The brief says "the message said about a zip" and asks us to "unlock this zip". The message it refers to is the decrypted transmission from Encoded Transmission:

```text
Well, i will be sending you the zip payload to you with password: 鵴𓅩鵟𓅡陟ꍬ𓉟驨𓉟𒁯𓅬𓁟𒉥鹵驲鑤𒁴饟鑯𐙩鹦𓉬陲驴
```

So we already had the password. The puzzle is which *form* of it each layer expects. The name "Final Tools" echoes the decoded password text, "this has all the tools required to do infiltrate".

## Step 1 – Identify the file by content, not by the brief

```bash
file 'Payload.7z'
7-zip archive data, version 0.4
```

The brief says zip; the bytes say 7z. We left the original untouched and worked on copies. (This attachment was identical to the payload we had already recovered earlier.)

## Step 2 – Line up the two password forms

From Encoded Transmission:

| Form | Value |
| --- | --- |
| Original field | 24 Unicode code points (table below) |
| Base65536-decoded | `this_has_all_the_tools_required_to_do_infiltrate` (48 ASCII bytes) |

| Positions | Code points |
| --- | --- |
| 1–6 | `U+9D74 U+13169 U+9D5F U+13161 U+965F U+A36C` |
| 7–12 | `U+1325F U+9A68 U+1325F U+1206F U+1316C U+1305F` |
| 13–18 | `U+12265 U+9E75 U+9A72 U+9464 U+12074 U+995F` |
| 19–24 | `U+946F U+10669 U+9E66 U+1326C U+9672 U+9A74` |

Re-encoding the ASCII text with Base65536 reproduces exactly this code-point sequence, so the two are the same secret in two encodings. We tried each against each layer:

| Archive | Accepted password |
| --- | --- |
| `Payload.7z` | the original 24-code-point Unicode field |
| `FLAG.zip` | `this_has_all_the_tools_required_to_do_infiltrate` |

The decoded ASCII does **not** open the outer archive: 7-Zip reports an encrypted-header error. That is the trap: decoding the password "properly" is the natural move, and it is wrong for the first lock.

## Step 3 – Open the outer 7z

```bash
7z l -slt 'Payload.7z'      # password: the Unicode field
7z t 'Payload.7z'
7z x 'Payload.7z' -oouter
```

| Property | Value |
| --- | --- |
| Container | 7z |
| Physical size | 465 bytes |
| Member | `FLAG.zip` (281 bytes) |
| Method | LZMA2 with 7zAES encryption |
| Integrity test | Everything is Ok |

Because the headers are encrypted, even the listing needs the password, which is why the wrong form fails with a header error rather than a CRC error.

## Step 4 – Open the inner zip

`FLAG.zip` holds one member, `FLAG.txt`, compressed with Deflate and encrypted with AES-256. The decoded ASCII password opens it:

```bash
7z l -slt outer/FLAG.zip        # password: this_has_all_the_tools_required_to_do_infiltrate
7z t outer/FLAG.zip
7z x outer/FLAG.zip -ofinal
```

Integrity test: Everything is Ok. `final/FLAG.txt` is an 82-byte ASCII file with no line terminator.

## Step 5 – Read the flag

```bash
cat final/FLAG.txt
```

```text
CRY{Johnny_4nD_M1Cha3L_w3re_tHe_3neMy_Wh0_st4yed_and_tried_to_lnf1itrAt3_the_base}
```

The flag names Johnny and Michael as the people who stayed and tried to infiltrate the base, closing the story of the "one month stay". Watch the look-alikes: `lnf1itrAt3` starts with a lowercase `l`, and the mixed case and digits must be kept exactly.

| Artifact | Result |
| --- | --- |
| `Payload.7z` | 465 bytes; Unicode password accepted; test passed |
| `FLAG.zip` | 281 bytes; ASCII password accepted; test passed |
| `FLAG.txt` | 82 ASCII bytes; full flag, no line terminator |
| Repeat extraction | both files matched the earlier `FLAG.zip` and `FLAG.txt` byte for byte |

## Flag

```text
CRY{Johnny_4nD_M1Cha3L_w3re_tHe_3neMy_Wh0_st4yed_and_tried_to_lnf1itrAt3_the_base}
```

## Why this is the right answer

- **Both locks are authenticated.** 7zAES and zip AES-256 both reject wrong passwords, and both integrity tests passed, so the extracted file is the real one.
- **Byte-for-byte repeatable.** A second extraction matched the earlier copies exactly.
- **Length check.** The flag is 82 characters, matching the 82-byte `FLAG.txt`.
- **Story fit.** It answers the brief's "final truth behind this one month stay".
- **Spelling note.** Our notes contain one transcription reading `were` instead of `w3re` (both 82 bytes). The headline, final-flag and conclusion entries all read `w3re`, which also matches the leetspeak of the rest of the flag, so that is the spelling recorded here.

## What we learned

- **Trust the bytes, not the brief.** "Zip" was a 7z; `file` settles it in one command.
- **Keep every form of a secret.** The encoded and decoded passwords were both needed, for different layers.
- **Read error types.** An encrypted-header error on the outer 7z meant "wrong password form", not "corrupt file".
- **Copy flags exactly.** Mixed case, digits and `l`/`I` look-alikes are easy to mistype; take the flag from the file, not from memory.

## Reproduce

```bash
cd solve
python3 solve.py      # needs ../attachments/Payload.7z and 7z on PATH
```

The helper builds the Unicode password from its code points (hard to type by hand), checks it against the ASCII form, and runs `7z x` on both layers. Full script: [`solve/solve.py`](solve/solve.py)

## References

- 7-Zip documentation of the 7z archive format
- qntm, Base65536 reference implementation

---

[← Back to Cryptography](../README.md) · [Challenge overview](README.md)
