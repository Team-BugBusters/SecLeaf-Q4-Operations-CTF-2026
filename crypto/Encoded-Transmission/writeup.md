# Encoded Transmission – full writeup

[← Back to Cryptography](../README.md) · [Challenge overview](README.md)

**Category:** Cryptography · **Points:** 175 · **Flag:** `CRY{ok_password_was_the_building_code_and_cost_in_yen_with_2underscore}`

**Author:** [Rutwik](https://github.com/Rutwik-712) · **Team:** Bug Busters

## TL;DR

1. The "two numbers" in the hint are the values we recovered in Riddled Code: building code `01000144` and parking cost `984720` yen.
2. Joined with two underscores they make `01000144__984720`, exactly 16 bytes: a raw AES-128 key.
3. The intercepted text is Base64 over 224 bytes (14 AES blocks). AES-128-ECB with PKCS#7 decrypts it to the flag plus a Unicode password.
4. The password is Base65536 and decodes to `this_has_all_the_tools_required_to_do_infiltrate`, which the next challenge needs.
5. Re-encrypting the plaintext and re-encoding the password both reproduce their inputs exactly.

## The challenge

We were given one long string in the Base64 alphabet, ending in a `=` pad (line breaks added for readability):

```text
ykt4faVZ2qGkcdWkMnDES8HXjpwvrTYiCVO65dg/1Vv/7R2+0KRe0XGDhfdw
B0U2UyMzvb5ZqskJG4wlz9dXKUHcFqXTpF09hg2uAUJI0NASWuPw1h/H4Zi/
1rRGmqnUJkdZzbW58HI2d81iUdS+XePbaQJ+bGwABg35WaJBizKXgQgtI3pt
vQRGuZlZNv6TFHmvpVRyf/TWulZVJPkrE25z1Yu3C+XnqHcqn7ZByHC/SAOf
Ojj6gvFo7MaKw7yOai0IwmdcLwByJAG8fyounsNL7mjMr4nTo4+0C69Raic=
```

The brief says the data must be **decrypted and decoded**, so there are at least two kinds of layer. The hint says the key is "2 numbers they were talking about", which points back to the location investigation in Riddled Code.

## Step 1 – Peel the Base64 layer

After removing whitespace the string is 300 Base64 characters. Decoding gives **224 bytes**, exactly **14 blocks of 16 bytes**. Random-looking bytes in a whole number of 16-byte blocks is what a block cipher such as AES produces, so we treated Base64 as transport and the bytes as ciphertext.

```bash
tr -d '[:space:]' < transmission_input.txt > transmission.b64
openssl base64 -d -A -in transmission.b64 -out transmission.bin   # 224 bytes
```

`-A` lets OpenSSL read Base64 on a single line.

## Step 2 – Build the key from the two numbers

Riddled Code had given us two values:

| Recovered value | Meaning |
| --- | --- |
| `01000144` | Building code for River Rise Utsubo Honmachi Building |
| `984720` | Total parking cost in yen for two vehicles in September 2022 |

The question is how to join them. AES-128 needs exactly 16 bytes:

```text
8 (building code) + 2 (underscores) + 6 (cost) = 16 bytes
```

One underscore gives 15 characters, which is not a valid key length; two give exactly 16. The building code has to stay text, so its leading zero survives. All characters are ASCII, so the UTF-8 bytes are the same 16 bytes:

```bash
printf '%s' '01000144__984720' | xxd -p
30313030303134345f5f393834373230
```

The earlier Riddled Code flag used a single underscore as a format separator, which is why the doubled separator is worth spelling out. The decrypted flag later confirms it in words: "building code and cost in yen with 2underscore".

## Step 3 – Decrypt AES-128-ECB

| Setting | Value |
| --- | --- |
| Cipher | AES-128 |
| Mode | ECB (no IV) |
| Key (literal) | `01000144__984720` |
| Key (hex, for OpenSSL `-K`) | `30313030303134345f5f393834373230` |
| Padding | PKCS#7 |

Passing the key as raw hex with `-K` matters: a passphrase (`-k`/`-pass`) would make OpenSSL derive a different key from it.

```bash
openssl enc -d -aes-128-ecb -nosalt \
  -K 30313030303134345f5f393834373230 \
  -in transmission.bin -out transmission.txt
```

The output is readable UTF-8 (221 bytes):

```text
CRY{ok_password_was_the_building_code_and_cost_in_yen_with_2underscore} Well, i will be sending you the zip payload to you with password: 鵴𓅩鵟𓅡陟ꍬ𓉟驨𓉟𒁯𓅬𓁟𒉥鹵驲鑤𒁴饟鑯𐙩鹦𓉬陲驴
```

The raw last block ended in three `0x03` bytes, valid PKCS#7 padding. Re-encrypting the padded plaintext with the same key and mode reproduced all 224 ciphertext bytes.

## Step 4 – Decode the Unicode password (Base65536)

The password is 24 unusual Unicode code points, not ASCII:

| Positions | Code points |
| --- | --- |
| 1–6 | `U+9D74 U+13169 U+9D5F U+13161 U+965F U+A36C` |
| 7–12 | `U+1325F U+9A68 U+1325F U+1206F U+1316C U+1305F` |
| 13–18 | `U+12265 U+9E75 U+9A72 U+9464 U+12074 U+995F` |
| 19–24 | `U+946F U+10669 U+9E66 U+1326C U+9672 U+9A74` |

Code points drawn from large CJK and hieroglyph blocks are the fingerprint of **Base65536**, which packs two bytes into each code point: the low 8 bits are the first byte, and which 256-code-point block the character sits in gives the second. You can see it by eye: `U+9D74` ends in `74` = `t`, `U+13169` ends in `69` = `i`, `U+9D5F` ends in `5F` = `_`.

The qntm Base65536 decoder gives 48 ASCII bytes:

```text
this_has_all_the_tools_required_to_do_infiltrate
```

Re-encoding those 48 bytes gave back the exact 24 code points. We kept **both** forms, because the next stage needs both.

| Check | Result |
| --- | --- |
| AES padding | `03 03 03`, valid PKCS#7 |
| AES re-encryption | all 224 ciphertext bytes match |
| Base65536 re-encoding | all 24 code points match |

## Flag

```text
CRY{ok_password_was_the_building_code_and_cost_in_yen_with_2underscore}
```

## Why this is the right answer

- **Padding and round trip.** Valid PKCS#7 padding, plus re-encryption reproducing the exact ciphertext, means key, mode and padding are all right, not just "something that looks readable".
- **The flag describes the key.** It literally says the password was the building code and the cost in yen with two underscores.
- **The rest of the plaintext is coherent.** It announces a zip payload and its password, which is exactly what [Final Tools](../Final-Tools/README.md) asks us to open.

## What we learned

- **Earlier answers can be key material.** Values from an OSINT stage became exact cryptographic bytes in the next stage.
- **Length tells you the separator.** AES key sizes are fixed (16/24/32 bytes); counting characters picked the two-underscore join over every other formatting.
- **Encoding is not encryption.** Base64 carried the ciphertext, AES protected it, Base65536 carried the follow-on password. Peel one layer at a time.
- **Keep the original artifact.** The Unicode field and its decoded ASCII are different passwords, and both were needed later.

## Reproduce

```bash
cd solve
python3 solve.py
```

The solver embeds the intercepted text and both numbers, uses a pure-Python AES (checked against FIPS-197), and checks padding, re-encryption and the Base65536 field. Full solver: [`solve/solve.py`](solve/solve.py)

CyberChef equivalent: **From Base64** → **AES Decrypt** (key `01000144__984720` as UTF8, mode ECB, input Raw, output Raw, no IV). The Base65536 step needs a separate decoder such as qntm's.

## References

- OpenSSL `enc` and `base64` documentation
- GCHQ CyberChef, AES Decrypt operation
- qntm, Base65536 reference implementation and decoder

---

[← Back to Cryptography](../README.md) · [Challenge overview](README.md)
