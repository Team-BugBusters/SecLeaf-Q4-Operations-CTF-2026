# Final Tools

![Event](https://img.shields.io/badge/SecLeaf_CTF-2026-101518?style=flat-square)
![Category](https://img.shields.io/badge/Category-Cryptography-B4441F?style=flat-square)
![Points](https://img.shields.io/badge/Points-100-2F5D3A?style=flat-square)

> **Solved by** [Ria](https://github.com/ri-Ria-ri) · **Team** Bug Busters · **Solved** 1 November 2026, 1:57 pm

## Challenge description

> Ohk, so the message said about a zip…. After further investigation and forensics, we found the zip file or payload they were talking about. Unlock this zip for final truth behind this one month stay.

**Flag format:** `CRY{...}`

**Attachments:** [`Payload.7z`](attachments/Payload.7z)

## Flag

```text
CRY{Johnny_4nD_M1Cha3L_w3re_tHe_3neMy_Wh0_st4yed_and_tried_to_lnf1itrAt3_the_base}
```

## Writeup

Read the full solve: **[writeup.md](writeup.md)**

**In one line:** the password from Encoded Transmission exists in two forms, and each archive layer takes a different one – the raw Base65536 Unicode string opens the outer 7z, its decoded ASCII opens the inner zip.

- The "zip" is actually a 465-byte encrypted 7z (LZMA2 + 7zAES, encrypted headers) holding `FLAG.zip`.
- The decoded ASCII password fails on the outer archive; the original 24-code-point Unicode field opens it.
- `FLAG.zip` (281 bytes, AES-256 + Deflate) opens with `this_has_all_the_tools_required_to_do_infiltrate`.
- `FLAG.txt` is 82 ASCII bytes with no newline: the flag.

## Files

| Path | What it is |
| --- | --- |
| [`writeup.md`](writeup.md) | Full solve |
| [`solve/solve.py`](solve/solve.py) | Builds both password forms from the code points, checks they agree, and drives `7z` through both layers |

## Run the solver

```bash
cd solve
python3 solve.py      # needs 7z on PATH
```

Expected output ends with:

```text
[+] FLAG: CRY{Johnny_4nD_M1Cha3L_w3re_tHe_3neMy_Wh0_st4yed_and_tried_to_lnf1itrAt3_the_base}
```

## Notes

- Verified on the original `Payload.7z` (downloaded as `Payload (2).7z`). The extracted `FLAG.txt` reads `…w3re…`, which settles the `w3re` / `were` mismatch in our notes.
- **Spelling discrepancy in the source notes:** the headline flag, the "Final Flag" section and the conclusion all read `w3re`; one quoted `cat FLAG.txt` output reads `were`. Both spellings are 82 bytes, so the byte count does not settle it. We publish `w3re` (three of four occurrences, the submitted-flag sections, and consistent with the leetspeak of the rest of the flag); if you have the attachment, the solver prints the file's exact contents.
- The `l` in `lnf1itrAt3` is a lowercase L, not a capital I.
- Last link of a chain: Riddled Code → [Encoded Transmission](../Encoded-Transmission/README.md) → Final Tools.

---

[← Back to Cryptography](../README.md) · [All writeups](../../README.md)
