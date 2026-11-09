# DevOps Flaw

![Event](https://img.shields.io/badge/SecLeaf_CTF-2026-101518?style=flat-square)
![Category](https://img.shields.io/badge/Category-Forensics-B4441F?style=flat-square)
![Points](https://img.shields.io/badge/Points-150-2F5D3A?style=flat-square)

> **Solved by** [Rutwik](https://github.com/Rutwik-712) · **Team** Bug Busters · **Solved** 1 November 2026, 6:50 am

## Challenge description

> A DevOps engineer experienced a catastrophic system crash. During recovery, only one partition could be restored. Your task is to investigate the recovered data and uncover what remains hidden within it.

**Flag format:** `SecLeaf{...}`

**Attachments:** [`Archive.7z`](attachments/Archive.7z) (21,720,227 bytes; password in the writeup)

## Flag

```text
SecLeaf{l3g4cY_reg1sTrY_m1graT1on_284}
```

## Writeup

Read the full solve: **[writeup.md](writeup.md)**

**In one line:** the key and the ciphertext were split across two files of the recovered project – `KEY_15_00f` in `.env.example` is a two-byte XOR key `00 0f`, and it decodes a strange value in the deployment log.

- Outer 7z (7zAES) password recovered by brute force: `299792458rocks`.
- 7z → `Archive.zip` → `challenge`, an MBR disk image with one ext partition holding `acme-infrastructure/`.
- `.env.example` had `DB_PASSWORD=KEY_15_00f`; `logs/deploy-2026-09-18.log` had a 38-character value after an Error label.
- Repeating XOR with `00 0f` gives the flag, which matches the log's ticket `INFRA-284`.

## Files

| Path | What it is |
| --- | --- |
| [`writeup.md`](writeup.md) | Full solve |
| [`solve/solve.py`](solve/solve.py) | Parses the key marker and XOR-decodes the embedded log value |

## Run the solver

```bash
cd solve
python3 solve.py
```

Expected output ends with:

```text
[+] FLAG: SecLeaf{l3g4cY_reg1sTrY_m1graT1on_284}
```

## Notes

- Our original notes called this challenge **"DevOps Flow"**. The scoreboard name is DevOps Flaw.
- The solver embeds the key marker and log value, so it needs no archive and uses only the standard library. Both values were re-checked against the archive: `Archive.7z` (password `299792458rocks`) holds `Archive.zip`, which holds a 2 GiB MBR image whose partition (offset 1,048,576) contains `acme-infrastructure/.env.example` (`DB_PASSWORD=KEY_15_00f`) and `logs/deploy-2026-09-18.log` with the same 38-byte error value.
- The disk image also holds an unrelated `Park.mp4` (about 21 MB) that the solve does not use.
- The brute-force mask used to recover `299792458rocks` was not recorded. (299,792,458 m/s is the speed of light.)

---

[← Back to Forensics](../README.md) · [All writeups](../../README.md)
