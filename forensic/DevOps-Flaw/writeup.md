# DevOps Flaw – full writeup

[← Back to Forensics](../README.md) · [Challenge overview](README.md)

**Category:** Forensics · **Points:** 150 · **Flag:** `SecLeaf{l3g4cY_reg1sTrY_m1graT1on_284}`

**Author:** [Rutwik](https://github.com/Rutwik-712) · **Team:** Bug Busters

## TL;DR

1. The 7z archive is encrypted. We recovered its password by brute force: `299792458rocks`.
2. Inside: a ZIP, inside that a 2 GiB MBR disk image with one ext partition holding a DevOps project, `acme-infrastructure`.
3. `.env.example` contains `DB_PASSWORD=KEY_15_00f`. A deployment log contains an odd 38-character value on an Error line.
4. XOR the log value with the repeating two-byte key `00 0f`. Out comes the flag.

## The challenge

> A DevOps engineer experienced a catastrophic system crash. During recovery, only one partition could be restored. Your task is to investigate the recovered data and uncover what remains hidden within it.

**"Only one partition"** tells us to expect a disk image and to look inside its filesystem. **"DevOps"** says what kind of files will be there: config, infrastructure templates, logs. In a project like that, secrets usually sit in env files and odd things show up in logs.

## Step 1 – Open the archive

The supplied `Archive.7z` was 21,720,227 bytes, encrypted with 7zAES. We recovered the password by brute force (hashcat has a 7-Zip mode, 11600):

```text
299792458rocks
```

Before relying on a cracked password, we tested it against the archive:

```bash
7z t -p299792458rocks Archive.7z      # Everything is Ok
7z x -p299792458rocks Archive.7z -oextracted
```

7z checks CRCs on test, so "Everything is Ok" means the password is right, not just accepted. The archive held another archive, `Archive.zip`.

## Step 2 – Find the partition

```bash
7z x extracted/Archive.zip -opartition
file partition/challenge          # MBR disk image
7z l partition/challenge          # one Linux partition, ext filesystem
```

| Property | Value |
| --- | --- |
| Disk size | 2,147,483,648 bytes |
| Partition start | sector 2048 |
| Byte offset | 1,048,576 (2048 × 512) |
| Filesystem label | `disk` |
| Block size | 4096 bytes |

We extracted the filesystem without mounting it, so the image stayed unchanged, and cross-checked the root directory with `debugfs` on a copy:

```bash
7z x partition/challenge -ofilesystem
```

The tree held a shell history and the `acme-infrastructure` project.

## Step 3 – Search the project for keys and anomalies

The shell history showed the engineer building the project: Terraform config, Ansible files, a Dockerfile, a Kubernetes deployment and a GitHub Actions workflow. Rather than read every file, we searched for key-like markers and log anomalies:

```bash
rg -n -i --hidden "KEY_|legacy|migration|ERROR" .
```

Two hits mattered:

| File | Finding |
| --- | --- |
| `acme-infrastructure/.env.example` | `DB_PASSWORD=KEY_15_00f` – too structured to be a real password |
| `acme-infrastructure/logs/deploy-2026-09-18.log` | An Error line whose value, after the label and a tab, is unexplained |

The log value (38 characters):

```text
SjcCenftl<g;cV_}eh1|T}YPm>g}a[1`nP274r
```

Nearby log lines mentioned a legacy registry reference, a rollback configuration and an open migration ticket, `INFRA-284`. We kept those in mind to check any decoded result against.

## Step 4 – Read the key marker

`KEY_15_00f` gives the same number twice: decimal `15` and hex `00f`. Both equal 0x0f. The question is the byte width. Hex `00f` is three digits; padded to whole bytes it is `000f`, which is **two bytes, `00 0f`**.

That difference changes the result:

| Key | Effect |
| --- | --- |
| `0f` (one byte) | Every byte XORed with 0x0f |
| `00 0f` (two bytes, repeating) | Even bytes unchanged, odd bytes XORed with 0x0f |

The ciphertext already hints at the answer: it starts `S…c…e…` in the even positions, and `S`, `c`, `e` are the 1st, 3rd and 5th letters of `SecLeaf`. Those bytes are untouched, which is what `00 0f` does.

## Step 5 – Decode

```python
ct  = b"SjcCenftl<g;cV_}eh1|T}YPm>g}a[1`nP274r"
key = bytes([0x00, 0x0f])
bytes(b ^ key[i % 2] for i, b in enumerate(ct))
# b'SecLeaf{l3g4cY_reg1sTrY_m1graT1on_284}'
```

We confirmed the same output in CyberChef (XOR, key `000f` hex, standard scheme, null-preserving off), pasting only the value – not the Error label, tab, or trailing newline, which would shift the key alignment or add junk bytes.

## Flag

```text
SecLeaf{l3g4cY_reg1sTrY_m1graT1on_284}
```

## Why this is the right answer

- **Prefix and length.** All 38 bytes decode to printable text with the `SecLeaf{` prefix and a closing `}`.
- **It matches the log.** The flag reads "legacy registry migration 284", and the log talks about a legacy registry and ticket `INFRA-284`.
- **Both key readings agree.** `15` and `00f` are the same value; only the two-byte reading produces the prefix.
- **The password was validated.** 7z's integrity test passed before we used it.

## What we learned

- **Validate a cracked password on the original.** A CRC-checked archive test proves it before you build on it.
- **Key and ciphertext can live in different files.** Here the env file had the key and the log had the data; neither alone is enough.
- **Key width matters.** `000f` and `0f` are different XOR keys. Look at which ciphertext bytes already look like plaintext to tell them apart.
- **Use context to check a decode.** The ticket number in the log confirmed the `284` at the end of the flag.

## Reproduce

```bash
cd solve
python3 solve.py
```

Full solver: [`solve/solve.py`](solve/solve.py). It embeds the key marker and log value, so it does not open the archive. `attachments/Archive.7z` is included, and Steps 1–3 above recover both inputs from it.

## References

- Hashcat example hashes (mode 11600 = 7-Zip): https://hashcat.net/wiki/doku.php?id=example_hashes
- GCHQ CyberChef: https://github.com/gchq/CyberChef

---

[← Back to Forensics](../README.md) · [Challenge overview](README.md)
