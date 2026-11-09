# Fallen Leaf

![Event](https://img.shields.io/badge/SecLeaf_CTF-2026-101518?style=flat-square)
![Category](https://img.shields.io/badge/Category-Forensics-B4441F?style=flat-square)
![Points](https://img.shields.io/badge/Points-100-2F5D3A?style=flat-square)

> **Solved by** [Rutwik](https://github.com/Rutwik-712) · **Team** Bug Busters · **Solved** 1 November 2026, 1:30 pm

## Challenge description

> We seized a workstation belonging to someone who 'cleans up after themselves'. Recover the harvest. Warning: this machine is full of things that look like flags.

**Flag format:** `SecLeaf{...}`

**Attachments:** [`leafdisk.img.xz`](attachments/leafdisk.img.xz)

## Flag

```text
SecLeaf{d3l3t3d_k3ys_n3v3r_d13_th3_xattr_r3m3mb3rs}
```

## Writeup

Read the full solve: **[writeup.md](writeup.md)**

**In one line:** the user's cleanup left a trail – the shell history gave the exact `openssl` command, the deleted gzip'd key backups were still recoverable from free inodes, and the second half of the flag sat in an extended attribute that `cat` never shows.

- `.bash_history` showed `harvest.txt` encrypted with AES-256-CBC + PBKDF2 (100,000 iterations), then shredded, keys deleted, history cleared.
- The key files were gzip'd and then deleted, but their inodes survived; of four recovered backups only `k_2024-10-11.txt.gz` hashes to the value in `notes.txt`: `Phl03m-X7lem-Fl0w-90`.
- Decrypting `harvest.enc` gave piece 1: `d3l3t3d_k3ys_n3v3r_d13`.
- The `user.leaf` xattr on `notes.txt` (inode 33), Base32-decoded, gave piece 2: `_th3_xattr_r3m3mb3rs`.

## Files

| Path | What it is |
| --- | --- |
| [`writeup.md`](writeup.md) | Full solve |
| [`attachments/leafdisk.img.xz`](attachments/leafdisk.img.xz) | Official challenge image (ext4, xz-compressed) |
| [`solve/solve.py`](solve/solve.py) | Full chain from the image: deleted-inode recovery → hash match → decrypt → xattr |
| [`solve/requirements.txt`](solve/requirements.txt) | `cryptography` (AES step); also needs `debugfs` |

## Run the solver

```bash
cd solve
python3 -m pip install -r requirements.txt
python3 solve.py
```

Expected output ends with:

```text
[+] FLAG: SecLeaf{d3l3t3d_k3ys_n3v3r_d13_th3_xattr_r3m3mb3rs}
```

## Notes

- Our original notes called this challenge **"Leafdisk"** (after the image name). The scoreboard name is Fallen Leaf.
- The solver needs `debugfs` from e2fsprogs (preinstalled on Linux; `brew install e2fsprogs` on macOS) and `cryptography`.
- Five decoys look like real flags: `SecLeaf{fl4g_txt_1s_n0t_th3_fl4g}`, `SecLeaf{4uth_l0g_n01s3}`, `SecLeaf{3ncrypt3d_but_n0t_d0n3}`, `SecLeaf{b4sh_h1st0ry_l13s}` and `SecLeaf{d3c0y_th3_tr33_h4s_n0_r00ts}` (inside the decrypted harvest itself). The writeup explains why each was ruled out.

---

[← Back to Forensics](../README.md) · [All writeups](../../README.md)
