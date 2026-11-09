# Fallen Leaf – full writeup

[← Back to Forensics](../README.md) · [Challenge overview](README.md)

**Category:** Forensics · **Points:** 100 · **Flag:** `SecLeaf{d3l3t3d_k3ys_n3v3r_d13_th3_xattr_r3m3mb3rs}`

**Author:** [Rutwik](https://github.com/Rutwik-712) · **Team:** Bug Busters

## TL;DR

1. `leafdisk.img.xz` is an ext4 image with one user's home directory. Several flag-shaped strings in it are decoys.
2. `.bash_history` shows how `harvest.txt` was encrypted (AES-256-CBC, PBKDF2, 100,000 iterations) and then destroyed.
3. The key files were gzip'd, then deleted, but ext4 left the deleted inodes intact. Of the four recovered backups, only `k_2024-10-11.txt.gz` holds a key whose SHA-256 matches `notes.txt`: `Phl03m-X7lem-Fl0w-90`.
4. Decrypting `harvest.enc` gives the first half of the flag. The `user.leaf` extended attribute on `notes.txt`, Base32-decoded, gives the second half.

## The challenge

> We seized a workstation belonging to someone who 'cleans up after themselves'. Recover the harvest. Warning: this machine is full of things that look like flags.

The brief sets three expectations:

- **"cleans up after themselves"** – the evidence has been deleted, so we look for what deletion leaves behind.
- **"Recover the harvest"** – the target is a file called harvest.
- **"full of things that look like flags"** – matching `SecLeaf{` will find decoys. Only a flag with a chain of evidence behind it counts.

## Step 1 – Unpack the image and map the home directory

```bash
xz -dk leafdisk.img.xz
file leafdisk.img        # ext4 filesystem
```

An ext4 image, not a loose folder of files, means the filesystem itself can hold evidence: deleted files, metadata, attributes. The user's home directory contained:

| Item | Why it matters |
| --- | --- |
| `.bash_history` | What the user did |
| `.cache/` | Compressed key backups |
| `.config/` | Contained a readme with a decoy flag |
| `Documents/harvest.enc` | The encrypted target |
| `notes.txt` | SHA-256 of the active key, plus a hidden xattr |
| `flag.txt`, `auth.log` | Decoys |

## Step 2 – Read the cleanup script in the shell history

`history -c` clears the in-memory history, but the file on disk still had the commands:

```bash
cd Documents
cat flag.txt

cd ~/.cache
for f in k_*.txt; do gzip -N $f; done

openssl enc -aes-256-cbc -pbkdf2 -iter 100000 -salt \
  -in harvest.txt \
  -out Documents/harvest.enc \
  -pass file:.cache/k_active

shred -u harvest.txt
rm -f .cache/k_*
history -c
```

This gives us everything except the password:

| Fact | Value |
| --- | --- |
| Cipher | AES-256-CBC |
| Key derivation | PBKDF2, 100,000 iterations, salted |
| Original file | `harvest.txt` (shredded) |
| Output | `Documents/harvest.enc` |
| Password | contents of `.cache/k_active` (deleted) |

The order is the mistake. The key files were gzip'd *first*. `gzip` writes a new `.gz` file and removes the original, so `rm -f .cache/k_*` removed the plain key files, but the compressed copies remained as `k_*.txt.gz`.

## Step 3 – Recover the deleted key backups, then pick one by hash

Read the history closely: `gzip -N` replaced each `k_*.txt` with `k_*.txt.gz`, and then `rm -f .cache/k_*` deleted **those too**, because the glob matches the `.gz` names. A plain `ls` of `.cache/` shows only the junk files.

Deleting a file on ext4 removes its directory entry and marks the inode free. It does not wipe the data blocks. `debugfs` still sees four deleted entries in `.cache/` and five deleted inodes with intact data:

```bash
debugfs -R "ls -d -l /home/leaf/.cache" leafdisk.img    # <0> k_2024-10-02.txt.gz ... k_2024-10-14.txt.gz
debugfs -R "lsdel" leafdisk.img                         # inodes 24, 25, 26, 27, 34
debugfs -R "dump <26> k26.gz" leafdisk.img              # repeat for each inode
```

The four gzip inodes still carry their original file names in the gzip header:

| Inode | Backup | Contents |
| ---: | --- | --- |
| 24 | `k_2024-10-02.txt.gz` | `leafkey:Gr33n-Sapl1ng-77` |
| 25 | `k_2024-10-09.txt.gz` | `leafkey:R00t-B4ll-Aut0mn-12` |
| 26 | `k_2024-10-11.txt.gz` | `leafkey:Phl03m-X7lem-Fl0w-90` |
| 27 | `k_2024-10-14.txt.gz` | `leafkey:C4mb1um-R1ng-2024` |

(Inode 34 is an unrelated deleted shopping list.)

`notes.txt` says: *"Active key is the one whose sha256 is `d389cee5d239c721a5c0967d956d0826d182ca3f537a6f45b5ba40386c0a4c55`."* Hashing the key value after `leafkey:` (no newline) gives exactly one match, inode 26:

```text
sha256("Phl03m-X7lem-Fl0w-90") = d389cee5d239c721a5c0967d956d0826d182ca3f537a6f45b5ba40386c0a4c55
```

Hash matching replaces guessing: four candidates, one match. The title says the same thing: *deleted keys never die*.

## Step 4 – Decrypt the harvest

Decrypt with the same parameters as the encryption command:

```bash
openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 \
  -in harvest.enc -out harvest.txt \
  -pass pass:'Phl03m-X7lem-Fl0w-90'
cat harvest.txt
```

A wrong password or wrong iteration count fails with a bad-decrypt error, so a clean decrypt confirms the key. `harvest.txt` read:

```text
== harvest log ==
FLAG=SecLeaf{d3c0y_th3_tr33_h4s_n0_r00ts}
Part one of the real flag: d3l3t3d_k3ys_n3v3r_d13
Part two travels with the note, not inside it. (base32, attribute 'leaf')
Real flag format: SecLeaf{<part1><part2>}
```

Even the decrypted target opens with a decoy (`FLAG=…d3c0y…`). The real content is the labelled **part one**, `d3l3t3d_k3ys_n3v3r_d13`, plus a pointer to part two: "travels with the note, not inside it", a Base32 attribute named `leaf`.

## Step 5 – Rule out the decoys

| Decoy | Where | Why it is not the flag |
| --- | --- | --- |
| `SecLeaf{fl4g_txt_1s_n0t_th3_fl4g}` | `flag.txt` | The file the user openly `cat`s, and the text says it is not the flag |
| `SecLeaf{4uth_l0g_n01s3}` | `auth.log` | Log noise. No link to the encrypt-and-delete chain |
| `SecLeaf{3ncrypt3d_but_n0t_d0n3}` | `.config/readme` | Says "encrypted but not done": a nudge to keep going, not an answer |
| `SecLeaf{b4sh_h1st0ry_l13s}` | `.bash_history` (`echo U2VjTGVh… \| base64 -d`) | The history "lies": it is a Base64 string the user echoed, not output of the encryption chain |
| `SecLeaf{d3c0y_th3_tr33_h4s_n0_r00ts}` | first line of the decrypted `harvest.txt` | Labelled `FLAG=` but contradicted two lines later by "Part one of the real flag" |

Only the labelled part one comes out of the `harvest.enc` chain the brief points to ("Recover the harvest"), and none of the decoys contains the `d3l3t3d_k3ys…` piece.

## Step 6 – Read the extended attribute on `notes.txt`

ext4 can store extended attributes (xattrs): name/value pairs kept in the inode, not in the file's content. `cat` never shows them. Listing attributes on `notes.txt` (inode 33) found:

```text
user.leaf = L52GQM27PBQXI5DSL5ZDG3JTNVRDG4TT
```

Upper-case letters and digits 2–7 only: Base32.

```bash
echo 'L52GQM27PBQXI5DSL5ZDG3JTNVRDG4TT' | base32 -d
# _th3_xattr_r3m3mb3rs
```

## Step 7 – Assemble

| # | Piece | Source |
| --- | --- | --- |
| 1 | `d3l3t3d_k3ys_n3v3r_d13` | decrypted `harvest.enc` |
| 2 | `_th3_xattr_r3m3mb3rs` | `user.leaf` xattr on `notes.txt` |

Piece 2 starts with `_`, so it follows piece 1, and together they read as a sentence: *deleted keys never die, the xattr remembers*.

## Flag

```text
SecLeaf{d3l3t3d_k3ys_n3v3r_d13_th3_xattr_r3m3mb3rs}
```

## Why this is the right answer

- **It comes out of the harvest chain.** Shell history → surviving gzip'd key → hash match → successful decrypt.
- **Both pieces are proven.** Piece 1 needs a key that passes the hash check and a clean AES decrypt. Piece 2 is a direct Base32 decode.
- **The text describes the solve.** Deleted keys survived as backups; the xattr held the rest.
- **The decoys fail the same test.** None of them comes from the encrypted harvest or the hidden attribute.

## What we learned

- **Cleanup order leaks.** Compressing files before deleting them leaves the compressed copies behind; read the history for the order of operations, not just the commands.
- **Use a hash to choose between candidates.** A stored SHA-256 turns "which backup is it?" into a check, not a guess.
- **Check metadata, not just content.** Extended attributes live in the inode and never show up in `cat` or `strings` of the file.
- **A flag needs a source.** When the brief warns about fake flags, accept only the one with a chain of evidence behind it.

## Reproduce

Manual recipe:

```bash
xz -dk leafdisk.img.xz
debugfs -R "cat /home/leaf/Documents/notes.txt" leafdisk.img
debugfs -R "lsdel" leafdisk.img
debugfs -R "dump <26> k_2024-10-11.txt.gz" leafdisk.img
gzip -dc k_2024-10-11.txt.gz | cut -d: -f2 | tr -d '\n' | shasum -a 256   # d389cee5... = notes.txt
debugfs -R "dump /home/leaf/Documents/harvest.enc harvest.enc" leafdisk.img
openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 -in harvest.enc -pass pass:'Phl03m-X7lem-Fl0w-90'
debugfs -R "ea_list /home/leaf/Documents/notes.txt" leafdisk.img
echo 'L52GQM27PBQXI5DSL5ZDG3JTNVRDG4TT' | base32 -d
```

Scripted: [`solve/solve.py`](solve/solve.py) runs the whole chain from `attachments/leafdisk.img.xz` with `debugfs` and needs no mounting: it hashes all four recovered backups, decrypts the harvest, skips its decoy line and decodes the xattr.

```bash
cd solve
python3 -m pip install -r requirements.txt
python3 solve.py
```

---

[← Back to Forensics](../README.md) · [Challenge overview](README.md)
