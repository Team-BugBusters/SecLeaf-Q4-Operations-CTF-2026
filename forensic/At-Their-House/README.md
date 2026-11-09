# At Their House

![Event](https://img.shields.io/badge/SecLeaf_CTF-2026-101518?style=flat-square)
![Category](https://img.shields.io/badge/Category-Forensics-B4441F?style=flat-square)
![Points](https://img.shields.io/badge/Points-150-2F5D3A?style=flat-square)

> **Solved by** [Vaidik](https://github.com/Vaidik-Makhasana) · **Team** Bug Busters · **Solved** 1 November 2026, 8:00 am

## Challenge description

> During the investigation of the first den, you uncovered the truth behind the local rumors: the syndicate's 6-digit locks are far more sophisticated than they appear.
>
> Neighbors whispered that the criminals could never open their doors on the first try, leading many to believe the locks were faulty.
>
> The mechanism is designed with a state-dependent requirement, meaning the lock must be "prepped" before it will even consider a valid entry.
>
> Criminals went to Japan and locked their base using this advanced lock. The enemy generally looked at this photo and then tried to open this lock and this photo was captured on the day lock was installed and used first.
>
> To move forward and infiltrate their remaining locations without alerting the enemy, you'll need to figure out exactly how to unlock the locks without alerting enemies of the unlock attempt.
>
> This lock software was also used in some phones.
>
> We have copied and saved it in Archive (Pass :1234)

**Flag format:** `CRY{...}`

**Attachments:** [`Box-1234.7z`](attachments/Box-1234.7z) · [`photooflock.zip`](attachments/photooflock.zip)

## Flag

```text
CRY{7im3_1n_phO70_u5ed_45_p1n_w45_54mE_45_d473_r34d_1n_jAp4n_8f2b}
```

## Writeup

Read the full solve: **[writeup.md](writeup.md)**

**In one line:** the photo's ZIP timestamp *is* the lock's two PINs (date as YYMMDD, time as HHMMSS), and the lock is a three-layer AES chain where the second PIN both overrides the middle layer's IV and keys the last layer.

- ZIP entry mtime `2022-07-15 10:04:52` → PIN 1 `220715` (the "prep" PIN), PIN 2 `100452`.
- `lock.exe` (from the 7z, password `1234`) holds a 112-byte ciphertext and decrypts it in three AES-256-CBC layers keyed with `EVP_BytesToKey(SHA-256)`.
- It brute-forces 11 × 11 × 11 = 1331 one-byte salts; the hit is **7-2-5** on try 875.
- Layer 3's padding check fails, but the program ignores it and uses the 96 bytes from `EVP_DecryptUpdate` – which contain the flag.

## Files

| Path | What it is |
| --- | --- |
| [`writeup.md`](writeup.md) | Full solve |
| [`solve/solve.py`](solve/solve.py) | Rebuilds the three-layer decrypt and salt search from the embedded 112-byte ciphertext |
| [`solve/requirements.txt`](solve/requirements.txt) | Python dependency (`pycryptodome`; `cryptography` also works) |

## Run the solver

```bash
cd solve
python3 -m pip install -r requirements.txt
python3 solve.py
```

Expected output ends with:

```text
[+] FLAG: CRY{7im3_1n_phO70_u5ed_45_p1n_w45_54mE_45_d473_r34d_1n_jAp4n_8f2b}
```

## Notes

- The scoreboard lists this under Forensics; the original notes filed it as Cryptography / Reverse Engineering. It is a bit of all three.
- The flag uses the `CRY{}` prefix, not `SecLeaf{}`. That is how the challenge shipped.
- The solver embeds the 112-byte ciphertext, so it runs without the attachments. With `attachments/` present it also reads the ZIP entry time and, if `py7zr` is installed, opens `Box-1234.7z` (password `1234`) and checks that `lock.exe` holds the same ciphertext at raw offset `0x2600`. The 7z-AES key derivation, header CRC check and BCJ + LZMA2 unpack are described in the writeup.
- The two downloads were saved as `Box-1234 (1).7z` and `photooflock (1).zip`; they are stored here under the names in the brief, with unchanged contents.
- The photo's EXIF had no capture time. The timestamp came from the ZIP entry's modification time.

---

[← Back to Forensics](../README.md) · [All writeups](../../README.md)
