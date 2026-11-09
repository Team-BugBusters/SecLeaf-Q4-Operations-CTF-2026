# SecLeaf CTF 2026 – Bug Busters Writeups

![SecLeaf_CTF](https://img.shields.io/badge/SecLeaf_CTF-2026-101518?style=flat-square) ![Team](https://img.shields.io/badge/Team-Bug_Busters-B4441F?style=flat-square) ![Missions](https://img.shields.io/badge/Missions-37-2F5D3A?style=flat-square)
![Writeups](https://img.shields.io/badge/Writeups-33-1F5F73?style=flat-square) ![Points](https://img.shields.io/badge/Points-7%2C405-4B4E8C?style=flat-square)

Field notes from **Team Bug Busters** at **SecLeaf CTF 2026** (`play.secleaf.xyz`), 31 October – 1 November 2026.

This repository is organised by category, then by challenge. Every challenge folder has a README (brief, flag, the key idea in one line) and a full writeup that explains *why* each step works, not just which tool was clicked. Where a solve needed real computation, a solver is included.

The goal: make each solve readable in five minutes and reproducible in ten.

## At a glance

| | |
| --- | ---: |
| Completed missions | **37** |
| Challenges with published writeups | **33** |
| Points from written-up challenges | **7,405** |
| Other completed missions | Sanity Check (1) · FEEDBACK (1) · The Place I Remember (0) · The Classified Dossier (0) |
| Categories | **9** |
| Solvers that print the flag | **25** |

## Team

| Member | GitHub | Writeups | Challenges |
| --- | --- | ---: | --- |
| Rutwik | [@Rutwik-712](https://github.com/Rutwik-712) | 17 | DevOps Flaw · Eightfold Funeral: Epitaph · Encoded Transmission · Fallen Leaf · Fault Atlas · Hensel Garden · Layers · Ledger · Night Shift Keying · Nonce Nursery · NullVector Ransomware · Riddled Code · Shadow Chronometry · Signing Shadow: Redshift · Subdomain Smuggling · TL Priv Escl #1 · Tomb Translation |
| Vaidik | [@Vaidik-Makhasana](https://github.com/Vaidik-Makhasana) | 11 | At Their House · Blackout Protocol · Blackroot Archive · Dead Letter Office · LeafSync · Maintainer of None · Null Choir · Reflected Storm · Signal & Noise · Sugar Glass · Verdant Eclipse |
| Shreya | [@doodleP](https://github.com/doodleP) | 3 | Third-Order Forest · Trip to Foreign · Water Hammer |
| Ria | [@ri-Ria-ri](https://github.com/ri-Ria-ri) | 2 | Final Tools · Slow Leak |

Sanity Check (Vaidik) is a completed mission without a writeup.

## All writeups

### [Cryptography](crypto/) – 9 writeups, 2,725 pts

| Challenge | Points | Solved by | Writeup |
| --- | ---: | --- | --- |
| [Fault Atlas](crypto/Fault-Atlas/) | 500 | [Rutwik](https://github.com/Rutwik-712) | [read](crypto/Fault-Atlas/writeup.md) |
| [Third-Order Forest](crypto/Third-Order-Forest/) | 500 | [Shreya](https://github.com/doodleP) | [read](crypto/Third-Order-Forest/writeup.md) |
| [Eightfold Funeral: Epitaph](crypto/Eightfold-Funeral-Epitaph/) | 500 | [Rutwik](https://github.com/Rutwik-712) | [read](crypto/Eightfold-Funeral-Epitaph/writeup.md) |
| [Signing Shadow: Redshift](crypto/Signing-Shadow-Redshift/) | 500 | [Rutwik](https://github.com/Rutwik-712) | [read](crypto/Signing-Shadow-Redshift/writeup.md) |
| [Nonce Nursery](crypto/Nonce-Nursery/) | 250 | [Rutwik](https://github.com/Rutwik-712) | [read](crypto/Nonce-Nursery/writeup.md) |
| [Encoded Transmission](crypto/Encoded-Transmission/) | 175 | [Rutwik](https://github.com/Rutwik-712) | [read](crypto/Encoded-Transmission/writeup.md) |
| [Hensel Garden](crypto/Hensel-Garden/) | 100 | [Rutwik](https://github.com/Rutwik-712) | [read](crypto/Hensel-Garden/writeup.md) |
| [Final Tools](crypto/Final-Tools/) | 100 | [Ria](https://github.com/ri-Ria-ri) | [read](crypto/Final-Tools/writeup.md) |
| [Tomb Translation](crypto/Tomb-Translation/) | 100 | [Rutwik](https://github.com/Rutwik-712) | [read](crypto/Tomb-Translation/writeup.md) |

### [Forensics](forensic/) – 8 writeups, 1,450 pts

| Challenge | Points | Solved by | Writeup |
| --- | ---: | --- | --- |
| [Verdant Eclipse](forensic/Verdant-Eclipse/) | 300 | [Vaidik](https://github.com/Vaidik-Makhasana) | [read](forensic/Verdant-Eclipse/writeup.md) |
| [Signal & Noise](forensic/Signal-and-Noise/) | 300 | [Vaidik](https://github.com/Vaidik-Makhasana) | [read](forensic/Signal-and-Noise/writeup.md) |
| [Blackroot Archive](forensic/Blackroot-Archive/) | 200 | [Vaidik](https://github.com/Vaidik-Makhasana) | [read](forensic/Blackroot-Archive/writeup.md) |
| [At Their House](forensic/At-Their-House/) | 150 | [Vaidik](https://github.com/Vaidik-Makhasana) | [read](forensic/At-Their-House/writeup.md) |
| [DevOps Flaw](forensic/DevOps-Flaw/) | 150 | [Rutwik](https://github.com/Rutwik-712) | [read](forensic/DevOps-Flaw/writeup.md) |
| [LeafSync](forensic/LeafSync/) | 150 | [Vaidik](https://github.com/Vaidik-Makhasana) | [read](forensic/LeafSync/writeup.md) |
| [Fallen Leaf](forensic/Fallen-Leaf/) | 100 | [Rutwik](https://github.com/Rutwik-712) | [read](forensic/Fallen-Leaf/writeup.md) |
| [Reflected Storm](forensic/Reflected-Storm/) | 100 | [Vaidik](https://github.com/Vaidik-Makhasana) | [read](forensic/Reflected-Storm/writeup.md) |

### [Reverse Engineering](rev/) – 5 writeups, 1,850 pts

| Challenge | Points | Solved by | Writeup |
| --- | ---: | --- | --- |
| [Maintainer of None](rev/Maintainer-of-None/) | 500 | [Vaidik](https://github.com/Vaidik-Makhasana) | [read](rev/Maintainer-of-None/writeup.md) |
| [Blackout Protocol](rev/Blackout-Protocol/) | 500 | [Vaidik](https://github.com/Vaidik-Makhasana) | [read](rev/Blackout-Protocol/writeup.md) |
| [Null Choir](rev/Null-Choir/) | 500 | [Vaidik](https://github.com/Vaidik-Makhasana) | [read](rev/Null-Choir/writeup.md) |
| [Dead Letter Office](rev/Dead-Letter-Office/) | 250 | [Vaidik](https://github.com/Vaidik-Makhasana) | [read](rev/Dead-Letter-Office/writeup.md) |
| [Sugar Glass](rev/Sugar-Glass/) | 100 | [Vaidik](https://github.com/Vaidik-Makhasana) | [read](rev/Sugar-Glass/writeup.md) |

### [Web](web/) – 3 writeups, 250 pts

| Challenge | Points | Solved by | Writeup |
| --- | ---: | --- | --- |
| [Ledger](web/Ledger/) | 100 | [Rutwik](https://github.com/Rutwik-712) | [read](web/Ledger/writeup.md) |
| [Water Hammer](web/Water-Hammer/) | 100 | [Shreya](https://github.com/doodleP) | [read](web/Water-Hammer/writeup.md) |
| [Slow Leak](web/Slow-Leak/) | 50 | [Ria](https://github.com/ri-Ria-ri) | [read](web/Slow-Leak/writeup.md) |

### [OSINT](osint/) – 3 writeups, 500 pts

| Challenge | Points | Solved by | Writeup |
| --- | ---: | --- | --- |
| [Riddled Code](osint/Riddled-Code/) | 200 | [Rutwik](https://github.com/Rutwik-712) | [read](osint/Riddled-Code/writeup.md) |
| [Trip to Foreign](osint/Trip-to-Foreign/) | 200 | [Shreya](https://github.com/doodleP) | [read](osint/Trip-to-Foreign/writeup.md) |
| [Shadow Chronometry](osint/Shadow-Chronometry/) | 100 | [Rutwik](https://github.com/Rutwik-712) | [read](osint/Shadow-Chronometry/writeup.md) |

### [Miscellaneous](misc/) – 2 writeups, 300 pts

| Challenge | Points | Solved by | Writeup |
| --- | ---: | --- | --- |
| [TL Priv Escl #1](misc/TL-Priv-Escl-1/) | 150 | [Rutwik](https://github.com/Rutwik-712) | [read](misc/TL-Priv-Escl-1/writeup.md) |
| [Layers](misc/Layers/) | 150 | [Rutwik](https://github.com/Rutwik-712) | [read](misc/Layers/writeup.md) |

### [Hardware](hardware/) – 1 writeup, 80 pts

| Challenge | Points | Solved by | Writeup |
| --- | ---: | --- | --- |
| [Night Shift Keying](hardware/Night-Shift-Keying/) | 80 | [Rutwik](https://github.com/Rutwik-712) | [read](hardware/Night-Shift-Keying/writeup.md) |

### [Network](network/) – 1 writeup, 100 pts

| Challenge | Points | Solved by | Writeup |
| --- | ---: | --- | --- |
| [Subdomain Smuggling](network/Subdomain-Smuggling/) | 100 | [Rutwik](https://github.com/Rutwik-712) | [read](network/Subdomain-Smuggling/writeup.md) |

### [Quantum Security](quantum/) – 1 writeup, 150 pts

| Challenge | Points | Solved by | Writeup |
| --- | ---: | --- | --- |
| [NullVector Ransomware](quantum/NullVector-Ransomware/) | 150 | [Rutwik](https://github.com/Rutwik-712) | [read](quantum/NullVector-Ransomware/writeup.md) |

## Repository map

```text
crypto/     9 writeups  Fault Atlas · Third-Order Forest · Eightfold Funeral: Epitaph · Signing Shadow: Redshift · Nonce Nursery · Encoded Transmission · Hensel Garden · Final Tools · Tomb Translation
forensic/   8 writeups  Verdant Eclipse · Signal & Noise · Blackroot Archive · At Their House · DevOps Flaw · LeafSync · Fallen Leaf · Reflected Storm
rev/        5 writeups  Maintainer of None · Blackout Protocol · Null Choir · Dead Letter Office · Sugar Glass
web/        3 writeups  Ledger · Water Hammer · Slow Leak
osint/      3 writeups  Riddled Code · Trip to Foreign · Shadow Chronometry
misc/       2 writeups  TL Priv Escl #1 · Layers
hardware/   1 writeup   Night Shift Keying
network/    1 writeup   Subdomain Smuggling
quantum/    1 writeup   NullVector Ransomware
```

## Reproducing the solves

Every script marked ✓ was run against the archived challenge files and prints the exact flag. Encoded Transmission and Riddled Code have no files; their scripts run on the values in the brief. Maintainer of None needs one file that was not kept (see its README). Web exploits take the (now offline) target URL as an argument. The `verify.sh` scripts feed the flag to the challenge's own Linux binary, inside Docker when the host isn't Linux x86-64.

| Challenge | Solver | Status | Dependencies |
| --- | --- | --- | --- |
| Fault Atlas | [`solve.py`](crypto/Fault-Atlas/solve/solve.py) | ✓ prints the flag | cryptography |
| Third-Order Forest | [`solve.py`](crypto/Third-Order-Forest/solve/solve.py) | ✓ prints the flag | numpy, cryptography |
| Eightfold Funeral: Epitaph | [`solve.py`](crypto/Eightfold-Funeral-Epitaph/solve/solve.py) | ✓ prints the flag | cryptography |
| Signing Shadow: Redshift | [`solve.py`](crypto/Signing-Shadow-Redshift/solve/solve.py) | ✓ prints the flag | cryptography |
| Nonce Nursery | [`solve.py`](crypto/Nonce-Nursery/solve/solve.py) | ✓ prints the flag | cryptography |
| Encoded Transmission | [`solve.py`](crypto/Encoded-Transmission/solve/solve.py) | ✓ prints the flag | stdlib |
| Hensel Garden | [`solve.py`](crypto/Hensel-Garden/solve/solve.py) | ✓ prints the flag | cryptography |
| Final Tools | [`solve.py`](crypto/Final-Tools/solve/solve.py) | ✓ prints the flag | 7z |
| Tomb Translation | [`solve.py`](crypto/Tomb-Translation/solve/solve.py) | ✓ prints the flag | stdlib |
| Verdant Eclipse | [`solve.py`](forensic/Verdant-Eclipse/solve/solve.py) | ✓ prints the flag | stdlib |
| Signal & Noise | [`solve.py`](forensic/Signal-and-Noise/solve/solve.py) | ✓ prints the flag | stdlib |
| Blackroot Archive | [`solve.py`](forensic/Blackroot-Archive/solve/solve.py) | ✓ prints the flag | stdlib |
| At Their House | [`solve.py`](forensic/At-Their-House/solve/solve.py) | ✓ prints the flag | pycryptodome |
| DevOps Flaw | [`solve.py`](forensic/DevOps-Flaw/solve/solve.py) | ✓ prints the flag | stdlib |
| LeafSync | [`solve.py`](forensic/LeafSync/solve/solve.py) | ✓ prints the flag | stdlib |
| Fallen Leaf | [`solve.py`](forensic/Fallen-Leaf/solve/solve.py) | ✓ prints the flag | cryptography, debugfs |
| Reflected Storm | [`solve.py`](forensic/Reflected-Storm/solve/solve.py) | ✓ prints the flag | stdlib |
| Maintainer of None | [`solve.py`](rev/Maintainer-of-None/solve/solve.py) | needs our solve dossier + Linux | stdlib |
| Blackout Protocol | [`verify.sh`](rev/Blackout-Protocol/solve/verify.sh) | ✓ original binary accepts the flag | Docker or Linux x86-64 |
| Null Choir | [`verify.sh`](rev/Null-Choir/solve/verify.sh) · [`gdb_extract.py`](rev/Null-Choir/solve/gdb_extract.py) | ✓ original binary accepts the flag | Docker or Linux x86-64 |
| Dead Letter Office | [`solve.py`](rev/Dead-Letter-Office/solve/solve.py) · [`verify.sh`](rev/Dead-Letter-Office/solve/verify.sh) | ✓ prints the flag | stdlib |
| Sugar Glass | [`solve.py`](rev/Sugar-Glass/solve/solve.py) · [`verify.sh`](rev/Sugar-Glass/solve/verify.sh) | ✓ prints the flag; original binary accepts it | stdlib, Docker or Linux x86-64 for `verify.sh` |
| Ledger | [`exploit.py`](web/Ledger/solve/exploit.py) | live target (offline) | stdlib |
| Water Hammer | [`exploit.py`](web/Water-Hammer/solve/exploit.py) | live target (offline) | stdlib |
| Slow Leak | [`exploit.py`](web/Slow-Leak/solve/exploit.py) | live target (offline) | stdlib |
| Riddled Code | [`solve.py`](osint/Riddled-Code/solve/solve.py) | ✓ prints the flag | stdlib |
| Shadow Chronometry | [`solve.py`](osint/Shadow-Chronometry/solve/solve.py) | ✓ prints the flag | stdlib |
| Layers | [`solve.py`](misc/Layers/solve/solve.py) | ✓ prints the flag | unar or 7z |
| Night Shift Keying | [`solve.py`](hardware/Night-Shift-Keying/solve/solve.py) | ✓ prints the flag | stdlib |
| Subdomain Smuggling | [`solve.py`](network/Subdomain-Smuggling/solve/solve.py) | ✓ prints the flag | stdlib |
| NullVector Ransomware | [`solve.py`](quantum/NullVector-Ransomware/solve/solve.py) | ✓ prints the flag | stdlib |

Run any solver from its own `solve/` directory: `cd <category>/<Challenge>/solve && python3 solve.py`.

## Scope and attribution

- **Credit:** each challenge README and writeup names the teammate who solved it and links their GitHub profile (see the Team table). Commits in this repository are made by the same people.
- **Flags are exact.** Prefixes vary by challenge: `SecLeaf{...}`, `CRY{...}`, `FLOWTRIQ{...}`, and one unwrapped value (Layers). All are kept as accepted.
- **Challenge authors:** several challenges credit `5h1kh4r`; their READMEs say so.
- **Attachments:** challenge files are kept byte-for-byte in each `attachments/` folder with a `SHA256SUMS` that was re-checked. Live web challenges, Trip to Foreign, TL Priv Escl #1, Riddled Code and Encoded Transmission had no files to archive. The one missing input is Maintainer of None's accepted dossier, described in its README.
- **Decoys:** several challenges planted fake flags (Fallen Leaf, Signal & Noise, Reflected Storm, Maintainer of None, Signing Shadow: Redshift). Each writeup explains how the real one was told apart.
- **Names:** folders use the scoreboard names. Where the team's notes used another name ("Leafdisk" for Fallen Leaf, "DevOps Flow" for DevOps Flaw), the README notes it.

## Adding a writeup

Use the same `README.md` + `writeup.md` + `attachments/` + `solve/` layout and add the row to the category README. See [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`NOTICE.md`](NOTICE.md).

---

Team Bug Busters · Event: SecLeaf CTF 2026 (`play.secleaf.xyz`)
