# Forensics

Packet captures, disk images, deleted keys and timestamps that give the game away.

**Team result:** 8 solved · **Points:** 1,450 · **Published writeups:** 8

## Published writeups

| Challenge | Solved by | Points | Solved | Writeup |
| --- | --- | ---: | --- | --- |
| [Verdant Eclipse](Verdant-Eclipse/) | [Vaidik](https://github.com/Vaidik-Makhasana) | 300 | 1 Nov, 7:12 am | [read](Verdant-Eclipse/writeup.md) |
| [Signal & Noise](Signal-and-Noise/) | [Vaidik](https://github.com/Vaidik-Makhasana) | 300 | 31 Oct, 3:52 pm | [read](Signal-and-Noise/writeup.md) |
| [Blackroot Archive](Blackroot-Archive/) | [Vaidik](https://github.com/Vaidik-Makhasana) | 200 | 31 Oct, 3:31 pm | [read](Blackroot-Archive/writeup.md) |
| [At Their House](At-Their-House/) | [Vaidik](https://github.com/Vaidik-Makhasana) | 150 | 1 Nov, 8:00 am | [read](At-Their-House/writeup.md) |
| [DevOps Flaw](DevOps-Flaw/) | [Rutwik](https://github.com/Rutwik-712) | 150 | 1 Nov, 6:50 am | [read](DevOps-Flaw/writeup.md) |
| [LeafSync](LeafSync/) | [Vaidik](https://github.com/Vaidik-Makhasana) | 150 | 31 Oct, 3:19 pm | [read](LeafSync/writeup.md) |
| [Fallen Leaf](Fallen-Leaf/) | [Rutwik](https://github.com/Rutwik-712) | 100 | 1 Nov, 1:30 pm | [read](Fallen-Leaf/writeup.md) |
| [Reflected Storm](Reflected-Storm/) | [Vaidik](https://github.com/Vaidik-Makhasana) | 100 | 31 Oct, 3:39 pm | [read](Reflected-Storm/writeup.md) |

## Notes

- `Verdant Eclipse`: DNS query labels spell the XOR key "foliage"; ten numbered leafsync UDP chunks XOR + Base64 decode to the flag.
- `Signal & Noise`: The loud ICMP flood is the decoy; 172.16.80.99 is both a TCP SYN source and the only DNS ANY amplification sender, so it is the pivot.
- `Blackroot Archive`: HTTP manifest says how, SMTP gives key "rootleaf", TCP/4711 carries hex; repeating-key XOR then Base64.
- `At Their House`: The photo ZIP's timestamp gives the two PINs (220715, 100452); the second PIN replaces the middle AES layer's IV and keys the last layer, salts 7-2-5.
- `DevOps Flaw`: KEY_15_00f in .env.example is the two-byte XOR key 00 0f that decodes the value in the deploy log.
- `LeafSync`: DNS query names <NN>.<base64>.sync-cache.training.local carry numbered Base64 chunks; sort, join, decode.
- `Fallen Leaf`: The cleanup deleted the gzip'd key backups, but their inodes survived; the one whose key hashes to notes.txt decrypts harvest.enc, and the second half sits Base32-encoded in the user.leaf xattr.
- `Reflected Storm`: The victim gets large DNS answers it never asked for: 600 ~1 KB port-53 responses to 10.0.55.200 from exactly 5 reflectors.

---

[← All writeups](../README.md)
