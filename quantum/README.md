# Quantum Security

A ransomware recovery dressed in post-quantum clothing.

**Team result:** 1 solved · **Points:** 150 · **Published writeups:** 1

## Published writeups

| Challenge | Solved by | Points | Solved | Writeup |
| --- | --- | ---: | --- | --- |
| [NullVector Ransomware](NullVector-Ransomware/) | [Rutwik](https://github.com/Rutwik-712) | 150 | 31 Oct, 7:42 pm | [read](NullVector-Ransomware/writeup.md) |

## Notes

- `NullVector Ransomware`: Given p,q unwrap the AES key via RSA, but the body is still ROTL3 + XOR (13i+0x7a) mod 256, recovered from a known banner.

---

[← All writeups](../README.md)
