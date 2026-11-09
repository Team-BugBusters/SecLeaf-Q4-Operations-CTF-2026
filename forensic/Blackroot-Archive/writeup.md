# Blackroot Archive – full writeup

[← Back to Forensics](../README.md) · [Challenge overview](README.md)

**Category:** Forensics · **Points:** 200 · **Flag:** `SecLeaf{exported_objects_reveal_the_archive_key}`

**Author:** [Vaidik](https://github.com/Vaidik-Makhasana) · **Team:** Bug Busters

## TL;DR

1. An HTTP download of `ledger-sync.manifest` tells us the encoding (`base64`), where the key is (`mail:archive-notice`) and where the data is (`tcp/4711`).
2. The SMTP "archive notice" email contains `Recovery key: rootleaf`.
3. The TCP/4711 conversation with the external archive service `198.51.100.144` carries ten hex chunks.
4. Concatenate the hex, XOR it with the repeating key `rootleaf`, Base64-decode: `SecLeaf{exported_objects_reveal_the_archive_key}`.

## The challenge

We were given `blackroot_archive.pcap`. The brief names three events in order, and each one turned out to be a protocol in the capture:

| Brief | Protocol |
| --- | --- |
| "downloaded a ledger synchronization manifest from an internal documentation portal" | HTTP |
| "an internal archive notice was sent to operations" | SMTP |
| "unusual communication with an external archive service" | TCP on a custom port |

That ordering is the hint: no single stream holds the flag, so we would need all three.

The hosts we identified:

| IP address | Role |
| --- | --- |
| `10.88.12.15` | Finance workstation |
| `10.88.12.80` | Internal documentation server |
| `10.88.12.53` | DNS resolver |
| `10.88.12.22` | Operations workstation |
| `10.88.12.25` | Internal mail server |
| `198.51.100.144` | External archive service |

## Step 1 – HTTP: the manifest is a set of instructions

Filter: `http`

The finance workstation requested:

```text
GET /exports/ledger-sync.manifest
Host: docs.blackroot.internal
```

The response body, once decoded, read:

```text
artifact=ledger-sync-2026
encoding=base64
key_source=mail:archive-notice
next_service=tcp/4711
```

This is not the flag but a map of the rest of the challenge:

| Field | What it told us |
| --- | --- |
| `artifact=ledger-sync-2026` | the archive we are after |
| `encoding=base64` | the final layer is Base64 |
| `key_source=mail:archive-notice` | the key is in an email from `archive-notice` |
| `next_service=tcp/4711` | the data travels over TCP port 4711 |

## Step 2 – SMTP: the key

Filter: `smtp`

Following `key_source=mail:archive-notice`, we found the email:

```text
From: archive-notice@blackroot.internal
To:   operations@blackroot.internal

Archive route confirmed.
Recovery key: rootleaf
Use the key only with the ledger synchronization service.
```

The last line ties it back to the manifest: this key belongs to the ledger-sync data. Key: `rootleaf`.

## Step 3 – TCP/4711: the ciphertext

Filter: `tcp.port == 4711`

Following `next_service=tcp/4711` led to a conversation with the external archive service `198.51.100.144`. The same host also answers on ports 4700–4703 with short `HELLO service=… status=healthy` health checks; those are noise. Only port 4711 carries data, as ten `record=NN;blob=…;state=ready` lines followed by `commit=true`. The ten `blob` values, in record order, are:

```text
275d391e382237
0e28011b18092d
231011013d1836
2358102b021f18
3556331c2a5c25
180808370e1029
56440d2237002b
37251e0d220d54
28395606363d0d
5f
```

Nine chunks of 7 bytes plus one of 1 byte: 64 bytes. Read as text it is garbage, so it is encrypted. We had a key and nothing else to use it on, so the key goes here.

## Step 4 – Repeating-key XOR, then Base64

The simplest cipher that takes a short text key and a byte stream is **repeating-key XOR**: byte `i` of the data is XORed with byte `i mod len(key)` of the key.

```text
plain[i] = cipher[i] XOR key[i mod 8]      key = "rootleaf"
```

The test that this guess is right is the output: if the key is correct, the result should be the Base64 the manifest promised (only `A-Z a-z 0-9 + / =`). With the wrong key it would be random bytes.

```python
import base64

hex_chunks = ["275d391e382237", "0e28011b18092d", "231011013d1836",
              "2358102b021f18", "3556331c2a5c25", "180808370e1029",
              "56440d2237002b", "37251e0d220d54", "28395606363d0d", "5f"]
data = bytes.fromhex("".join(hex_chunks))
key = b"rootleaf"
xored = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
print(xored.decode())
print(base64.b64decode(xored).decode())
```

Output:

```text
U2VjTGVhZntleHBvcnRlZF9vYmplY3RzX3JldmVhbF90aGVfYXJjaGl2ZV9rZXl9
SecLeaf{exported_objects_reveal_the_archive_key}
```

The XOR output is clean Base64 (64 characters, a multiple of 4), and it starts `U2VjTGVh`, which is the Base64 of `SecLea`. The second line is the flag.

## Flag

```text
SecLeaf{exported_objects_reveal_the_archive_key}
```

## Why this is the right answer

- **Every step was directed, not guessed.** The manifest named the encoding, the key's location and the data's port; each one was found exactly where it pointed.
- **The XOR output validates the key.** A wrong key cannot produce 64 characters of valid Base64 that decodes to readable ASCII.
- **Format match.** The result is a well-formed `SecLeaf{...}` flag, and its wording ("exported objects reveal the archive key") describes the method: the key and manifest are objects exported from HTTP and SMTP.

## What we learned

- **Follow the breadcrumbs the data leaves.** A config/manifest file in a capture is often the challenge's own instruction sheet.
- **Multi-protocol challenges split key and ciphertext.** Here the key rode on SMTP and the data on a custom TCP port; neither alone was enough.
- **Use the expected plaintext as the oracle.** "The output should be Base64" is a cheap, decisive check that the XOR key is right.
- **Script the boring part.** Joining chunks, XORing and decoding in a few lines of Python avoids copy-paste errors across ten fragments.

## Reproduce

```bash
cd solve
python3 solve.py                      # uses the chunks and key quoted above
python3 solve.py /path/to/blackroot_archive.pcap   # also carves them from the capture
```

Full solver: [`solve/solve.py`](solve/solve.py)

---

[← Back to Forensics](../README.md) · [Challenge overview](README.md)
