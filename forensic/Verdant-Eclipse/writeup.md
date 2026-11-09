# Verdant Eclipse – full writeup

[← Back to Forensics](../README.md) · [Challenge overview](README.md)

**Category:** Forensics · **Points:** 300 · **Flag:** `SecLeaf{multistage_network_forensics_mastery}`

**Author:** [Vaidik](https://github.com/Vaidik-Makhasana) · **Team:** Bug Busters

## TL;DR

1. Workstation `10.55.10.15` downloads `plant-monitor.sh`; the HTTP response header `X-Incident-Route: DNS-ALPHA` points at the DNS traffic.
2. Three DNS queries carry Base64 in their labels (`Zm9s`, `aWFn`, `ZQ==`). Joined and decoded, they give the XOR key `foliage`.
3. Workstation `10.55.10.27` sends ten numbered `leafsync` UDP chunks of hex to `198.51.100.77:6060`.
4. Join the chunks in order, XOR with `foliage`, Base64-decode: the flag.

## The challenge

> A researcher downloaded a monitoring script from an internal documentation server. After the download, multiple systems generated unusual DNS and UDP traffic.
>
> Analyze the supplied PCAP, reconstruct the incident timeline, identify the relevant evidence, and recover the flag.

The brief names three protocols in order – HTTP download, then DNS, then UDP – and says **multiple systems** are involved. That turned out to be the structure: one host leaks the key, a second leaks the data.

## Step 1 – Get an overview of the capture

`verdant_eclipse.pcap` is small:

| Protocol | Frames |
| --- | ---: |
| IPv4 | 82 |
| UDP | 76 |
| TCP | 6 |
| ARP | 4 |
| **Total** | **86** |

The hosts:

| System | IP |
| --- | --- |
| Research workstation 1 | `10.55.10.15` |
| Research workstation 2 | `10.55.10.27` |
| Documentation server | `10.55.10.80` |
| DNS resolver | `10.55.10.53` |
| External destination | `198.51.100.77` (UDP 6060 and 9000) |

Both workstations talk to the external address. That is the exfiltration target.

## Step 2 – The download, and the header that routes us

Filter: `ip.addr == 10.55.10.15 && ip.addr == 10.55.10.80 && tcp.port == 80`.

```http
GET /research/tools/plant-monitor.sh HTTP/1.1
Host: docs.verdant.internal
User-Agent: curl/8.5.0
```

The `200 OK` response is a two-line script:

```sh
#!/bin/sh
echo 'Plant monitor synchronization started'
```

The script does nothing interesting. The response *header* does:

```text
X-Incident-Route: DNS-ALPHA
```

That points at DNS, and at something labelled "alpha".

## Step 3 – DNS labels carry the key

Filter: `dns && ip.src == 10.55.10.15`. Three queries stand out:

```text
01.Zm9s.alpha.verdant-lab.local
02.aWFn.alpha.verdant-lab.local
03.ZQ==.alpha.verdant-lab.local
```

Each name has a sequence number, a payload, and the `alpha` zone from the header. All three got NXDOMAIN. Nobody expected these names to resolve; the query itself is the message. This is DNS tunnelling.

Join the payloads in sequence order:

```text
Zm9s + aWFn + ZQ== = Zm9saWFnZQ==   (Base64: the trailing == is padding)
```

```python
base64.b64decode("Zm9saWFnZQ==")   # b'foliage'
```

Key: **`foliage`**, which fits the plant theme.

## Step 4 – The UDP channel carries the ciphertext

Filter: `ip.dst == 198.51.100.77 && udp`. The payloads are `key=value` text, and the `channel` field splits them into three streams:

| Channel | Port | Packets |
| --- | ---: | ---: |
| `metrics` | 6060 | 18 |
| `leafsync` | 6060 | 10 |
| `backup` | 9000 | 10 |

`leafsync` is the one with numbered, hex-looking chunks, all from `10.55.10.27`:

```text
channel=leafsync;source=research-27;seq=01;chunk=335d3a033520;status=queued
```

| Seq | Chunk |
| ---: | --- |
| 01 | `335d3a033520` |
| 02 | `330e35021d15` |
| 03 | `03321e5f0d31` |
| 04 | `2f573c310b00` |
| 05 | `315352090227` |
| 06 | `081f020a1100` |
| 07 | `350150183d32` |
| 08 | `53150d3e2f1d` |
| 09 | `3d545e040a52` |
| 10 | `350905010050` |

Ten chunks × 6 bytes = 60 bytes of ciphertext.

## Step 5 – XOR, then Base64

We have a short text key and opaque bytes. Repeating-key XOR is the obvious first try:

```python
ct  = bytes.fromhex("".join(chunks))          # ordered by seq
key = b"foliage"
pt  = bytes(b ^ key[i % len(key)] for i, b in enumerate(ct))
# U2VjTGVhZnttdWx0aXN0YWdlX25ldHdvcmtfZm9yZW5zaWNzX21hc3Rlcnl9
```

All printable, all Base64 characters, and starts with `U2Vj` – the Base64 of `Sec`. One more decode:

```python
base64.b64decode(pt)   # b'SecLeaf{multistage_network_forensics_mastery}'
```

## Step 6 – Timeline

The brief asked for one. From the packet timestamps (UTC):

| Time | Event |
| --- | --- |
| 13:28:13–14 | Initial DNS activity |
| 13:28:14.875 | HTTP connection established |
| 13:28:15.015 | `plant-monitor.sh` requested |
| 13:28:15.057–15.149 | Script downloaded; `DNS-ALPHA` header returned |
| 13:28:15.884–16.220 | Three key-carrying DNS queries |
| 13:28:16.250–17.360 | `metrics` UDP traffic |
| 13:28:17.424–17.993 | Ten `leafsync` chunks |
| 13:28:18.053–18.730 | `backup` channel UDP traffic |

Download → key out over DNS → data out over UDP, all within six seconds.

## Flag

```text
SecLeaf{multistage_network_forensics_mastery}
```

## Why this is the right answer

- **Each layer checked itself.** The XOR output was clean Base64 starting with `U2Vj`; a wrong key or wrong chunk order would have produced junk.
- **The pieces link up.** The HTTP header names `DNS-ALPHA`, the DNS queries sit under `alpha.`, and the key they spell is used on the one sequenced UDP channel.
- **The order is given, not guessed.** DNS fragments carry `01`–`03` and UDP chunks carry `seq=01`–`10`.
- **Format.** `SecLeaf{…}` with no spaces. One line of our notes had stray spaces inside the braces; the decoded bytes have none.

## What we learned

- **Read headers, not just bodies.** The downloaded script was harmless; the custom response header was the clue.
- **NXDOMAIN on structured names suggests tunnelling.** Sequence numbers plus Base64-looking labels mean the query is the payload.
- **Split UDP traffic by application field.** Port alone mixed `metrics` and `leafsync`; the `channel=` field separated signal from noise.
- **Check each decode for a recognisable prefix.** `U2Vj` is `Sec` in Base64, so we knew the XOR was right before the last decode.

## Reproduce

```bash
cd solve
python3 solve.py
```

Full solver: [`solve/solve.py`](solve/solve.py). Inputs are embedded, and the script re-checks them against `attachments/verdant_eclipse.pcap` when it is present. The Wireshark filters above reproduce the extraction by hand.

---

[← Back to Forensics](../README.md) · [Challenge overview](README.md)
