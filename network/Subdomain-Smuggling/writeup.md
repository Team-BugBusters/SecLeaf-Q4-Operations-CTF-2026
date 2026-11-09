# Subdomain Smuggling – full writeup

[← Back to Network](../README.md) · [Challenge overview](README.md)

**Category:** Network · **Points:** 100 · **Flag:** `SecLeaf{D474_3xf1l_DN5}`

**Author:** [Rutwik](https://github.com/Rutwik-712) · **Team:** Bug Busters

## TL;DR

1. No big transfers and no POSTs means the data left through a protocol nobody blocks: DNS.
2. Of 39 DNS queries, four from `192.168.1.20` had encoded leftmost labels and the same suffix, `evil.com`.
3. Strip `.evil.com`, keep the labels' exact case, and join them in frame order (167, 293, 395, 502).
4. Base64-decode the joined string: `SecLeaf{D474_3xf1l_DN5}`.

## The challenge

We were given `suspicious_activity.pcap`, a capture of one compromised workstation. The brief rules things out before it rules anything in: the attacker "blend[ed] their activity with normal web browsing", the firewall saw "no large file transfers or suspicious HTTP POST requests", and they "abused a core network protocol to slowly leak the data".

The title finishes the thought. *Subdomain smuggling* means the cargo is hidden in subdomains, which only exist in DNS names. So instead of looking for a big upload, we read the DNS question names as data.

## Step 1 – Size up the capture

| Measure | Value |
| --- | ---: |
| Packets | 1,038 |
| TCP | 960 |
| DNS over UDP | 78 |
| DNS queries | 39 |
| DNS responses | 39 |

The TCP is the "normal web browsing" cover. The DNS traffic is small, which fits "slowly leak".

## Step 2 – Look at requests only

Filter:

```text
dns.flags.response == 0
```

A DNS response repeats the question it answers, so every name appears twice in the capture. Filtering to requests (QR bit = 0) gives one copy of each name and avoids doubling fragments during reassembly.

Most requests were for well-known sites: `google.com`, `github.com`, `microsoft.com`, `ubuntu.com`, `cloudflare.com`. Four were different: an encoded-looking label on the left and the suffix `evil.com`. All four were `A` queries from `192.168.1.20` to the resolver `8.8.8.8`.

## Step 3 – Pull out the suspicious queries

Filter:

```text
dns.flags.response == 0 && dns.qry.name contains "evil.com"
```

| Frame | Query name |
| ---: | --- |
| 167 | `U2VjTGVhZn.evil.com` |
| 293 | `tENDc0XzN4.evil.com` |
| 395 | `ZjFsX0RONX.evil.com` |
| 502 | `0=.evil.com` |

The four requests span 2.399395 s to 6.912527 s from the start of the capture.

A note on addresses: `8.8.8.8` is a public resolver, not the attacker. The resolver forwards each question to the authoritative server for `evil.com`, which in a DNS exfiltration setup is run by the attacker. The data is already in the question name, so the attacker receives it just by logging the lookups.

## Step 4 – Reassemble the payload

Drop `.evil.com` and take the labels in increasing frame order:

```text
U2VjTGVhZn
tENDc0XzN4
ZjFsX0RONX
0=
```

Three details matter here:

- **No sequence numbers**, so capture order is the only ordering available. We did not sort alphabetically and did not use the responses.
- **Case is data.** Base64 is case-sensitive (`a` and `A` are different 6-bit values). DNS itself is case-insensitive, so a tool that lower-cases names would silently corrupt the payload. We kept the labels exactly as captured.
- **Join first, then decode.** The labels are 10, 10, 10 and 2 characters long, which do not fall on Base64's 4-character group boundaries. Decoding each label separately would fail or give garbage; the string only becomes valid once it is whole.

Joined:

```text
U2VjTGVhZntENDc0XzN4ZjFsX0RONX0=
```

32 characters, a multiple of 4, ending in one `=` of padding: a well-formed Base64 string.

## Step 5 – Decode

```bash
echo 'U2VjTGVhZntENDc0XzN4ZjFsX0RONX0=' | base64 -d
```

```text
SecLeaf{D474_3xf1l_DN5}
```

23 bytes, in the `SecLeaf{...}` format. In leetspeak: "data exfil DNS".

## Flag

```text
SecLeaf{D474_3xf1l_DN5}
```

## Why this is the right answer

Four independent facts line up:

- **Common suffix:** all four labels sit under `evil.com`; no ordinary query does.
- **Common source:** all four come from the workstation `192.168.1.20`.
- **Order:** frames 167 → 293 → 395 → 502 put the padded fragment (`0=`) last, which is the only place Base64 padding can be.
- **Valid decode:** the joined string is well-formed Base64 and decodes to a correctly formatted flag that describes the technique.

What the capture does **not** show: the brief speaks of a "confidential file", but these four queries carry only the 23-byte payload above. There is no separate filename and no larger document in the DNS traffic. The flag is what was actually smuggled.

## What we learned

- **Protocol fields can be payload.** A DNS query name is attacker-controlled text that leaves the network by design.
- **Keep queries and responses apart.** Counting both doubles every fragment and breaks reassembly.
- **Order and case are part of the data.** Use capture order when there is no sequence number, and never normalise case on Base64.
- **The resolver is not the culprit.** The destination IP of a DNS packet is usually a resolver; the real receiver is the authoritative server for the suffix.

## Reproduce

```bash
cd solve
python3 solve.py                                   # uses the four names quoted above
python3 solve.py /path/to/suspicious_activity.pcap   # also carves them from the capture
```

Full solver: [`solve/solve.py`](solve/solve.py)

---

[← Back to Network](../README.md) · [Challenge overview](README.md)
