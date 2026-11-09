# Signal & Noise – full writeup

[← Back to Forensics](../README.md) · [Challenge overview](README.md)

**Category:** Forensics · **Points:** 300 · **Flag:** `FLOWTRIQ{decoy_icmp_pivot_172.16.80.99}`

**Author:** [Vaidik](https://github.com/Vaidik-Makhasana) · **Team:** Bug Busters

## TL;DR

1. The capture holds three apparent DDoS vectors against `10.0.88.10`: an ICMP echo flood, a TCP SYN flood on port 443, and DNS `ANY` amplification.
2. The ICMP flood is the loudest (800 packets, 50 sources), which is exactly what a decoy should be.
3. One address, `172.16.80.99`, appears among the TCP SYN sources **and** is the only host sending the DNS `ANY` queries. That is the pivot.
4. The ICMP flood is the one vector the pivot never touches, so ICMP is the decoy: `FLOWTRIQ{decoy_icmp_pivot_172.16.80.99}`.

## The challenge

We were given `signal-and-noise.pcap`, a two-minute capture (119.4 s) from an infrastructure team under a multi-vector DDoS. The brief asks for two things:

- the **decoy**: the vector that "looks hostile but is not the real threat";
- the **pivot**: "the single IP address that appears in one attack vector and then reappears orchestrating a second, different vector".

The title is the first hint. *Signal & Noise* says that some of the traffic is there to be loud, not to matter. So we did not rank vectors by volume. We looked at each protocol on its own and then asked which hosts connect them.

The capture contains three kinds of traffic of interest: ICMP, TCP and DNS.

## Step 1 – ICMP: the loud one

Filter: `icmp`

| Observation | Value |
| --- | --- |
| Packet type | ICMP Echo Request |
| Destination | `10.0.88.10` (the victim) |
| Packets | 800 |
| Distinct sources | 50, all in `10.99.0.0/24` |
| Active for | 117.5 s of the 119.4 s capture |

On its own this looks like a textbook ping flood, and by volume it is the most obvious thing in the file. That is precisely why we did not stop here: a decoy built to waste an analyst's time has to be the first thing they see. We noted it as *suspicious, not yet proven* and moved on.

## Step 2 – TCP: a SYN flood on 443

Filter:

```text
ip.dst == 10.0.88.10 && tcp.dstport == 443 && tcp.flags.syn == 1
```

| Observation | Value |
| --- | --- |
| Packets | 560 TCP SYNs |
| Destination | `10.0.88.10:443` (HTTPS) |
| Distinct sources | 44 |

Many hosts opening connections to the same service and never finishing the handshake is a SYN flood. That is a second, real-looking vector. On its own it does not tell us who is behind it, but its source list is the set we will cross-check against.

## Step 3 – DNS: one host asking for everything

Filter: `dns`

One internal address stood out: `172.16.80.99`. It sent DNS `ANY` queries, again and again, for the same name:

| Observation | Value |
| --- | --- |
| Query source | `172.16.80.99` |
| Query type | `ANY` |
| Name | `big-record.example.org` |
| Queries | 31 |
| Resolvers queried | `198.18.0.11`, `198.18.0.22`, `198.18.0.33`, `198.18.0.44` |
| DNS responses sent to the victim | 350, about 714 bytes each |

Why this matters: an `ANY` query asks a server for *every* record type it holds for a name. Pick a name with a deliberately large record set (`big-record`) and each small query buys a large answer. Spread the queries across several resolvers and the large answers converge on the target. That is the shape of DNS amplification, and here the large responses are landing on `10.0.88.10`.

So the DNS vector has an orchestrator, and it is a single, named host.

## Step 4 – Correlate: find the host that is in two vectors

`172.16.80.99` is also one of the 44 sources in the TCP SYN flood from Step 2. That gives us the brief's pivot exactly:

```text
172.16.80.99
  ├── appears in vector 1:  TCP SYN flood  -> 10.0.88.10:443
  └── orchestrates vector 2: DNS ANY queries for big-record.example.org
                             via 4 resolvers -> 350 large responses at 10.0.88.10
```

| Traffic | Observation | Linked to the pivot? |
| --- | --- | --- |
| ICMP | 800 Echo Requests from 50 sources | no |
| TCP | 560 SYNs to port 443 from 44 sources | **yes**, `172.16.80.99` is a source |
| DNS queries | 31 `ANY` queries | **yes**, all from `172.16.80.99` |
| DNS servers | four resolvers | queried by the pivot |
| DNS responses | 350 to the victim | the amplified result |

## Step 5 – Name the decoy

With the pivot in hand, the decoy falls out. The two vectors that matter are connected through one host; the ICMP flood is the vector the pivot never takes part in. It is high-volume and hostile-looking, and it is disconnected from the actual operator of the attack. That is the brief's definition of the decoy.

Filling the format `FLOWTRIQ{decoy_<vector>_pivot_<pivot_ip>}`:

```text
decoy = icmp
pivot = 172.16.80.99
```

## Flag

```text
FLOWTRIQ{decoy_icmp_pivot_172.16.80.99}
```

## Why this is the right answer

- **The pivot satisfies both halves of its definition.** It is a participant in one vector (a SYN source) and the sole sender in another (every `ANY` query). The brief promises a *single* such IP, and since `172.16.80.99` is the only `ANY` sender, no other host can link the DNS vector to a flood.
- **The decoy is defined relative to the pivot.** Once the TCP and DNS vectors are tied together by the same host, ICMP is the only vector left unlinked, despite being the loudest.
- **The example flag is a template, not a candidate.** `FLOWTRIQ{decoy_ntp_pivot_192.168.1.1}` comes from the brief to show the format. There is no NTP traffic in this capture, and `192.168.1.1` is not one of the hosts involved, so it cannot be the answer.
- **Format match.** Our answer follows the example's structure exactly: lowercase protocol name, then the dotted IPv4 address.

## What we learned

- **Volume is not importance.** The biggest flow in a capture can be the one placed there to soak up attention.
- **Split by protocol, then join by host.** Each vector looked plausible alone; the answer only appeared when we intersected their source lists.
- **`ANY` queries for a fat record are an amplification tell.** One host repeatedly asking several resolvers for every record of the same large name is orchestration, not browsing.
- **Let the definitions do the work.** The brief defined both "decoy" and "pivot"; finding the pivot first made the decoy a deduction rather than a guess.

## Reproduce

The core Wireshark filters:

```text
icmp
ip.dst == 10.0.88.10 && tcp.dstport == 443 && tcp.flags.syn == 1
dns.qry.type == 255
```

Or run the solver, which does the per-vector counts and the source-set intersection without Wireshark:

```bash
# copy signal-and-noise.pcap into ../attachments/ first
cd solve
python3 solve.py
```

Full solver: [`solve/solve.py`](solve/solve.py)

---

[← Back to Forensics](../README.md) · [Challenge overview](README.md)
