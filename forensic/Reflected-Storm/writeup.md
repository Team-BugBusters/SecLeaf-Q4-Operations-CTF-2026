# Reflected Storm – full writeup

[← Back to Forensics](../README.md) · [Challenge overview](README.md)

**Category:** Forensics · **Points:** 100 · **Flag:** `FLOWTRIQ{10.0.55.200_5_reflectors}`

**Author:** [Vaidik](https://github.com/Vaidik-Makhasana) · **Team:** Bug Busters

## TL;DR

1. The capture carries a lot of UDP, and one host, `10.0.55.200`, receives 600 UDP packets, all from source port 53.
2. The small queries (~75 bytes) leave "from" the victim; the large answers (~1,014 bytes) come back to it. Small request, big reply, wrong recipient: DNS reflection with amplification.
3. Grouping the 600 responses by source IP gives exactly five reflectors.
4. Flag: `FLOWTRIQ{10.0.55.200_5_reflectors}`.

## The challenge

We were given `reflected-storm.pcap`. The brief describes a server whose bandwidth "spiked without explanation" and asks for two numbers: the **victim** "being hammered by amplified traffic" and **how many reflectors** the attacker abused.

Both hint words point at the same attack class. *Reflected* means the traffic reaches the victim via third-party servers, not directly from the attacker. *Amplified* means each reflected packet is larger than what triggered it. So we were looking for one destination receiving many large responses from several different servers.

## Step 1 – Find where the UDP is going

Filter: `udp`

The capture carries a lot of UDP, and much of it goes to a single destination. A sudden wall of UDP at one host is the signature of either a plain UDP flood or a reflection attack; the next steps tell the two apart.

## Step 2 – Identify the victim

Grouping UDP packets by destination, one address dominated:

```text
victim: 10.0.55.200
```

Filter:

```text
ip.dst == 10.0.55.200 && udp
```

All 600 UDP packets arriving at `10.0.55.200` have **source port 53**. Port 53 is DNS, so these are DNS *responses*. Hundreds of DNS answers converging on one server is the first sign that it is being sent replies it did not genuinely ask for.

## Step 3 – Prove amplification from the packet sizes

| Direction | Approximate size |
| --- | --- |
| Outgoing UDP query (source address = the victim) | ~75 bytes |
| Incoming UDP response to the victim | ~1,014 bytes |

Why this matters: in a reflection attack the attacker sends small queries to open servers with the **source address spoofed to the victim's**. The servers answer the address they see, so the replies land on the victim. When the reply is much larger than the query (here roughly 1,014 / 75 ≈ 13.5 times), the attacker's bandwidth is multiplied. That is the "amplified traffic" in the brief, and it is also what separates this from a single-host UDP flood: the bytes are coming from many legitimate-looking servers, not from the attacker.

## Step 4 – Count the reflectors

The reflectors are simply the distinct sources of those responses:

```text
ip.dst == 10.0.55.200 && udp.srcport == 53
```

| Reflector IP | Packets to the victim |
| --- | ---: |
| `198.51.100.22` | 133 |
| `203.0.113.5` | 120 |
| `192.0.2.17` | 119 |
| `198.51.100.10` | 118 |
| `203.0.113.88` | 110 |
| **Total** | **600** |

Five sources, and their counts add up to exactly the 600 packets the victim received. No port-53 traffic to the victim is left unaccounted for.

## Summary of findings

| Parameter | Finding |
| --- | --- |
| Victim IP | `10.0.55.200` |
| Attack protocol | UDP |
| Service abused | DNS |
| Source port of incoming traffic | 53 |
| Incoming packets | 600 |
| Reflectors | 5 |
| Request size | ~75 bytes |
| Response size | ~1,014 bytes |

## Flag

```text
FLOWTRIQ{10.0.55.200_5_reflectors}
```

## Why this is the right answer

- **Victim:** `10.0.55.200` is the destination of all the port-53 traffic and the address the small queries claim to come from. That pairing is what reflection looks like.
- **Count:** the five reflectors' packet counts sum to 600, the total the victim received. A missing or extra reflector would break that sum.
- **Amplification confirmed:** the ~13.5x size ratio matches the brief's "amplified traffic".
- **The example flag is a template.** `FLOWTRIQ{192.168.1.1_3_reflectors}` only illustrates the format; the victim here is `10.0.55.200`, not `192.168.1.1`, and there are five reflectors, not three.

## What we learned

- **In reflection, look at who receives, not who sends.** The attacker's address never appears; the victim shows up as both the spoofed query source and the response destination.
- **Packet size is evidence.** Comparing request and response sizes is what turns "lots of DNS" into "amplification".
- **Make the counts reconcile.** Per-source counts that add up to the total are a quick proof that the reflector list is complete.
- **Combine fields.** Destination IP, source port, source IP and size together tell the story; any one of them alone is ambiguous.

## Reproduce

Wireshark filters used:

```text
udp
ip.dst == 10.0.55.200 && udp
ip.dst == 10.0.55.200 && udp.srcport == 53
```

Or run the solver, which picks the victim, lists the reflectors with their counts and prints the size ratio:

```bash
# copy reflected-storm.pcap into ../attachments/ first
cd solve
python3 solve.py
```

Full solver: [`solve/solve.py`](solve/solve.py)

---

[← Back to Forensics](../README.md) · [Challenge overview](README.md)
