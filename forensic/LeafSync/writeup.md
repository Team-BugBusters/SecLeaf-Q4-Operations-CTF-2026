# LeafSync – full writeup

[← Back to Forensics](../README.md) · [Challenge overview](README.md)

**Category:** Forensics · **Points:** 150 · **Flag:** `SecLeaf{dns_labels_hide_the_truth}`

**Author:** [Vaidik](https://github.com/Vaidik-Makhasana) · **Team:** Bug Busters

## TL;DR

1. Among ordinary DNS traffic, workstation `10.20.30.15` sent queries to `10.20.30.53` for odd names under `sync-cache.training.local`.
2. Each name has the form `<NN>.<chunk>.sync-cache.training.local`: a two-digit sequence number and a Base64 fragment.
3. Sort by sequence number (`01` to `06`), strip the suffix, join the chunks.
4. Base64-decode: `SecLeaf{dns_labels_hide_the_truth}`.

## The challenge

We were given `leafsync.pcap`. The brief says a workstation fetched a "synchronization helper" and then began "sending repeated DNS queries to an unfamiliar domain", and asks what data was **exfiltrated**.

That sentence already names the channel. DNS is allowed out of almost every network, and the name in a query is attacker-controlled text. A helper that keeps asking about one strange domain is the classic setup for DNS tunnelling: the data is in the question, not the answer.

## Step 1 – Isolate DNS

Filter: `dns`

Most queries looked like normal resolution. A handful did not: their leftmost labels were not hostnames anyone would type.

## Step 2 – Spot the pattern in the suspicious names

All the odd queries came from the workstation `10.20.30.15`, went to the resolver `10.20.30.53`, and ended in the same domain, `sync-cache.training.local`:

```text
01.U2VjTGVh.sync-cache.training.local
02.ZntkbnNf.sync-cache.training.local
03.bGFiZWxz.sync-cache.training.local
04.X2hpZGVf.sync-cache.training.local
05.dGhlX3Ry.sync-cache.training.local
06.dXRofQ==.sync-cache.training.local
```

Two things stand out:

- **A numeric first label, `01` to `06`.** That is a sequence number. An exfiltration tool that splits data into pieces has to tell the receiver how to put them back together, because DNS queries can arrive out of order or be retried.
- **A second label made of `A-Z a-z 0-9` with `==` on the last one.** That is the Base64 alphabet, and `==` is Base64 padding, which only ever appears at the very end of an encoded string. Its position on chunk `06` confirms that `06` is the last piece.

## Step 3 – Reassemble

Strip the sequence number and the domain suffix, then order by sequence:

| Seq | Chunk |
| ---: | --- |
| 01 | `U2VjTGVh` |
| 02 | `ZntkbnNf` |
| 03 | `bGFiZWxz` |
| 04 | `X2hpZGVf` |
| 05 | `dGhlX3Ry` |
| 06 | `dXRofQ==` |

Joined with no separators:

```text
U2VjTGVhZntkbnNfbGFiZWxzX2hpZGVfdGhlX3RydXRofQ==
```

## Step 4 – Decode

```python
import base64
print(base64.b64decode(
    "U2VjTGVh" "ZntkbnNf" "bGFiZWxz" "X2hpZGVf" "dGhlX3Ry" "dXRofQ=="
).decode())
```

```text
SecLeaf{dns_labels_hide_the_truth}
```

No further layer: the exfiltrated data was the flag itself, Base64-encoded only so that it could travel as DNS label text.

## Flag

```text
SecLeaf{dns_labels_hide_the_truth}
```

## Why this is the right answer

- **The order is explicit, not inferred.** The sequence numbers are part of the data, and the padding sits on the last-numbered chunk, exactly where it must be.
- **The decode is clean.** Six 8-character chunks give a 48-character string that decodes without errors to printable ASCII in the `SecLeaf{...}` format.
- **The story fits the brief.** One workstation, one unfamiliar domain, repeated queries, and the output is data that was clearly not a hostname lookup.

## What we learned

- **DNS query names are a data channel.** Long, encoded-looking, or numbered subdomains under a single domain should be read as payload.
- **Look for the ordering key.** Exfiltration tools usually carry their own sequence numbers; sort by them rather than by arrival time.
- **Padding marks the end.** `=` / `==` in a Base64 fragment tells you which piece is last.
- **Identify the encoding before reaching for crypto.** Recognising Base64 meant no key or cipher was needed at all.

## Reproduce

```bash
cd solve
python3 solve.py                       # uses the six names quoted above
python3 solve.py /path/to/leafsync.pcap  # also carves them from the capture
```

Full solver: [`solve/solve.py`](solve/solve.py)

---

[← Back to Forensics](../README.md) · [Challenge overview](README.md)
