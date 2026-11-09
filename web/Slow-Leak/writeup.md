# Slow Leak – full writeup

[← Back to Web](../README.md) · [Challenge overview](README.md)

**Category:** Web · **Points:** 50 · **Flag:** `SecLeaf{h34d3r5_l34k_0n3_dr1p_4t_4_t1m3}`

**Author:** [Ria](https://github.com/ri-Ria-ri) · **Team:** Bug Busters

## TL;DR

1. The telemetry page looks the same on every refresh – two raw bodies diff to nothing, so the secret is not in the HTML.
2. Each HTTP response carries a custom `X-Drip` header with one character and `X-Drip-Serial: n/40` giving that character's position.
3. A signed `work_order` cookie tracks per-visitor progress and a shuffle seed, so the same cookie must be carried across requests to advance; a fresh client always restarts at drop 1.
4. Request the page ~200 times reusing the cookie, keep one char per serial until 40/40, then sort by serial and concatenate – that is the flag.

## The challenge

Fetching the page shows a pipe diagram, a live-readings panel (pressure, flow, a
"Drops lost on your ticket" counter), and an incident log written as repair-crew
notes. The name *Slow Leak* and the log are the brief, and the crew notes are
three precise instructions:

- *"It loses one drop every time somebody refreshes this display, and only this display."* → one piece of data per request to this endpoint.
- *"My first drop is the same as every other first drop. The front desk treats you as new unless you bring your work order back."* → the server tracks you by a cookie; without carrying it back you are treated as new and always get the same first piece.
- *"Drops arrive in no useful order, but each is stamped with a serial number. We need the complete set."* → the pieces are shuffled and must be reordered by an embedded index.

"Every display reads normal" is the misdirection: the visible page is a decoy.

## Step 1 – Confirm the body is a decoy

```bash
curl -s http://web.secleaf.xyz:8080/
```

Fetching twice and diffing the two raw bodies shows **no difference at all**.
If the secret changed per request it would have to show up somewhere in the
response – and it is not in the body, so it must be in the metadata around it:
the HTTP response headers.

## Step 2 – Find the leak in the headers

We re-fetched with headers shown and a cookie jar, so the "work order" cookie is
stored and sent back on the next request:

```bash
curl -i -c jar.txt -b jar.txt http://web.secleaf.xyz:8080/
```

Two headers stand out:

```http
X-Drip: S
X-Drip-Serial: 1/40
```

`X-Drip` carries a single character; `X-Drip-Serial` gives its position in a
40-piece sequence. The `work_order` cookie is a signed value holding a drops
counter and a seed – confirming the server tracks progress per visitor and
shuffles the delivery order from that seed. That is exactly what the incident
log described.

## Step 3 – Automate the collection

Because drops are shuffled and arrive one per refresh, and the cookie must
persist so the server advances the same visitor, the collector keeps a single
session (cookie jar) and loops until every serial is seen:

```python
import http.cookiejar, urllib.request

jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

drops, total = {}, None
for _ in range(200):
    with opener.open("http://web.secleaf.xyz:8080/") as r:
        ch, ser = r.headers.get("X-Drip"), r.headers.get("X-Drip-Serial")
        r.read()
    if ch is None or ser is None:
        continue
    n, total = map(int, ser.split("/"))
    drops[n] = ch
    if len(drops) == total:
        break

print("".join(drops[k] for k in sorted(drops)))
```

(The original solve used `requests.Session()`; the archived
[`solve/exploit.py`](solve/exploit.py) uses the stdlib equivalent above.)
Running it against the live challenge produced **40 of 40** unique serials with
nothing missing.

## Step 4 – Reassemble

Each drop is already a plain ASCII character of the final string, so sorting the
dictionary by serial key and concatenating gives a readable flag with no further
decoding:

```text
SecLeaf{h34d3r5_l34k_0n3_dr1p_4t_4_t1m3}
```

In leetspeak: "headers leak, one drip at a time."

## Flag

```text
SecLeaf{h34d3r5_l34k_0n3_dr1p_4t_4_t1m3}
```

## Why this is the right answer

- **Forward check:** collecting all 40 serials and ordering by index yields a clean, printable `SecLeaf{...}` string with no garbled characters and no padding to decode – a wrong reassembly would not read cleanly.
- **The flag describes the mechanism:** `h34d3r5_l34k_0n3_dr1p_4t_4_t1m3` = "headers leak one drip at a time", matching the one-character-per-header side channel.
- **Completeness:** the loop stops only at 40/40 distinct serials, so no piece is missing or duplicated.

## What we learned

- **Inspect the whole response, not the rendered page.** `curl -i` (or Burp's HTTP history) surfaces headers a browser view never shows – a common place to hide a side channel.
- **A signed cookie is a progress hint.** When the server hands you signed state, it is probably tracking you across requests; preserving it is often required to advance.
- **Delivery order is not storage order.** When data arrives in pieces, look for an explicit index/serial and sort by it rather than trusting arrival order.
- **Small scripts beat manual refreshing.** Automating collect-and-sort made confirming 40/40 trivial.

## Reproduce

```bash
cd solve
python3 exploit.py                       # recipe only, no network
python3 exploit.py http://web.secleaf.xyz:8080   # live run (target offline after the event)
```

Full exploit: [`solve/exploit.py`](solve/exploit.py)

---

[← Back to Web](../README.md) · [Challenge overview](README.md)
