# Ledger – full writeup

[← Back to Web](../README.md) · [Challenge overview](README.md)

**Category:** Web · **Points:** 100 · **Flag:** `SecLeaf{ledger_8dfe7383f5657393289a132423dfeaf5be6f}`

**Author:** [Rutwik](https://github.com/Rutwik-712) · **Team:** Bug Busters

## TL;DR

1. The archive serves records at `GET /api/records/<id>?view=<view>`. RD-947 is private; its public view is redacted.
2. The brief frames the system as a **gateway** that authorises a view and a **renderer** that picks the content – two decision points.
3. Supplying the `view` parameter twice (`view=public&view=restricted`) is HTTP Parameter Pollution: nginx authorises on the first value, Flask renders on the last.
4. The one polluted request returns the restricted revision with `"status":"recovered"` and the flag.

## The challenge

We started from the archive console and the record index:

| Record | Title | Access |
| --- | --- | --- |
| `RD-102` | Receiving Bay | public |
| `RD-516` | Inventory Variance | public |
| `RD-947` | Sealed Reconciliation | private |

The name *Ledger* and the subtitle *Archive Consistency* are the hint: the
challenge is about two layers of the application **disagreeing** about the same
request. The brief says a gateway authorises a view before a renderer decides
what to return – so authorisation and content selection are separate steps that
could read the request differently. The target was the protected revision of
RD-947; the record id was already known, so no brute force was needed.

## Step 1 – Establish normal behaviour

The console's public request for the target record is:

```http
GET /api/records/RD-947?view=public HTTP/1.1
Host: ledger.secleaf.xyz
```

It returns HTTP 200 with a redacted body:

```json
{
  "id": "RD-947",
  "note": "Internal revision is not available.",
  "status": "redacted",
  "view": "public"
}
```

Simply changing the single parameter to `view=restricted` is **denied** – the
gateway refuses the restricted view outright. So the id is reachable but the
authorisation on the view stands in the way.

## Step 2 – Suspect split parsing

Why does the brief separate "authorise" from "render"? Because the two stages
can parse the query string differently. When a query string contains the *same*
parameter twice, there is no single standard for which value wins – different
servers pick the first, the last, or combine them. If the authorising layer and
the rendering layer pick **different** occurrences, one request can be authorised
under a safe value while being rendered under a dangerous one. That is HTTP
Parameter Pollution (HPP).

Using Burp's Proxy history we located the records-API request issued by the
console and sent it to Repeater to edit the query string directly.

## Step 3 – Pollute the `view` parameter

We added a second `view` value to the request:

```http
GET /api/records/RD-947?view=public&view=restricted HTTP/1.1
Host: ledger.secleaf.xyz
```

For this stack the two layers split as follows:

| Component | Occurrence used | Value seen |
| --- | --- | --- |
| nginx gateway | **first** | `public` → authorised |
| Flask renderer | **last** | `restricted` → rendered |

So the gateway sees `public` and lets the request through, while the renderer
reaches the end of the query string, reads `restricted`, and serves the
protected revision. Both values are present in one request; each component
simply trusts a different one.

> This first-vs-last split is a property of *this* deployment, not a universal
> rule for nginx or Flask.

## Step 4 – Recover the protected revision

Replaying the polluted request in Repeater returned the restricted revision.
Two challenge-specific signals confirmed we had crossed the authorisation
boundary rather than just getting a different error:

- the JSON body carried `"status":"recovered"` (not `"redacted"`);
- the response included the header `X-CTF-Probe: duplicate-view`.

The recovered revision contained the flag.

## Flag

```text
SecLeaf{ledger_8dfe7383f5657393289a132423dfeaf5be6f}
```

## Why this is the right answer

- **Forward check:** the same request path with a single `view=public` returns a redacted record, and `view=restricted` alone is denied; only the duplicated-parameter request returns `"status":"recovered"` with the flag.
- **Challenge-specific confirmation:** the `X-CTF-Probe: duplicate-view` header is emitted by the challenge precisely when the duplicate-view path is exercised – it names the intended bug.
- **Format match:** the value matches `SecLeaf{...}`.

## What we learned

- **Read the brief as an architecture hint.** "Gateway authorises, renderer decides" is a direct nudge toward two parsers that can disagree.
- **Duplicate parameters are an authorisation primitive.** When a security decision and a content decision read the same parameter independently, a valid value can mask a forbidden one.
- **Trust the content, not the status code.** The recovered revision, the `status` marker, and the probe header were stronger evidence than a bare HTTP 200.
- **Fix at the parser.** Reject duplicated security-critical parameters, or normalise them to one value before any layer reads them.

## Reproduce

```bash
cd solve
python3 exploit.py                       # request recipe only, no network
python3 exploit.py https://ledger.secleaf.xyz   # live run (target offline after the event)
```

Equivalent raw request:

```bash
curl -i 'https://ledger.secleaf.xyz/api/records/RD-947?view=public&view=restricted'
```

Full exploit: [`solve/exploit.py`](solve/exploit.py)

---

[← Back to Web](../README.md) · [Challenge overview](README.md)
