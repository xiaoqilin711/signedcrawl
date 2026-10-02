# Case study — reverse-engineering a signed, encrypted live-scores API

> **Redaction note.** This writeup is published at "public-safety" level. The
> target's domain, API paths, AES key/IV, signature salts, channel identifiers
> and real payloads are all withheld or generalized. Every secret is described
> by *shape*, not value. This document is about the method, not the target.

---

## TL;DR

A sports live-scores site served two data streams that had to be combined to
reconstruct live match state:

1. an **HTTP snapshot** endpoint — team names, initial scores, odds, polled
   every 30 s, protected by an MD5 request signature;
2. a **WebSocket** push — incremental events (goals, corners, cards), AES
   encrypted, and additionally shielded by a WAF that silently dropped
   non-browser clients.

I recovered the signature formula, the AES key/IV, and both decryption chains,
and shipped the *reusable* parts (a parameterized signer + decryption helpers)
into the `signedcrawl` package. The parts that could not be made reusable — the
target-specific secrets and the browser-only WebSocket path — are documented
here rather than shipped.

## The problem

To show live scores you need two things that arrive through two different
channels:

- **Who is playing and what the current state is** — only in the HTTP snapshot.
- **What changed in the last second** — only in the WebSocket push.

Both channels were obfuscated in different ways, so the job split cleanly into
two reverses plus one infrastructure problem.

## Walkthrough

### 1. Locating the logic in a minified bundle

The front end was a Nuxt SSR app whose JS was split into webpack chunks and
served **gzip-compressed**. Naive `grep` over the files finds nothing — the
chunks have to be decompressed first. That alone is a common trap worth naming:
always `gunzip` the chunks before searching, or every keyword search silently
returns zero hits.

Once decompressed, the two entry points were found by grepping for the WS URL
and for the request interceptor:

- the WebSocket connect/subscribe code,
- an `axios` request interceptor that appended `st` and `sign` query params.

### 2. The WebSocket (push side)

The subscription was a single text frame; the server then pushed **binary
blobs**. The decryption was traced through a `FileReader`:

```js
// read blob as text  ->  that text is the base64 of the AES ciphertext
fr.readAsText(blob);
fr.onload = () => AES.decrypt(fr.result, key, { iv, mode: CBC, padding: Pkcs7 })
               .toString(Utf8);
```

Two non-obvious details:

1. **Double base64.** The blob's bytes are ASCII holding the base64 of the
   ciphertext — reading it as text is what turns it into something the AES
   call can consume. Replicating this in Python means
   `b64decode(blob) → b64decode(ascii) → AES-decrypt`.
2. The key/IV were **not** hidden — they were plain 16-byte ASCII literals
   sitting a few lines above the decrypt call. The obfuscation was structural,
   not cryptographic.

This is now `decrypt_ws_frame`.

### 3. The HTTP signature (snapshot side)

The interceptor did, in effect:

```js
params.st = Date.now();                       // ms timestamp, before signing
sign = md5( baseUrl + concat(sorted(params)) + md5(salt) ).toLowerCase() + "99";
```

The salt was not readable directly — the hash function was imported from a
minified module graph. Rather than chase the import chain, I **recovered the
salt empirically**: I had captured `(st, sign)` pairs from the browser's
network log. Guessing the formula `md5(url + sorted_params + md5(salt)) + "99"`
and brute-checking a handful of plausible salt placements against those pairs
closed it in minutes — MD5 makes verification cheap.

The decisive gotcha was the **URL**. The interceptor was written to strip the
host via `url.replace(config.apiHost, "")` before signing — but the site's
`apiHost` config pointed at a **dead/legacy domain**, so the `replace` silently
no-op'd and the signature was actually computed over the **full URL**. Signing
the stripped path (the "obvious" thing to try) produces a wrong digest; signing
the full URL matches. This is exactly the class of bug that costs hours if you
trust the code's stated intent instead of the observed data.

This is now `Signer`, with the salt/suffix/URL all parameterized.

### 4. The HTTP response chain (gzip trap)

The snapshot response was an envelope `{"code": "200", "data": "<base64>"}`.
Unwrapping it:

```
data → base64 → AES-128-CBC → base64 → gzip → JSON
```

The trap: the page's `unzip` step used an inflate call, so the natural Python
translation is `zlib.decompress` — which dies with `incorrect header check`,
because the payload is **gzip** (`1f 8b`), not zlib (`0x78`). One line, but it
separates "works" from "stuck for an afternoon."

This is now `decrypt_http`, with the compression algorithm an explicit
argument (`gzip` default, `zlib`/`raw` available).

## The gotchas, summarized

| # | Gotcha | Lesson |
|---|---|---|
| 1 | JS chunks are gzip-compressed | `gunzip` before grepping |
| 2 | `apiHost` pointed at a dead domain | sign the *full* URL, not the "intended" path |
| 3 | `unzip` was actually gzip | parameterize the compression, default `gzip` |
| 4 | WAF silently dropped non-browser WS clients | TLS fingerprint alone isn't enough on push channels |

## The WAF boundary (honest limit)

The HTTP snapshot endpoint could be reached from **pure Python** with a
browser-grade TLS fingerprint (via `curl_cffi`). The WebSocket could **not**:
pure-Python clients completed the handshake but received **zero** frames, and
no combination of impersonation and headers changed that. Reaching the push
stream required driving a real browser (CDP) that had already passed the WAF's
JS challenge.

I report this as a boundary, not as a solved problem. `decrypt_ws_frame` is
real and tested; *acquiring* the frames against that specific target was only
possible through a browser, and that connector is not part of the public
package.

## What shipped

From the one-off job, the reusable layer was extracted into `signedcrawl`:

- `Signer` — the signature pattern, salt/suffix/timestamp parameterized.
- `decrypt_http` / `decrypt_ws_frame` — the two decryption chains, key/iv
  parameterized.
- round-trip tests + a CLI + an example, all running on placeholder data.

The target-specific layer (domain, paths, key, IV, salt, field mapping) was
deliberately **not** shipped — it is the part that carries both the legal risk
and the attack surface, and it is not reusable anyway.

## Honest boundaries

- Verified: signature formula (against captured pairs), both decryption chains
  (against live data), the gzip-not-zlib detail, and the HTTP-via-`curl_cffi`
  path.
- Not verified / not shipped: the browser-only WebSocket connector, and any
  turnkey scraper for a specific site.
- This writeup omits all target identifiers; do not ask me to add them back.
