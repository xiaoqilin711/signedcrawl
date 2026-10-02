# signedcrawl

Parameterized helpers for reverse-engineering data APIs that **sign their
requests** and **encrypt their responses**.

Two small, dependency-light building blocks, extracted from a real
reverse-engineering job and stripped of every site-specific secret. See
[docs/case-study.md](docs/case-study.md) for the redacted end-to-end
walkthrough.

---

## What this is

| Module | What it does |
|---|---|
| `signedcrawl.Signer` | Builds the common `md5(base + sorted(k=v…) + hash(salt)).lower() + suffix` request signature, with salt / suffix / timestamp field / hash all parameterized. |
| `signedcrawl.decrypt_http` | Decrypts the nested HTTP envelope `b64 → AES-128-CBC → b64 → (gzip·zlib·raw) → JSON`. |
| `signedcrawl.decrypt_ws_frame` | Decrypts a binary WebSocket frame `b64(blob) → ascii(b64(cipher)) → AES → JSON`. |

No domain, key, IV, salt, cookie, or real payload lives in this package — every
secret is a caller-supplied argument, and the examples/tests run on placeholder
data with no network.

## Why this shape

The two things that took the most effort to reverse were not "exotic crypto"
— they were **parameterization mistakes**:

1. The request signature is a one-liner, but the *URL fed into it* is the full
   URL, because the site's own `apiHost` config pointed at a dead domain and the
   strip silently no-op'd.
2. The "unzip" step in the response chain is **gzip**, not zlib — a one-line
   difference that breaks every naive Python port with `incorrect header check`.

This package bakes both lessons into the API surface: the signer takes the base
URL explicitly, and the decompression algorithm is an explicit argument with a
sane default plus `zlib`/`raw` alternatives.

## Features

- Zero secrets in code; everything parameterized.
- Core dependency is just `pycryptodome`.
- Pure-Python logic covered by round-trip tests (8 assertions, run without any
  network).
- A CLI (`signedcrawl demo|sign|decrypt`) and a runnable example that both work
  out of the box.

## Install

```bash
pip install -e .            # core (pycryptodome)
pip install -e ".[browser]" # optional: websockets for browser-driven paths
```

## Quick start

```bash
# self-contained round-trip demo (no network, no secret)
signedcrawl demo

# build a request signature for a fictional target
signedcrawl sign --base "https://api.example.com/list" \
                 --salt "example-salt" \
                 --param comId=8 --param lang=zh

# decrypt an HTTP data field
signedcrawl decrypt --kind http --data "<base64>" \
                    --key "0123456789abcdef" --iv "fedcba9876543210"
```

Or run the fuller walkthrough:

```bash
python examples/demo.py
```

## How it works

```
                 Signer                      decryption
   ┌──────────────────────────┐   ┌──────────────────────────────────┐
   │ base URL (full, no query)│   │ HTTP: b64 → AES → b64 → gzip → JSON│
   │ + sorted k=v params      │   │ WS  : b64(blob) → AES → JSON        │
   │ + hash(salt)             │   └──────────────────────────────────┘
   │ → hash(seed).lower()+suffix          key / iv passed in
   └──────────────────────────┘
```

The signature pattern generalizes to any API using
`md5(sorted-params + salt) + suffix`; the decryption helpers generalize to any
endpoint whose response is `AES(base64(gzip(json)))`. Change the salt / key / iv
per target — the logic stays the same.

## Honest boundaries

What is **verified** here:

- The signing formula and the two decryption chains are exact (extracted from a
  minified bundle and validated against captured requests / a live round-trip).
- The HTTP path works from pure Python with a browser-grade TLS fingerprint
  (`curl_cffi`, not included as a dependency).

What is **not** claimed:

- The **WebSocket** of the original target is protected by a WAF that silently
  drops non-browser clients; pure-Python access was **not** achieved there. The
  frame-decryption logic is real and tested, but *obtaining* those frames
  required driving a real browser (documented in the case study, not shipped as
  a turnkey connector).
- This package does **not** include any working scraper for a specific site, and
  it must not be pointed at data you are not authorized to collect.

## Case study

The full reverse-engineering narrative — how the signing salt was recovered
from captured `st`/`sign` pairs, how the gzip-vs-zlib trap was found, and where
the WAF boundary sat — is in [docs/case-study.md](docs/case-study.md), redacted
to public-safety level.

## License

MIT — see [LICENSE](LICENSE).
