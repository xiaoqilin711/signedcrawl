"""Command-line entry points for demonstrating the package.

Three subcommands:

* ``demo``    — round-trip the HTTP decryption chain against in-memory sample
  data (no network, no secret), proving the pipeline is self-consistent.
* ``sign``    — build a signature for a base URL + parameter list.
* ``decrypt`` — decrypt a base64 HTTP ``data`` field or a WebSocket frame.

Everything here is parameterized; run ``signedcrawl demo`` with no arguments
to see the package work end-to-end.
"""

from __future__ import annotations

import argparse
import base64
import gzip
import json
import sys

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from .decryption import decrypt_http, decrypt_ws_frame
from .signing import Signer

# Placeholder key/iv for the self-contained demo only — never a real secret.
DEMO_KEY = b"0123456789abcdef"
DEMO_IV = b"fedcba9876543210"


def _encrypt_http(obj: dict, key: bytes, iv: bytes) -> str:
    """Inverse of decrypt_http, used solely for the round-trip demo."""
    raw = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    compressed = gzip.compress(raw)
    plain = base64.b64encode(compressed)  # AES input is base64-of-gzip
    cipher = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(plain, AES.block_size))
    return base64.b64encode(cipher).decode("ascii")


def _cmd_demo(_: argparse.Namespace) -> int:
    sample = {
        "matches": [
            {"home": "Home FC", "guest": "Guest FC", "score": "1-0"},
            {"home": "Alpha United", "guest": "Beta City", "score": "0-0"},
        ]
    }
    data_field = _encrypt_http(sample, DEMO_KEY, DEMO_IV)
    recovered = decrypt_http(data_field, DEMO_KEY, DEMO_IV)
    assert recovered == sample, "round-trip mismatch"
    print("encrypted data field (truncated):", data_field[:48] + "...")
    print("decrypted payload:")
    print(json.dumps(recovered, ensure_ascii=False, indent=2))
    return 0


def _cmd_sign(args: argparse.Namespace) -> int:
    params = dict(p.split("=", 1) for p in args.param)
    signer = Signer(salt=args.salt, suffix=args.suffix, ts_field=None if args.no_ts else "st")
    if args.no_ts:
        sig = signer.sign(args.base, params)
        print(f"sign={sig}")
    else:
        out = signer.build_request(args.base, params)
        print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


def _cmd_decrypt(args: argparse.Namespace) -> int:
    key = args.key.encode("utf-8")
    iv = args.iv.encode("utf-8")
    if args.kind == "http":
        result = decrypt_http(args.data, key, iv, compression=args.compression)
    else:
        result = decrypt_ws_frame(args.data, key, iv)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="signedcrawl")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("demo", help="round-trip decrypt demo on sample data")

    p_sign = sub.add_parser("sign", help="build a request signature")
    p_sign.add_argument("--base", required=True)
    p_sign.add_argument("--salt", required=True)
    p_sign.add_argument("--suffix", default="99")
    p_sign.add_argument("--param", action="append", default=[])
    p_sign.add_argument("--no-ts", action="store_true")

    p_dec = sub.add_parser("decrypt", help="decrypt an HTTP field or WS frame")
    p_dec.add_argument("--kind", choices=["http", "ws"], required=True)
    p_dec.add_argument("--data", required=True)
    p_dec.add_argument("--key", required=True)
    p_dec.add_argument("--iv", required=True)
    p_dec.add_argument("--compression", default="gzip", choices=["gzip", "zlib", "raw"])

    args = parser.parse_args(argv)
    handlers = {"demo": _cmd_demo, "sign": _cmd_sign, "decrypt": _cmd_decrypt}
    try:
        return handlers[args.command](args)
    except Exception as exc:  # noqa: BLE001 — surface a clean CLI error
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
