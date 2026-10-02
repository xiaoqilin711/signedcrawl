"""Round-trip tests for the decryption helpers.

Encryption here is only a test oracle (the inverse transform) used to prove
the decryption pipeline is correct — it is not a reversed artifact itself.

Run with ``pytest`` or directly: ``python tests/test_decryption.py``.
"""

import base64
import gzip
import json
import os
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Crypto.Cipher import AES  # noqa: E402
from Crypto.Util.Padding import pad  # noqa: E402

from signedcrawl.decryption import decrypt_http, decrypt_ws_frame  # noqa: E402

KEY = b"0123456789abcdef"
IV = b"fedcba9876543210"


def _encrypt_http(obj, key=KEY, iv=IV, algorithm="gzip"):
    raw = json.dumps(obj).encode("utf-8")
    if algorithm == "gzip":
        compressed = gzip.compress(raw)
    elif algorithm == "zlib":
        compressed = zlib.compress(raw)
    else:
        compressed = zlib.compress(raw)[2:-4]  # raw deflate
    plain = base64.b64encode(compressed)
    cipher = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(plain, AES.block_size))
    return base64.b64encode(cipher).decode("ascii")


def _encrypt_ws(obj, key=KEY, iv=IV):
    raw = json.dumps(obj).encode("utf-8")
    cipher = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(raw, AES.block_size))
    blob = base64.b64encode(cipher)  # blob bytes == ascii(base64 ciphertext)
    return base64.b64encode(blob).decode("ascii")


def test_http_roundtrip_gzip():
    obj = {"matches": [{"home": "A", "score": "1-0"}], "count": 1}
    assert decrypt_http(_encrypt_http(obj), KEY, IV) == obj


def test_http_roundtrip_zlib():
    obj = {"x": [1, 2, 3]}
    assert decrypt_http(_encrypt_http(obj, algorithm="zlib"), KEY, IV, "zlib") == obj


def test_http_roundtrip_raw_deflate():
    obj = {"x": "raw"}
    assert decrypt_http(_encrypt_http(obj, algorithm="raw"), KEY, IV, "raw") == obj


def test_ws_roundtrip():
    obj = {"data": {"homeScore": 1}, "thirdId": "123", "type": 3}
    assert decrypt_ws_frame(_encrypt_ws(obj), KEY, IV) == obj


if __name__ == "__main__":
    import traceback

    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for fn in tests:
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except Exception:
            failed += 1
            print(f"FAIL {fn.__name__}")
            traceback.print_exc()
    print(f"{len(tests) - failed}/{len(tests)} passed")
    raise SystemExit(1 if failed else 0)
