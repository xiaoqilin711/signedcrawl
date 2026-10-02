"""Tests for the parameterized signature builder.

Run with ``pytest`` or directly: ``python tests/test_signing.py``.
"""

import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from signedcrawl.signing import Signer  # noqa: E402


def _md5(text: str) -> str:
    return hashlib.md5(text.encode("utf-8")).hexdigest()


def test_sign_matches_reference_formula():
    signer = Signer(salt="salt", suffix="99", ts_field=None)
    base = "https://www.example.com/api"
    params = {"b": "2", "a": "1"}
    # md5(base + sorted(k=v...) + md5(salt)).lower() + "99"
    expected = _md5(base + "a1b2" + _md5("salt")) + "99"
    assert signer.sign(base, params) == expected


def test_sign_sorts_keys_ascending():
    signer = Signer(salt="s", ts_field=None)
    base = "/x"
    a = signer.sign(base, {"b": "2", "a": "1"})
    b = signer.sign(base, {"a": "1", "b": "2"})
    assert a == b
    assert a == _md5("/x" + "a1b2" + _md5("s")) + "99"


def test_build_request_injects_timestamp_before_signing():
    signer = Signer(salt="salt", ts_field="st", ts_provider=lambda: 1234567890123)
    out = signer.build_request("https://www.example.com/api", {"b": "2", "a": "1"})
    assert out["st"] == 1234567890123
    expected = _md5("https://www.example.com/api" + "a1b2st1234567890123" + _md5("salt")) + "99"
    assert out["sign"] == expected


def test_suffix_is_appended_literally():
    signer = Signer(salt="s", suffix="XX", ts_field=None)
    assert signer.sign("/x", {"a": "1"}).endswith("XX")


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
