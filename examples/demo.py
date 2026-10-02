"""End-to-end usage example for ``signedcrawl``.

Runs against a fictional target with placeholder secrets, so it works with no
network and no real credentials. It demonstrates both halves of the package:

1. **Signing** — build a ``st`` + ``sign`` request for a fictional API.
2. **Decryption** — round-trip the HTTP envelope and a binary WebSocket frame.

Run::

    python examples/demo.py
"""

import base64
import gzip
import json

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from signedcrawl import Signer, decrypt_http, decrypt_ws_frame

# Fictional target — every value here is a placeholder, never a real secret.
BASE_URL = "https://api.example.com/football/list"
SALT = "example-salt"
KEY = b"0123456789abcdef"
IV = b"fedcba9876543210"


def demo_signing() -> None:
    signer = Signer(salt=SALT)
    params = {"comId": "8", "lang": "zh", "platform": "pc"}
    signed = signer.build_request(BASE_URL, params)
    url = BASE_URL + "?" + "&".join(f"{k}={v}" for k, v in signed.items())
    print("[signing]")
    print("  params:", signed)
    print("  url   :", url)
    print()


def demo_http_decrypt() -> None:
    payload = {"matches": [{"home": "Home FC", "guest": "Guest FC", "score": "1-0"}]}
    # Server side (fictional): json -> gzip -> base64 -> AES-CBC -> base64.
    raw = json.dumps(payload).encode("utf-8")
    plain = base64.b64encode(gzip.compress(raw))
    cipher = AES.new(KEY, AES.MODE_CBC, IV).encrypt(pad(plain, AES.block_size))
    data_field = base64.b64encode(cipher).decode("ascii")

    recovered = decrypt_http(data_field, KEY, IV)
    print("[http decrypt]")
    print("  data field (truncated):", data_field[:48] + "...")
    print("  recovered:", recovered)
    assert recovered == payload
    print()


def demo_ws_decrypt() -> None:
    frame = {"data": {"homeScore": 1}, "thirdId": "123", "type": 3}
    raw = json.dumps(frame).encode("utf-8")
    cipher = AES.new(KEY, AES.MODE_CBC, IV).encrypt(pad(raw, AES.block_size))
    blob_b64 = base64.b64encode(base64.b64encode(cipher)).decode("ascii")

    recovered = decrypt_ws_frame(blob_b64, KEY, IV)
    print("[ws decrypt]")
    print("  recovered:", recovered)
    assert recovered == frame


if __name__ == "__main__":
    demo_signing()
    demo_http_decrypt()
    demo_ws_decrypt()
    print("all examples passed")
