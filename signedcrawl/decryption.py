"""Multi-layer decryption for encrypted API responses and WebSocket frames.

Two payload shapes are common in the wild, and both are covered here with the
key and IV left as caller-supplied arguments (so no secret is hard-coded):

HTTP envelope::

    b64 -> AES-128-CBC -> b64 -> (gzip | zlib | raw-deflate) -> JSON

WebSocket binary frame::

    b64(blob) -> ascii(b64(ciphertext)) -> AES-128-CBC -> JSON

The AES mode, block size and padding (CBC / PKCS#7) are the defaults that show
up most often in minified front-end bundles; override with lower-level
:func:`aes_cbc_decrypt` when a target differs.
"""

from __future__ import annotations

import base64
import gzip
import json
import zlib
from typing import Any

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


def aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-CBC decrypt with PKCS#7 unpadding. ``key``/``iv`` are raw bytes."""
    return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext), AES.block_size)


def decompress(data: bytes, algorithm: str = "gzip") -> bytes:
    """Decompress ``data`` using ``gzip``, ``zlib`` or ``raw`` (deflate).

    The algorithm is a parameter because the on-page inflate call does not
    always correspond to Python's default ``zlib`` — a very common gotcha.
    """
    if algorithm == "gzip":
        return gzip.decompress(data)
    if algorithm == "zlib":
        return zlib.decompress(data)
    if algorithm == "raw":
        return zlib.decompress(data, -15)
    raise ValueError(f"unsupported compression algorithm: {algorithm!r}")


def decrypt_http(
    data_field: str,
    key: bytes,
    iv: bytes,
    compression: str = "gzip",
) -> dict[str, Any]:
    """Decrypt an HTTP response ``data`` field into a JSON object.

    ``data_field`` is the base64 string usually wrapped in an envelope like
    ``{"code": "200", "data": "<base64>"}``.
    """
    ciphertext = base64.b64decode(data_field)
    plain = aes_cbc_decrypt(ciphertext, key, iv)  # base64 of the compressed payload
    payload = base64.b64decode(plain)
    return json.loads(decompress(payload, compression).decode("utf-8"))


def decrypt_ws_frame(blob_b64: str, key: bytes, iv: bytes) -> dict[str, Any]:
    """Decrypt a binary WebSocket frame that arrived as a base64-encoded blob.

    The blob's own bytes are an ASCII string holding the base64 of the AES
    ciphertext — a double-encoding produced by reading the blob as text before
    decrypting.
    """
    blob = base64.b64decode(blob_b64)
    ciphertext = base64.b64decode(blob.decode("ascii"))
    plain = aes_cbc_decrypt(ciphertext, key, iv)
    return json.loads(plain.decode("utf-8"))
