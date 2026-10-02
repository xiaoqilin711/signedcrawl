"""signedcrawl — parameterized helpers for reverse-engineered data APIs.

Exposes two small, dependency-light building blocks:

* :class:`~signedcrawl.signing.Signer` — builds the common
  ``md5(base + sorted(k=v...) + hash(salt)).lower() + suffix`` request
  signature, with the timestamp field and salt kept as parameters.
* :func:`~signedcrawl.decryption.decrypt_http` and
  :func:`~signedcrawl.decryption.decrypt_ws_frame` — decrypt the two most
  common encrypted-payload shapes (nested HTTP envelope, binary WebSocket
  frame) with key/iv supplied by the caller.

No site-specific secret (domain, key, iv, salt, cookie) lives in this
package. See ``docs/case-study.md`` for a redacted end-to-end walkthrough of
the real case these helpers were extracted from.
"""

from .signing import Signer
from .decryption import (
    aes_cbc_decrypt,
    decompress,
    decrypt_http,
    decrypt_ws_frame,
)

__all__ = [
    "Signer",
    "aes_cbc_decrypt",
    "decompress",
    "decrypt_http",
    "decrypt_ws_frame",
]

__version__ = "0.1.0"
