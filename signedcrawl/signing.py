"""Parameterized request-signature builder.

A large family of data APIs protect their endpoints with a lightweight
signature of the shape::

    sign = md5(base + concat(sorted_params) + md5(salt)).lower() + suffix

where ``base`` is the full request URL (query string stripped), ``salt`` is a
short constant, and a millisecond timestamp is injected into the parameter
map *before* signing (so it is covered by the digest, which also makes the
signature anti-replay within a small window).

:class:`Signer` generalizes exactly this pattern. The salt, suffix, hash
function, timestamp field name and timestamp provider are all constructor
arguments, so a signature reversed from one target can be reused against
another without hard-coding the secret.
"""

from __future__ import annotations

import hashlib
import time
from typing import Callable, Mapping


def md5_hex(data: bytes | str) -> str:
    """MD5 digest as lowercase hex, accepting bytes or str."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.md5(data).hexdigest()


class Signer:
    """Build ``md5(base + concat(sorted params) + hash(salt)).lower() + suffix``.

    Parameters
    ----------
    salt:
        Constant appended (after being hashed) to the seed before the final
        digest. This is the secret to reverse per target.
    suffix:
        Literal string appended to the final hex digest (e.g. ``"99"``).
    hash_fn:
        One-shot hash producing hex output. Defaults to MD5.
    sort_keys:
        Whether to sort parameter keys before concatenation. Most such
        signatures sort ascending; keep ``True`` unless proven otherwise.
    ts_field:
        Name of the timestamp parameter injected before signing, or ``None``
        to disable auto-injection.
    ts_provider:
        Callable returning the timestamp value (default: 13-digit
        milliseconds, matching JS ``(new Date).getTime()``).
    lower:
        Whether to lowercase the final digest before appending the suffix.
    """

    def __init__(
        self,
        salt: str,
        suffix: str = "99",
        hash_fn: Callable[[bytes | str], str] = md5_hex,
        sort_keys: bool = True,
        ts_field: str | None = "st",
        ts_provider: Callable[[], int] | None = None,
        lower: bool = True,
    ) -> None:
        self.salt = salt
        self.suffix = suffix
        self.hash_fn = hash_fn
        self.sort_keys = sort_keys
        self.ts_field = ts_field
        self.ts_provider = ts_provider or (lambda: int(time.time() * 1000))
        self.lower = lower

    def _digest(self, base: str, params: Mapping[str, object]) -> str:
        keys = sorted(params) if self.sort_keys else list(params)
        kv = "".join(f"{k}{params[k]}" for k in keys)
        seed = base + kv + self.hash_fn(self.salt)
        digest = self.hash_fn(seed)
        return digest.lower() if self.lower else digest

    def sign(self, base: str, params: Mapping[str, object]) -> str:
        """Return the signature for an *already complete* parameter map.

        The timestamp field, if configured, must already be present in
        ``params``; it is *not* injected here. Use :meth:`build_request` for
        the convenience path that injects it for you.
        """
        return self._digest(base, params) + self.suffix

    def build_request(self, base: str, params: Mapping[str, object]) -> dict:
        """Return a parameter map with timestamp and ``sign`` injected.

        This is the end-to-end helper: it stamps ``ts_field`` (if enabled),
        computes the signature over the stamped map, and returns a dict ready
        to be serialized into a query string or POST body.
        """
        out = dict(params)
        if self.ts_field is not None and self.ts_field not in out:
            out[self.ts_field] = self.ts_provider()
        out["sign"] = self._digest(base, out) + self.suffix
        return out
