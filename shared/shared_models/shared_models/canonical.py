"""Canonical serialization and cryptographic encoding primitives.

One implementation of the deterministic-JSON contract used across the
platform — evidence content hashing, finding fingerprints, CBOM JWS
signing (RFC 7515), and HMAC verification. Every service that needs
byte-stable JSON must go through here so hashes and signatures remain
interoperable.

Canonical form: recursively sorted keys, ``(",", ":")`` separators,
``ensure_ascii=False``, UTF-8 encoded.
"""

from __future__ import annotations

import hashlib
import hmac as hmac_module
import json
from typing import Any, Iterable


def canonical_json(data: Any, *, default: Any = None) -> str:
    """Serialize ``data`` to the canonical JSON string.

    Args:
        data: JSON-compatible structure (dicts/lists/scalars).
        default: Optional ``json.dumps`` fallback for non-serializable
            objects (mirrors :func:`json.dumps` semantics).
    """
    kwargs: dict[str, Any] = {
        "sort_keys": True,
        "separators": (",", ":"),
        "ensure_ascii": False,
    }
    if default is not None:
        kwargs["default"] = default
    return json.dumps(data, **kwargs)


def canonical_bytes(data: Any, *, default: Any = None) -> bytes:
    """Canonical JSON encoded as UTF-8 bytes (hash/signature input)."""
    return canonical_json(data, default=default).encode("utf-8")


def exclude_fields(data: Any, fields: Iterable[str]) -> Any:
    """Recursively drop the named keys from dicts inside ``data``.

    Used to strip runtime-only fields (ids, timestamps) before hashing.
    """
    removed = set(fields)

    def _clean(obj: Any) -> Any:
        if isinstance(obj, dict):
            return {k: _clean(v) for k, v in obj.items() if k not in removed}
        if isinstance(obj, list):
            return [_clean(item) for item in obj]
        return obj

    return _clean(data)


def sha256_hex(data: Any, *, default: Any = None) -> str:
    """SHA-256 of the canonical form, lowercase hex."""
    return hashlib.sha256(canonical_bytes(data, default=default)).hexdigest()


def sha256_digest(data: Any, *, default: Any = None) -> bytes:
    """SHA-256 of the canonical form, raw digest bytes."""
    return hashlib.sha256(canonical_bytes(data, default=default)).digest()


# --------------------------------------------------------------------------- #
# RFC 7515 base64url (unpadded)
# --------------------------------------------------------------------------- #


def b64url_encode(data: bytes) -> str:
    """Base64url without padding, ASCII string (JWS compact form)."""
    import base64

    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    """Inverse of :func:`b64url_encode`; accepts padded input too."""
    import base64

    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


# --------------------------------------------------------------------------- #
# HMAC
# --------------------------------------------------------------------------- #


def hmac_sha256(secret: str | bytes, data: bytes) -> bytes:
    """HMAC-SHA256 (JWS HS256)."""
    key = secret.encode("utf-8") if isinstance(secret, str) else secret
    return hmac_module.new(key, data, hashlib.sha256).digest()


def constant_time_eq(a: str | bytes, b: str | bytes) -> bool:
    """Constant-time comparison for secrets/mac values."""
    left = a.encode("utf-8") if isinstance(a, str) else a
    right = b.encode("utf-8") if isinstance(b, str) else b
    return hmac_module.compare_digest(left, right)
