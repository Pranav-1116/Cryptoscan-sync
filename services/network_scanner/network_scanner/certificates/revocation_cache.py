"""Bounded on-disk cache for revocation artifacts (CRLs).

Keyed by SHA-256 of the source URL, TTL-bounded so a stale CRL can never be
served indefinitely.  ``ttl <= 0`` disables caching entirely.  The cache only
ever stores raw bytes; parsing/freshness decisions stay with the caller.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
import time
from typing import Any

DEFAULT_TTL = 3600.0


def cache_dir() -> str:
    override = os.environ.get("CRYPTOSCAN_REVOCATION_CACHE_DIR", "").strip()
    path = override or os.path.join(tempfile.gettempdir(), "cryptoscan-revocation")
    os.makedirs(path, exist_ok=True)
    return path


def cache_ttl() -> float:
    raw = os.environ.get("CRYPTOSCAN_REVOCATION_CACHE_TTL", "").strip()
    if not raw:
        return DEFAULT_TTL
    try:
        return max(0.0, float(raw))
    except ValueError:
        return DEFAULT_TTL


def _path_for(url: str) -> str:
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()
    return os.path.join(cache_dir(), f"{digest}.bin")


def cache_get(url: str, *, ttl: float | None = None) -> dict[str, Any] | None:
    """Return ``{"data": bytes, "age": seconds}`` for a fresh entry, else None."""
    effective = cache_ttl() if ttl is None else ttl
    if effective <= 0:
        return None
    path = _path_for(url)
    try:
        stat = os.stat(path)
    except OSError:
        return None
    age = max(0.0, time.time() - stat.st_mtime)
    if age >= effective:
        return None
    with open(path, "rb") as handle:
        return {"data": handle.read(), "age": age}


def cache_put(url: str, data: bytes) -> None:
    if cache_ttl() <= 0:
        return
    path = _path_for(url)
    temp = f"{path}.{os.getpid()}.tmp"
    with open(temp, "wb") as handle:
        handle.write(data)
    os.replace(temp, path)
