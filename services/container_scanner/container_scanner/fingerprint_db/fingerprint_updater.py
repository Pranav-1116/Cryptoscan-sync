"""Merge a hashed binary into the in-memory fingerprint catalog."""

from __future__ import annotations

from typing import Any

from container_scanner.fingerprint_db.fingerprint_database import FingerprintDatabase


def add_hash(
    catalog: FingerprintDatabase,
    digest: str,
    *,
    library: str,
    version: str | None = None,
    file: str | None = None,
) -> dict[str, Any]:
    payload = {"library": library, "version": version, "file": file, "sha256": digest.lower()}
    catalog.repo._hashes[digest.lower()] = payload
    return payload
