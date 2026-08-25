"""Lookup a hashed binary in the cryptographic library fingerprint catalog."""

from __future__ import annotations

from typing import Any

from container_scanner.fingerprints.repository import FingerprintRepository


def lookup_hash(digest: str | None, catalog: FingerprintRepository | None = None) -> dict[str, Any] | None:
    repo = catalog or FingerprintRepository()
    return repo.lookup_hash(digest)


def lookup_name(name: str | None, catalog: FingerprintRepository | None = None) -> dict[str, Any] | None:
    repo = catalog or FingerprintRepository()
    return repo.lookup(name) or repo.match_binary(name)
