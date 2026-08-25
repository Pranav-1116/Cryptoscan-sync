"""DB access for the cryptographic library fingerprint catalog."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from container_scanner.fingerprints.repository import FingerprintRepository


class FingerprintDatabase:
    """Thin named wrapper around `FingerprintRepository`."""

    def __init__(self, fingerprint_db: dict[str, Any] | None = None, path: Path | None = None):
        self.repo = FingerprintRepository(fingerprint_db, path=path)

    def lookup(self, name: str | None) -> dict[str, Any] | None:
        return self.repo.lookup(name)

    def lookup_hash(self, digest: str | None) -> dict[str, Any] | None:
        return self.repo.lookup_hash(digest)

    def match_binary(self, filename: str | None) -> dict[str, Any] | None:
        return self.repo.match_binary(filename)

    def canonical(self, name: str | None) -> str:
        return self.repo.canonical(name)

    def algorithms_for(self, name: str | None) -> list[str]:
        return self.repo.algorithms_for(name)
