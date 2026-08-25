"""Library fingerprint lookups (JSON catalog — no extra table)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session


class FingerprintRepository:
    """Named fingerprint catalog used by container / binary scanners."""

    def __init__(self, session: Session | None = None, path: Path | None = None):
        self.session = session
        from container_scanner.fingerprints.repository import FingerprintRepository as Catalog

        self.catalog = Catalog(path=path) if path else Catalog()

    def lookup(self, name: str | None) -> dict[str, Any] | None:
        return self.catalog.lookup(name)

    def lookup_hash(self, digest: str | None) -> dict[str, Any] | None:
        return self.catalog.lookup_hash(digest)

    def match_binary(self, filename: str | None) -> dict[str, Any] | None:
        return self.catalog.match_binary(filename)

    def canonical(self, name: str | None) -> str:
        return self.catalog.canonical(name)

    def algorithms_for(self, name: str | None) -> list[str]:
        return self.catalog.algorithms_for(name)
