"""Deterministic deduplication.

The dedup key is a content identity: SHA-256 over the canonical JSON of the
fields that make an observation THE SAME observation (kind, system, endpoint,
fingerprint, algorithm). Re-observing the same thing updates a counter and a
last_seen — it never creates a second asset.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

from eventstream.envelope import canonical_bytes

_IDENTITY_FIELDS = ("kind", "system", "endpoint", "proto", "cert_fingerprint", "algorithm")


def dedup_key(canonical: dict[str, Any]) -> str:
    identity = {f: canonical.get(f) for f in _IDENTITY_FIELDS}
    return hashlib.sha256(canonical_bytes(identity)).hexdigest()


class DedupIndex:
    """In-memory merge index (per stream-processor state snapshot)."""

    def __init__(self) -> None:
        self.entries: dict[str, dict[str, Any]] = {}

    def merge(self, canonical: dict[str, Any], *, now: datetime | None = None) -> tuple[bool, dict[str, Any]]:
        """Returns (is_new, entry). First observation is new; later ones bump
        seen_count/last_seen on the SAME entry."""
        key = dedup_key(canonical)
        now = now or datetime.now(timezone.utc)
        entry = self.entries.get(key)
        if entry is None:
            entry = {"dedup_key": key, "first_seen": now.isoformat(),
                     "last_seen": now.isoformat(), "seen_count": 1,
                     "current": dict(canonical)}
            self.entries[key] = entry
            return True, entry
        entry["seen_count"] = int(entry["seen_count"]) + 1
        entry["last_seen"] = now.isoformat()
        entry["current"] = dict(canonical)
        return False, entry

    def __len__(self) -> int:
        return len(self.entries)
