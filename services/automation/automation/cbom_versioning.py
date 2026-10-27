"""Deterministic live CBOM versioning (no AI/ML).

The cryptographic bill of materials is a *live*, versioned inventory rather than
a one-off report. Each time observations change, a new immutable version is
derived: the component set is canonicalized, content-addressed (SHA-256), and
diffed against the previous version to list exactly what appeared, disappeared,
or changed (algorithm/key-size/mode on a component). Versions are monotonic and
the same state always produces the same fingerprint — replayable and auditable.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable


def _canon_component(comp: dict[str, Any]) -> dict[str, Any]:
    """Project a component/observation to its stable identity + crypto state."""
    identity = (
        str(comp.get("component_id") or comp.get("id")
            or comp.get("name") or comp.get("file_path") or "").strip()
    )
    return {
        "id": identity,
        "algorithm": str(comp.get("algorithm") or comp.get("standard_name") or "UNKNOWN").upper(),
        "key_size": comp.get("key_size"),
        "mode": (comp.get("mode") or "").upper() or None,
        "library": str(comp.get("library") or comp.get("component_name") or ""),
        "library_version": str(comp.get("library_version") or comp.get("version") or ""),
    }


def _component_key(c: dict[str, Any]) -> str:
    return f"{c['id']}|{c['algorithm']}|{c.get('key_size')}|{c.get('mode') or ''}"


def _state_fingerprint(components: list[dict[str, Any]]) -> str:
    canonical = json.dumps(
        sorted((_canon_component(c) for c in components), key=_component_key),
        sort_keys=True, separators=(",", ":"), default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass
class CbomVersion:
    version: int
    fingerprint: str
    component_count: int
    components: list[dict[str, Any]]
    created_at: str
    parent_fingerprint: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": self.version, "fingerprint": self.fingerprint,
            "component_count": self.component_count,
            "parent_fingerprint": self.parent_fingerprint,
            "created_at": self.created_at,
        }


@dataclass
class CbomDiff:
    changed: bool
    new_version: int
    added: list[dict[str, Any]] = field(default_factory=list)
    removed: list[dict[str, Any]] = field(default_factory=list)
    fingerprint: str = ""
    previous_fingerprint: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "changed": self.changed, "new_version": self.new_version,
            "added": self.added, "removed": self.removed,
            "added_count": len(self.added), "removed_count": len(self.removed),
            "fingerprint": self.fingerprint,
            "previous_fingerprint": self.previous_fingerprint,
        }


class LiveCbom:
    """Append-only, content-addressed CBOM version store (in-memory or backed)."""

    def __init__(self) -> None:
        self._versions: list[CbomVersion] = []

    def latest(self) -> CbomVersion | None:
        return self._versions[-1] if self._versions else None

    @property
    def version_count(self) -> int:
        return len(self._versions)

    def update(self, observations: Iterable[dict[str, Any]], *,
               now: datetime | None = None) -> CbomDiff:
        """Apply a new set of observations; create a version only on change."""
        now = now or datetime.now(timezone.utc)
        components = [_canon_component(c) for c in observations]
        fingerprint = _state_fingerprint(components)
        prev = self.latest()

        if prev is not None and prev.fingerprint == fingerprint:
            return CbomDiff(changed=False, new_version=prev.version,
                            fingerprint=fingerprint, previous_fingerprint=prev.fingerprint)

        added, removed = [], []
        prev_index: dict[str, dict[str, Any]] = {}
        if prev is not None:
            prev_index = {_component_key(c): c for c in prev.components}
        cur_index = {_component_key(c): c for c in components}
        for key, c in sorted(cur_index.items()):
            if key not in prev_index:
                added.append(c)
        for key, c in sorted(prev_index.items()):
            if key not in cur_index:
                removed.append(c)

        new_version_number = (prev.version + 1) if prev is not None else 1
        version = CbomVersion(
            version=new_version_number, fingerprint=fingerprint,
            component_count=len(components), components=components,
            created_at=now.isoformat(),
            parent_fingerprint=prev.fingerprint if prev else None,
        )
        self._versions.append(version)
        return CbomDiff(changed=True, new_version=new_version_number,
                        added=added, removed=removed, fingerprint=fingerprint,
                        previous_fingerprint=prev.fingerprint if prev else None)

    def history(self) -> list[dict[str, Any]]:
        return [v.as_dict() for v in self._versions]
