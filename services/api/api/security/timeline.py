"""Unified cross-system timeline (audit 78, P0 #4).

The platform keeps two disjoint event histories: the hash-chained
``AuditLog`` (who did what to which entity — human and system mutations)
and ``MonitorEvent`` platform events (lifecycle transitions, automation
runs, alerts — the operational stream). Forensics needs them as ONE
chronology: "what happened around this asset, in order, regardless of
which subsystem recorded it".

``merge_timeline`` is a pure normaliser/merger — no I/O, no clock reads.
Each row becomes::

    {
        "source": "audit" | "platform",
        "at": "<iso timestamp>",
        "actor": "...",            # audit actor; platform events carry actor
        "action": "...",           # audit action / platform event_type
        "target": "...",           # target_id (audit) / target_name (platform)
        "target_type": "...",
        "detail": {...},           # parsed detail / payload
        "event_id": "...",
    }

Sorted newest-first, capped. Determinism: identical timestamps keep the
caller's (stable, per-source ordered) input order — the merge never
invents an ordering the sources did not record.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Iterable


def _iso(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _parse_detail(value: Any) -> Any:
    """Audit detail is stored as a JSON string; platform payload is JSON."""
    if isinstance(value, str) and value.startswith(("{", "[")):
        try:
            return json.loads(value)
        except (TypeError, ValueError):
            return value
    return value


def normalize_audit_row(row: Any) -> dict[str, Any]:
    return {
        "source": "audit",
        "at": _iso(getattr(row, "created_at", None)),
        "actor": getattr(row, "actor", None),
        "action": getattr(row, "action", None),
        "target": getattr(row, "target_id", None),
        "target_type": getattr(row, "target_type", None),
        "detail": _parse_detail(getattr(row, "detail", None)),
        "outcome": getattr(row, "outcome", None),
        "event_id": getattr(row, "id", None),
    }


def normalize_platform_row(row: Any) -> dict[str, Any]:
    payload = getattr(row, "payload", None) or {}
    # platform events carry the acting human under different keys depending
    # on the emitter — the known set is checked in priority order
    actor = None
    for key in ("actor", "user", "accepted_by", "completed_by",
                "created_by", "triggered_by"):
        if payload.get(key):
            actor = payload[key]
            break
    return {
        "source": "platform",
        "at": _iso(getattr(row, "created_at", None)),
        "actor": actor or "system",
        "action": getattr(row, "event_type", None),
        "target": getattr(row, "target_name", None),
        "target_type": "platform_event",
        "detail": payload,
        "outcome": None,
        "event_id": getattr(row, "id", None),
    }


def merge_timeline(
    audit_rows: Iterable[Any],
    platform_rows: Iterable[Any],
    *,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Merge the two histories into one newest-first timeline."""
    merged = [normalize_audit_row(r) for r in audit_rows]
    merged += [normalize_platform_row(r) for r in platform_rows]
    merged.sort(key=lambda e: (e.get("at") or ""), reverse=True)
    return merged[:limit]
