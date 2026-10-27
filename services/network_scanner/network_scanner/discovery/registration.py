"""Turn discovered endpoints into scheduler targets (due-scan rotation).

Discovery without registration is a dead end: endpoints found by a subnet
sweep appear once in a report and never get rescanned.  This module converts
discovered ``host:port`` strings into target records the scheduler already
understands (``scan_frequency`` / ``enabled`` / ``next_scan_time``) and
upserts them through any repository exposing ``upsert_target(endpoint, **kw)``.

Design choices, honestly:

* newly discovered endpoints are due **immediately** (``next_scan_time=now``)
  — discovery means "posture unknown", so the next ``run-due`` pass should
  pick them up instead of waiting a full interval;
* unknown frequencies degrade to ``daily`` (mirrors the scheduler);
* ``next_scan_time`` is stored as ISO-8601 UTC in records (JSON-safe) and
  converted back to ``datetime`` only at the repository boundary, where the
  DB column expects one;
* endpoints are deduplicated and blank entries dropped — a sweep that finds
  the same host on several ports still registers each ``host:port`` once.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable

VALID_FREQUENCIES = {"hourly", "daily", "weekly", "monthly"}


def _now_utc(now: datetime | None = None) -> datetime:
    stamp = now or datetime.now(timezone.utc)
    if stamp.tzinfo is None:
        return stamp.replace(tzinfo=timezone.utc)
    return stamp


def _normalize_frequency(frequency: str | None) -> str:
    text = str(frequency or "daily").strip().lower()
    return text if text in VALID_FREQUENCIES else "daily"


def build_target_records(
    endpoints: Iterable[str],
    *,
    scan_frequency: str | None = "daily",
    enabled: bool = True,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    """Dedupe + normalize endpoints into scheduler-ready target records."""
    stamp = _now_utc(now)
    frequency = _normalize_frequency(scan_frequency)
    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in endpoints or []:
        endpoint = str(raw or "").strip()
        if not endpoint or endpoint in seen:
            continue
        seen.add(endpoint)
        records.append(
            {
                "endpoint": endpoint,
                "scan_frequency": frequency,
                "enabled": bool(enabled),
                "next_scan_time": stamp.isoformat(),
                "discovered_at": stamp.isoformat(),
                "source": "subnet-discovery",
            }
        )
    return records


def register_targets(
    repo: Any,
    endpoints: Iterable[str],
    *,
    scan_frequency: str | None = "daily",
    enabled: bool = True,
    existing: Iterable[str] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Upsert target records; returns honest new-vs-updated counts.

    ``existing`` (when provided) is the set of endpoints already known to the
    repository, so the result can distinguish ``registered`` (new) from
    ``updated`` (frequency/next-scan refreshed).
    """
    frequency = _normalize_frequency(scan_frequency)
    records = build_target_records(
        endpoints, scan_frequency=frequency, enabled=enabled, now=now
    )
    known = {str(item) for item in (existing or [])}
    registered = updated = 0
    for record in records:
        due_at = datetime.fromisoformat(record["next_scan_time"])
        repo.upsert_target(
            record["endpoint"],
            scan_frequency=record["scan_frequency"],
            enabled=record["enabled"],
            next_scan_time=due_at,
        )
        if record["endpoint"] in known:
            updated += 1
        else:
            registered += 1
    return {
        "registered": registered,
        "updated": updated,
        "total": len(records),
        "scan_frequency": frequency,
        "endpoints": [record["endpoint"] for record in records],
    }
