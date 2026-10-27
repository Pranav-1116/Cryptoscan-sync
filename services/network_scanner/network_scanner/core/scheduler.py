"""Decide which TLS targets are due given last_scan_time + frequency."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping

INTERVALS = {
    "hourly": timedelta(hours=1),
    "daily": timedelta(days=1),
    "weekly": timedelta(days=7),
    "monthly": timedelta(days=30),
}


def _as_dt(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    text = str(value)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def interval_for(frequency: str | None) -> timedelta:
    return INTERVALS.get(str(frequency or "daily").lower(), INTERVALS["daily"])


def next_scan_time(last_scan: Any, frequency: str | None = "daily", *, now: datetime | None = None) -> datetime:
    now = now or datetime.now(timezone.utc)
    last = _as_dt(last_scan)
    if last is None:
        return now
    return last + interval_for(frequency)


def is_due(target: Mapping[str, Any], *, now: datetime | None = None) -> bool:
    now = now or datetime.now(timezone.utc)
    if target.get("enabled") is False:
        return False
    scheduled = _as_dt(target.get("next_scan_time"))
    if scheduled is not None:
        return scheduled <= now
    return next_scan_time(target.get("last_scan_time"), target.get("scan_frequency"), now=now) <= now


def due_targets(targets: Iterable[Mapping[str, Any]], *, now: datetime | None = None) -> list[dict[str, Any]]:
    now = now or datetime.now(timezone.utc)
    out = []
    for target in targets:
        payload = dict(target)
        payload["due"] = is_due(payload, now=now)
        payload["computed_next_scan_time"] = next_scan_time(
            payload.get("last_scan_time"), payload.get("scan_frequency"), now=now
        ).isoformat()
        if payload["due"]:
            out.append(payload)
    return out
