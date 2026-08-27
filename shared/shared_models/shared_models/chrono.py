"""Shared datetime contract for the platform.

All persistence and API boundaries exchange timezone-aware UTC datetimes;
SQLite drivers return naive datetimes that must be re-aware'd before
comparison. These helpers are the single source of that rule.
"""

from __future__ import annotations

from datetime import datetime, timezone


def utcnow() -> datetime:
    """Current timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def aware(dt: datetime | None) -> datetime | None:
    """Return ``dt`` as timezone-aware UTC; naive values are assumed UTC.

    ``None`` passes through unchanged (nullable DB columns).
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def iso_utc(dt: datetime | None = None) -> str:
    """ISO-8601 UTC timestamp string (aware, with offset)."""
    return (dt or utcnow()).isoformat()


def parse_iso(value: str | None) -> datetime | None:
    """Parse an ISO-8601 string to an aware datetime; ``None`` on failure.

    Naive inputs are assumed UTC (legacy rows written before the aware
    convention).
    """
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return aware(parsed)


def epoch_seconds(dt: datetime | None = None) -> float:
    """POSIX epoch seconds for an (aware) datetime, UTC normalised."""
    return aware(dt or utcnow()).timestamp()
