"""Durable event/queue semantics for the scan orchestrator.

Provides deterministic helpers for priority ordering, retry/backoff and
lease handling that operate on plain dicts (rows from ``cp_queued_events``).
Transport in production is Redis (the worker already uses it); the table is
the persistent outbox/audit and fallback. This keeps orchestration logic
unit-testable without a broker.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

PRIORITY_RANK = {"critical": 0, "high": 1, "normal": 2, "low": 3}


def ordering_key(event: dict) -> tuple[int, str]:
    """Critical first, then by enqueue time (FIFO within a priority)."""
    return (PRIORITY_RANK.get(event.get("priority", "normal"), 2), str(event.get("created_at") or ""))


def next_available(events: list[dict], *, now: datetime | None = None) -> dict | None:
    """Pick the highest-priority event whose availability time has arrived and
    which is not already completed/dead."""
    now = now or datetime.now(timezone.utc)
    eligible = []
    for e in events:
        if e.get("status") not in {"queued"}:
            continue
        avail = e.get("available_at")
        if isinstance(avail, str):
            try:
                avail = datetime.fromisoformat(avail.replace("Z", "+00:00"))
            except ValueError:
                avail = None
        if isinstance(avail, datetime) and avail > now:
            continue
        eligible.append(e)
    if not eligible:
        return None
    return min(eligible, key=ordering_key)


def backoff_delay(attempts: int, base_seconds: int = 30, max_seconds: int = 3600) -> int:
    """Exponential backoff with cap for retried events."""
    delay = base_seconds * (2 ** max(0, attempts - 1))
    return min(max_seconds, delay)


def classify_after_failure(event: dict, *, now: datetime | None = None) -> dict:
    """Return updated status/availability fields after a processing failure.

    Dead-letters after max_attempts; otherwise schedules a backoff retry.
    """
    now = now or datetime.now(timezone.utc)
    attempts = int(event.get("attempts", 0)) + 1
    max_attempts = int(event.get("max_attempts", 5))
    if attempts >= max_attempts:
        return {"attempts": attempts, "status": "dead",
                "leased_by": None, "available_at": now}
    return {"attempts": attempts, "status": "queued", "leased_by": None,
            "available_at": now + timedelta(seconds=backoff_delay(attempts))}


def lease_event(event: dict, worker_id: str, *, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    return {"status": "leased", "leased_by": worker_id, "leased_at": now,
            "attempts": int(event.get("attempts", 0)) + 1}
