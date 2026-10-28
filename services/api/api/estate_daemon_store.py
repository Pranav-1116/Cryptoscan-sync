"""Read/write the estate daemon heartbeat (spec 93 §18)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping

from sqlalchemy import select

from db.models.estate_daemon import EstateDaemon

FIELDS = (
    "worker", "state", "version", "started_at", "last_cycle_at", "last_cycle_seconds", "cycles", "runs",
    "failures", "consecutive_failures", "last_error", "next_wake_at", "idle_reason", "pid",
)

DATETIME_FIELDS = ("started_at", "last_cycle_at", "next_wake_at")


def _utc(moment: datetime | None) -> datetime | None:
    if moment is None:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def _parse(value: Any) -> Any:
    if isinstance(value, datetime):
        return _utc(value)
    if isinstance(value, str) and value:
        try:
            return _utc(datetime.fromisoformat(value.replace("Z", "+00:00")))
        except ValueError:
            return None
    return None


def record_heartbeat(db: Any, heartbeat: Mapping[str, Any]) -> EstateDaemon:
    """Upsert one heartbeat. The worker name is the identity, not a new row per cycle."""
    worker = str(heartbeat.get("worker") or "cryptoscan-daemon")
    row = db.execute(select(EstateDaemon).where(EstateDaemon.worker == worker)).scalars().first()
    if row is None:
        row = EstateDaemon(worker=worker)
        db.add(row)
    for field in FIELDS:
        if field not in heartbeat:
            continue
        value = heartbeat[field]
        if field in DATETIME_FIELDS:
            value = _parse(value)
        setattr(row, field, value)
    db.flush()
    return row


def as_dict(row: EstateDaemon) -> dict[str, Any]:
    return {
        "worker": row.worker,
        "state": row.state,
        "version": row.version,
        "started_at": _utc(row.started_at).isoformat() if row.started_at else None,
        "last_cycle_at": _utc(row.last_cycle_at).isoformat() if row.last_cycle_at else None,
        "last_cycle_seconds": row.last_cycle_seconds,
        "cycles": int(row.cycles or 0),
        "runs": int(row.runs or 0),
        "failures": int(row.failures or 0),
        "consecutive_failures": int(row.consecutive_failures or 0),
        "last_error": row.last_error,
        "next_wake_at": _utc(row.next_wake_at).isoformat() if row.next_wake_at else None,
        "idle_reason": row.idle_reason,
        "pid": row.pid,
        "updated_at": _utc(row.updated_at).isoformat() if row.updated_at else None,
    }


def heartbeats(db: Any, *, limit: int = 10) -> list[dict[str, Any]]:
    rows = db.execute(
        select(EstateDaemon).order_by(EstateDaemon.last_cycle_at.desc().nullslast()).limit(limit)
    ).scalars().all()
    return [as_dict(row) for row in rows]


def latest(db: Any) -> dict[str, Any] | None:
    rows = heartbeats(db, limit=1)
    return rows[0] if rows else None
