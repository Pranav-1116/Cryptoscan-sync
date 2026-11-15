"""Target-scoped scan locks: prevent conflicting jobs on one target (§10).

Two workers scanning the same target duplicate findings and race on
shared state. This module is the coordination primitive behind
``TargetScanLock`` (migration 0159): one lock row per (tenant, target),
acquired by compare-and-set, stealable when the holder's lease expired,
released after the run.

Design notes:
- A conflict is READER-INFORMED: the loser learns who holds the lock and
  until when, so the caller can defer the job (retryable) instead of
  failing it silently.
- An expired lock is stealable: a worker that died mid-scan must not
  wedge its target forever. The steal is itself a CAS on ``owner``.
- Tenant isolation is part of the lock identity: two tenants scanning the
  same target string are independent estates and never contend. A NULL
  tenant (platform estate) is normalized to ``""`` because NULLs never
  collide in a unique index — without this the platform's own locks would
  not exclude each other.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterator, Optional

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

LOCK_TTL_SECONDS = 900

_STATS = {"acquired": 0, "released": 0, "conflicts": 0, "steals": 0}


class TargetLocked(Exception):
    """Raised when the target is held by another owner. Carries the
    holder and expiry so the caller can report the conflict honestly."""

    def __init__(self, result: Dict[str, Any]):
        super().__init__(result.get("reason", "target locked"))
        self.result = result


def lock_stats() -> Dict[str, int]:
    return dict(_STATS)


def target_key_for(job: Any) -> str:
    """The lock identity of a job's target: repo + branch for repository
    scans, the target string otherwise. Bounded by the column."""
    repo = str(getattr(job, "target_repo", "") or "")
    branch = str(getattr(job, "target_branch", "main") or "main")
    return f"{repo}#{branch}"[:200]


def _scope(tenant_id: Optional[str]) -> str:
    return tenant_id or ""


def _aware(value: Optional[datetime]) -> Optional[datetime]:
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def acquire_target_lock(db, tenant_id: Optional[str], target_key: str,
                        owner: str, *,
                        ttl_seconds: int = LOCK_TTL_SECONDS,
                        now: Optional[datetime] = None) -> Dict[str, Any]:
    """Acquire the lock for (tenant, target) under CAS semantics.

    Returns a dict: ``acquired`` plus either the lease (``owner``,
    ``expires_at``) or the current holder on conflict (``owner``,
    ``expires_at``, ``reason``). An expired holder is stolen — a dead
    worker's lock must not wedge the target."""
    from db.models.target_scan_lock import TargetScanLock

    now = now or datetime.now(timezone.utc)
    scope = _scope(tenant_id)
    lease = now + timedelta(seconds=ttl_seconds)
    row = db.scalar(select(TargetScanLock).where(
        TargetScanLock.tenant_id == scope,
        TargetScanLock.target_key == target_key))
    if row is None:
        lock = TargetScanLock(tenant_id=scope, target_key=target_key,
                              owner=owner, acquired_at=now, expires_at=lease)
        db.add(lock)
        try:
            db.commit()
        except IntegrityError:
            # Lost the insert race: another worker committed between our
            # SELECT and INSERT. That is a conflict, never a silent overwrite.
            db.rollback()
            _STATS["conflicts"] += 1
            contender = db.scalar(select(TargetScanLock).where(
                TargetScanLock.tenant_id == scope,
                TargetScanLock.target_key == target_key))
            return {
                "acquired": False,
                "owner": contender.owner if contender else None,
                "expires_at": _aware(contender.expires_at) if contender else None,
                "reason": "target locked: lost the insert race",
            }
        _STATS["acquired"] += 1
        return {"acquired": True, "owner": owner, "expires_at": lease}

    current_owner = row.owner
    current_expiry = _aware(row.expires_at)
    if current_owner == owner:
        # Re-entrant: the same job retried after a deferred run refreshes.
        row.acquired_at = now
        row.expires_at = lease
        db.commit()
        _STATS["acquired"] += 1
        return {"acquired": True, "owner": owner, "expires_at": lease}

    if current_expiry is not None and current_expiry <= now:
        # Steal: the holder's lease expired (worker died mid-scan). The
        # steal is a CAS on owner so two thieves cannot both win.
        result = db.execute(
            TargetScanLock.__table__.update()
            .where(TargetScanLock.id == row.id,
                   TargetScanLock.owner == current_owner)
            .values(owner=owner, acquired_at=now, expires_at=lease))
        db.commit()
        if result.rowcount == 1:
            _STATS["steals"] += 1
            _STATS["acquired"] += 1
            return {"acquired": True, "owner": owner, "expires_at": lease,
                    "stole": True, "previous_owner": current_owner}
        _STATS["conflicts"] += 1
        return {"acquired": False, "owner": current_owner,
                "expires_at": current_expiry,
                "reason": "target locked: steal race lost"}

    _STATS["conflicts"] += 1
    return {
        "acquired": False,
        "owner": current_owner,
        "expires_at": current_expiry,
        "reason": (f"target locked by {current_owner} until "
                   f"{current_expiry.isoformat() if current_expiry else 'expiry unknown'}"),
    }


def release_target_lock(db, tenant_id: Optional[str], target_key: str,
                        owner: str) -> bool:
    """Release a lock we own. A lock held by another owner is never
    released (the steal already moved it on)."""
    from db.models.target_scan_lock import TargetScanLock

    row = db.scalar(select(TargetScanLock).where(
        TargetScanLock.tenant_id == _scope(tenant_id),
        TargetScanLock.target_key == target_key))
    if row is None or row.owner != owner:
        return False
    db.delete(row)
    db.commit()
    _STATS["released"] += 1
    return True


@contextmanager
def target_scan_lock(db, tenant_id: Optional[str], target_key: str,
                     owner: str, *,
                     ttl_seconds: int = LOCK_TTL_SECONDS
                     ) -> Iterator[Dict[str, Any]]:
    """Hold the lock for the duration of a run. Raises ``TargetLocked``
    on conflict (with the holder's identity) and always releases."""
    result = acquire_target_lock(db, tenant_id, target_key, owner,
                                 ttl_seconds=ttl_seconds)
    if not result.get("acquired"):
        raise TargetLocked(result)
    try:
        yield result
    finally:
        release_target_lock(db, tenant_id, target_key, owner)


@contextmanager
def with_job_target_lock(job: Any, *,
                         ttl_seconds: int = LOCK_TTL_SECONDS
                         ) -> Iterator[Dict[str, Any]]:
    """Hold the target lock for one job's run. Sessions are short-lived —
    the lock is a committed row, not a transaction held across the scan.

    Degraded mode: when the lock table cannot be consulted at all (a
    deployment without migration 0159 yet, a database that is itself the
    outage), the job proceeds UNLOCKED with a loud warning. The execution
    gate above already fails closed on a database it cannot read; the lock
    is an anti-conflict measure, not the authority boundary. A genuine
    CONFLICT is never degraded away — it raises ``TargetLocked``."""
    import logging

    from db.connection.session import SessionLocal

    key = target_key_for(job)
    owner = getattr(job, "job_id", "unknown")
    try:
        with SessionLocal() as db:
            result = acquire_target_lock(db, getattr(job, "tenant_id", None),
                                         key, owner, ttl_seconds=ttl_seconds)
    except Exception as exc:  # noqa: BLE001 - degraded mode is the point
        logging.getLogger(__name__).warning(
            "target_lock_unavailable_proceeding_unlocked",
            extra={"job_id": owner, "target": key,
                   "error_type": type(exc).__name__})
        yield {"acquired": True, "owner": owner, "degraded": True}
        return
    if not result.get("acquired"):
        raise TargetLocked(result)
    try:
        yield result
    finally:
        try:
            with SessionLocal() as db:
                release_target_lock(db, getattr(job, "tenant_id", None),
                                    key, owner)
        except Exception:  # noqa: BLE001 - release is best-effort; expiry steals
            logging.getLogger(__name__).warning(
                "target_lock_release_failed", exc_info=True,
                extra={"job_id": owner, "target": key})
