"""Live monitoring control plane: watch-list CRUD, live status, event feed.

The daemon (scripts/run_monitor.py) does the scanning; these endpoints manage
what it watches and expose the live picture for the dashboard. `scan-now`
runs one target synchronously through the same engine — a live TLS probe for
NETWORK targets, so expect probe latency, not instant results.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session, require_auditor

router = APIRouter(tags=["monitor"])

VALID_TYPES = ("NETWORK", "CLOUD", "REPO", "CONTAINER", "PAYMENT", "OT", "VENDOR")
# Change-watch (realtime rescan-on-change) is only meaningful where a cheap
# fingerprint probe exists: git HEAD for REPO, local image id for CONTAINER,
# OT capture-directory fingerprint for OT.
WATCHABLE_TYPES = ("REPO", "CONTAINER", "OT")


def _validate_config(config: dict, target_type: str) -> dict:
    """Validate + sanitize a target config before it reaches the daemon."""
    clean = dict(config or {})
    # watch_state is engine-managed (fingerprints / probe errors) — never client-supplied
    clean.pop("watch_state", None)
    if clean.get("watch"):
        if target_type not in WATCHABLE_TYPES:
            raise HTTPException(
                status_code=422,
                detail=f"config.watch is only supported for {WATCHABLE_TYPES} (got {target_type}) — "
                       "enable change-watch on a REPO or CONTAINER target",
            )
    return clean


class TargetCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    target_type: str
    config: dict = Field(default_factory=dict)
    interval_seconds: int | None = None


class TargetUpdate(BaseModel):
    enabled: bool | None = None
    interval_seconds: int | None = None
    config: dict | None = None


def _repo(db: Session):
    from db.repositories.monitor_repository import MonitorRepository

    return MonitorRepository(db)


def _daemon_health(db: Session) -> dict:
    """Is a monitor daemon alive *right now*? Reads the leader-lease row.

    The daemon heartbeats ``monitor_leases`` (name='monitor') every tick; a
    lease held with an unexpired ``expires_at`` is proof a daemon is running.
    No row / expired row = nobody is watching — honest, not assumed.
    """
    from datetime import datetime, timezone

    from sqlalchemy import select

    from db.models.monitor import MonitorLease

    try:
        row = db.execute(select(MonitorLease).where(MonitorLease.name == "monitor")).scalar_one_or_none()
    except Exception:
        return {"alive": False, "detail": "lease table unavailable", "script": "scripts/run_monitor.py"}
    now = datetime.now(timezone.utc)
    if row is None or row.expires_at is None:
        return {"alive": False, "detail": "no leader lease — daemon not observed", "script": "scripts/run_monitor.py"}
    expires = row.expires_at if row.expires_at.tzinfo else row.expires_at.replace(tzinfo=timezone.utc)
    alive = expires > now
    return {
        "alive": alive,
        "holder": row.holder,
        "expires_at": row.expires_at.isoformat() if row.expires_at else None,
        "detail": "lease held" if alive else "lease expired — daemon down or failover in progress",
        "script": "scripts/run_monitor.py",
    }


def _serialize(target) -> dict:
    return {
        "id": target.id,
        "name": target.name,
        "target_type": target.target_type,
        "config": target.config or {},
        "interval_seconds": target.interval_seconds,
        "enabled": target.enabled,
        "status": target.status,
        "last_scan_at": target.last_scan_at.isoformat() if target.last_scan_at else None,
        "next_scan_at": target.next_scan_at.isoformat() if target.next_scan_at else None,
        "last_summary": target.last_summary,
        "consecutive_failures": target.consecutive_failures,
        "last_error": target.last_error,
    }


@router.get("/monitor/targets")
def list_targets(
    enabled: bool | None = None,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    return {"targets": [_serialize(row) for row in _repo(db).list_targets(enabled=enabled)]}


@router.post("/monitor/targets", status_code=201)
def create_target(
    body: TargetCreate,
    user: str = Depends(require_auditor),
    db: Session = Depends(get_db_session),
):
    from worker.monitor.engine import DEFAULT_INTERVALS, default_interval

    if body.target_type not in VALID_TYPES:
        raise HTTPException(status_code=422, detail=f"target_type must be one of {VALID_TYPES}")
    if body.target_type == "NETWORK" and not (
        body.config.get("endpoints")
        or body.config.get("endpoint")
        or body.config.get("ipsec")
        or body.config.get("dnssec")
    ):
        raise HTTPException(
            status_code=422,
            detail="NETWORK targets need config.endpoints (['host:port', …]) or config.ipsec / config.dnssec lists",
        )
    if body.target_type == "OT" and not (body.config.get("path") or body.config.get("directory")):
        raise HTTPException(status_code=422, detail="OT targets need config.path (passive capture/log directory)")
    if body.target_type == "VENDOR" and not (body.config.get("name") or "").strip():
        raise HTTPException(status_code=422, detail="VENDOR targets need config.name (vendor name)")
    if body.interval_seconds is not None and not (60 <= body.interval_seconds <= 2_592_000):
        raise HTTPException(status_code=422, detail="interval_seconds must be between 60 and 2592000")
    config = _validate_config(body.config, body.target_type)
    repo = _repo(db)
    if repo.get_by_name(body.name) is not None:
        raise HTTPException(status_code=409, detail=f"target '{body.name}' already exists")
    row = repo.create(
        name=body.name,
        target_type=body.target_type,
        config=config,
        interval_seconds=body.interval_seconds or DEFAULT_INTERVALS.get(body.target_type, default_interval(body.target_type)),
        created_by=user,
    )
    db.commit()
    return _serialize(row)


@router.patch("/monitor/targets/{target_id}")
def update_target(
    target_id: str,
    body: TargetUpdate,
    user: str = Depends(require_auditor),
    db: Session = Depends(get_db_session),
):
    repo = _repo(db)
    row = repo.get(target_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Target not found")
    if body.interval_seconds is not None:
        if not (60 <= body.interval_seconds <= 2_592_000):
            raise HTTPException(status_code=422, detail="interval_seconds must be between 60 and 2592000")
        row.interval_seconds = body.interval_seconds
    if body.config is not None:
        row.config = _validate_config(body.config, row.target_type)
    if body.enabled is not None:
        row.enabled = body.enabled
        if not body.enabled and row.status not in {"PAUSED"}:
            row.status = "PAUSED"
        elif body.enabled and row.status == "PAUSED":
            row.status = "PENDING"
    db.commit()
    return _serialize(row)


@router.delete("/monitor/targets/{target_id}")
def delete_target(
    target_id: str,
    user: str = Depends(require_auditor),
    db: Session = Depends(get_db_session),
):
    if not _repo(db).delete(target_id):
        raise HTTPException(status_code=404, detail="Target not found")
    db.commit()
    return {"deleted": target_id}


@router.post("/monitor/targets/{target_id}/scan-now")
def scan_now(
    target_id: str,
    user: str = Depends(require_auditor),
    db: Session = Depends(get_db_session),
):
    """Run one target immediately, synchronously (live probe for NETWORK)."""
    from worker.monitor.engine import MonitorEngine

    repo = _repo(db)
    target = repo.get(target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")
    if not target.enabled:
        raise HTTPException(status_code=409, detail="target is paused — enable it first")
    outcome = MonitorEngine(db).run_target(target)
    db.commit()
    return outcome


@router.get("/monitor/status")
def monitor_status(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    """The live picture: what is watched, its health, what happened lately."""
    from datetime import datetime, timezone

    repo = _repo(db)
    targets = repo.list_targets()
    overview = {
        "targets_total": len(targets),
        "by_status": repo.status_counts(),
        "by_type": repo.type_counts(),
        "enabled": sum(1 for row in targets if row.enabled),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "daemon": "scripts/run_monitor.py (this API does not run the loop)",
        "daemon_health": _daemon_health(db),
    }
    attention = [
        _serialize(row)
        for row in targets
        if row.status in {"FAILING", "BLOCKED", "DEGRADED"} and row.enabled
    ]
    events = [
        {
            "id": event.id,
            "target_name": event.target_name,
            "event_type": event.event_type,
            "detail": event.detail,
            "created_at": event.created_at.isoformat() if event.created_at else None,
        }
        for event in repo.list_events(limit=20)
    ]
    return {"overview": overview, "needs_attention": attention, "recent_events": events}


@router.get("/monitor/events")
def monitor_events(
    target_id: str | None = None,
    limit: int = 50,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    rows = _repo(db).list_events(target_id=target_id, limit=limit)
    return {
        "events": [
            {
                "id": event.id,
                "target_id": event.target_id,
                "target_name": event.target_name,
                "event_type": event.event_type,
                "detail": event.detail,
                "payload": event.payload,
                "created_at": event.created_at.isoformat() if event.created_at else None,
            }
            for event in rows
        ]
    }
