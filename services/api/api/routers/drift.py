"""Drift events."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from api.dependencies import get_current_user, get_db_session, get_drift_repository, require_auditor
from api.schemas.drift_schemas import DriftEventResponse, DriftListResponse
from db.repositories.drift_repository import DriftRepository

router = APIRouter(prefix="/drift", tags=["drift"])


class AckBody(BaseModel):
    notes: str | None = None


def _to_response(row) -> DriftEventResponse:
    return DriftEventResponse(
        drift_id=row.id,
        current_scan_id=row.current_scan_id,
        baseline_id=row.baseline_id,
        drift_type=row.drift_type,
        severity=row.severity,
        detected_at=row.detected_at.isoformat() if row.detected_at else None,
        resolution_status=row.resolution_status,
        drift_details=row.drift_details,
        resolved_by=row.resolved_by,
        resolution_notes=row.resolution_notes,
    )


@router.get("", response_model=DriftListResponse)
def list_drift(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    severity: str | None = None,
    status: str | None = None,
    scan_id: str | None = None,
    drift_type: str | None = Query(None, description="Filter by drift type, e.g. CONFIG_CHANGED"),
    user: str = Depends(get_current_user),
    repo: DriftRepository = Depends(get_drift_repository),
):
    rows, total = repo.list_events(
        severity=severity,
        status=status,
        scan_id=scan_id,
        drift_type=drift_type,
        page=page,
        page_size=page_size,
    )
    return DriftListResponse(
        events=[_to_response(r) for r in rows],
        total_count=total,
        page=page,
        page_size=page_size,
    )


@router.get("/digest")
def drift_digest(
    hours: int = Query(24, ge=1, le=168),
    user: str = Depends(get_current_user),
    repo: DriftRepository = Depends(get_drift_repository),
):
    from drift.alerts.daily_digest import build_digest, window_start

    events = repo.list_since(window_start(hours=hours), page_size=500)
    return build_digest(events, window_hours=hours)


def _audit(db, actor: str, action: str, drift_id: str, body) -> None:
    try:
        from db.repositories.user_repository import UserRepository

        UserRepository(db).audit(
            actor, action, target_type="drift_event", target_id=drift_id,
            detail={"notes": body.notes if body else None},
        )
        db.commit()
    except Exception:
        pass


@router.post("/{drift_id}/acknowledge", response_model=DriftEventResponse)
def acknowledge(
    drift_id: str,
    body: AckBody | None = None,
    user: str = Depends(require_auditor),
    repo: DriftRepository = Depends(get_drift_repository),
    db=Depends(get_db_session),
):
    row = repo.acknowledge(drift_id, user, notes=(body.notes if body else None))
    if row is None:
        raise HTTPException(status_code=404, detail="Drift event not found")
    _audit(db, user, "drift.acknowledge", drift_id, body)
    return _to_response(row)


@router.post("/{drift_id}/resolve", response_model=DriftEventResponse)
def resolve_drift(
    drift_id: str,
    body: AckBody | None = None,
    user: str = Depends(require_auditor),
    repo: DriftRepository = Depends(get_drift_repository),
    db=Depends(get_db_session),
):
    row = repo.resolve(drift_id, user, notes=(body.notes if body else None))
    if row is None:
        raise HTTPException(status_code=404, detail="Drift event not found")
    _audit(db, user, "drift.resolve", drift_id, body)
    return _to_response(row)


@router.post("/{drift_id}/false-positive", response_model=DriftEventResponse)
def false_positive(
    drift_id: str,
    body: AckBody | None = None,
    user: str = Depends(require_auditor),
    repo: DriftRepository = Depends(get_drift_repository),
    db=Depends(get_db_session),
):
    row = repo.mark_false_positive(drift_id, user, notes=(body.notes if body else None))
    if row is None:
        raise HTTPException(status_code=404, detail="Drift event not found")
    _audit(db, user, "drift.false_positive", drift_id, body)
    return _to_response(row)
