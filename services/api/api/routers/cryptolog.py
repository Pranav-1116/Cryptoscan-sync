"""CryptoLog ingestion and search API (docs/cryptolog/01_PRODUCT_SPEC.md,
Phase 2: the secure CryptoLog ingestion service).

Ingestion validates identity, schema, tenant and evidence metadata through
the Phase-1 contract (every construction-time refusal applies to stored
records), is idempotent per the identity rules, and never overwrites:
a conflicting event is refused and a correction supersedes with its own
provenance. Reads are keyset-paginated and tenant-scoped.
"""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session
from db.repositories.cryptolog_repository import CryptoLogRepository
from shared_models.bulk_result import (
    ACCEPTED, REJECTED, SKIPPED, bulk_result, item as bulk_item,
)
from shared_models.cryptolog_alerts import evaluate as evaluate_rules, transition as transition_alert
from shared_models.cryptolog_events import (
    CONFLICT, DUPLICATE, INSERTED, supersede, validate_event,
)

router = APIRouter(prefix="/cryptolog", tags=["cryptolog"])

_BATCH_OUTCOMES = {INSERTED: ACCEPTED, DUPLICATE: SKIPPED, CONFLICT: REJECTED}


class EventIn(BaseModel):
    model_config = {"extra": "allow"}

    event_id: Optional[str] = None
    event_type: Optional[str] = None
    category: Optional[str] = None
    logging_kind: Optional[str] = None
    tenant_id: Optional[str] = None
    severity: Optional[str] = None
    asset_id: Optional[str] = None
    business_system_id: Optional[str] = None
    source: dict[str, Any] = Field(default_factory=dict)
    cryptographic_context: dict[str, Any] = Field(default_factory=dict)
    observation: dict[str, Any] = Field(default_factory=dict)
    evidence: dict[str, Any] = Field(default_factory=dict)
    relationships: dict[str, Any] = Field(default_factory=dict)
    processing: dict[str, Any] = Field(default_factory=dict)
    investigation_status: Optional[str] = None
    telemetry_mode: Optional[str] = None
    approval_ref: Optional[str] = None
    attributes: dict[str, Any] = Field(default_factory=dict)


class BatchIn(BaseModel):
    events: list[dict[str, Any]] = Field(default_factory=list)


class CorrectionIn(BaseModel):
    corrected_event: dict[str, Any] = Field(default_factory=dict)
    reason: str
    actor: str
    evidence_ids: list[str] = Field(default_factory=list)


def _repo(db: Session) -> CryptoLogRepository:
    return CryptoLogRepository(db)


@router.post("/events", status_code=201)
def ingest_event(body: EventIn, response: Response,
                 db: Session = Depends(get_db_session),
                 user: str = Depends(get_current_user)) -> dict:
    """Ingest one event. 201 INSERTED, 200 DUPLICATE (idempotent), 409
    CONFLICT (a different event under an existing key is never a silent
    overwrite)."""
    try:
        result = _repo(db).insert_event(body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if result["outcome"] == CONFLICT:
        raise HTTPException(status_code=409, detail={
            "outcome": result["outcome"], "note": result["note"],
            "existing_event_id": result["event"].get("event_id")})
    if result["outcome"] == DUPLICATE:
        response.status_code = 200
    return result


@router.post("/events/batch")
def ingest_batch(body: BatchIn,
                 db: Session = Depends(get_db_session),
                 user: str = Depends(get_current_user)) -> dict:
    """Batch ingestion with explicit partial success: every item carries an
    ACCEPTED / SKIPPED / REJECTED outcome and a reason; totals are derived
    from the items, never invented."""
    rows = []
    repo = _repo(db)
    for index, raw in enumerate(body.events):
        key = f"events[{index}]"
        try:
            result = repo.insert_event(raw)
        except ValueError as exc:
            rows.append(bulk_item(key, REJECTED, str(exc)))
            continue
        rows.append(bulk_item(key, _BATCH_OUTCOMES[result["outcome"]],
                              result["note"]))
    return bulk_result(rows)


@router.get("/events")
def list_events(tenant_id: Optional[str] = Query(None),
                category: Optional[str] = Query(None),
                severity: Optional[str] = Query(None),
                event_type: Optional[str] = Query(None),
                asset_id: Optional[str] = Query(None),
                investigation_status: Optional[str] = Query(None),
                limit: int = Query(50, ge=1, le=200),
                cursor: Optional[str] = Query(None),
                db: Session = Depends(get_db_session),
                user: str = Depends(get_current_user)) -> dict:
    """Keyset-paginated event search. ``next_cursor`` is null on the last
    page; the response claims no totals it did not count."""
    try:
        return _repo(db).list_events(
            tenant_id=tenant_id, category=category, severity=severity,
            event_type=event_type, asset_id=asset_id,
            investigation_status=investigation_status, limit=limit,
            cursor=cursor)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/events/{event_id}")
def get_event(event_id: str,
              db: Session = Depends(get_db_session),
              user: str = Depends(get_current_user)) -> dict:
    row = _repo(db).get_event(None, event_id)
    if row is None:
        raise HTTPException(status_code=404, detail="event not found")
    from db.repositories.cryptolog_repository import row_to_event
    return row_to_event(row)


@router.post("/events/{event_id}/corrections", status_code=201)
def correct_event(event_id: str, body: CorrectionIn,
                  db: Session = Depends(get_db_session),
                  user: str = Depends(get_current_user)) -> dict:
    """Supersede an event with a correction. The original row is preserved
    byte-identical; the correction carries its own reason, actor and
    evidence."""
    repo = _repo(db)
    row = repo.get_event(None, event_id)
    if row is None:
        raise HTTPException(status_code=404, detail="event not found")
    from db.repositories.cryptolog_repository import row_to_event
    original = row_to_event(row)
    try:
        corrected = validate_event(body.corrected_event or {})
        correction = supersede(original=original, corrected=corrected,
                               reason=body.reason, actor=body.actor,
                               evidence_ids=body.evidence_ids)
        return repo.insert_correction(
            tenant_id=str(original.get("tenant_id") or ""),
            original=original, correction=correction)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/events/{event_id}/corrections")
def list_corrections(event_id: str,
                     db: Session = Depends(get_db_session),
                     user: str = Depends(get_current_user)) -> dict:
    rows = _repo(db).list_corrections(event_id)
    return {"event_id": event_id, "corrections": rows,
            "returned": len(rows)}


class AlertEvaluateIn(BaseModel):
    events: list[dict[str, Any]] = Field(default_factory=list)
    previous_by_asset: dict[str, dict[str, Any]] = Field(default_factory=dict)
    assessments: dict[str, dict[str, Any]] = Field(default_factory=dict)


class AlertTransitionIn(BaseModel):
    alert: dict[str, Any] = Field(default_factory=dict)
    action: str
    actor: str
    at: str
    note: Optional[str] = None
    resolution: Optional[str] = None
    evidence_ids: list[str] = Field(default_factory=list)


@router.post("/alerts/evaluate")
def evaluate_alerts(body: AlertEvaluateIn,
                    db: Session = Depends(get_db_session),
                    user: str = Depends(get_current_user)) -> dict:
    """Deterministic rules CL-001..CL-015 over a recorded event stream.
    Every result is an OPEN investigation carrying what is proven and what
    is not — a pattern never automatically becomes a confirmed compromise,
    and severity is named drivers, never one unexplained number."""
    try:
        alerts = evaluate_rules(body.events,
                                previous_by_asset=body.previous_by_asset,
                                assessments=body.assessments)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"alerts": alerts, "returned": len(alerts)}


@router.post("/alerts/transition")
def alert_transition(body: AlertTransitionIn,
                     db: Session = Depends(get_db_session),
                     user: str = Depends(get_current_user)) -> dict:
    """Append-only alert lifecycle. CONFIRMED_INCIDENT is the only
    resolution that names a compromise, and it demands a named actor with
    evidence — the engine never declares one."""
    try:
        return transition_alert(body.alert, action=body.action,
                                actor=body.actor, at=body.at, note=body.note,
                                resolution=body.resolution,
                                evidence_ids=body.evidence_ids)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
