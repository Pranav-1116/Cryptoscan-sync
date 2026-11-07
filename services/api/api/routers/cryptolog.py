"""CryptoLog ingestion and search API (docs/cryptolog/01_PRODUCT_SPEC.md,
Phase 2: the secure CryptoLog ingestion service).

Ingestion validates identity, schema, tenant and evidence metadata through
the Phase-1 contract (every construction-time refusal applies to stored
records), is idempotent per the identity rules, and never overwrites:
a conflicting event is refused and a correction supersedes with its own
provenance. Reads are keyset-paginated and tenant-scoped.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session
from db.repositories.cryptolog_repository import (
    CryptoLogAlertRepository, CryptoLogRepository,
)
from shared_models.bulk_result import (
    ACCEPTED, REJECTED, SKIPPED, bulk_result, item as bulk_item,
)
from shared_models.cryptolog_alerts import evaluate as evaluate_rules, transition as transition_alert
from shared_models.cryptolog_integrity import (
    build_chain, chain_genesis, make_checkpoint, merkle_proof, merkle_root,
    verify_merkle_proof, verify_checkpoint, verify_range,
)
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
    store = CryptoLogAlertRepository(db)
    tenant = (str(body.events[0].get("tenant_id")) if body.events
              and body.events[0].get("tenant_id") else None) or _tenant(user)
    by_id = {str(e.get("event_id") or ""): e for e in body.events}
    persisted = {"INSERTED": 0, "DUPLICATE": 0}
    stored_alerts = []
    for alert in alerts:
        row = _alert_row(alert, by_id)
        outcome = store.insert_alert(tenant_id=str(tenant), alert=row)["outcome"]
        persisted[outcome] = persisted.get(outcome, 0) + 1
        stored_alerts.append({**alert, "alert_id": row["alert_id"]})
    return {"alerts": stored_alerts, "returned": len(stored_alerts),
            "persisted": persisted}


def _alert_row(alert: Mapping[str, Any],
               events_by_id: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    """Storage identity for a Phase-5 alert: deterministic per rule and its
    supporting events, so re-evaluation is idempotent and never invents a
    second alert for the same finding."""
    import hashlib
    rule_id = str(alert.get("rule_id") or "")
    event_ids = [str(e) for e in (alert.get("supporting_event_ids") or [])]
    key = f"{rule_id}|{','.join(sorted(event_ids))}"
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:20]
    affected = alert.get("affected") or {}
    asset_ids = list(affected.get("asset_ids") or []) if isinstance(affected, dict) else []
    first = events_by_id.get(event_ids[0]) if event_ids else None
    occurred = ""
    if first is not None:
        occurred = str((first.get("observation") or {}).get("observed_at")
                       or first.get("observed") or "")
    lifecycle = alert.get("lifecycle") or {}
    return {
        "alert_id": f"alrt_{digest}",
        "rule_id": rule_id,
        "event_id": event_ids[0] if event_ids else "unattributed",
        "asset_id": asset_ids[0] if asset_ids else "unattributed",
        "severity": str(alert.get("severity") or "INFO"),
        "state": str(lifecycle.get("status") or "OPEN"),
        "title": f"{rule_id}: {(alert.get('rule') or {}).get('detection') or rule_id}",
        "basis": {
            "severity_basis": alert.get("severity_basis"),
            "severity_drivers": alert.get("severity_drivers"),
            "rule": alert.get("rule"),
        },
        "what_is_proven": list(alert.get("what_is_proven") or []),
        "what_is_not_proven": list(alert.get("what_is_not_proven") or []),
        "evidence_ids": list(alert.get("supporting_evidence_ids") or []),
        "occurred_at": occurred,
        "transitions": list(lifecycle.get("history") or []),
    }


class AlertOut(BaseModel):
    model_config = {"extra": "allow"}

    alert_id: str
    rule_id: str
    event_id: str
    asset_id: str
    severity: str
    state: str
    title: str
    basis: dict[str, Any] = Field(default_factory=dict)
    what_is_proven: list[Any] = Field(default_factory=list)
    what_is_not_proven: list[Any] = Field(default_factory=list)
    evidence_ids: list[Any] = Field(default_factory=list)
    occurred_at: str = ""
    transitions: list[Any] = Field(default_factory=list)


class AlertsPageOut(BaseModel):
    rows: list[AlertOut] = Field(default_factory=list)
    total_count: int = 0
    next_cursor: Optional[str] = None
    has_more: bool = False


class CheckpointOut(BaseModel):
    model_config = {"extra": "allow"}

    checkpoint_ref: str
    schema: Optional[str] = None
    partition_id: Optional[str] = None
    sequence: Optional[int] = None
    chain_hash: Optional[str] = None
    merkle_root_hash: Optional[str] = None
    event_count: Optional[int] = None
    signer_id: Optional[str] = None
    signature: Optional[str] = None
    retention_ref: Optional[str] = None


class CheckpointsPageOut(BaseModel):
    rows: list[CheckpointOut] = Field(default_factory=list)
    total_count: int = 0


class MerkleProofOut(BaseModel):
    event_id: str
    event_hash: str
    index: int
    checkpoint_ref: str
    merkle_root_hash: str
    proof: list[Any] = Field(default_factory=list)
    verified: bool = False


class CheckpointCreateOut(BaseModel):
    outcome: str
    checkpoint: CheckpointOut


class VerifyOut(BaseModel):
    model_config = {"extra": "allow"}

    schema: Optional[str] = None
    partition_id: Optional[str] = None
    results: list[Any] = Field(default_factory=list)
    overall_state: str = "UNVERIFIED"
    note: str = ""
    checkpoint_used: bool = False
    input: dict[str, Any] = Field(default_factory=dict)


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


def _tenant(user: Any) -> Optional[str]:
    """Tenancy from the authenticated principal whether it is a user model
    or the bare identity string the tests inject."""
    tid = getattr(user, "tenant_id", None)
    if tid:
        return str(tid)
    return str(user) if isinstance(user, str) else None


# ---------------------------------------------------------------------------
# Alerts: listing with honest counts, and append-only transitions.
# ---------------------------------------------------------------------------


@router.get("/alerts")
def list_alerts(
    response: Response,
    tenant_id: Optional[str] = Query(None),
    state: Optional[str] = None,
    severity: Optional[str] = None,
    rule_id: Optional[str] = None,
    event_id: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    cursor: Optional[str] = None,
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
) -> AlertsPageOut:
    """Alert listing. total_count reflects the active filters — never a
    page size mistaken for a corpus size."""
    repo = CryptoLogAlertRepository(db)
    result = repo.list_alerts(
        tenant_id=tenant_id, state=state, severity=severity,
        rule_id=rule_id, event_id=event_id, limit=limit, cursor=cursor)
    response.headers["X-Total-Count"] = str(result["total_count"])
    return {
        "rows": result["rows"],
        "total_count": result["total_count"],
        "next_cursor": result["next_cursor"],
        "has_more": result["has_more"],
    }


@router.get("/alerts/{alert_id}")
def get_alert(
    alert_id: str,
    tenant_id: Optional[str] = Query(None),
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
) -> AlertOut:
    repo = CryptoLogAlertRepository(db)
    alert = repo.get_alert(tenant_id, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail=f"alert not found: {alert_id}")
    return alert


class TransitionIn(BaseModel):
    model_config = {"extra": "allow"}

    action: str
    actor: str
    at: Optional[str] = None
    note: Optional[str] = None
    resolution: Optional[str] = None
    evidence_ids: list[str] = Field(default_factory=list)
    tenant_id: Optional[str] = None


@router.post("/alerts/{alert_id}/transition", status_code=201)
def transition_alert_state(
    alert_id: str,
    payload: TransitionIn,
    response: Response,
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
) -> AlertOut:
    """Append-only transition: the history entry is added, never rewritten.
    CONFIRMED_INCIDENT stays governed by the Phase-5 transition rules."""
    repo = CryptoLogAlertRepository(db)
    alert = repo.get_alert(payload.tenant_id, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail=f"alert not found: {alert_id}")
    at = payload.at or datetime.now(timezone.utc).isoformat()
    try:
        updated_alert = transition_alert(
            dict(alert),
            action=payload.action,
            actor=payload.actor,
            at=at,
            note=payload.note,
            resolution=payload.resolution,
            evidence_ids=payload.evidence_ids,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    history = (updated_alert.get("lifecycle") or {}).get("history") or []
    entry = dict(history[-1]) if history else {}
    entry["state"] = (updated_alert.get("lifecycle") or {}).get("status") or alert["state"]
    updated = repo.append_transition(
        tenant_id=payload.tenant_id, alert_id=alert_id, entry=entry)
    response.status_code = 201
    return updated


# ---------------------------------------------------------------------------
# Integrity: checkpoints and verification (section 5). Signing uses an
# operator-held key supplied through the environment; without one the
# service refuses to sign and verification reports honestly.
# ---------------------------------------------------------------------------


def _checkpoint_secret() -> Optional[str]:
    import os
    return os.environ.get("CRYPTOLOG_CHECKPOINT_SECRET") or None


def _signer_id() -> str:
    import os
    return os.environ.get("CRYPTOLOG_SIGNER_ID") or "cryptolog-service"


def _hmac_sign(secret: str):
    import hashlib
    import hmac as _hmac

    def sign(payload: bytes) -> str:
        return _hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return sign


def _hmac_verify(secret: str):
    import hashlib
    import hmac as _hmac

    def verify(signature: str, payload: bytes) -> bool:
        expected = _hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
        return _hmac.compare_digest(expected, str(signature))
    return verify


class CheckpointIn(BaseModel):
    model_config = {"extra": "allow"}

    checkpoint_ref: str
    retention_ref: str
    tenant_id: Optional[str] = None
    start_occurred: Optional[str] = None
    end_occurred: Optional[str] = None
    previous_checkpoint_ref: Optional[str] = None


@router.post("/integrity/checkpoint", status_code=201)
def create_checkpoint(
    payload: CheckpointIn,
    response: Response,
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
) -> CheckpointCreateOut:
    """Checkpoint one partition over the selected window. A checkpoint
    covering several chains is refused: a root over mixed partitions would
    verify nothing."""
    secret = _checkpoint_secret()
    if not secret:
        raise HTTPException(
            status_code=503,
            detail="no signing key configured (CRYPTOLOG_CHECKPOINT_SECRET); "
                   "a checkpoint cannot be honestly signed")
    repo = CryptoLogAlertRepository(db)
    events = repo.events_in_range(
        tenant_id=payload.tenant_id,
        start_occurred=payload.start_occurred,
        end_occurred=payload.end_occurred)
    partitions = {str(e.get("partition_id") or "") for e in events}
    if len(partitions) > 1:
        raise HTTPException(
            status_code=422,
            detail="the window spans multiple partitions; one checkpoint "
                   "covers one chain")
    partition_id = next(iter(partitions)) if partitions else f"{payload.tenant_id or 'unknown'}:empty"
    hashes = [str(e["event_hash"]) for e in events]
    chain = build_chain(partition_id, hashes)
    chain_hash = chain[-1] if chain else chain_genesis(partition_id)
    root_hash = merkle_root(hashes)
    sequence = repo.count_checkpoints(payload.tenant_id, partition_id)
    created_at = datetime.now(timezone.utc).isoformat()
    checkpoint = make_checkpoint(
        partition_id=partition_id, sequence=sequence, chain_hash=chain_hash,
        merkle_root_hash=root_hash, event_count=len(events),
        created_at=created_at, retention_ref=payload.retention_ref,
        signer_id=_signer_id(), sign=_hmac_sign(secret))
    previous = None
    if payload.previous_checkpoint_ref:
        previous = repo.get_checkpoint(payload.tenant_id, payload.previous_checkpoint_ref)
        if previous is None:
            raise HTTPException(
                status_code=404,
                detail=f"previous checkpoint not found: {payload.previous_checkpoint_ref}")
    record = dict(checkpoint)
    record["checkpoint_ref"] = payload.checkpoint_ref
    record["chain_head_event_id"] = events[-1]["event"]["event_id"] if events else None
    record["window"] = {
        "start_event_id": events[0]["event"]["event_id"] if events else None,
        "end_event_id": events[-1]["event"]["event_id"] if events else None,
        "start_occurred": payload.start_occurred,
        "end_occurred": payload.end_occurred,
    }
    record["previous_checkpoint"] = (
        {"checkpoint_ref": previous["checkpoint_ref"]} if previous else {})
    result = repo.insert_checkpoint(tenant_id=str(payload.tenant_id or ""), checkpoint=record)
    if result["outcome"] == DUPLICATE:
        response.status_code = 200
    return result


@router.get("/integrity/checkpoints")
def list_checkpoints(
    tenant_id: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
) -> CheckpointsPageOut:
    return CryptoLogAlertRepository(db).list_checkpoints(
        tenant_id=tenant_id, limit=limit)


class VerifyIn(BaseModel):
    model_config = {"extra": "allow"}

    checkpoint_ref: Optional[str] = None
    tenant_id: Optional[str] = None
    start_occurred: Optional[str] = None
    end_occurred: Optional[str] = None


@router.post("/integrity/verify")
def verify_integrity(
    payload: VerifyIn,
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
) -> VerifyOut:
    """Recompute hashes and the chain over stored events. VERIFIED requires
    a checkpoint whose signature checks out; a hash chain proves integrity
    relative to the trusted checkpoint — the original observations still
    need source validation."""
    repo = CryptoLogAlertRepository(db)
    events = repo.events_in_range(
        tenant_id=payload.tenant_id,
        start_occurred=payload.start_occurred,
        end_occurred=payload.end_occurred)
    partitions = {str(e.get("partition_id") or "") for e in events}
    partition_id = next(iter(partitions)) if len(partitions) == 1 \
        else f"{payload.tenant_id or 'unknown'}:empty"
    hashes = [str(e["event_hash"]) for e in events]
    chain = build_chain(partition_id, hashes)
    entries = [
        {"event_id": e["event"]["event_id"], "event_hash": h, "chain_hash": c}
        for e, h, c in zip(events, hashes, chain)
    ]
    checkpoint = None
    checkpoint_valid: Optional[bool] = None
    if payload.checkpoint_ref:
        stored = repo.get_checkpoint(payload.tenant_id, payload.checkpoint_ref)
        if stored is None:
            raise HTTPException(
                status_code=404,
                detail=f"checkpoint not found: {payload.checkpoint_ref}")
        checkpoint = stored
        secret = _checkpoint_secret()
        verify = _hmac_verify(secret) if secret else None
        checkpoint_valid = bool(
            verify and verify_checkpoint(checkpoint, verify))
    result = verify_range(
        partition_id=partition_id,
        entries=entries,
        events_by_id={e["event"]["event_id"]: e["event"] for e in events},
        checkpoint=checkpoint,
        verify=_hmac_verify(_checkpoint_secret()) if _checkpoint_secret() else None)
    result["input"] = {
        "event_count": len(events),
        "checkpoint_ref": payload.checkpoint_ref,
        "checkpoint_signature_verified": checkpoint_valid,
    }
    return result


@router.get("/integrity/merkle-proof")
def get_merkle_proof(
    event_id: str,
    checkpoint_ref: str,
    tenant_id: Optional[str] = Query(None),
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
) -> MerkleProofOut:
    repo = CryptoLogAlertRepository(db)
    checkpoint = repo.get_checkpoint(tenant_id, checkpoint_ref)
    if checkpoint is None:
        raise HTTPException(status_code=404, detail=f"checkpoint not found: {checkpoint_ref}")
    window = checkpoint.get("window") or {}
    events = repo.events_in_range(
        tenant_id=tenant_id,
        start_occurred=window.get("start_occurred"),
        end_occurred=window.get("end_occurred"))
    hashes = [str(e["event_hash"]) for e in events]
    index = next((i for i, e in enumerate(events)
                  if e["event"]["event_id"] == event_id), None)
    if index is None:
        raise HTTPException(
            status_code=404,
            detail=f"event not in checkpoint window: {event_id}")
    proof = merkle_proof(hashes, index)
    root_hash = str(checkpoint.get("merkle_root_hash") or "")
    return {
        "event_id": event_id,
        "event_hash": hashes[index],
        "index": index,
        "checkpoint_ref": checkpoint_ref,
        "merkle_root_hash": root_hash,
        "proof": proof,
        "verified": verify_merkle_proof(hashes[index], proof, root_hash),
    }


# ---------------------------------------------------------------------------
# Insights: overview and timeline (section 9). Server-side aggregation over
# the recorded events — every count names what it counts, and the counts
# are never presented as complete estate coverage.
# ---------------------------------------------------------------------------


def _observed_at(event: Mapping[str, Any]) -> str:
    obs = event.get("observation") or {}
    return str(event.get("observed") or obs.get("observed_at") or "")


class TimelineBucket(BaseModel):
    bucket_start: str
    total: int = 0
    by_category: dict[str, int] = Field(default_factory=dict)
    by_severity: dict[str, int] = Field(default_factory=dict)
    critical_changes: int = 0


class TimelineOut(BaseModel):
    model_config = {"extra": "allow"}

    bucket: str = "day"
    window: dict[str, Any] = Field(default_factory=dict)
    event_count: int = 0
    buckets: list[TimelineBucket] = Field(default_factory=list)
    note: str = ""


@router.get("/timeline")
def event_timeline(
    bucket: str = Query("day", pattern="^(day|hour)$"),
    tenant_id: Optional[str] = Query(None),
    start_occurred: Optional[str] = Query(None),
    end_occurred: Optional[str] = Query(None),
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
) -> TimelineOut:
    """Bucketed event volume from the recorded events. A bucket with no
    events is a bucket with no recorded events — never evidence that the
    estate was quiet."""
    repo = CryptoLogAlertRepository(db)
    events = [r["event"] for r in repo.events_in_range(
        tenant_id=tenant_id, start_occurred=start_occurred,
        end_occurred=end_occurred)]
    width = 10 if bucket == "day" else 13
    grouped: dict[str, dict[str, Any]] = {}
    for event in events:
        stamp = _observed_at(event)[:width]
        entry = grouped.setdefault(stamp, {
            "bucket_start": stamp or "unknown", "total": 0,
            "by_category": {}, "by_severity": {}, "critical_changes": 0})
        entry["total"] += 1
        cat = str(event.get("category") or "UNKNOWN")
        sev = str(event.get("severity") or "UNKNOWN")
        entry["by_category"][cat] = entry["by_category"].get(cat, 0) + 1
        entry["by_severity"][sev] = entry["by_severity"].get(sev, 0) + 1
        if str(event.get("logging_kind")) == "CHANGE" and sev in ("HIGH", "CRITICAL"):
            entry["critical_changes"] += 1
    buckets = [TimelineBucket(**grouped[k]) for k in sorted(grouped)]
    return TimelineOut(
        bucket=bucket,
        window={"start_occurred": start_occurred, "end_occurred": end_occurred},
        event_count=len(events),
        buckets=buckets,
        note="Counts cover recorded CryptoLog events only. A gap is a gap "
             "in the record, never proof the estate was quiet: sampling or "
             "aggregation never claims complete event coverage.")


class CollectorHealth(BaseModel):
    collector_id: str
    event_count: int = 0
    telemetry_modes: dict[str, int] = Field(default_factory=dict)


class IntegritySummary(BaseModel):
    model_config = {"extra": "allow"}

    state: str = "UNVERIFIED"
    checkpoint_count: int = 0
    latest_checkpoint_ref: Optional[str] = None
    latest_created_at: Optional[str] = None
    note: str = ""


class OverviewOut(BaseModel):
    model_config = {"extra": "allow"}

    event_total: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_category: dict[str, int] = Field(default_factory=dict)
    by_logging_kind: dict[str, int] = Field(default_factory=dict)
    critical_changes: int = 0
    alerts_total: int = 0
    alerts_open: int = 0
    collectors: list[CollectorHealth] = Field(default_factory=list)
    integrity: IntegritySummary = Field(default_factory=IntegritySummary)
    note: str = ""


@router.get("/overview")
def cryptolog_overview(
    tenant_id: Optional[str] = Query(None),
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
) -> OverviewOut:
    """Event volume, critical changes, integrity and collection health —
    every figure computed over the recorded events and named as such."""
    repo = CryptoLogAlertRepository(db)
    events = [r["event"] for r in repo.events_in_range(tenant_id=tenant_id)]
    by_severity: dict[str, int] = {}
    by_category: dict[str, int] = {}
    by_kind: dict[str, int] = {}
    collectors: dict[str, dict[str, Any]] = {}
    critical = 0
    for event in events:
        sev = str(event.get("severity") or "UNKNOWN")
        cat = str(event.get("category") or "UNKNOWN")
        kind = str(event.get("logging_kind") or "UNKNOWN")
        by_severity[sev] = by_severity.get(sev, 0) + 1
        by_category[cat] = by_category.get(cat, 0) + 1
        by_kind[kind] = by_kind.get(kind, 0) + 1
        if kind == "CHANGE" and sev in ("HIGH", "CRITICAL"):
            critical += 1
        source = event.get("source") or {}
        cid = str(source.get("collector_id") or "unattributed")
        entry = collectors.setdefault(cid, {
            "collector_id": cid, "event_count": 0, "telemetry_modes": {}})
        entry["event_count"] += 1
        mode = str(event.get("telemetry_mode") or "EVENT")
        entry["telemetry_modes"][mode] = entry["telemetry_modes"].get(mode, 0) + 1

    alert_rows = CryptoLogAlertRepository(db).list_alerts(
        tenant_id=tenant_id, limit=1)
    open_rows = CryptoLogAlertRepository(db).list_alerts(
        tenant_id=tenant_id, state="OPEN", limit=1)

    checkpoints = repo.list_checkpoints(tenant_id=tenant_id, limit=1)
    latest = checkpoints["rows"][0] if checkpoints["rows"] else None
    integrity = IntegritySummary(
        state="CHECKPOINTED" if latest else "UNVERIFIED",
        checkpoint_count=checkpoints["total_count"],
        latest_checkpoint_ref=(latest or {}).get("checkpoint_ref"),
        latest_created_at=(latest or {}).get("created_at"),
        note="an event store without a signed checkpoint is UNVERIFIED: "
             "this is not a failed chain, it is a chain not yet anchored"
             if not latest else
             "checkpointed store: run verification for the per-entry state")

    return OverviewOut(
        event_total=len(events),
        by_severity=by_severity,
        by_category=by_category,
        by_logging_kind=by_kind,
        critical_changes=critical,
        alerts_total=alert_rows["total_count"],
        alerts_open=open_rows["total_count"],
        collectors=[CollectorHealth(**c) for c in
                    sorted(collectors.values(),
                           key=lambda c: (-c["event_count"], c["collector_id"]))],
        integrity=integrity,
        note="Every figure counts recorded CryptoLog events and alerts. "
             "A recorded count is not an estate guarantee: a missing "
             "collector is named in collection health, never a clean zero.")


# ---------------------------------------------------------------------------
# Reports (section 9): the auditor and management export. One archive whose
# manifest hashes every file — an examiner proves the pack is untouched with
# any sha256sum check, and a missing artifact is unverifiable, not valid.
# ---------------------------------------------------------------------------


class ReportIn(BaseModel):
    model_config = {"extra": "allow"}

    tenant_id: Optional[str] = None
    start_occurred: Optional[str] = None
    end_occurred: Optional[str] = None
    severity: Optional[str] = None
    category: Optional[str] = None


def _doc_bytes(document: Any) -> bytes:
    import json as _json
    return _json.dumps(document, indent=2, sort_keys=True,
                       default=str).encode("utf-8")


@router.post("/reports/export")
def export_report(
    payload: ReportIn,
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
):
    """The auditor pack as one ZIP: events, alerts, integrity and a
    management rendering, each hashed into manifest.json. Binary by design
    — deliberately recorded untyped rather than publishing a JSON contract
    for an archive (see 103-untyped-response-operations.json)."""
    import hashlib
    import io
    import json as _json
    import uuid
    import zipfile

    from shared_models.report_manifest import MANIFEST_SCHEMA, build_manifest

    repo = CryptoLogAlertRepository(db)
    records = repo.events_in_range(
        tenant_id=payload.tenant_id,
        start_occurred=payload.start_occurred,
        end_occurred=payload.end_occurred)
    events_doc = {
        "schema": "cryptoscan.cryptolog-report-events/1",
        "window": {"start_occurred": payload.start_occurred,
                   "end_occurred": payload.end_occurred},
        "events": records,
    }
    alerts_page = repo.list_alerts(
        tenant_id=payload.tenant_id, severity=payload.severity, limit=1000)
    alerts_doc = {
        "schema": "cryptoscan.cryptolog-report-alerts/1",
        "alerts": alerts_page["rows"],
        "total_count": alerts_page["total_count"],
    }

    # Integrity section: the checkpoint register plus an honest verification
    # over the exported window against the latest checkpoint.
    checkpoints = repo.list_checkpoints(tenant_id=payload.tenant_id)
    checkpoint = checkpoints["rows"][0] if checkpoints["rows"] else None
    partition_ids = {str(r.get("partition_id") or "") for r in records}
    partition_id = next(iter(partition_ids)) if len(partition_ids) == 1 \
        else f"{payload.tenant_id or 'unknown'}:empty"
    hashes = [str(r["event_hash"]) for r in records]
    chain = build_chain(partition_id, hashes)
    entries = [
        {"event_id": r["event"]["event_id"], "event_hash": h, "chain_hash": c}
        for r, h, c in zip(records, hashes, chain)
    ]
    secret = _checkpoint_secret()
    verification = verify_range(
        partition_id=partition_id,
        entries=entries,
        events_by_id={r["event"]["event_id"]: r["event"] for r in records},
        checkpoint=checkpoint,
        verify=_hmac_verify(secret) if (secret and checkpoint) else None)
    integrity_doc = {
        "schema": "cryptoscan.cryptolog-report-integrity/1",
        "checkpoints": checkpoints["rows"],
        "verification": verification,
    }

    report = {
        "schema": "cryptoscan.cryptolog-report/1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "filters": {"tenant_id": payload.tenant_id,
                    "start_occurred": payload.start_occurred,
                    "end_occurred": payload.end_occurred,
                    "severity": payload.severity,
                    "category": payload.category},
        "totals": {
            "events": len(records),
            "alerts": alerts_page["total_count"],
            "checkpoints": checkpoints["total_count"],
        },
        "integrity_state": verification["overall_state"],
        "proven": [
            "every figure counts recorded CryptoLog records in the stated window",
            f"the archive's manifest hashes each of its {4} documents",
        ],
        "not_proven": [
            "complete estate coverage: a collector gap is a gap in the record",
            "the truth of any individual observation: source validation is separate",
        ],
        "note": "management rendering of the auditor pack; the JSON documents "
                "are the record and the manifest binds them",
    }
    report_md = "\n".join([
        "# CryptoLog report",
        "",
        f"Generated: {report['generated_at']}",
        f"Filters: {_json.dumps(report['filters'], sort_keys=True)}",
        "",
        f"- recorded events: {report['totals']['events']}",
        f"- alerts: {report['totals']['alerts']}",
        f"- checkpoints: {report['totals']['checkpoints']}",
        f"- integrity state: {report['integrity_state']}",
        "",
        "## What is proven",
        *[f"- {line}" for line in report["proven"]],
        "",
        "## What is NOT proven",
        *[f"- {line}" for line in report["not_proven"]],
        "",
        report["note"],
    ])

    files = {
        "events.json": _doc_bytes(events_doc),
        "alerts.json": _doc_bytes(alerts_doc),
        "integrity.json": _doc_bytes(integrity_doc),
        "report.md": report_md.encode("utf-8"),
    }
    generated_at = datetime.now(timezone.utc)
    manifest = build_manifest(
        schema_version=MANIFEST_SCHEMA,
        report_id=f"cryptolog-{generated_at.strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}",
        tenant_id=payload.tenant_id,
        scope=payload.tenant_id or "platform-estate",
        filters=report["filters"],
        totals=report["totals"],
        generated_at=generated_at.isoformat(),
        extra={
            "kind": "cryptoscan-cryptolog-auditor-pack",
            "files": {
                name: {"sha256": hashlib.sha256(blob).hexdigest(),
                       "bytes": len(blob)}
                for name, blob in sorted(files.items())
            },
        },
    )
    files["manifest.json"] = _doc_bytes(manifest)

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, blob in sorted(files.items()):
            info = zipfile.ZipInfo(name, date_time=generated_at.timetuple()[:6])
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, blob)
    return Response(
        content=buffer.getvalue(),
        media_type="application/zip",
        headers={
            "Content-Disposition":
                f'attachment; filename="cryptolog-report-{generated_at.strftime("%Y%m%dT%H%M%SZ")}.zip"',
            "X-Report-Id": manifest["report_id"],
            "X-Archive-Files": str(len(files)),
        },
    )


class ReportVerifyIn(BaseModel):
    model_config = {"extra": "allow"}

    manifest: dict[str, Any]
    documents: dict[str, Any] = Field(default_factory=dict)


class ReportVerifyOut(BaseModel):
    verified: bool = False
    files: dict[str, str] = Field(default_factory=dict)
    problems: list[Any] = Field(default_factory=list)
    note: str = ""


@router.post("/reports/verify")
def verify_report_bundle(
    payload: ReportVerifyIn,
    user=Depends(get_current_user),
) -> ReportVerifyOut:
    """Examiner-side check of a returned bundle: every manifest-recorded
    document must be present and hash to its digest. A missing artifact is
    unverifiable, not valid; a changed artifact is a named mismatch."""
    from shared_models.report_manifest import verify_manifest_files
    try:
        verdict = verify_manifest_files(
            payload.manifest,
            {name: doc.encode("utf-8") if isinstance(doc, str)
             else _doc_bytes(doc)
             for name, doc in payload.documents.items()})
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return ReportVerifyOut(
        verified=verdict["verified"],
        files=verdict["files"],
        problems=verdict["problems"],
        note="every recorded artifact must be present and hash to its digest: "
             "a missing artifact is unverifiable, not valid")
