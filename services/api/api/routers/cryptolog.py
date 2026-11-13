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

from api.dependencies import (get_current_user, get_db_session,
                              require_intelligence_manager,
                              require_intelligence_writer,
                              require_query_tenant_scope)
from db.repositories.cryptolog_repository import (
    CryptoLogAlertRepository, CryptoLogRepository, CryptoLogWindowTooLarge,
)
from shared_models.bulk_result import (
    ACCEPTED, REJECTED, SKIPPED, bulk_result, item as bulk_item,
)
from shared_models.cryptolog_alerts import (
    RULES as DETECTION_RULES, evaluate as evaluate_rules, transition as transition_alert,
)
from shared_models.cryptolog_integrity import (
    build_chain, chain_genesis, make_checkpoint, merkle_proof, merkle_root,
    verify_merkle_proof, verify_checkpoint, verify_range,
)
from shared_models.cryptolog_events import (
    CONFLICT, DUPLICATE, INSERTED, event_hash, supersede, validate_event,
)

router = APIRouter(prefix="/cryptolog", tags=["cryptolog"],
                   dependencies=[Depends(require_query_tenant_scope)])

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


def _require_actor(actor: str, principal: str) -> None:
    """An append-only correction/decision cannot impersonate another actor."""
    if actor != principal:
        raise HTTPException(status_code=403,
                            detail="actor must match the authenticated principal")


def _require_event_tenant(tenant_id: Optional[str]) -> None:
    from db.tenancy import current_tenant

    scoped = current_tenant()
    if scoped is not None and tenant_id != scoped:
        raise HTTPException(status_code=403,
                            detail="event tenant does not match the "
                                   "authenticated tenant scope")


@router.post("/events", status_code=201,
             dependencies=[Depends(require_intelligence_writer)])
def ingest_event(body: EventIn, response: Response,
                 db: Session = Depends(get_db_session),
                 user: str = Depends(get_current_user)) -> dict:
    """Ingest one event. 201 INSERTED, 200 DUPLICATE (idempotent), 409
    CONFLICT (a different event under an existing key is never a silent
    overwrite)."""
    _require_event_tenant(body.tenant_id)
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


@router.post("/events/batch",
             dependencies=[Depends(require_intelligence_writer)])
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
            _require_event_tenant(raw.get("tenant_id"))
            result = repo.insert_event(raw)
        except (ValueError, HTTPException) as exc:
            reason = exc.detail if isinstance(exc, HTTPException) else str(exc)
            rows.append(bulk_item(key, REJECTED, reason))
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


@router.post("/events/{event_id}/corrections", status_code=201,
             dependencies=[Depends(require_intelligence_manager)])
def correct_event(event_id: str, body: CorrectionIn,
                  db: Session = Depends(get_db_session),
                  user: str = Depends(get_current_user)) -> dict:
    """Supersede an event with a correction. The original row is preserved
    byte-identical; the correction carries its own reason, actor and
    evidence."""
    _require_actor(body.actor, user)
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


@router.post("/alerts/evaluate",
             dependencies=[Depends(require_intelligence_manager)])
def evaluate_alerts(body: AlertEvaluateIn,
                    db: Session = Depends(get_db_session),
                    user: str = Depends(get_current_user)) -> dict:
    """Deterministic rules CL-001..CL-015 over a recorded event stream.
    Every result is an OPEN investigation carrying what is proven and what
    is not — a pattern never automatically becomes a confirmed compromise,
    and severity is named drivers, never one unexplained number."""
    if len(body.events) > 1000:
        raise HTTPException(status_code=413,
                            detail="at most 1000 recorded events per alert evaluation")
    from db.repositories.cryptolog_repository import row_to_event

    repo = _repo(db)
    stored_events = []
    tenants = set()
    for supplied in body.events:
        event_id = str(supplied.get("event_id") or "")
        tenant_id = str(supplied.get("tenant_id") or "")
        if not event_id or not tenant_id:
            raise HTTPException(status_code=422,
                                detail="alert evaluation requires recorded event and tenant IDs")
        _require_event_tenant(tenant_id)
        row = repo.get_event(tenant_id, event_id)
        if row is None:
            raise HTTPException(status_code=404,
                                detail="recorded event not found in selected tenant")
        try:
            supplied_hash = event_hash(validate_event(supplied))
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        if supplied_hash != row.event_hash:
            raise HTTPException(status_code=409,
                                detail="event payload differs from the recorded ledger")
        stored_events.append(row_to_event(row))
        tenants.add(tenant_id)
    if len(tenants) > 1:
        raise HTTPException(status_code=422,
                            detail="evaluate one tenant's recorded events at a time")
    tenant = next(iter(tenants), None)
    assets = {str(event.get("asset_id") or "") for event in stored_events}
    if set(body.assessments) - assets:
        raise HTTPException(status_code=422,
                            detail="assessment names no recorded event asset")
    if body.previous_by_asset and tenant is None:
        raise HTTPException(status_code=422,
                            detail="a predecessor requires a recorded current event")
    previous: dict[str, dict[str, Any]] = {}
    for asset, supplied in body.previous_by_asset.items():
        if asset not in assets or not isinstance(supplied, dict):
            raise HTTPException(status_code=422,
                                detail="predecessor asset is not in the recorded event set")
        prior_id = str(supplied.get("event_id") or "")
        row = repo.get_event(tenant, prior_id) if prior_id else None
        if row is None:
            raise HTTPException(status_code=404,
                                detail="recorded predecessor not found in selected tenant")
        if row.asset_id != asset:
            raise HTTPException(status_code=422,
                                detail="predecessor does not belong to this asset")
        try:
            if event_hash(validate_event(supplied)) != row.event_hash:
                raise HTTPException(status_code=409,
                                    detail="predecessor differs from the recorded ledger")
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        prior = row_to_event(row)
        try:
            before = datetime.fromisoformat(str(prior["observation"]["observed_at"]).replace("Z", "+00:00"))
            current = min(datetime.fromisoformat(str(event["observation"]["observed_at"]).replace("Z", "+00:00"))
                          for event in stored_events if event.get("asset_id") == asset)
            if before.tzinfo is None or current.tzinfo is None or before >= current:
                raise ValueError("predecessor is not earlier than the recorded observation")
        except (KeyError, TypeError, ValueError) as exc:
            raise HTTPException(status_code=422,
                                detail="predecessor and current events require ordered, timezone-aware observations") from exc
        previous[asset] = prior
    try:
        # Caller-declared factors are not independent severity evidence. Keep
        # them as labelled context, but compute the authoritative rule severity
        # only from the recorded event stream until backed assessments exist.
        alerts = evaluate_rules(stored_events,
                                previous_by_asset=previous,
                                assessments={})
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    store = CryptoLogAlertRepository(db)
    by_id = {str(e["event_id"]): e for e in [*previous.values(), *stored_events]}
    for alert in alerts:
        affected = (alert.get("affected") or {}).get("asset_ids") or []
        if any(asset in body.assessments for asset in affected):
            alert["severity_basis"]["unapplied_operator_assessments"] = True
            alert["what_is_not_proven"] += (
                "; caller-declared severity factors were not independently "
                "verified and did not change the rule severity")
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
    _require_actor(body.actor, user)
    try:
        return transition_alert(body.alert, action=body.action,
                                actor=body.actor, at=body.at, note=body.note,
                                resolution=body.resolution,
                                evidence_ids=body.evidence_ids)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


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


@router.post("/alerts/{alert_id}/transition", status_code=201,
             dependencies=[Depends(require_intelligence_manager)])
def transition_alert_state(
    alert_id: str,
    payload: TransitionIn,
    response: Response,
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
) -> AlertOut:
    """Append-only transition: the history entry is added, never rewritten.
    CONFIRMED_INCIDENT stays governed by the Phase-5 transition rules."""
    _require_actor(payload.actor, user)
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


@router.post("/integrity/checkpoint", status_code=201,
             dependencies=[Depends(require_intelligence_manager)])
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
    asset_id: Optional[str] = Query(None),
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
        tenant_id=tenant_id, asset_id=asset_id,
        start_occurred=start_occurred, end_occurred=end_occurred)]
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
        window={"start_occurred": start_occurred, "end_occurred": end_occurred,
                "asset_id": asset_id},
        event_count=len(events),
        buckets=buckets,
        note=("Counts cover this asset's recorded CryptoLog events only. "
              if asset_id else "Counts cover all recorded CryptoLog events in the selected tenant. ")
             + "A gap is a gap "
             "in the record, never proof the estate was quiet: sampling or "
             "aggregation never claims complete event coverage.")


class CollectorHealth(BaseModel):
    collector_id: str
    event_count: int = 0
    telemetry_modes: dict[str, int] = Field(default_factory=dict)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    asset_count: int = 0
    assets: list[str] = Field(default_factory=list)


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
            "collector_id": cid, "event_count": 0, "telemetry_modes": {},
            "first_seen": None, "last_seen": None,
            "assets": []})
        entry["event_count"] += 1
        mode = str(event.get("telemetry_mode") or "EVENT")
        entry["telemetry_modes"][mode] = entry["telemetry_modes"].get(mode, 0) + 1
        stamp = _observed_at(event)
        if stamp and (entry["last_seen"] is None or stamp > entry["last_seen"]):
            entry["last_seen"] = stamp
        if stamp and (entry["first_seen"] is None or stamp < entry["first_seen"]):
            entry["first_seen"] = stamp
        asset_id = str(event.get("asset_id") or "")
        if asset_id and asset_id not in entry["assets"]:
            entry["assets"].append(asset_id)
        entry["asset_count"] = len(entry["assets"])

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

    from db.tenancy import current_tenant

    scoped = current_tenant()
    if scoped is not None and payload.tenant_id not in (None, scoped):
        raise HTTPException(status_code=403,
                            detail="report tenant does not match the "
                                   "authenticated tenant scope")
    if payload.category:
        raise HTTPException(status_code=422,
                            detail="category-filtered ledger export is not "
                                   "supported: skipping chain entries would "
                                   "make the archive unverifiable")
    tenant_id = scoped or payload.tenant_id
    repo = CryptoLogAlertRepository(db)
    try:
        records = repo.events_in_range(
            tenant_id=tenant_id,
            start_occurred=payload.start_occurred,
            end_occurred=payload.end_occurred,
            max_events=10000)
    except CryptoLogWindowTooLarge as exc:
        raise HTTPException(
            status_code=409,
            detail="auditor pack exceeds the 10000-event export budget; "
                   "narrow the event window — a partial chain is never "
                   "presented as verifiable") from exc
    partition_ids = {str(r.get("partition_id") or "") for r in records}
    if len(partition_ids) > 1:
        raise HTTPException(status_code=409,
                            detail="export spans multiple ledger partitions; "
                                   "select one tenant/window for verifiable "
                                   "integrity rather than joining chains")
    events_doc = {
        "schema": "cryptoscan.cryptolog-report-events/1",
        "window": {"start_occurred": payload.start_occurred,
                   "end_occurred": payload.end_occurred},
        "events": records,
    }
    alerts_page = repo.list_alerts(
        tenant_id=tenant_id, severity=payload.severity, limit=1000)
    if alerts_page["total_count"] > len(alerts_page["rows"]):
        raise HTTPException(
            status_code=409,
            detail="auditor pack exceeds the 1000-alert export budget; "
                   "a partial alert list is never presented as complete")
    alerts_doc = {
        "schema": "cryptoscan.cryptolog-report-alerts/1",
        "alerts": alerts_page["rows"],
        "total_count": alerts_page["total_count"],
    }

    # Integrity section: the checkpoint register plus an honest verification
    # over the exported window against the latest checkpoint.
    checkpoints = repo.list_checkpoints(tenant_id=tenant_id)
    if checkpoints["total_count"] > len(checkpoints["rows"]):
        raise HTTPException(
            status_code=409,
            detail="auditor pack exceeds the 50-checkpoint export budget; "
                   "a partial checkpoint list is never presented as complete")
    checkpoint = checkpoints["rows"][0] if checkpoints["rows"] else None
    partition_id = next(iter(partition_ids)) if partition_ids \
        else f"{tenant_id or 'unknown'}:empty"
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
        "filters": {"tenant_id": tenant_id,
                    "start_occurred": payload.start_occurred,
                    "end_occurred": payload.end_occurred,
                    "severity": payload.severity,
                    "severity_applies_to": "alerts only",
                    "time_window_applies_to": "events only",
                    "checkpoint_scope": "tenant-wide register",
                    "category": None},
        "totals": {
            "events": len(records),
            "alerts": alerts_page["total_count"],
            "checkpoints": checkpoints["total_count"],
        },
        "integrity_state": verification["overall_state"],
        "proven": [
            "event totals count the stated event window; alert totals use "
            "the tenant/severity register, not that time window",
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
        tenant_id=tenant_id,
        scope=tenant_id or "all-recorded-tenants (platform operator)",
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


# ---------------------------------------------------------------------------
# Retention (section 10): policy in the open, plans as projections. The
# plan never executes — DELETE_CANDIDATE is its strongest claim, and
# execution is a separate, disposition-gated act.
# ---------------------------------------------------------------------------


class RetentionPolicyOut(BaseModel):
    model_config = {"extra": "allow"}

    schema: Optional[str] = None
    activity_retention_days: int = 180
    change_retention_days: int = 3650
    audit_retention_days: int = 3650
    archive_after_days: int = 90
    require_disposition_ref: bool = True
    note: str = ""


@router.get("/retention/policy")
def get_retention_policy(user=Depends(get_current_user)) -> RetentionPolicyOut:
    """The retention defaults in the open: named windows per retention
    class, and a deletion that always requires a disposition."""
    from shared_models.cryptolog_retention import DEFAULT_POLICY
    return RetentionPolicyOut(
        **DEFAULT_POLICY,
        note="policy is stated, not hidden: every planned action cites the "
             "window it applied, and a deletion always requires a named "
             "disposition — the plan grants none")


class RetentionPlanIn(BaseModel):
    model_config = {"extra": "allow"}

    policy: dict[str, Any] = Field(default_factory=dict)
    tenant_id: Optional[str] = None
    start_occurred: Optional[str] = None
    end_occurred: Optional[str] = None


class RetentionPlanOut(BaseModel):
    model_config = {"extra": "allow"}

    schema: Optional[str] = None
    generated_at: str = ""
    policy: dict[str, Any] = Field(default_factory=dict)
    counts: dict[str, int] = Field(default_factory=dict)
    rows: list[Any] = Field(default_factory=list)
    proven: list[str] = Field(default_factory=list)
    not_proven: list[str] = Field(default_factory=list)
    note: str = ""


@router.post("/retention/plan")
def plan_retention(
    payload: RetentionPlanIn,
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
) -> RetentionPlanOut:
    """A retention PLAN: a deterministic projection over recorded events.
    It performs nothing — executing it is a separate, disposition-gated
    act, and the plan says so in its own not_proven."""
    from shared_models.cryptolog_retention import plan as build_plan
    repo = CryptoLogAlertRepository(db)
    records = repo.events_in_range(
        tenant_id=payload.tenant_id,
        start_occurred=payload.start_occurred,
        end_occurred=payload.end_occurred)
    result = build_plan([r["event"] for r in records], payload.policy,
                        datetime.now(timezone.utc))
    return RetentionPlanOut(**result)


# ── Phase 5 reads: the deterministic rule catalogue and event correlation ──


class RuleOut(BaseModel):
    rule_id: str
    detection: str
    suggested_severity: str
    investigation: str


class RulesOut(BaseModel):
    rules: list[RuleOut]
    note: str


@router.get("/rules", response_model=RulesOut)
def list_rules(user=Depends(get_current_user)) -> RulesOut:
    """The deterministic detection catalogue that /alerts/evaluate applies.
    A rule states what it detects and the investigation it suggests; it is
    a detection, never a verdict."""
    rows = [RuleOut(rule_id=rid,
                    detection=str(spec.get("detection", "")),
                    suggested_severity=str(spec.get("suggested_severity", "")),
                    investigation=str(spec.get("investigation", "")))
            for rid, spec in sorted(DETECTION_RULES.items())]
    return RulesOut(
        rules=rows,
        note="Deterministic rules over recorded CryptoLog events only. A "
             "rule is a detection, never a verdict: it carries a suggested "
             "investigation, it never names a system weak or broken on its "
             "own, and a rule that did not run is unmeasured, never clean.")


class CorrelationGroup(BaseModel):
    basis: str
    key: str
    event_ids: list[str] = Field(default_factory=list)
    asset_ids: list[str] = Field(default_factory=list)
    event_count: int = 0
    evidence_backed: bool = False
    note: str = ""


class CorrelationOut(BaseModel):
    groups: list[CorrelationGroup] = Field(default_factory=list)
    event_count: int = 0
    groups_truncated: bool = False
    note: str = ""


_GROUP_BASIS_NOTES = {
    "shared_evidence": "Events carrying the same recorded evidence "
                       "reference — the relation rests on shared evidence.",
    "shared_asset": "Events recorded on the same asset identity — the "
                    "recorded identity is the basis; relatedness of the "
                    "underlying changes is never inferred.",
    "shared_algorithm": "The same algorithm name appears across these "
                        "assets — a possible dependency and a hypothesis "
                        "only, never an established edge.",
}


@router.get("/correlation", response_model=CorrelationOut)
def correlate_events(
    tenant_id: Optional[str] = Query(None),
    start_occurred: Optional[str] = Query(None),
    end_occurred: Optional[str] = Query(None),
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
) -> CorrelationOut:
    """Deterministic correlation over the recorded event store: shared
    evidence references, recorded asset identity and repeated algorithm
    names. A group is a pattern in the record — never proof of dependency,
    and an empty result is absence of recorded correlation, never proof
    that nothing relates."""
    repo = CryptoLogAlertRepository(db)
    events = [r["event"] for r in repo.events_in_range(
        tenant_id=tenant_id, start_occurred=start_occurred,
        end_occurred=end_occurred)]

    by_algorithm: dict[str, list[Mapping[str, Any]]] = {}
    by_asset: dict[str, list[Mapping[str, Any]]] = {}
    by_evidence: dict[str, list[Mapping[str, Any]]] = {}
    for event in events:
        event_id = str(event.get("event_id") or "")
        if not event_id:
            continue
        asset_id = str(event.get("asset_id") or "")
        context = event.get("cryptographic_context") or {}
        attributes = event.get("attributes") or {}
        algorithm = str(context.get("algorithm") or attributes.get("algorithm") or "")
        if algorithm:
            by_algorithm.setdefault(algorithm, []).append(event)
        if asset_id:
            by_asset.setdefault(asset_id, []).append(event)
        evidence = event.get("evidence") or {}
        for ev_id in (evidence.get("evidence_ids") or []):
            ev_id = str(ev_id)
            if ev_id:
                by_evidence.setdefault(ev_id, []).append(event)

    groups: list[CorrelationGroup] = []

    def _add(basis: str, key: str, members: list[Mapping[str, Any]]) -> None:
        if len(members) < 2:
            return
        seen: list[str] = []
        assets: list[str] = []
        for event in members:
            event_id = str(event.get("event_id") or "")
            if event_id and event_id not in seen:
                seen.append(event_id)
            asset_id = str(event.get("asset_id") or "")
            if asset_id and asset_id not in assets:
                assets.append(asset_id)
        groups.append(CorrelationGroup(
            basis=basis, key=key, event_ids=sorted(seen),
            asset_ids=sorted(assets), event_count=len(seen),
            evidence_backed=basis in ("shared_evidence", "shared_asset"),
            note=_GROUP_BASIS_NOTES[basis]))

    for key, members in sorted(by_evidence.items()):
        _add("shared_evidence", key, members)
    for key, members in sorted(by_asset.items()):
        _add("shared_asset", key, members)
    for key, members in sorted(by_algorithm.items()):
        _add("shared_algorithm", key, members)

    groups.sort(key=lambda g: (-g.event_count, g.basis, g.key))
    truncated = len(groups) > 50
    shown = groups[:50]
    return CorrelationOut(
        groups=shown,
        event_count=len(events),
        groups_truncated=truncated,
        note="Correlation groups are computed from recorded CryptoLog events "
             "only. Shared evidence references and recorded asset identity "
             "are evidence-backed relations; a shared algorithm name is a "
             "possible dependency — a hypothesis, never an established "
             "edge. Absence of groups is absence of recorded correlation, "
             "never proof that nothing relates."
             + (" The list is truncated at 50 groups."
                if truncated else ""))
