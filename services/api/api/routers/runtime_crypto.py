"""Runtime cryptography scan API (spec 92).

Ingest, read back, correlate and score *runtime* crypto observations: what
operation actually ran, in which process, with which algorithm and parameters.

Three boundaries this router refuses to cross:

* **no scope, no instrumentation** — an observation outside the approved
  host/application/process set or outside the collection window is rejected
  with a code, not stored and flagged later;
* **no content** — plaintext, payload, key material and customer data are
  rejected for the whole batch;
* **no level inflation** — a Level 4 network observation is labelled as such and
  never scored as the application's own crypto.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session
from db.repositories.scan_run_repository import ScanRunRepository
from db.tenancy import current_tenant
from runtime.engine.adapters import EVENT_FIELDS
from runtime.engine.assets import (
    build_runtime_cbom,
    build_runtime_techbom,
    summarize_runtime_events,
)
from runtime.engine.events import (
    CryptoObservationRejected,
    assert_metadata_only,
    build_runtime_events,
)
from runtime.engine.levels import level_table
from runtime.engine.policy import evaluate_runtime, runtime_pqc_readiness
from runtime.engine.scope import (
    DATA_RESTRICTIONS,
    DEFAULT_DATA_RESTRICTIONS,
    RUNTIME_METHODS,
    RuntimeScopeViolation,
    check_runtime_scope,
    normalize_runtime_scope,
    scope_window_state,
)

router = APIRouter(tags=["runtime"])

RUN_KIND = "runtime-crypto"
_SCOPE_PREFIX = "runtime:crypto-scope"


# --------------------------------------------------------------------------- #
# scope
# --------------------------------------------------------------------------- #


class RuntimeScopeIn(BaseModel):
    name: str = Field(default="runtime-target", max_length=160)
    hosts: list[str] = Field(default_factory=list, max_length=500)
    applications: list[str] = Field(default_factory=list, max_length=200)
    processes: list[str] = Field(default_factory=list, max_length=200)
    runtime_methods: list[str] = Field(default_factory=list, max_length=16)
    data_restrictions: list[str] = Field(default_factory=lambda: list(DEFAULT_DATA_RESTRICTIONS), max_length=16)
    collection_window: dict[str, str] | None = None
    network_scope: list[str] = Field(default_factory=list, max_length=200)
    approved_by: str | None = Field(default=None, max_length=160)
    inventory_id: str = Field(default="default", max_length=160)


def _scope_key(tenant_id: str | None, inventory_id: str) -> str:
    return f"{_SCOPE_PREFIX}:{tenant_id or 'platform'}:{inventory_id}"


def _load_scope(db: Session, inventory_id: str) -> dict[str, Any] | None:
    from db.models.app_setting import AppSetting

    row = db.execute(select(AppSetting).where(AppSetting.key == _scope_key(current_tenant(), inventory_id))).scalars().first()
    if row is None or not row.value:
        return None
    try:
        payload = json.loads(row.value)
    except (TypeError, ValueError):
        return None
    payload["_key"] = row.key
    payload["_saved_by"] = row.updated_by
    return payload


def _save_scope(db: Session, payload: dict[str, Any], *, user: str, inventory_id: str) -> dict[str, Any]:
    from db.models.app_setting import AppSetting

    key = _scope_key(current_tenant(), inventory_id)
    body = {**payload, "saved_at": datetime.now(timezone.utc).isoformat(), "saved_by": user, "inventory_id": inventory_id}
    row = db.execute(select(AppSetting).where(AppSetting.key == key)).scalars().first()
    if row is None:
        db.add(AppSetting(key=key, value=json.dumps(body), updated_by=user))
    else:
        row.value = json.dumps(body)
        row.updated_by = user
    db.commit()
    body["_key"] = key
    return body


@router.get("/runtime/crypto-scope")
def get_runtime_crypto_scope(
    inventory_id: str = "default",
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """The approved runtime scope and whether its window is open right now."""
    scope = _load_scope(db, inventory_id)
    window = scope_window_state(scope)
    return {
        "model": "cryptoscan.runtime-scope/1",
        "configured": scope is not None,
        "scope": scope,
        "window": window,
        "permitted": bool(scope) and window["open"],
        "runtime_methods": list(RUNTIME_METHODS),
        "data_restrictions": list(DATA_RESTRICTIONS),
        "note": "without a saved scope no runtime observation is accepted",
    }


@router.put("/runtime/crypto-scope")
def put_runtime_crypto_scope(
    body: RuntimeScopeIn,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Save an approved runtime scope (hosts, window, methods, restrictions)."""
    try:
        normalized = normalize_runtime_scope(body.model_dump(mode="json"))
    except RuntimeScopeViolation as exc:
        raise HTTPException(status_code=422, detail={"error": exc.code, "reason": exc.reason, **exc.detail}) from exc
    saved = _save_scope(db, normalized, user=user, inventory_id=body.inventory_id)
    window = scope_window_state(saved)
    return {
        "model": "cryptoscan.runtime-scope/1",
        "saved": True,
        "scope": saved,
        "window": window,
        "permitted": window["open"],
    }


@router.post("/runtime/crypto-scope/validate")
def validate_runtime_crypto_scope(body: RuntimeScopeIn, user: str = Depends(get_current_user)):
    """Validate a scope without saving it.

    Authenticated like every other scope read: the normalized result names the
    hosts and the window a scope would open, which is not public information.
    """
    try:
        normalized = normalize_runtime_scope(body.model_dump(mode="json"))
    except RuntimeScopeViolation as exc:
        return {
            "model": "cryptoscan.runtime-scope-validation/1",
            "valid": False,
            "error": exc.code,
            "reason": exc.reason,
            "detail": exc.detail,
        }
    return {
        "model": "cryptoscan.runtime-scope-validation/1",
        "valid": True,
        "scope": normalized,
        "window": scope_window_state(normalized),
    }


@router.get("/runtime/crypto-adapters")
def runtime_crypto_adapters(user: str = Depends(get_current_user)):
    """Adapter registry and the Level 1–6 observation hierarchy."""
    from runtime.engine.adapters import adapter_catalog

    catalog = adapter_catalog()
    catalog["levels"] = level_table()
    catalog["event_fields"] = list(EVENT_FIELDS)
    catalog["note"] = (
        "each adapter lists what it cannot report; those fields stay UNKNOWN in every event it produces"
    )
    return catalog


# --------------------------------------------------------------------------- #
# ingest / read back
# --------------------------------------------------------------------------- #


class RuntimeEventsIn(BaseModel):
    observations: list[dict[str, Any]] = Field(default_factory=list, min_length=1, max_length=2000)
    inventory_id: str = Field(default="default", max_length=160)
    observed_at: str | None = None


def _assert_known_fields(observation: dict[str, Any]) -> None:
    unknown = sorted(key for key in observation if key not in EVENT_FIELDS and key not in {"adapter", "runtime_method", "method"})
    if unknown:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "runtime_event_field_unknown",
                "reason": f"unrecognised observation field(s): {', '.join(unknown)} — payload and key material cannot be carried",
                "allowed": list(EVENT_FIELDS),
            },
        )


@router.post("/runtime/crypto-events")
def ingest_runtime_crypto_events(
    body: RuntimeEventsIn,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Ingest runtime crypto observations under the approved scope.

    Every observation is authorized individually: a batch that mixes an
    approved host with an unapproved one is refused whole, so nothing
    out-of-scope reaches the evidence store.
    """
    scope = _load_scope(db, body.inventory_id)
    if scope is None:
        raise HTTPException(
            status_code=409,
            detail={
                "error": "runtime_scope_missing",
                "reason": "no approved runtime scope — save one before any instrumentation runs",
            },
        )
    for observation in body.observations:
        try:
            assert_metadata_only(observation)
        except CryptoObservationRejected as exc:
            raise HTTPException(
                status_code=422,
                detail={"error": "runtime_observation_rejected", "reason": str(exc)},
            ) from exc
        _assert_known_fields(observation)

    authorizations: list[dict[str, Any]] = []
    try:
        for observation in body.observations:
            authorizations.append(check_runtime_scope(observation, scope))
    except RuntimeScopeViolation as exc:
        raise HTTPException(status_code=403, detail={"error": exc.code, "reason": exc.reason, **exc.detail}) from exc

    try:
        events = build_runtime_events(
            body.observations,
            authorization=authorizations[0] if len(authorizations) == 1 else {"decision": "PERMITTED"},
            observed_at=body.observed_at,
        )
    except CryptoObservationRejected as exc:
        raise HTTPException(
            status_code=422,
            detail={"error": "runtime_observation_rejected", "reason": str(exc)},
        ) from exc

    from api.security.runtime_evidence_chain import append as append_to_chain
    from api.security.runtime_evidence_chain import ensure_event_ids

    # ids are assigned before storage so the run, the response and the hash
    # chain all reference the same event identity
    events = ensure_event_ids(events)
    summary = summarize_runtime_events(events)
    payload = {
        "runtime_events": events,
        "runtime_summary": summary,
        "scope_name": scope.get("name"),
        "collection": {
            "schema": "cryptoscan.runtime-collection/1",
            "kind": RUN_KIND,
            "evidence_schema": "cryptoscan.runtime-crypto-event/1",
            "authorizations": authorizations,
        },
    }
    row = ScanRunRepository(db).create_run(payload, target_kind=RUN_KIND)
    chain_receipt = append_to_chain(db, events, run_id=row.id, tenant_id=current_tenant(), user=user)
    db.commit()
    return {
        "model": "cryptoscan.runtime-crypto-ingest/1",
        "run_id": row.id,
        "stored": len(events),
        "events": events,
        "summary": summary,
        "evidence_chain": chain_receipt,
        "note": "Level 6 and algorithm-less observations are blind spots, not clean results",
    }


def _latest_runs(db: Session, *, limit: int) -> list[Any]:
    return ScanRunRepository(db).list_runs(limit=limit, target_kind=RUN_KIND, owner=current_tenant())


def _latest_events(db: Session, *, limit: int = 5) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in _latest_runs(db, limit=limit):
        for event in (row.result or {}).get("runtime_events") or []:
            key = str(event.get("event_id") or "")
            if key and key in seen:
                continue
            seen.add(key)
            events.append(event)
    return events


def _events_by_run(db: Session, run_ids) -> dict[str, list[dict[str, Any]]]:
    """Load the events of the runs a chain entry references."""
    repo = ScanRunRepository(db)
    out: dict[str, list[dict[str, Any]]] = {}
    for run_id in run_ids:
        if not run_id:
            continue
        row = repo.get_run(run_id, owner=current_tenant())
        if row is None:
            continue
        result = (row.to_dict() or {}).get("result") or {}
        out[str(run_id)] = list(result.get("runtime_events") or [])
    return out


def _integrity(db: Session) -> dict[str, Any]:
    """Recompute the runtime chain against the events it references."""
    from api.security.runtime_evidence_chain import read_chain, verify

    chain = read_chain(db, tenant_id=current_tenant())
    run_ids = {str(entry.get("run_id")) for entry in chain.get("entries") or []}
    return verify(chain, events_by_run=_events_by_run(db, run_ids))


@router.get("/runtime/crypto-events")
def list_runtime_crypto_events(
    limit: int = Query(default=5, ge=1, le=50),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Latest runtime crypto events with their attribution levels and chain position."""
    from api.security.runtime_evidence_chain import attach_integrity, read_chain

    events = _latest_events(db, limit=limit)
    chained = attach_integrity(events, read_chain(db, tenant_id=current_tenant()))
    return {
        "model": "cryptoscan.runtime-crypto-events/1",
        "events": chained,
        "summary": summarize_runtime_events(events),
        "integrity": _integrity(db),
        "limit": limit,
        "note": "an application with no event is NOT_OBSERVED — it is not crypto-free",
    }


@router.get("/runtime/crypto-events/verify")
def verify_runtime_crypto_events(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Recompute the runtime evidence chain and report any broken link.

    ``verified: false`` with ``tampered_records``/``problems`` means a stored
    event no longer matches the hash it was chained with. ``unverifiable_entries``
    are honest gaps (events outside the loaded window), not passes.
    """
    from api.security.runtime_evidence_chain import read_chain

    chain = read_chain(db, tenant_id=current_tenant())
    report = _integrity(db)
    report["chain"] = {
        "entries": len(chain.get("entries") or []),
        "seq": chain.get("seq"),
        "head_hash": chain.get("head"),
        "updated_at": chain.get("updated_at"),
    }
    return report


@router.get("/runtime/crypto-cbom")
def runtime_crypto_cbom(
    limit: int = Query(default=5, ge=1, le=50),
    estate: str | None = None,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Runtime CBOM + TechBOM built from stored events."""
    events = _latest_events(db, limit=limit)
    return {
        "cbom": build_runtime_cbom(events, estate=estate),
        "techbom": build_runtime_techbom(events),
        "events": len(events),
    }


class RuntimeRiskIn(BaseModel):
    events: list[dict[str, Any]] | None = None
    policy: dict[str, Any] | None = None
    limit: int = Field(default=5, ge=1, le=50)
    include_pqc: bool = True


@router.post("/runtime/crypto-risk")
def runtime_crypto_risk(
    body: RuntimeRiskIn,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Score runtime operations against the bank baseline; blind spots stay blind spots."""
    events = body.events if body.events is not None else _latest_events(db, limit=body.limit)
    report = evaluate_runtime(events, body.policy)
    report["sources"] = {"events": len(events), "origin": "request" if body.events is not None else "stored_events"}
    if body.include_pqc:
        report["pqc"] = runtime_pqc_readiness(events)
    return report


# --------------------------------------------------------------------------- #
# Drift and runtime <-> network correlation (spec 92 §12-§13)
# --------------------------------------------------------------------------- #


class RuntimeDriftRequest(BaseModel):
    """Compare two observation windows without pretending a missing event is a removal."""

    previous_run_id: str | None = None
    current_run_id: str | None = None
    previous_events: list[dict[str, Any]] | None = None
    current_events: list[dict[str, Any]] | None = None
    limit: int = Field(default=10, ge=2, le=50)


def _run_events(db: Session, run_id: str) -> list[dict[str, Any]]:
    row = ScanRunRepository(db).get_run(run_id, owner=current_tenant())
    if row is None:
        raise HTTPException(
            status_code=404,
            detail={"error": "runtime_run_not_found", "reason": f"no runtime run {run_id!r} for this tenant"},
        )
    return list(((row.to_dict() or {}).get("result") or {}).get("runtime_events") or [])


@router.post("/runtime/crypto-drift")
def runtime_crypto_drift(
    body: RuntimeDriftRequest,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Diff two runtime observation windows: new, removed, changed operations.

    A removal means "not observed in the newer window", never "the process stopped
    using it" — the response says so on every removed entry.
    """
    from runtime.engine.drift import compare_runs

    if body.previous_events is not None and body.current_events is not None:
        previous, current = body.previous_events, body.current_events
        source = "request"
    else:
        runs = _latest_runs(db, limit=body.limit)
        previous_id = body.previous_run_id or (runs[1].id if len(runs) > 1 else None)
        current_id = body.current_run_id or (runs[0].id if runs else None)
        if not previous_id or not current_id:
            raise HTTPException(
                status_code=409,
                detail={
                    "error": "runtime_drift_needs_two_windows",
                    "reason": "drift needs two observed windows; supply events or run two collections first",
                },
            )
        previous, current = _run_events(db, str(previous_id)), _run_events(db, str(current_id))
        source = "stored_runs"
        body = body.model_copy(update={"previous_run_id": str(previous_id), "current_run_id": str(current_id)})

    report = compare_runs(previous, current)
    report["sources"] = {
        "origin": source,
        "previous_run_id": body.previous_run_id,
        "current_run_id": body.current_run_id,
        "previous_events": len(previous),
        "current_events": len(current),
    }
    return report


class RuntimeNetworkCorrelationRequest(BaseModel):
    """Correlate runtime crypto events with network transport observations."""

    runtime_events: list[dict[str, Any]] | None = None
    runtime_limit: int = Field(default=5, ge=1, le=50)
    network_evidence: list[dict[str, Any]] | None = None
    network_limit: int = Field(default=10, ge=1, le=50)
    host_map: dict[str, str] = Field(default_factory=dict)


@router.post("/runtime/network-correlation")
def runtime_network_correlation(
    body: RuntimeNetworkCorrelationRequest,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Join runtime events to network evidence without merging the layers.

    Only comparable transport fields are compared, host identity comes from a
    declared ``host_map`` (never inferred), and every other pair is reported as
    ``NOT_COMPARABLE`` with the reason.
    """
    from api.security.runtime_network_correlation import correlate

    if body.runtime_events is not None:
        runtime_events, runtime_source = body.runtime_events, "request"
    else:
        runtime_events, runtime_source = _latest_events(db, limit=body.runtime_limit), "stored_events"

    if body.network_evidence is not None:
        network, network_source = body.network_evidence, "request"
    else:
        from api.routers.network import _latest_evidence

        network, network_source = _latest_evidence(db, limit=body.network_limit), "stored_evidence"

    report = correlate(runtime_events, network, host_map=body.host_map)
    report["sources"] = {
        "runtime": runtime_source,
        "network": network_source,
        "runtime_events": len(runtime_events),
        "network_records": len(network),
        "host_map_entries": len(body.host_map),
    }
    return report
