"""Live observation intake: the estate is observed continuously, and only changes are stored.

This is the agent-facing half of the live architecture. It exists because copying an entire
estate every few minutes costs the bank storage and costs the platform the one thing it
sells: a twin that is current. The rule is one baseline, then changes:

1. the agent normalises what it sees and computes a **state hash** of that normalised state;
2. it posts the observation (optionally signed) with the hash it computed;
3. this router builds the same graph the projection engine builds, computes the platform's
   own hash, and compares it with the stored twin's;
4. **equal** → nothing is stored except a single heartbeat row. No run, no evidence, no BOM
   revision. The response says ``NO_CHANGE`` and names the projection it compared against;
5. **different** → the observation goes through the estate engine's own ``run_discovery``, so
   a transferred observation is stored exactly like a collected one: same graph, same
   evidence store, same change feed, same six projections.

Three things this file refuses to do:

* **it does not call a 200 an ingest.** ``state`` comes from the comparison, ``stored`` says
  whether anything was written, and ``projection_id`` names the evidence state a later BOM
  download will project;
* **it does not hide an unauthenticated observation.** The verdict
  (``VALID``/``UNSIGNED``/``SIGNED_UNVERIFIED``/``KEY_MISMATCH``/``INVALID``) is returned and
  recorded with the run. A deployment can require signatures
  (``CRYPTOSCAN_REQUIRE_SIGNED_OBSERVATIONS=1``), in which case anything but ``VALID`` is
  refused; the default says what it accepted instead of implying authenticity;
* **it does not treat a silent agent as a quiet estate.** ``/live/status`` computes the
  connection state from the age of the last observation. No observation inside the expected
  interval is ``STALE``, and no observation at all is ``NEVER_CONNECTED`` — never ``LIVE``.
"""

from __future__ import annotations

import os
from datetime import datetime, time, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api import estate_change_feed
from api.dependencies import get_current_user, get_db_session
from api.routers import estate_graph
from db.repositories.scan_run_repository import ScanRunRepository
from db.tenancy import current_tenant
from shared_models import live_estate, release_signature
from shared_models.estate_graph import build_graph

import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ingestion", tags=["ingestion"])

#: the twin, the change feed and the BOM projections all read this one run kind, so a live
#: observation is not a second class of estate state
LIVE_RUN_KIND = estate_graph.RUN_KIND

#: one pruned row per tenant: proof the agent reported, without storing the estate again
HEARTBEAT_KIND = "ingestion-heartbeat"

#: where this deployment's trusted collector keys live (PEM path, base64 key, comma/:_sep list)
TRUST_KEY_ENV = "CRYPTOSCAN_COLLECTOR_TRUST_KEYS"

#: "1" turns "authenticity is reported" into "authenticity is required"
REQUIRE_SIGNATURES_ENV = "CRYPTOSCAN_REQUIRE_SIGNED_OBSERVATIONS"

#: how often an agent is expected to report; drives the LIVE/STALE boundary
INTERVAL_ENV = "CRYPTOSCAN_OBSERVATION_INTERVAL_SECONDS"

OBSERVATION_SCHEMA = "cryptoscan.live-observation/1"
SCHEMA = "cryptoscan.live-ingest/1"

NO_TRUSTED_KEY = "NO_TRUSTED_COLLECTOR_KEY"


class LiveObservationRequest(BaseModel):
    """One observation of the estate, as an agent sees it right now."""

    assets: list[dict[str, Any]] = Field(default_factory=list, max_length=20000)
    evidence: list[dict[str, Any]] = Field(default_factory=list, max_length=100000)
    relationships: list[dict[str, Any]] = Field(default_factory=list, max_length=100000)
    collectors: list[dict[str, Any]] = Field(default_factory=list, max_length=100)
    coverage: list[dict[str, Any]] = Field(default_factory=list, max_length=500)
    estate: str = Field(default="default", max_length=160)
    scope: str | None = Field(default=None, max_length=160)
    inventory_id: str = Field(default="default", max_length=160)
    observed_at: str | None = Field(default=None, max_length=64)
    state_hash: str | None = Field(
        default=None,
        max_length=128,
        description="the agent's own hash of its normalised state; compared, never trusted",
    )
    signature: dict[str, Any] | None = Field(
        default=None,
        description="an Ed25519 signature block over this observation (see /ingestion/live/status)",
    )
    include_boms: bool = Field(default=True)
    persist: bool = Field(default=True)


# --------------------------------------------------------------------------- #
# deployment configuration (never request fields)
# --------------------------------------------------------------------------- #


def trusted_keys() -> list:
    """Keys this deployment trusts for observations. A broken entry is skipped, not trusted."""
    raw = os.getenv(TRUST_KEY_ENV, "").strip()
    if not raw:
        return []
    keys = []
    for candidate in raw.replace(",", os.pathsep).split(os.pathsep):
        entry = candidate.strip()
        if not entry:
            continue
        try:
            keys.append(release_signature.load_public_key(entry))
        except Exception:  # noqa: BLE001 — a typo must degrade to "no key", not to "any key"
            logger.warning("release_public_key_unreadable", exc_info=True)
            continue
    return keys


def signatures_required() -> bool:
    return str(os.getenv(REQUIRE_SIGNATURES_ENV, "")).strip().lower() in {"1", "true", "yes", "on"}


def interval_seconds() -> int:
    try:
        return max(30, int(os.getenv(INTERVAL_ENV, str(live_estate.DEFAULT_INTERVAL_SECONDS))))
    except ValueError:
        return live_estate.DEFAULT_INTERVAL_SECONDS


def signed_document(body: LiveObservationRequest) -> dict[str, Any]:
    """The exact document a signature covers — the observation, without the signature."""
    return {
        "schema": OBSERVATION_SCHEMA,
        "estate": body.estate,
        "scope": body.scope,
        "inventory_id": body.inventory_id,
        "observed_at": body.observed_at,
        "assets": body.assets,
        "evidence": body.evidence,
        "relationships": body.relationships,
        "collectors": body.collectors,
        "coverage": body.coverage,
    }


def _authenticity(document: dict[str, Any], signature: dict[str, Any] | None) -> dict[str, Any]:
    keys = trusted_keys()
    trusted = keys[0] if keys else None
    verdict = release_signature.verify_document(
        {**document, "signature": signature} if signature else document,
        trusted_key=trusted,
    )
    out = {
        "schema": "cryptoscan.authenticity/1",
        "status": verdict.get("status"),
        "proves": verdict.get("proves"),
        "reason": verdict.get("reason"),
        "meaning": verdict.get("meaning"),
        "key_id": verdict.get("key_id"),
        "trust_keys_configured": len(keys),
        "signatures_required": signatures_required(),
        "store_authorised_for_authenticity": verdict.get("status") == release_signature.VALID,
    }
    findings: list[str] = []
    if not keys:
        findings.append(
            f"{NO_TRUSTED_KEY}: no collector key is configured on this deployment "
            f"({TRUST_KEY_ENV}), so no observation can reach {release_signature.VALID} here"
        )
    if len(keys) > 1:
        findings.append(
            f"{len(keys)} collector keys are configured; only the first is used for this verdict"
        )
    if verdict.get("status") != release_signature.VALID:
        findings.append(
            "the observation was not authenticated: it is stored as evidence the platform saw, "
            "not as evidence a named collector produced"
        )
    out["deployment_findings"] = findings
    return out


def _require_bound_identity(request: Request, signature: dict[str, Any] | None) -> None:
    """Refuse an observation whose signer is not the agent its certificate proved.

    Only active when the deployment requires machine identity
    (``CRYPTOSCAN_REQUIRE_AGENT_IDENTITY``); the middleware has then already
    resolved — or refused — the certificate, so an absent identity here means the
    middleware was bypassed, which is itself a refusal.
    """
    from api.security import agent_identity

    if not agent_identity.enforcement_enabled():
        return
    state = getattr(request, "state", None)
    agent = getattr(state, "agent_identity", None) if state is not None else None
    if agent is None:
        raise HTTPException(
            status_code=403,
            detail={
                "error": "agent_identity_unregistered",
                "reason": getattr(state, "agent_identity_reason", None)
                or "no agent identity was established for this request",
                "stored": False,
            },
        )
    bound, reason = agent_identity.check_signature_binding(agent, signature)
    if not bound:
        raise HTTPException(
            status_code=401,
            detail={
                "error": "signature_not_bound_to_agent",
                "agent_id": agent.agent_id,
                "reason": reason,
                "note": ("the certificate proves which machine connected; the signature "
                         "must be the key registered for that machine, or the two facts "
                         "are unrelated and neither is evidence"),
                "stored": False,
            },
        )


# --------------------------------------------------------------------------- #
# heartbeat: one row per tenant, so a 24/7 agent does not grow the table
# --------------------------------------------------------------------------- #


def _write_heartbeat(
    db: Session,
    *,
    state: str,
    projection_id: str,
    counts: dict[str, Any],
    authenticity: dict[str, Any],
    observed_at: str | None,
) -> dict[str, Any]:
    repo = ScanRunRepository(db)
    tenant = current_tenant()
    for row in repo.list_runs(limit=50, target_kind=HEARTBEAT_KIND, owner=tenant):
        db.delete(row)
    row = repo.create_run(
        {
            "heartbeat": {
                "state": state,
                "projection_id": projection_id,
                "counts": counts,
                "observed_at": observed_at,
                "authenticity": authenticity.get("status"),
                "recorded_at": datetime.now(timezone.utc).isoformat(),
            }
        },
        target_kind=HEARTBEAT_KIND,
    )
    db.commit()
    return {
        "run_id": row.id,
        "recorded_at": str(getattr(row, "created_at", "") or ""),
        "state": state,
        "stores_estate": False,
    }


def _last_observation(db: Session) -> Any:
    """Newest sign of life: a heartbeat, else a stored run. Never invented."""
    repo = ScanRunRepository(db)
    tenant = current_tenant()
    beats = repo.list_runs(limit=1, target_kind=HEARTBEAT_KIND, owner=tenant)
    runs = repo.list_runs(limit=1, target_kind=LIVE_RUN_KIND, owner=tenant)
    candidates = [row for row in (beats[0] if beats else None, runs[0] if runs else None) if row is not None]
    if not candidates:
        return None
    return max(candidates, key=lambda row: _aware(getattr(row, "created_at", None)) or datetime.min.replace(tzinfo=timezone.utc))


# --------------------------------------------------------------------------- #
# push an observation
# --------------------------------------------------------------------------- #


@router.post("/observations")
def push_observation(
    body: LiveObservationRequest,
    request: Request,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
) -> JSONResponse:
    """Store this observation only if the estate changed, and say which one happened."""
    document = signed_document(body)
    authenticity = _authenticity(document, body.signature)
    _require_bound_identity(request, body.signature)
    if signatures_required() and authenticity["status"] != release_signature.VALID:
        raise HTTPException(
            status_code=401,
            detail={
                "error": "observation_not_authentic",
                "authenticity": authenticity,
                "reason": (
                    "this deployment requires a signed observation from a trusted collector key; "
                    "nothing was stored"
                ),
            },
        )

    try:
        graph = build_graph(
            {
                "estate": body.estate,
                "scope": body.scope,
                "assets": body.assets,
                "evidence": body.evidence,
                "relationships": body.relationships,
                "collectors": body.collectors,
                "coverage": body.coverage,
            }
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "observation_rejected",
                "reason": str(exc),
                "note": (
                    "evidence must target a declared asset, and a relationship needs a basis plus "
                    "evidence; an unsupported edge is refused rather than assumed"
                ),
                "stored": False,
            },
        ) from exc

    projection_id = graph.fingerprint()
    repo = ScanRunRepository(db)
    previous = repo.list_runs(limit=1, target_kind=LIVE_RUN_KIND, owner=current_tenant())
    warnings: list[str] = []
    previous_id: str | None = None
    if previous:
        try:
            previous_id = estate_graph._graph_from_run(previous[0]).fingerprint()
        except Exception as exc:  # noqa: BLE001 — an unreadable baseline is stated, not guessed
            warnings.append(
                f"PREVIOUS_TWIN_UNREADABLE: the stored observation {previous[0].id} could not be "
                f"rebuilt ({type(exc).__name__}: {exc}), so this observation is stored as a new baseline"
            )

    comparison = live_estate.compare_state(previous_id, projection_id)
    state_hash = live_estate.state_hash_report(projection_id, body.state_hash)
    counts = {
        "assets": len(body.assets),
        "evidence": len(body.evidence),
        "relationships": len(body.relationships),
        "collectors": len(body.collectors),
        "coverage_rows": len(body.coverage),
    }

    # -- no change: keep the connection, not the estate ---------------------- #
    if not comparison["store"]:
        heartbeat = (
            _write_heartbeat(
                db,
                state=comparison["state"],
                projection_id=projection_id,
                counts=counts,
                authenticity=authenticity,
                observed_at=body.observed_at,
            )
            if body.persist
            else None
        )
        return JSONResponse(
            status_code=200,
            content={
                "schema": SCHEMA,
                "state": comparison["state"],
                "stored": False,
                "run_id": None,
                "comparison": comparison,
                "state_hash": state_hash,
                "authenticity": authenticity,
                "projection_id": projection_id,
                "counts": counts,
                "heartbeat": heartbeat,
                "warnings": warnings,
                "note": (
                    "the normalised state equals the stored twin, so no evidence, run or BOM "
                    "revision was written; the heartbeat records that the agent reported"
                ),
                "limits": live_estate.LIMITS,
            },
        )

    # -- changed: store the observation through the estate engine ------------ #
    request = estate_graph.EstateDiscoverRequest(
        estate=body.estate,
        scope=body.scope,
        inventory_id=body.inventory_id,
        assets=body.assets,
        evidence=body.evidence,
        relationships=body.relationships,
        collectors=body.collectors,
        coverage=body.coverage,
        include_boms=body.include_boms,
        persist=body.persist,
    )
    result = estate_graph.run_discovery(db, user, request, graph=graph)
    detection = result.get("detection") or {}
    impact = live_estate.bom_impact(detection.get("changes") or [])
    heartbeat = (
        _write_heartbeat(
            db,
            state=comparison["state"],
            projection_id=projection_id,
            counts=counts,
            authenticity=authenticity,
            observed_at=body.observed_at,
        )
        if body.persist
        else None
    )
    return JSONResponse(
        status_code=201,
        content={
            "schema": SCHEMA,
            "state": comparison["state"],
            "stored": body.persist,
            "comparison": comparison,
            "state_hash": state_hash,
            "authenticity": authenticity,
            "projection_id": projection_id,
            "run_id": result.get("run_id"),
            "counts": counts,
            "coverage": result.get("coverage"),
            "unknown": result.get("unknown"),
            "detection": detection or None,
            "bom_impact": impact,
            "bom_counts": result.get("bom_counts"),
            "evidence_store": result.get("evidence_store"),
            "boms": result.get("boms") if body.include_boms else None,
            "heartbeat": heartbeat,
            "warnings": warnings,
            "note": (
                "a stored change: the twin, the evidence store and the change feed advanced "
                "together, and the projections listed in bom_impact are the ones a download will "
                "render from this projection_id"
            ),
            "limits": live_estate.LIMITS,
        },
    )


# --------------------------------------------------------------------------- #
# retention: the change feed grows, the twin does not
# --------------------------------------------------------------------------- #


class CompactionRequest(BaseModel):
    """What to keep when trimming live history. A dry run unless ``confirm`` is true."""

    keep_days: int = Field(default=30, ge=1, le=3650)
    keep_latest_observations: int = Field(
        default=3,
        ge=1,
        le=50,
        description="always keep the newest N stored observations, however old they are",
    )
    include_change_events: bool = Field(
        default=True, description="trim change events too; the newest event is always kept"
    )
    acknowledged_only: bool = Field(
        default=True,
        description="only trim change events somebody has acknowledged — an unread claim is not history yet",
    )
    confirm: bool = Field(
        default=False, description="false = report what would be deleted, delete nothing"
    )


@router.post("/live/compact")
def compact_live_history(
    body: CompactionRequest,
    _user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
) -> dict:
    """Trim live history by age — the one part of live mode that grows without bound.

    Storage grows with *changes*, so the change feed is the only table that needs a policy.
    The rules are stated rather than tuned silently:

    * the newest N observations are kept regardless of age — they are the twin;
    * change events nobody has acknowledged are kept — deleting an unread claim would make
      the feed a place where history disappears before it is read;
    * a dry run is the default, because a retention call made in passing should not be able
      to shorten an audit trail.
    """
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=int(body.keep_days))
    tenant = current_tenant()
    repo = ScanRunRepository(db)

    runs = repo.list_runs(limit=500, target_kind=LIVE_RUN_KIND, owner=tenant)
    keep_ids = {row.id for row in runs[: int(body.keep_latest_observations)]}
    stale_runs = [
        row
        for row in runs
        if row.id not in keep_ids
        and _aware(getattr(row, "created_at", None)) is not None
        and _aware(row.created_at) < cutoff
    ]

    events = estate_change_feed.list_events(db, tenant_id=tenant, include_acknowledged=True, limit=200)
    newest_event_id = events[0].id if events else None
    stale_events = []
    if body.include_change_events:
        for row in events:
            if row.id == newest_event_id:
                continue
            if body.acknowledged_only and getattr(row, "acknowledged_at", None) is None:
                continue
            detected = _aware(getattr(row, "last_detected_at", None) or getattr(row, "first_detected_at", None))
            if detected is not None and detected < cutoff:
                stale_events.append(row)

    run_bytes = sum(len(str(row.result or "")) for row in stale_runs)
    event_bytes = sum(
        len(str(row.changes or "")) + len(str(row.headline or "")) for row in stale_events
    )

    deleted = {"observations": 0, "change_events": 0}
    if body.confirm:
        for row in stale_runs:
            db.delete(row)
        for row in stale_events:
            db.delete(row)
        db.commit()
        deleted = {"observations": len(stale_runs), "change_events": len(stale_events)}

    return {
        "schema": SCHEMA,
        "dry_run": not body.confirm,
        "cutoff": cutoff.isoformat(),
        "keep_days": body.keep_days,
        "candidates": {
            "observations": len(stale_runs),
            "change_events": len(stale_events),
            "approx_bytes": run_bytes + event_bytes,
        },
        "deleted": deleted,
        "preserved": {
            "newest_observations": min(len(runs), int(body.keep_latest_observations)),
            "newest_change_event": newest_event_id,
            "unacknowledged_events": len(
                [row for row in events if getattr(row, "acknowledged_at", None) is None]
            ),
            "heartbeat": len(repo.list_runs(limit=1, target_kind=HEARTBEAT_KIND, owner=tenant)),
        },
        "note": (
            "nothing was deleted: pass confirm=true to apply this policy"
            if not body.confirm
            else "the listed rows were deleted; the latest observation, the latest change event "
            "and every unacknowledged claim were kept"
        ),
        "limits": [
            "deleting an observation removes the twin state stored with it; the change events "
            "derived from it remain unless they are trimmed too",
            "retention is per tenant and by observation time, not by row write time",
            "no compaction runs on a schedule in this build — the endpoint is manual",
        ],
    }


# --------------------------------------------------------------------------- #
# read the live state
# --------------------------------------------------------------------------- #


@router.get("/observations")
def list_observations(
    limit: int = Query(default=20, ge=1, le=200),
    _user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
) -> dict:
    """Stored observations, newest first — the ones that carried a change.

    A quiet estate produces no rows here. That is the point of live mode, and it is why the
    connection state below is measured from the heartbeat instead of from this list.
    """
    rows = ScanRunRepository(db).list_runs(limit=limit, target_kind=LIVE_RUN_KIND, owner=current_tenant())
    observations = []
    for row in rows:
        result = row.result or {}
        summary = result.get("estate_summary") or {}
        observations.append(
            {
                "run_id": row.id,
                "recorded_at": str(getattr(row, "created_at", "") or ""),
                "estate": (result.get("estate_discovery") or {}).get("estate"),
                "scope": (result.get("estate_discovery") or {}).get("scope"),
                "projection_id": summary.get("projection_id"),
                "assets": summary.get("assets"),
                "evidence": summary.get("evidence"),
                "relationships": summary.get("relationships"),
            }
        )
    return {
        "schema": SCHEMA,
        "count": len(observations),
        "observations": observations,
        "note": (
            "only observations that changed the estate are stored; an unchanged observation "
            "produces a heartbeat, not a row"
        ),
    }


@router.get("/live/status")
def live_status(
    _user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
) -> dict:
    """Is this estate live, what is the twin, and what can be downloaded right now?"""
    repo = ScanRunRepository(db)
    tenant = current_tenant()
    last = _last_observation(db)
    connection = live_estate.connection_state(last_created_at(last), interval_seconds=interval_seconds())
    keys = trusted_keys()

    runs = repo.list_runs(limit=1, target_kind=LIVE_RUN_KIND, owner=tenant)
    twin: dict[str, Any]
    boms: dict[str, Any]
    changes_today: dict[str, Any]
    if runs:
        row = runs[0]
        try:
            graph = estate_graph._graph_from_run(row)
            summary = graph.summary()
            projections = graph.project_all()
            twin = {
                "state": "OBSERVED",
                "run_id": row.id,
                "projection_id": summary["projection_id"],
                "assets": summary["assets"],
                "evidence": summary["evidence"],
                "relationships": summary["relationships"],
                "coverage": summary["coverage"],
                "unknown": summary["unknown"],
                "recorded_at": str(getattr(row, "created_at", "") or ""),
            }
            boms = {
                "projection_id": projections["projection_id"],
                "counts": projections["counts"],
                "kinds": {
                    kind: {
                        "available": True,
                        "download": f"/api/v1/estate/evidence/boms/{kind}/export?fmt=cyclonedx",
                    }
                    for kind in projections["counts"]
                },
            }
        except Exception as exc:  # noqa: BLE001 — unreadable twin is reported, not hidden
            twin = {
                "state": "UNREADABLE",
                "run_id": row.id,
                "reason": f"{type(exc).__name__}: {exc}",
            }
            boms = {"projection_id": None, "kinds": {}, "reason": "the stored twin cannot be rebuilt"}
    else:
        twin = {
            "state": "NOT_OBSERVED",
            "reason": "no observation has been accepted for this estate",
        }
        boms = {
            "projection_id": None,
            "kinds": {},
            "reason": "nothing to project: a BOM download would be a document about no evidence",
        }

    today = datetime.combine(datetime.now(timezone.utc).date(), time.min, tzinfo=timezone.utc)
    events = estate_change_feed.list_events(db, tenant_id=tenant, limit=200)
    recent = [
        estate_change_feed.public_event(row)
        for row in events
        if (_aware(getattr(row, "last_detected_at", None)) or datetime.min.replace(tzinfo=timezone.utc)) >= today
    ]
    changes_today = {
        "count": len(recent),
        "by_severity": _count(item.get("severity") for item in recent),
        "by_verdict": _count(item.get("verdict") for item in recent),
        "unacknowledged": len([item for item in recent if not item.get("acknowledged")]),
        "note": "counts of stored change events detected today (UTC), not of open risk",
    }

    return {
        "schema": SCHEMA,
        "connection": connection,
        "twin": twin,
        "boms": boms,
        "changes_today": changes_today,
        "trust": {
            "signatures_required": signatures_required(),
            "trust_keys_configured": len(keys),
            "findings": (
                []
                if keys
                else [
                    f"{NO_TRUSTED_KEY}: observations are accepted and recorded as unauthenticated "
                    f"because no key is configured ({TRUST_KEY_ENV})"
                ]
            ),
        },
        "note": (
            "the twin is the live state; the six BOMs are projections of it and are never stored "
            "as separate truth"
        ),
        "limits": live_estate.LIMITS,
    }


def _aware(moment: Any) -> datetime | None:
    """A stored timestamp as an aware UTC datetime; SQLite returns naive ones."""
    if not isinstance(moment, datetime):
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def last_created_at(row: Any) -> Any:
    """The timestamp a stored row was written, or ``None`` — never a plausible substitute."""
    return getattr(row, "created_at", None) if row is not None else None


def _count(values) -> dict[str, int]:
    out: dict[str, int] = {}
    for value in values:
        key = str(value or "UNKNOWN")
        out[key] = out.get(key, 0) + 1
    return dict(sorted(out.items()))
