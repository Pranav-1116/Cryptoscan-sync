"""Estate evidence graph API — one discovery, six BOM projections (spec 93).

This router exposes the *estate engine*, not six scanners:

* ``POST /estate/evidence/discover`` ingests one discovery payload (assets,
  evidence, relationships, collector outcomes, expected/collected counts), builds
  the graph, and returns the coverage matrix, the unknown inventory and — on
  request — all six BOM projections from that same snapshot;
* ``GET /estate/evidence/{summary,graph,coverage,boms}`` read the latest
  discovery for the tenant back out of the stored run.

Three things this router refuses to do:

* it never turns a failed collector into "none" — the response carries ``FAILED``
  with an impact statement for the BOMs that depended on it;
* it never reports coverage as "percent of crypto discovered" — it reports
  attempted/expected targets;
* it never lets a relationship exist without a basis and evidence (the engine
  records it as ``UNKNOWN`` instead).

The pre-existing ``/estate`` router (cloud campaign planning) is untouched; these
routes live under ``/estate/evidence`` so the two never shadow each other.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api import (
    estate_catalog,
    estate_conflicts,
    estate_crypto_intel,
    estate_lifecycle,
    estate_trust,
    estate_observations,
    estate_remediation,
    estate_search,
    estate_change_feed,
    estate_discovery,
    estate_drift,
    estate_graph_loader,
    estate_schedule,
    estate_simulation_store,
    estate_twin_store,
)
from api.dependencies import get_current_user, get_db_session
from db.repositories.scan_run_repository import ScanRunRepository
from db.tenancy import current_tenant
from api.security import anchor_export
from api.security.estate_bom_anchor import AnchorError, create_anchor, list_anchors, verify_anchor
from shared_models import estate_twin
from shared_models.estate_graph import BOM_KINDS, SCHEMA, build_graph

router = APIRouter(prefix="/estate/evidence", tags=["estate-evidence"])

RUN_KIND = "estate-discovery"


class EstateAnchorRequest(BaseModel):
    """Sign the current projected BOM set into an exportable receipt."""

    note: str | None = Field(default=None, max_length=400)


class EstateScheduleRequest(BaseModel):
    """A saved cadence for the estate job."""

    name: str = Field(min_length=1, max_length=100)
    every: str | None = Field(default=None, max_length=20, description="interval, e.g. 6h")
    cron: str | None = Field(default=None, max_length=120, description="five-field UTC cron")
    scope: str = Field(default="production", max_length=80)
    estate: str = Field(default="default", max_length=120)
    planes: list[str] | None = Field(default=None, max_length=12)
    enabled: bool = True


class EstateScheduleToggle(BaseModel):
    enabled: bool


class EstateTickRequest(BaseModel):
    worker: str = Field(default="api-tick", max_length=120)
    lease_seconds: int = Field(default=900, ge=30, le=86400)
    limit: int = Field(default=20, ge=1, le=200)


class EstateAnchorExportRequest(BaseModel):
    anchor_id: str | None = Field(default=None, max_length=80)


class EstateAnchorVerifyRequest(BaseModel):
    """Verify one stored receipt against the BOMs projected from the stored graph."""

    anchor_id: str | None = Field(default=None, max_length=80)


class EstateScanRequest(BaseModel):
    """One estate-discovery job over the planes this deployment can read."""

    estate: str = Field(default="default", max_length=160)
    scope: str | None = Field(default=None, max_length=160)
    planes: list[str] | None = Field(
        default=None,
        max_length=len(estate_discovery.PLANES),
        description="subset of the discovery planes; omitting it runs every plane",
    )
    include_boms: bool = True
    persist: bool = True


class EstateDiscoverRequest(BaseModel):
    """One estate discovery payload — the same evidence feeds every BOM."""

    estate: str = Field(default="default", max_length=160)
    scope: str | None = Field(default=None, max_length=160)
    inventory_id: str = Field(default="default", max_length=160)
    assets: list[dict[str, Any]] = Field(default_factory=list, max_length=20000)
    evidence: list[dict[str, Any]] = Field(default_factory=list, max_length=100000)
    relationships: list[dict[str, Any]] = Field(default_factory=list, max_length=100000)
    collectors: list[dict[str, Any]] = Field(default_factory=list, max_length=100)
    coverage: list[dict[str, Any]] = Field(default_factory=list, max_length=500)
    include_boms: bool = True
    persist: bool = True


def _build(body: EstateDiscoverRequest):
    try:
        return build_graph(
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
                "error": "estate_payload_rejected",
                "reason": str(exc),
                "note": (
                    "evidence must target a declared asset, and a relationship needs a basis plus "
                    "evidence — an unsupported edge is refused, never assumed"
                ),
            },
        ) from exc


def _latest_run(db: Session) -> Any:
    runs = ScanRunRepository(db).list_runs(limit=1, target_kind=RUN_KIND, owner=current_tenant())
    if not runs:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "no_estate_discovery",
                "reason": (
                    "no estate discovery has run for this tenant — run POST /estate/evidence/discover; "
                    "an empty estate is NOT_OBSERVED, not an estate without crypto"
                ),
            },
        )
    return runs[0]


def _latest_twin_graph_or_none(db: Session) -> Any | None:
    """The newest twin, or ``None`` when nothing has been observed yet.

    Conflicts do not need a live run to be answerable — the durable per-fact record holds
    disputes on its own — so this returns None rather than raising, and the caller
    reports the history half instead of a 404.
    """
    runs = ScanRunRepository(db).list_runs(limit=1, target_kind=RUN_KIND, owner=current_tenant())
    if not runs:
        return None
    try:
        return _graph_from_run(runs[0])
    except Exception:  # noqa: BLE001 — a corrupt run must not hide the recorded disputes
        return None


def _graph_from_run(run) -> Any:
    """Rebuild the twin from a stored run.

    ``build_graph`` is the only constructor on purpose: an unknown predicate or a
    dangling endpoint raises here rather than being quietly dropped, so a corrupt
    stored run surfaces as an error instead of a smaller-looking estate.
    """
    payload = (run.result or {}).get("estate_discovery") or {}
    return build_graph(payload)


def _report_from_run(run) -> dict[str, Any]:
    """Rebuild one stored discovery into the report shape the drift module reads."""
    graph = _graph_from_run(run)
    payload = ((run.result or {}).get("estate_discovery") or {})
    projections = graph.project_all()
    return {
        "run_id": run.id,
        "projection_id": graph.fingerprint(),
        "estate": payload.get("estate"),
        "scope": payload.get("scope"),
        "summary": graph.summary(),
        "coverage": graph.coverage(),
        "collectors": payload.get("collectors") or [],
        "boms": projections["boms"],
    }


@router.get("/drift")
def estate_drift_view(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Drift between the two newest stored discovery snapshots.

    One run is ``NO_BASELINE`` rather than "no drift", and a plane that stopped
    collecting is reported as coverage debt, not as the estate losing assets.
    """
    runs = ScanRunRepository(db).list_runs(limit=2, target_kind=RUN_KIND, owner=current_tenant())
    reports = [_report_from_run(run) for run in runs]
    return estate_drift.compare_latest(reports)


@router.post("/boms/anchor")
def estate_boms_anchor(
    body: EstateAnchorRequest,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Sign the projected BOM set with a key the database does not hold."""
    run = _latest_run(db)
    graph = _graph_from_run(run)
    projections = graph.project_all()
    try:
        return create_anchor(
            db,
            boms=projections["boms"],
            projection_id=projections["projection_id"],
            tenant_id=current_tenant(),
            run_id=run.id,
            user=user,
            note=body.note,
        )
    except AnchorError as exc:
        raise HTTPException(
            status_code=409, detail={"error": exc.code, "reason": exc.reason}
        ) from exc


@router.get("/boms/anchors")
def estate_boms_anchors(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Stored projected-BOM anchor receipts, oldest first."""
    return list_anchors(db, tenant_id=current_tenant())


@router.post("/boms/anchor/verify")
def estate_boms_anchor_verify(
    body: EstateAnchorVerifyRequest,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Recompute the current BOM digests and compare them with a stored receipt."""
    from api.security.network_evidence_anchor import anchor_key

    stored = list_anchors(db, tenant_id=current_tenant())["anchors"]
    if not stored:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "no_bom_anchor",
                "reason": (
                    "no projected BOM set has been anchored for this tenant — POST /estate/evidence/boms/anchor; "
                    "an unanchored projection is not evidence of what was published"
                ),
            },
        )
    receipt = None
    if body.anchor_id:
        receipt = next((item for item in stored if item.get("anchor_id") == body.anchor_id), None)
        if receipt is None:
            raise HTTPException(
                status_code=404,
                detail={"error": "unknown_bom_anchor", "reason": f"no receipt with id {body.anchor_id!r}"},
            )
    else:
        receipt = stored[-1]
    run = _latest_run(db)
    graph = _graph_from_run(run)
    projections = graph.project_all()
    key, _source = anchor_key()
    verification = verify_anchor(receipt, projections["boms"], key=key)
    verification["run_id"] = run.id
    verification["current_projection_id"] = projections["projection_id"]
    return verification


@router.get("/boms/anchor/export/status")
def estate_boms_anchor_export_status(user: str = Depends(get_current_user)):
    """Whether an external export sink is configured, and which one."""
    return anchor_export.sink_status()


@router.post("/boms/anchor/export")
def estate_boms_anchor_export(
    body: EstateAnchorExportRequest,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Push a stored anchor receipt to storage CryptoScan does not control.

    A signed receipt inside our own database proves nothing about the outside
    world: this is the step that puts it where the bank's auditors can read it
    without asking us. The sink confirms the write; without confirmation the
    anchor is *not* external and the call fails.
    """
    stored = list_anchors(db, tenant_id=current_tenant())["anchors"]
    if not stored:
        raise HTTPException(
            status_code=404,
            detail={"error": "no_bom_anchor",
                    "reason": "create an anchor receipt first (POST /estate/evidence/boms/anchor)"},
        )
    receipt = None
    if body.anchor_id:
        receipt = next((item for item in stored if item.get("anchor_id") == body.anchor_id), None)
        if receipt is None:
            raise HTTPException(
                status_code=404,
                detail={"error": "unknown_bom_anchor", "reason": f"no receipt with id {body.anchor_id!r}"},
            )
    else:
        receipt = stored[-1]
    try:
        return anchor_export.export_receipt(receipt)
    except anchor_export.AnchorExportError as exc:
        raise HTTPException(
            status_code=409 if exc.code in {"anchor_export_not_configured", "already_exported"} else 502,
            detail={"error": exc.code, "reason": exc.reason, **exc.detail},
        ) from exc


@router.get("/schedules")
def estate_schedules(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    """Saved estate cadences with the outcome of their last run."""
    rows = _schedule_rows(db)
    return {
        "model": "cryptoscan.estate-schedules/1",
        "schedules": rows,
        "note": (
            "a schedule is a database row, not a crontab line: it survives deploys, the console can see it, "
            "and each run records its verdict so a nightly PARTIAL_COVERAGE estate cannot pass unnoticed"
        ),
    }


def _schedule_rows(db: Session) -> list[dict[str, Any]]:
    tenant = current_tenant()
    return [estate_schedule.as_dict(row) for row in estate_schedule.list_schedules(
        db, tenant_id=tenant, exact_tenant=True)]


def _schedule_actor(db: Session, request: Request, user: str) -> str:
    from api.assurance.store import actor

    return actor(db, request, user, "monitor.manage")


@router.post("/schedules", status_code=201)
def estate_schedule_create(
    body: EstateScheduleRequest,
    request: Request,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """A current monitor manager schedules only explicitly selected persisted planes."""
    actor_id = _schedule_actor(db, request, user)
    try:
        row = estate_schedule.create_schedule(
            db,
            name=body.name,
            tenant_id=current_tenant(),
            scope=body.scope,
            estate=body.estate,
            every=body.every,
            cron=body.cron,
            planes=body.planes,
            enabled=body.enabled,
            user=actor_id,
        )
    except estate_schedule.ScheduleError as exc:
        raise HTTPException(status_code=409 if exc.code == "schedule_exists" else 422,
                            detail={"error": exc.code, "reason": exc.reason}) from exc
    return estate_schedule.as_dict(row)


@router.patch("/schedules/{identifier}")
def estate_schedule_toggle(
    identifier: str,
    body: EstateScheduleToggle,
    request: Request,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Pause or resume a schedule without deleting its history."""
    _schedule_actor(db, request, user)
    try:
        row = estate_schedule.set_enabled(db, identifier, body.enabled, tenant_id=current_tenant())
    except estate_schedule.ScheduleError as exc:
        raise HTTPException(status_code=404 if exc.code == "schedule_not_found" else 409,
                            detail={"error": exc.code, "reason": exc.reason}) from exc
    return estate_schedule.as_dict(row)


@router.delete("/schedules/{identifier}")
def estate_schedule_delete(
    identifier: str,
    request: Request,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    _schedule_actor(db, request, user)
    try:
        estate_schedule.delete_schedule(db, identifier, tenant_id=current_tenant())
    except estate_schedule.ScheduleError as exc:
        raise HTTPException(status_code=404 if exc.code == "schedule_not_found" else 409,
                            detail={"error": exc.code, "reason": exc.reason}) from exc
    raise HTTPException(status_code=500, detail="Schedule deletion has no retained tombstone receipt")


@router.post("/tick")
def estate_tick(
    body: EstateTickRequest,
    request: Request,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Run what is due now. The lease makes a manual tick and a sidecar safe together."""
    _schedule_actor(db, request, user)
    return estate_schedule.tick(
        db, worker=body.worker, lease_seconds=body.lease_seconds, limit=body.limit,
        tenant_id=current_tenant(), exact_tenant=True,
    )


@router.get("/realtime")
def estate_realtime(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    """Is the estate actually running right now? (§18, 24/7)

    Three facts, none of which the API's own liveness can fake:

    * the daemon heartbeat (``LIVE`` / ``STALE`` / ``STOPPED`` / ``NEVER_STARTED``)
      with its age and next wake;
    * the schedules — how many are enabled, when the next one is due, and whether
      any lease is held (a held lease means a run is in flight *somewhere*);
    * the runs — the most recent scheduled runs and how long ago the last one
      completed, so "the daemon is up" is never confused with "scans are happening".
    """
    from datetime import datetime, timedelta, timezone

    from db.models.estate_schedule import EstateScheduleRun

    from api import estate_daemon_store
    from api.estate_daemon import stale_state

    now = datetime.now(timezone.utc)
    beat = estate_daemon_store.latest(db)
    liveness = stale_state(beat, now=now)

    schedules = estate_schedule.list_schedules(db, tenant_id=current_tenant(), include_disabled=True,
                                               exact_tenant=True)
    enabled = [row for row in schedules if row.enabled]
    next_due = min((estate_schedule._utc(row.next_run_at) for row in enabled), default=None)
    leases = [
        {"name": row.name, "worker": row.claimed_by,
         "until": estate_schedule._iso(row.claimed_until) if row.claimed_until else None}
        for row in enabled if row.claimed_until and estate_schedule._utc(row.claimed_until) > now
    ]

    recent = (
        db.query(EstateScheduleRun)
        .filter(EstateScheduleRun.tenant_id == current_tenant())
        .order_by(EstateScheduleRun.started_at.desc())
        .limit(10)
        .all()
    )
    runs = [
        {
            "schedule_id": row.schedule_id,
            "started_at": estate_schedule._iso(row.started_at),
            "finished_at": estate_schedule._iso(row.finished_at),
            "status": row.status,
            "verdict": row.verdict,
            "coverage_state": row.coverage_state,
            "run_id": row.estate_run_id,
            "detail": row.detail,
        }
        for row in recent
    ]
    last_finished = next((row.finished_at for row in recent if row.finished_at), None)
    last_run_age = round((now - estate_schedule._utc(last_finished)).total_seconds(), 3) if last_finished else None

    if liveness["state"] != "LIVE":
        verdict = "NOT_RUNNING"
        reason = liveness["meaning"]
        next_action = liveness["next_action"]
    elif not enabled:
        verdict = "IDLE_NO_SCHEDULES"
        reason = "the daemon is alive but no schedule is enabled: nothing is being re-scanned"
        next_action = "select an authorized persisted-evidence plane — `cryptoscan schedule add nightly --every 6h --plane STATIC`; this reprojects stored observations, it does not collect source"
    elif leases:
        verdict = "RUNNING"
        reason = f"{len(leases)} schedule(s) are leased right now: a run is in flight"
        next_action = None
    elif any(row.last_verdict in {"ERROR", "PARTIAL_COVERAGE"} or row.last_coverage_state in
             {"NOT_OBSERVED", "PARTIAL", "FAILED"} for row in enabled if row.last_run_at):
        verdict = "DEGRADED"
        reason = "a scheduled projection reported an error or incomplete coverage; a live daemon cannot clear that result"
        next_action = "inspect the failed run and its source receipts before claiming current coverage"
    elif next_due is not None and next_due < now - timedelta(seconds=180):
        verdict = "DEGRADED"
        reason = "an enabled schedule is overdue despite a live daemon"
        next_action = "inspect its lease and daemon log; the cadence is not being met"
    else:
        verdict = "WAITING"
        reason = "the daemon is alive and the next run is not yet due"
        next_action = None

    return {
        "schema": "cryptoscan.estate-realtime/1",
        "at": now.isoformat(),
        "verdict": verdict,
        "reason": reason,
        "next_action": next_action,
        "daemon": {"heartbeat": beat, "liveness": liveness},
        "schedules": {
            "total": len(schedules),
            "enabled": len(enabled),
            "next_due_at": estate_schedule._iso(next_due) if next_due else None,
            "seconds_until_due": round((next_due - now).total_seconds(), 3) if next_due else None,
            "leases": leases,
        },
        "runs": {
            "recent": runs,
            "last_finished_at": estate_schedule._iso(last_finished) if last_finished else None,
            "last_run_age_seconds": last_run_age,
        },
        "meaning": (
            "a live daemon is not proof of coverage: read the run verdict and the coverage state, and treat "
            "STALE/NEVER_STARTED as 'nothing is being scanned'"
        ),
    }


@router.get("/plan")
def estate_plan(user: str = Depends(get_current_user)):
    """The collector plan: which planes run, from which source, and what each cannot see."""
    return estate_discovery.plan()


@router.post("/scan")
def estate_scan(
    body: EstateScanRequest,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Run **one** estate-discovery job and project the six BOMs from its graph.

    This is the fan-out the directive asked for: a single job reads every plane's
    persisted evidence, joins it into one graph, and reports coverage per plane.
    A collector that fails is reported as ``FAILED`` with an impact statement —
    never as an empty plane — and the response carries the lifecycle phases that
    actually ran.
    """
    try:
        return estate_discovery.run(
            db,
            estate=body.estate,
            scope=body.scope,
            planes=body.planes,
            persist=body.persist,
            include_boms=body.include_boms,
            trigger="api",
            # every run compares itself with the previous one, so a console (or
            # an alert rule) learns about change without polling /drift
            previous=(estate_discovery.previous_report(db, tenant_id=current_tenant())
                      if body.persist else None),
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "estate_scan_rejected",
                "reason": str(exc),
                "note": "a known plane must be requested; an unseen plane is NOT_ATTEMPTED, not empty",
            },
        ) from exc


@router.post("/discover")
def estate_discover(
    body: EstateDiscoverRequest,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Discover the estate once and project the BOMs from the same evidence graph.

    Every response carries its coverage matrix and unknown inventory, because a
    BOM without them invites the reader to assume the estate is complete.
    """
    graph = _build(body)
    projections = graph.project_all() if body.include_boms else None
    payload = {
        "estate": body.estate,
        "scope": body.scope,
        "inventory_id": body.inventory_id,
        "assets": body.assets,
        "evidence": body.evidence,
        "relationships": body.relationships,
        "collectors": body.collectors,
        "coverage": body.coverage,
    }
    # the observation before this one, read *before* this run is stored — comparing
    # a run with itself would report "no change" forever
    previous_run = None
    if body.persist:
        earlier = ScanRunRepository(db).list_runs(limit=1, target_kind=RUN_KIND, owner=current_tenant())
        previous_run = earlier[0] if earlier else None

    run_id = None
    if body.persist:
        row = ScanRunRepository(db).create_run(
            {
                "estate_discovery": payload,
                "estate_summary": graph.summary(),
                "coverage": graph.coverage(),
            },
            target_kind=RUN_KIND,
        )
        db.commit()
        run_id = row.id

    # -- live change detection --------------------------------------------- #
    # Ingesting an observation *is* observing the estate, so it goes through the same
    # detector as the collector path. A previous observation that cannot be rebuilt is
    # reported as an unknown baseline rather than silently compared against nothing.
    detection: dict[str, Any] | None = None
    if body.persist:
        previous_error = None
        previous_graph = None
        if previous_run is not None:
            try:
                previous_graph = _graph_from_run(previous_run)
            except Exception as exc:  # noqa: BLE001 — an unreadable baseline is stated, not guessed
                previous_error = f"{type(exc).__name__}: {exc}"
        detection = estate_change_feed.observe(
            db,
            previous_graph,
            graph,
            tenant_id=current_tenant(),
            run_id=run_id,
            trigger="ingest",
            detected_by=user,
            previous_error=previous_error,
        )

    response: dict[str, Any] = {
        "schema": SCHEMA,
        "model": "cryptoscan.estate-discovery/1",
        "run_id": run_id,
        "estate": body.estate,
        "projection_id": graph.fingerprint(),
        "summary": graph.summary(),
        "coverage": graph.coverage(),
        "unknown": graph.unknown_inventory(),
        "conflicts": graph.conflicts(),
        "unresolved_relationships": graph.unresolved_relationships(),
        "merged_identities": graph.merged_identities(),
        "note": (
            "coverage is attempted/expected targets, never 'percent of crypto discovered'; "
            "a failed collector leaves its plane UNKNOWN"
        ),
    }
    if projections is not None:
        response["boms"] = projections["boms"]
        response["bom_counts"] = projections["counts"]
        response["consistency"] = projections["consistency"]
    # the catalogue is the twin's memory: an ingested observation is materialised the
    # same way a collected one is, so history does not depend on how the run arrived
    if body.persist:
        try:
            catalog = estate_catalog.sync(db, graph, tenant_id=current_tenant(), run_id=run_id)
            response["catalog"] = catalog
        except Exception as exc:  # noqa: BLE001 — the observation already happened
            db.rollback()
            response["catalog"] = {"error": f"{type(exc).__name__}: {exc}"}

    if detection is not None:
        response["detection"] = {
            "verdict": detection["verdict"],
            "severity": detection["severity"],
            "headline": detection["headline"],
            "changes": detection["changes"],
            "counts": detection["counts"],
            "next_action": detection["next_action"],
            "recorded": detection.get("recorded"),
            "note": detection["meaning"],
        }
    return response


@router.get("/summary")
def estate_summary(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Latest estate discovery: asset/evidence counts, coverage and unknown totals."""
    run = _latest_run(db)
    graph = _graph_from_run(run)
    return {
        "schema": SCHEMA,
        "model": "cryptoscan.estate-summary/1",
        "run_id": run.id,
        "captured_at": str(getattr(run, "created_at", "") or ""),
        "summary": graph.summary(),
        "coverage": graph.coverage(),
        "unknown": graph.unknown_inventory(),
    }


@router.get("/graph")
def estate_graph_view(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """The canonical graph: nodes, established edges and unresolved edges."""
    run = _latest_run(db)
    graph = _graph_from_run(run)
    return {
        "schema": SCHEMA,
        "model": "cryptoscan.estate-graph-view/1",
        "run_id": run.id,
        "projection_id": graph.fingerprint(),
        "nodes": [
            {
                "asset_id": asset["asset_id"],
                "type": asset["type"],
                "name": asset["name"],
                "environment": asset.get("environment"),
                "owner": asset.get("owner"),
                "evidence_ids": asset.get("evidence_refs") or [],
            }
            for asset in graph.assets()
        ],
        "edges": [
            {
                "from": edge["subject"],
                "to": edge["object"],
                "predicate": edge["predicate"],
                "basis": edge["basis"],
                "confidence": edge.get("confidence"),
                "evidence_ids": edge["evidence_ids"],
            }
            for edge in graph.relationships()
        ],
        "unresolved_edges": graph.unresolved_relationships(),
        "note": "an unresolved edge is UNKNOWN, not drawn as a relationship",
    }


@router.get("/coverage")
def estate_coverage(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """The coverage matrix — attempted versus expected, per target class."""
    run = _latest_run(db)
    return {"run_id": run.id, **_graph_from_run(run).coverage()}


@router.get("/pqc")
def estate_pqc(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Post-quantum exposure per layer, deliberately without a single score."""
    run = _latest_run(db)
    return {"run_id": run.id, **_graph_from_run(run).pqc_readiness()}


@router.get("/unknown")
def estate_unknown_workflow(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """The unknown inventory as a workflow: one state per asset, plus open work.

    ``IMPORTED``, ``VENDOR_DECLARED`` and ``INFERRED`` appear here as *open work*
    with a next action — never as answers about how the bank uses crypto.
    """
    run = _latest_run(db)
    return {"run_id": run.id, **_graph_from_run(run).unknown_workflow()}


@router.get("/boms")
def estate_boms(
    bom: str | None = Query(default=None, description="SBOM | CBOM | HBOM | NBOM | VBOM | TECHBOM"),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """All six BOMs (or one) projected from the stored evidence graph."""
    kind = (bom or "").strip().upper()
    if kind and kind not in BOM_KINDS:
        raise HTTPException(
            status_code=422,
            detail={"error": "unknown_bom", "reason": f"expected one of {', '.join(BOM_KINDS)}"},
        )
    run = _latest_run(db)
    graph = _graph_from_run(run)
    if kind:
        return {"run_id": run.id, "projection_id": graph.fingerprint(), **graph.project(kind)}
    projections = graph.project_all()
    return {
        "run_id": run.id,
        "projection_id": projections["projection_id"],
        "boms": projections["boms"],
        "counts": projections["counts"],
        "consistency": projections["consistency"],
    }


# --------------------------------------------------------------------------- #
# Digital Twin (spec 94)
# --------------------------------------------------------------------------- #


class TwinImpactRequest(BaseModel):
    """A blast-radius selector: an algorithm, protocol, key size, version or asset."""

    algorithm: str | None = Field(default=None, max_length=120)
    protocol: str | None = Field(default=None, max_length=120)
    mode: str | None = Field(default=None, max_length=120)
    curve: str | None = Field(default=None, max_length=120)
    key_size: int | str | None = Field(default=None, max_length=20)
    version: str | None = Field(default=None, max_length=80)
    asset: str | None = Field(default=None, max_length=200)
    depth: int = Field(default=3, ge=1, le=6)


class TwinSimulationRequest(BaseModel):
    """A scenario applied to a *copy* of the twin — never to the live estate."""

    kind: str = Field(description="REPLACE_ALGORITHM | RETIRE_ALGORITHM | DISABLE_PROTOCOL | UPGRADE_COMPONENT")
    from_: str | None = Field(default=None, alias="from", max_length=160)
    to: str | None = Field(default=None, max_length=160)
    key_size: int | None = Field(default=None, ge=1, le=100000)
    targets: list[str] | None = Field(default=None, max_length=200)
    label: str | None = Field(default=None, max_length=160)
    persist: bool = Field(
        default=False,
        description=(
            "store the result, quarantined: a stored simulation is never counted as estate state, and it "
            "records which evidence state it was computed against"
        ),
    )

    model_config = {"populate_by_name": True}


@router.get("/twin")
def estate_twin_overview(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """The Digital Twin: placement, summary and completeness for one snapshot."""
    run = _latest_run(db)
    graph = _graph_from_run(run)
    return {"run_id": run.id, "captured_at": str(getattr(run, "created_at", "") or ""),
            **estate_twin.overview(graph)}


@router.get("/twin/placement")
def estate_twin_placement(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """§4 — where everything belongs, at every level the evidence supports.

    The upper levels (region, data centre, cloud account) appear only when a collector
    asserted them. What nothing asserts is listed under ``unassigned`` with the reason,
    and levels with no data at all are named in ``levels_unobserved`` rather than drawn
    as empty boxes — an empty box gets filled in by the reader's imagination.
    """
    run = _latest_run(db)
    return estate_twin.placement_model(_graph_from_run(run))


@router.get("/twin/completeness")
def estate_twin_completeness(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """How completely the twin describes the estate — explicitly not a posture score."""
    run = _latest_run(db)
    graph = _graph_from_run(run)
    return {"run_id": run.id, **estate_twin.completeness(graph)}


@router.get("/twin/snapshot")
def estate_twin_snapshot(
    include_payload: bool = Query(default=False, description="include the full evidence payload"),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """The current twin snapshot (content-addressed by the projection id)."""
    run = _latest_run(db)
    graph = _graph_from_run(run)
    snap = estate_twin.snapshot(graph)
    if not include_payload:
        snap = {key: value for key, value in snap.items() if key != "payload"}
    return {"run_id": run.id, **snap}


@router.get("/twin/snapshots")
def estate_twin_snapshots(
    limit: int = Query(default=10, ge=1, le=50),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Twin snapshots, newest first — the history a drift comparison runs over.

    Persisted snapshots win, because a snapshot is content-addressed and survives
    the scan runs it came from. When nothing has been captured yet the stored runs
    are listed instead, with ``persisted: false`` — the two are not the same object
    and the response says which one you are looking at.
    """
    rows = estate_twin_store.list_snapshots(db, tenant_id=current_tenant(), limit=limit)
    if rows:
        return {
            "model": "cryptoscan.estate-twin-snapshots/1",
            "persisted": True,
            "snapshots": [estate_twin_store.public(row) for row in rows],
            "count": len(rows),
            "note": (
                "a snapshot is identified by its projection id, so identical evidence appears once with "
                "an observation count. Compare any two with GET /twin/compare"
            ),
        }

    runs = ScanRunRepository(db).list_runs(limit=limit, target_kind=RUN_KIND, owner=current_tenant())
    entries: list[dict[str, Any]] = []
    for run in runs:
        graph = _graph_from_run(run)
        entries.append(
            {
                "run_id": run.id,
                "created_at": str(getattr(run, "created_at", "") or ""),
                "snapshot_id": f"twin:{graph.fingerprint()}",
                "projection_id": graph.fingerprint(),
                "estate": graph.estate,
                "counts": {
                    "assets": len(graph.assets()),
                    "evidence": len(graph.evidence()),
                    "relationships": len(graph.relationships()),
                    "unresolved_relationships": len(graph.unresolved_relationships()),
                },
                "completeness_percent": estate_twin.completeness(graph)["overall_percent"],
            }
        )
    return {
        "model": "cryptoscan.estate-twin-snapshots/1",
        "persisted": False,
        "snapshots": entries,
        "count": len(entries),
        "note": (
            "these are derived from stored estate-discovery runs, not captured snapshots. POST "
            "/twin/snapshots to persist one, which is what makes it comparable years later"
        ),
    }


@router.get("/twin/search")
def estate_twin_search(
    q: str = Query(min_length=1, max_length=200, description="algorithm, key size, protocol, name, type or owner"),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Search the twin — by algorithm, key size, protocol, name, type or owner."""
    run = _latest_run(db)
    graph = _graph_from_run(run)
    return {"run_id": run.id, **estate_twin.search(graph, q)}


@router.get("/twin/assets/{ref}")
def estate_twin_asset(
    ref: str,
    depth: int = Query(default=3, ge=1, le=6),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Asset investigation: crypto, dependencies, neighbourhood, evidence strength."""
    run = _latest_run(db)
    graph = _graph_from_run(run)
    view = estate_twin.investigate(graph, ref, depth=depth)
    if view is None:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "unknown_asset",
                "reason": (
                    f"no asset matches {ref!r}. This is not 'the asset has no crypto' — the twin has "
                    "no evidence describing it at all"
                ),
            },
        )
    return {"run_id": run.id, **view}


@router.get("/twin/why")
def estate_twin_why(
    subject: str | None = Query(default=None, max_length=200),
    predicate: str | None = Query(default=None, max_length=60),
    object: str | None = Query(default=None, max_length=200),
    evidence_id: str | None = Query(default=None, max_length=120),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Why is this relationship present? Collector, source, timestamp and hash — or a refusal."""
    if not any((subject, predicate, object, evidence_id)):
        raise HTTPException(
            status_code=422,
            detail={"error": "empty_query", "reason": "ask about a subject, predicate, object or evidence id"},
        )
    run = _latest_run(db)
    graph = _graph_from_run(run)
    return {"run_id": run.id, **estate_twin.why(
        graph, subject=subject, predicate=predicate, obj=object, evidence_id=evidence_id
    )}


@router.post("/twin/impact")
def estate_twin_impact(
    body: TwinImpactRequest,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Blast radius for an algorithm, protocol, key size or asset, with its blind spots."""
    run = _latest_run(db)
    graph = _graph_from_run(run)
    selector = {key: value for key, value in body.model_dump().items() if key != "depth" and value not in (None, "")}
    return {"run_id": run.id, **estate_twin.impact(graph, selector, depth=body.depth)}


@router.post("/twin/simulate")
def estate_twin_simulate(
    body: TwinSimulationRequest,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Simulate a cryptographic change on a copy of the twin.

    The live graph is read-only here: the scenario is applied to a snapshot
    payload, the six BOMs are re-projected from the copy, and the response states
    whether the live projection id changed (it must not).
    """
    run = _latest_run(db)
    graph = _graph_from_run(run)
    scenario = {
        "kind": body.kind,
        "from": body.from_,
        "to": body.to,
        "key_size": body.key_size,
        "targets": body.targets or [],
        "label": body.label,
    }
    result = estate_twin.simulate(graph, scenario)
    response: dict[str, Any] = {"run_id": run.id, **result}
    if body.persist:
        if result.get("status") != "SIMULATED":
            response["persisted"] = False
            response["persist_refused_because"] = (
                f"status {result.get('status')!r} is not a simulation result. Storing 'the scenario "
                "matched nothing' as a run would make an empty answer look like a finding"
            )
        else:
            row, created = estate_simulation_store.record_simulation(
                db,
                result,
                tenant_id=current_tenant(),
                created_by=user,
                label=body.label,
            )
            response["persisted"] = True
            response["simulation_record"] = estate_simulation_store.public_simulation(
                row, current_projection_id=graph.fingerprint()
            )
            response["persist_note"] = (
                "stored as a new quarantined run"
                if created
                else "this exact scenario against this exact evidence was already stored; the observation "
                "counter advanced instead of creating a second result"
            )
    return response


# -- twin history, compare, crypto graph, graph export ----------------------- #


class TwinCaptureRequest(BaseModel):
    """Capture the current evidence as a twin snapshot."""

    note: str | None = Field(default=None, max_length=400)


@router.post("/twin/snapshots", status_code=201)
def estate_twin_capture(
    body: TwinCaptureRequest | None = None,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Persist the current twin as a content-addressed snapshot.

    Capturing the same evidence twice returns the same snapshot with a higher
    ``observations`` count — ``created`` says which happened, because "we re-observed
    the same estate" and "the estate moved" are different operational facts.
    """
    run = _latest_run(db)
    graph = _graph_from_run(run)
    row, created = estate_twin_store.record_snapshot(
        db,
        graph,
        tenant_id=current_tenant(),
        captured_by=user,
        source_run_id=str(getattr(run, "id", "") or "") or None,
        note=(body.note if body else None),
    )
    return {
        "created": created,
        "snapshot": estate_twin_store.public(row),
        "note": (
            "this evidence was already captured; the observation counter advanced and nothing was "
            "duplicated"
            if not created
            else "new snapshot: this evidence state had not been seen before"
        ),
    }


@router.get("/twin/compare")
def estate_twin_compare(
    before: str | None = Query(default=None, description="snapshot id, projection id or row id"),
    after: str | None = Query(default=None),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Diff two twins: assets, relationships, crypto usage state, coverage, evidence.

    With no arguments this compares the two most recent **distinct** snapshots.
    A coverage loss outranks a crypto change in the verdict: once a plane stopped
    collecting, everything below it is unreliable.
    """
    tenant = current_tenant()
    if before or after:
        before_row = estate_twin_store.get_snapshot(db, before or "", tenant_id=tenant) if before else None
        after_row = estate_twin_store.get_snapshot(db, after or "", tenant_id=tenant) if after else None
        if (before and before_row is None) or (after and after_row is None):
            raise HTTPException(
                status_code=404,
                detail={
                    "error": "unknown_snapshot",
                    "reason": (
                        "one of the requested snapshots does not exist for this tenant. Capture history "
                        "with POST /twin/snapshots first — an absent snapshot is not 'no change'"
                    ),
                },
            )
    else:
        recent = estate_twin_store.list_snapshots(db, tenant_id=tenant, limit=2)
        before_row = recent[1] if len(recent) > 1 else None
        after_row = recent[0] if recent else None

    if before_row is None or after_row is None:
        return {
            "model": "cryptoscan.estate-twin-compare/1",
            "verdict": "NOT_COMPARABLE",
            "reason": (
                "fewer than two persisted snapshots exist for this tenant, so there is no baseline. "
                "This is not 'no drift'"
            ),
            "snapshots": len([row for row in (before_row, after_row) if row is not None]),
        }

    result = estate_twin.compare(
        estate_twin_store.graph_from_row(before_row),
        estate_twin_store.graph_from_row(after_row),
    )
    return {
        "before_snapshot": estate_twin_store.public(before_row),
        "after_snapshot": estate_twin_store.public(after_row),
        **result,
    }


@router.get("/twin/crypto-graph")
def estate_twin_crypto_graph(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Capability, configuration, runtime and wire observations on separate planes."""
    run = _latest_run(db)
    return {"run_id": run.id, **estate_twin.crypto_graph(_graph_from_run(run))}


@router.get("/twin/graph")
def estate_twin_graph_export(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Typed nodes and edges for a graph-database projection (spec 94 §20).

    The export is a projection of the canonical evidence records: if a graph store
    and this export disagree, the evidence wins and the store is rebuilt.
    """
    run = _latest_run(db)
    return {"run_id": run.id, **estate_twin.graph_export(_graph_from_run(run))}


# -- simulation history (quarantined) --------------------------------------- #


@router.get("/twin/simulations")
def estate_twin_simulations(
    limit: int = Query(default=20, ge=1, le=100),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Stored simulations — quarantined by construction.

    Nothing on this route is estate state. Each row records the evidence state it
    was computed against, so a stored answer about a different estate is marked
    ``superseded`` instead of being presented as a current impact assessment.
    """
    run = _latest_run(db)
    graph = _graph_from_run(run)
    projection_id = graph.fingerprint()
    rows = estate_simulation_store.list_simulations(db, tenant_id=current_tenant(), limit=limit)
    return {
        "model": "cryptoscan.estate-simulations/1",
        "simulations": [
            estate_simulation_store.public_simulation(row, current_projection_id=projection_id)
            for row in rows
        ],
        "count": len(rows),
        **estate_simulation_store.QUARANTINE,
        "note": (
            "a simulation is a question asked of a copy. These rows are stored for the audit trail of "
            "'what we considered', never as observations of the estate"
        ),
    }


@router.get("/twin/simulations/{identifier}")
def estate_twin_simulation(
    identifier: str,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """One stored simulation, with its quarantine and freshness stated."""
    run = _latest_run(db)
    graph = _graph_from_run(run)
    row = estate_simulation_store.get_simulation(db, identifier, tenant_id=current_tenant())
    if row is None:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "unknown_simulation",
                "reason": "no stored simulation with that id for this tenant",
            },
        )
    return estate_simulation_store.public_simulation(row, current_projection_id=graph.fingerprint())


# -- graph store load (spec 94 §20) ---------------------------------------- #


class TwinGraphLoadRequest(BaseModel):
    """Load the current twin graph export into a graph store."""

    dry_run: bool = Field(default=True, description="plan the statements without writing anything")
    database: str | None = Field(default=None, max_length=64)
    batch_size: int = Field(default=500, ge=1, le=5000)
    prune_missing: bool = Field(
        default=False,
        description=(
            "after a successful load, delete nodes of this estate that the export no longer contains. "
            "Destructive, so it is opt-in and only runs once the load verified"
        ),
    )


@router.post("/twin/graph/load")
def estate_twin_graph_load(
    body: TwinGraphLoadRequest,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Write the twin graph export into the configured graph store.

    Defaults to ``dry_run``: the response is the plan — every statement, every row
    count — so a bank can read what would be written before anything is. The loader
    validates identifiers, refuses an unknown export schema, merges by deterministic
    id (so a re-load converges), and then reads its own counts back; a mismatch is
    reported as a failure rather than as "loaded".

    The store is a projection. If it and ``GET /twin/graph`` disagree, the evidence
    wins and the store is rebuilt.
    """
    run = _latest_run(db)
    export = estate_twin.graph_export(_graph_from_run(run))

    driver = None
    if not body.dry_run:
        try:
            from graph_engine.connection.neo4j_driver import get_driver

            driver = get_driver()
        except Exception:  # pragma: no cover - optional dependency / misconfiguration
            driver = None

    result = estate_graph_loader.load(
        export,
        driver=driver,
        database=body.database,
        batch_size=body.batch_size,
        dry_run=body.dry_run,
        prune_missing=body.prune_missing,
    )
    return {"run_id": run.id, **result}


# -- live change detection (spec 94 §17–§18) -------------------------------- #


@router.get("/changes")
def estate_changes(
    severity: str | None = Query(default=None, description="CRITICAL | WARNING | INFO | BASELINE"),
    kind: str | None = Query(default=None, description="e.g. CRYPTO_DEMOTED, COVERAGE_DEGRADED"),
    unacknowledged_only: bool = Query(default=False),
    limit: int = Query(default=50, ge=1, le=200),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """What changed between observations, newest first.

    Every entry is a set of named claims (subject, before → after, what it means)
    derived from two stored observations. An empty feed means nothing moved while
    the collectors ran — not that the estate is safe, and not that anything was
    recently looked at.
    """
    return estate_change_feed.feed(
        db,
        tenant_id=current_tenant(),
        severity=severity,
        kind=kind,
        include_acknowledged=not unacknowledged_only,
        limit=limit,
    )


@router.post("/changes/detect")
def estate_changes_detect(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Detect change now, between the two newest observations.

    The scheduled path already does this on every run; this exists for the case an
    operator needs the answer without waiting for the next scan, and for re-deriving
    the feed after a restore. It compares stored observations — it never re-collects
    to confirm a change, because a re-collection would be a different observation.
    """
    runs = ScanRunRepository(db).list_runs(limit=2, target_kind=RUN_KIND, owner=current_tenant())
    if not runs:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "no_estate_discovery",
                "reason": "nothing has been observed yet, so there is nothing to compare",
            },
        )
    current = _graph_from_run(runs[0])
    previous = _graph_from_run(runs[1]) if len(runs) > 1 else None
    # the same entry point the collector path uses: one answer, one announcement,
    # whether the detection came from a run or from an operator pressing "detect"
    detection = estate_change_feed.observe(
        db,
        previous,
        current,
        tenant_id=current_tenant(),
        run_id=runs[0].id,
        trigger="manual",
        detected_by=user,
    )
    return {
        **detection,
        "stored": detection.get("recorded"),
        "announced": detection.get("announced"),
    }


@router.get("/changes/{identifier}")
def estate_change(
    identifier: str,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    row = estate_change_feed.get_event(db, identifier, tenant_id=current_tenant())
    if row is None:
        raise HTTPException(
            status_code=404,
            detail={"error": "unknown_change", "reason": "no change event with that id for this tenant"},
        )
    return estate_change_feed.public_event(row)


class ChangeAcknowledgement(BaseModel):
    note: str | None = Field(default=None, max_length=2000)


@router.post("/changes/{identifier}/acknowledge")
def estate_change_acknowledge(
    identifier: str,
    body: ChangeAcknowledgement,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Record that a human saw this change.

    Only the acknowledgement moves. The findings are immutable: a feed whose
    contents can be edited is not an audit trail.
    """
    row = estate_change_feed.acknowledge(
        db, identifier, tenant_id=current_tenant(), user=user, note=body.note
    )
    if row is None:
        raise HTTPException(
            status_code=404,
            detail={"error": "unknown_change", "reason": "no change event with that id for this tenant"},
        )
    return estate_change_feed.public_event(row)


# -- the durable catalogue (spec 94 §19, §25, §26) -------------------------- #


@router.get("/catalog")
def estate_catalog_summary(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """What the twin remembers: how many assets, of which types, and how much is stale."""
    return estate_catalog.summary(db, tenant_id=current_tenant())


@router.get("/catalog/assets")
def estate_catalog_assets(
    asset_type: str | None = Query(default=None, description="e.g. HSM, APPLICATION, CERTIFICATE"),
    environment: str | None = Query(default=None),
    owner: str | None = Query(default=None),
    lifecycle: str | None = Query(default=None, description="ACTIVE | STALE"),
    q: str | None = Query(default=None, description="substring match on name, id, owner, environment"),
    limit: int = Query(default=100, ge=1, le=200),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Browse the asset catalogue across observations.

    ``STALE`` is shown, never hidden: an asset absent from the latest observation is
    history worth keeping, and the response says how current each row is rather than
    silently dropping what stopped answering.
    """
    rows = estate_catalog.list_assets(
        db,
        tenant_id=current_tenant(),
        asset_type=asset_type,
        environment=environment,
        owner=owner,
        lifecycle=lifecycle,
        q=q,
        limit=limit,
    )
    return {
        "schema": estate_catalog.SCHEMA,
        "count": len(rows),
        "assets": [estate_catalog.public_asset(row) for row in rows],
        "filters": {
            "asset_type": asset_type,
            "environment": environment,
            "owner": owner,
            "lifecycle": lifecycle,
            "q": q,
        },
        "note": (
            "the catalogue is derived from evidence and kept across observations; an empty result "
            "means nothing matching has been observed, not that nothing exists"
        ),
    }


@router.get("/catalog/assets/{identifier}")
def estate_catalog_asset(
    identifier: str,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """One asset as the catalogue knows it: crypto, relationships, evidence, lifecycle."""
    detail = estate_catalog.asset_detail(db, identifier, tenant_id=current_tenant())
    if detail is None:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "unknown_asset",
                "reason": (
                    "no catalogue record for that asset id or name in this tenant. That is not "
                    "'the asset does not exist' — it may simply never have been observed"
                ),
            },
        )
    return detail


@router.get("/catalog/relationships")
def estate_catalog_relationships(
    subject: str | None = Query(default=None, description="asset id or exact name"),
    predicate: str | None = Query(default=None),
    status: str | None = Query(default="ESTABLISHED", description="ESTABLISHED | UNRESOLVED | ALL"),
    limit: int = Query(default=100, ge=1, le=200),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Established edges with their basis and evidence — and the refused candidates.

    ``status=UNRESOLVED`` returns the edges the graph refused to establish, with the
    reason. They are kept because they are what a bank most wants to chase, and they
    are returned separately because none of them is a relationship.
    """
    rows = estate_catalog.list_relationships(
        db,
        tenant_id=current_tenant(),
        subject=subject,
        predicate=predicate,
        status=status,
        limit=limit,
    )
    return {
        "schema": estate_catalog.SCHEMA,
        "count": len(rows),
        "relationships": [estate_catalog.public_relationship(row) for row in rows],
        "status_filter": status,
        "note": (
            "an UNRESOLVED row is a candidate, not an edge: the graph required a basis and evidence "
            "before it would establish anything, and this is the list of what failed that test"
        ),
    }


@router.get("/catalog/crypto")
def estate_catalog_crypto(
    q: str | None = Query(default=None, description="algorithm, protocol, curve or asset name"),
    asset_type: str | None = Query(default=None),
    include_stale: bool = Query(default=True),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """The algorithm registry: who uses what, per usage state (spec §26).

    Answers "RSA-2048 → which assets, of which types" without merging capability into
    use: each algorithm is reported per ``usage_state`` with the assets behind it.
    """
    return estate_catalog.registry(
        db,
        tenant_id=current_tenant(),
        query=q,
        asset_type=asset_type,
        include_stale=include_stale,
    )


# -- evidence records and per-fact history (spec 94 §11, §19, §28) ---------- #


@router.get("/evidence/records")
def estate_evidence_records(
    target: str | None = Query(default=None, description="asset id or collector target"),
    evidence_type: str | None = Query(default=None, description="OBSERVED | CONFIGURED | INFERRED | ..."),
    limit: int = Query(default=200, ge=1, le=1000),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Every stored evidence record, with its collector, source, confidence and age (§11).

    Evidence is content-addressed, so a record observed in forty runs is one row whose
    ``observation_count`` is forty — not forty rows that make a quiet estate look busy.
    """
    return estate_observations.evidence_for(
        db,
        target=target,
        evidence_type=evidence_type,
        limit=limit,
        tenant_id=current_tenant(),
    )


@router.get("/evidence/records/{evidence_id}")
def estate_evidence_record(
    evidence_id: str,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """One stored evidence record by id.

    A 404 here means *this estate does not hold that record* — not that it never existed
    anywhere: the read is tenant-scoped, and a platform-estate record is invisible to a
    bank-estate caller.
    """
    found = estate_observations.evidence_record(db, evidence_id, tenant_id=current_tenant())
    if found is None:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "evidence_not_in_this_estate",
                "reason": "no stored evidence record with that id belongs to the selected estate",
                "list": "/api/v1/estate/evidence/evidence/records",
            },
        )
    return found


@router.get("/evidence/records/{evidence_id}/verify")
def estate_evidence_record_verify(
    evidence_id: str,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Recompute the record's content address from its stored fields.

    This checks that the stored row still hashes to the id it is filed under. It does not
    attest the observation: nothing signs a collector's output yet, and the payload says so
    in ``not_checked`` rather than leaving the caller to assume otherwise.
    """
    verdict = estate_observations.verify_record(db, evidence_id, tenant_id=current_tenant())
    if verdict is None:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "evidence_not_in_this_estate",
                "reason": "no stored evidence record with that id belongs to the selected estate",
            },
        )
    return verdict


@router.get("/history/summary")
def estate_observation_summary(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """How much history the twin holds: current and historical facts, and the disputes."""
    return estate_observations.summary(db, tenant_id=current_tenant())


@router.get("/history/assets/{identifier}")
def estate_asset_history(
    identifier: str,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Every fact this asset ever asserted, current value first, with windows (§19).

    A fact's state is ``CURRENT``, ``HISTORICAL`` or ``CONFLICT``. ``CONFLICT`` means two
    values are still asserted and the twin will not pick one: that is a question for a
    human, and it is reported as such.
    """
    detail = estate_observations.history(db, identifier, tenant_id=current_tenant())
    if detail["fact_count"] == 0:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "no_history",
                "reason": (
                    "the catalogue holds no fact for that asset id. Either the asset has never been "
                    "observed, or it was catalogued before per-fact history existed — this is not an "
                    "assertion that it has no properties"
                ),
            },
        )
    return detail


@router.get("/why/{identifier}")
def estate_why(
    identifier: str,
    fact_type: str = Query(..., description="e.g. environment, attribute:region, crypto:algorithm"),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """§28: why does the twin believe this fact about this asset?

    Returns the windows in which each value held and the evidence behind the asset, and
    states the limit plainly: collectors attribute evidence to an asset, not to an
    individual attribute, so this is the evidence for the asset rather than per-value
    provenance dressed up as more than it is.
    """
    answer = estate_observations.why(db, identifier, fact_type, tenant_id=current_tenant())
    if answer is None:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "nothing_to_explain",
                "reason": (
                    "no catalogue record or no observation of that fact for this asset in this "
                    "tenant. Absence of an explanation is not evidence that the fact is false"
                ),
            },
        )
    return answer


# -- one search over the recorded estate (spec 94 §26) ---------------------- #


@router.get("/search")
def estate_search_query(
    q: str = Query(..., min_length=1, max_length=200, description="asset, algorithm, collector, region, change…"),
    kinds: str | None = Query(
        default=None,
        description="comma-separated subset of ASSETS, CRYPTO, RELATIONSHIPS, EVIDENCE, FACTS, CHANGES",
    ),
    limit: int = Query(default=25, ge=1, le=25, description="per kind; results are a shortlist, not an export"),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Search everything the twin has recorded, in one call (§26).

    Four questions arrive together — which assets, which artefacts, which edges, and
    which evidence says so — so they are answered together and grouped, never merged
    into one list where a capability row and a runtime observation look alike.

    An empty result means *nothing matching has been recorded*, which is not the same
    as the bank having none of it; the response states that rather than leaving an
    operator to read zero rows as a finding.
    """
    wanted = [item.strip() for item in (kinds or "").split(",") if item.strip()] or None
    try:
        return estate_search.search(db, q, tenant_id=current_tenant(), kinds=wanted, limit=limit)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail={"error": "bad_search", "reason": str(exc)}) from exc


# -- store parity (spec 94 §20–§21) ----------------------------------------- #


class TwinGraphVerifyRequest(BaseModel):
    """Ask the graph store whether it still equals this projection."""

    database: str | None = Field(default=None, max_length=64)


@router.post("/twin/graph/verify")
def estate_twin_graph_verify(
    body: TwinGraphVerifyRequest | None = None,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Compare the graph store with the canonical records, id by id (§20–§21).

    The loader already reads counts back after writing. Counts are a weak test — a store
    that kept yesterday's nodes and gained today's has *more* than expected and passes a
    ">=" check while holding a superseded estate. This compares the exact id set per
    node kind and the relationship count per type, and names what differs.

    ``STALE_ONLY`` is the honest middle state: the store holds everything the projection
    has plus nodes it no longer contains. ``NOT_CONNECTED`` is not parity, and the
    response says so rather than returning an empty difference list.
    """
    run = _latest_run(db)
    export = estate_twin.graph_export(_graph_from_run(run))

    driver = None
    try:
        from graph_engine.connection.neo4j_driver import get_driver

        driver = get_driver()
    except Exception:  # pragma: no cover - optional dependency / misconfiguration
        driver = None

    result = estate_graph_loader.parity(
        export,
        driver=driver,
        database=(body.database if body else None),
    )
    return {"run_id": run.id, **result}


# -- conflicts, kept as conflicts (spec 94 §23) ----------------------------- #


@router.get("/twin/conflicts")
def estate_twin_conflicts(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Every disagreement the twin is holding, classified and never resolved (§23).

    ``REAL`` conflicts are two sources on one plane disagreeing — one of them is wrong and
    a human has to find out which. ``EXPLAINED`` ones come from different planes and can
    both be true (capability vs use). Reporting the second kind as the first is how an
    operator learns to ignore conflicts, so the two are counted separately and every
    entry carries the evidence behind each value.
    """
    graph = _latest_twin_graph_or_none(db)
    return estate_conflicts.survey(db, graph, tenant_id=current_tenant())


@router.get("/twin/lifecycle")
def estate_twin_lifecycle(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Which phases of the twin's loop are actually running, and where it breaks (§2).

    Every phase reports CONNECTED / PARTIAL / NOT_CONNECTED / NOT_STARTED from the table it
    writes, so "nothing has observed the estate yet" cannot look like "the loop is wired",
    and ``REMEDIATE`` says plainly that the twin opens no work item. ``loop_closed`` is
    computed from the phases, and ``first_break`` names the phase worth building next.
    """
    graph = _latest_twin_graph_or_none(db)
    return estate_lifecycle.survey(db, graph, tenant_id=current_tenant())


class TwinRemediationRequest(BaseModel):
    """``persist`` is the whole difference between a proposal and a queue entry."""

    persist: bool = False


@router.get("/twin/remediation")
def estate_twin_remediation(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Every work item the twin has opened, with the proof each one needs (§23).

    A ``PROVEN`` item names the observation that closed it; an ``ABANDONED`` one is kept so
    the estate remembers work that was started and dropped. Nothing here executes a fix.
    """
    return estate_remediation.listing(db, tenant_id=current_tenant())


@router.post("/twin/remediate")
def estate_twin_remediate(
    body: TwinRemediationRequest | None = None,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Ask the twin what work it would open. Writes only when ``persist`` is true.

    Work comes from three places: a REAL or UNKNOWN conflict, a collector plane that did not
    run to completion, and a simulation blocker. Each candidate carries the observation that
    would close it. A dry run is the default because a queue nobody asked for is how a
    remediation surface gets muted.
    """
    request = body or TwinRemediationRequest()
    graph = _latest_twin_graph_or_none(db)
    stored = estate_simulation_store.list_simulations(db, tenant_id=current_tenant(), limit=1)
    simulation = (
        estate_simulation_store.public_simulation(stored[0]) if stored else None
    )
    return estate_remediation.propose(
        db,
        graph=graph,
        simulation=simulation,
        tenant_id=current_tenant(),
        persist=request.persist,
        opened_by=user,
        opened_from="api",
    )


@router.post("/twin/remediation/reconcile")
def estate_twin_reconcile(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Close what was actually proven, and say why the rest was not (§23).

    ``PROVEN`` cites the observation row and the evidence id. ``PROOF_UNAVAILABLE`` means
    the fact is no longer asserted at all, which is not a fix, and a ``HUMAN`` item is never
    auto-closed.
    """
    graph = _latest_twin_graph_or_none(db)
    return estate_remediation.reconcile(db, graph=graph, tenant_id=current_tenant())


@router.get("/twin/intel")
def estate_twin_intel(
    limit: int = Query(200, ge=1, le=2000),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Weak, unidentified and post-quantum cryptography across the estate (§12, §24).

    Capability is counted apart from use — a library that supports DES has not used DES —
    and a verdict is labelled as coming from this product's algorithm registry rather than
    from the bank's own policy. An unrecognised value is reported as unknown, never as
    compliant.
    """
    graph = _latest_twin_graph_or_none(db)
    if graph is None:
        return {
            "schema": estate_crypto_intel.SCHEMA,
            "status": "NOT_OBSERVED",
            "detail": (
                "there is no stored estate observation, so there is no cryptography to read. "
                "This is not an empty answer and not a clean one"
            ),
            "artifacts_examined": 0,
        }
    return estate_crypto_intel.survey(graph, limit=limit)


@router.get("/twin/algorithm/{name}")
def estate_twin_algorithm(
    name: str,
    limit: int = Query(200, ge=1, le=2000),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Everything the estate holds about one algorithm — who uses it, who merely supports it."""
    graph = _latest_twin_graph_or_none(db)
    if graph is None:
        return {
            "schema": estate_crypto_intel.ALGORITHM_SCHEMA,
            "query": name,
            "status": "NOT_OBSERVED",
            "detail": (
                "there is no stored estate observation, so no answer about this algorithm can "
                "be given. That is different from 'nothing uses it'"
            ),
            "found": False,
        }
    return estate_crypto_intel.algorithm(graph, name, limit=limit)


@router.get("/twin/trust-paths")
def estate_twin_trust_paths(
    limit: int = Query(200, ge=1, le=2000),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Certificate chains as the evidence describes them, and where each one stops (§24).

    ``ROOTED``, ``SELF_SIGNED``, ``BROKEN``, ``CYCLE`` and ``UNKNOWN_ISSUER`` are five
    different answers: an issuer outside the collected scope and an invalid chain look
    identical from here, and neither is chosen for the reader. No signature is verified and
    no expiry is checked.
    """
    graph = _latest_twin_graph_or_none(db)
    if graph is None:
        return {
            "schema": estate_trust.SCHEMA,
            "status": "NOT_OBSERVED",
            "detail": (
                "there is no stored estate observation, so no chain can be walked. That is not "
                "the same as an estate with no certificates"
            ),
            "count": 0,
        }
    return estate_trust.survey(graph, limit=limit)


@router.get("/twin/graph/traversal")
def estate_twin_graph_traversal(
    asset: str = Query(..., min_length=1, max_length=200),
    depth: int = Query(3, ge=1, le=10),
    database: str | None = Query(None, max_length=64),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Ask the graph store the twin's own blast-radius question (§20–§21).

    ``/twin/graph/verify`` proves the store holds this projection; this proves whether a
    *question* asked of the store gets the twin's answer. Both sets are compared as sets, so
    an asset only the store reaches is named as loudly as one only the twin reaches.

    ``TRAVERSAL_PARITY`` is a statement about one asset at one depth, not a general claim;
    ``TRAVERSAL_MISMATCH`` is not "the store is wrong" — it means one side is answering a
    different question, and the note says which three things to check.
    """
    run = _latest_run(db)
    graph = _graph_from_run(run)
    impact = estate_twin.impact(graph, {"asset": asset}, depth=depth)
    export = estate_twin.graph_export(graph)

    driver = None
    try:
        from graph_engine.connection.neo4j_driver import get_driver

        driver = get_driver()
    except Exception:  # pragma: no cover - optional dependency / misconfiguration
        driver = None

    result = estate_graph_loader.traversal_parity(
        export, impact, driver=driver, database=database
    )
    return {"run_id": run.id, **result}
