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

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api import estate_discovery, estate_drift, estate_schedule
from api.dependencies import get_current_user, get_db_session
from db.repositories.scan_run_repository import ScanRunRepository
from db.tenancy import current_tenant
from api.security import anchor_export
from api.security.estate_bom_anchor import AnchorError, create_anchor, list_anchors, verify_anchor
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


def _graph_from_run(run) -> Any:
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
    return [estate_schedule.as_dict(row) for row in estate_schedule.list_schedules(db, tenant_id=tenant)]


@router.post("/schedules", status_code=201)
def estate_schedule_create(
    body: EstateScheduleRequest,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Save a cadence. ``every`` or ``cron`` — exactly one."""
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
            user=user,
        )
    except estate_schedule.ScheduleError as exc:
        raise HTTPException(status_code=409 if exc.code == "schedule_exists" else 422,
                            detail={"error": exc.code, "reason": exc.reason}) from exc
    return estate_schedule.as_dict(row)


@router.patch("/schedules/{identifier}")
def estate_schedule_toggle(
    identifier: str,
    body: EstateScheduleToggle,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Pause or resume a schedule without deleting its history."""
    try:
        row = estate_schedule.set_enabled(db, identifier, body.enabled, tenant_id=current_tenant())
    except estate_schedule.ScheduleError as exc:
        raise HTTPException(status_code=404, detail={"error": exc.code, "reason": exc.reason}) from exc
    return estate_schedule.as_dict(row)


@router.delete("/schedules/{identifier}")
def estate_schedule_delete(
    identifier: str,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    try:
        removed = estate_schedule.delete_schedule(db, identifier, tenant_id=current_tenant())
    except estate_schedule.ScheduleError as exc:
        raise HTTPException(status_code=404, detail={"error": exc.code, "reason": exc.reason}) from exc
    return {"deleted": removed}


@router.post("/tick")
def estate_tick(
    body: EstateTickRequest,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Run what is due now. The lease makes a manual tick and a sidecar safe together."""
    return estate_schedule.tick(
        db, worker=body.worker, lease_seconds=body.lease_seconds, limit=body.limit
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
    from datetime import datetime, timezone

    from db.models.estate_schedule import EstateScheduleRun

    from api import estate_daemon_store
    from api.estate_daemon import stale_state

    now = datetime.now(timezone.utc)
    beat = estate_daemon_store.latest(db)
    liveness = stale_state(beat, now=now)

    schedules = estate_schedule.list_schedules(db, tenant_id=current_tenant(), include_disabled=True)
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
        next_action = "create one — `cryptoscan schedule add nightly --every 6h`"
    elif leases:
        verdict = "RUNNING"
        reason = f"{len(leases)} schedule(s) are leased right now: a run is in flight"
        next_action = None
    elif last_run_age is not None and last_run_age > 3600:
        verdict = "DEGRADED"
        reason = (
            f"the daemon is alive but the last scheduled run finished {round(last_run_age)}s ago"
        )
        next_action = "check the schedule cadence and the daemon log for skipped cycles"
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
