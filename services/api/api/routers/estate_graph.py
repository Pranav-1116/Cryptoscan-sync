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

from api import estate_discovery, estate_drift
from api.dependencies import get_current_user, get_db_session
from db.repositories.scan_run_repository import ScanRunRepository
from db.tenancy import current_tenant
from api.security.estate_bom_anchor import AnchorError, create_anchor, list_anchors, verify_anchor
from shared_models.estate_graph import BOM_KINDS, SCHEMA, build_graph

router = APIRouter(prefix="/estate/evidence", tags=["estate-evidence"])

RUN_KIND = "estate-discovery"


class EstateAnchorRequest(BaseModel):
    """Sign the current projected BOM set into an exportable receipt."""

    note: str | None = Field(default=None, max_length=400)


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
