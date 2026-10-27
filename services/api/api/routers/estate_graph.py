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

from api import estate_discovery
from api.dependencies import get_current_user, get_db_session
from db.repositories.scan_run_repository import ScanRunRepository
from db.tenancy import current_tenant
from shared_models.estate_graph import BOM_KINDS, SCHEMA, build_graph

router = APIRouter(prefix="/estate/evidence", tags=["estate-evidence"])

RUN_KIND = "estate-discovery"


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
