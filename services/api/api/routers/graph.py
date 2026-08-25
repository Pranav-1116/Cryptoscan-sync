"""Dependency graph and blast-radius APIs (Neo4j when configured)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session
from api.graph_builder import collect_graph_payload, graph_from_db, sync_graph
from business_context.core.enricher import enrich_assets
from graph_engine.core.facade import graph_health

router = APIRouter(tags=["graph"])


@router.get("/graph/health")
def get_graph_health(user: str = Depends(get_current_user)):
    return graph_health()


@router.post("/graph/sync")
def post_graph_sync(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    return sync_graph(db)


@router.get("/graph")
def get_graph(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    graph = graph_from_db(db)
    vis = graph.to_vis()
    health = graph_health()
    vis["health"] = health
    vis["backend"] = getattr(graph, "backend", vis.get("backend") or health.get("backend"))
    return vis


@router.get("/graph/blast-radius")
def blast_radius(
    system_id: str = Query(...),
    hops: int = Query(5, ge=1, le=12),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    result = graph_from_db(db).blast_radius(system_id, hops=hops)
    if not result["start"] and result["nodes_visited"] == 0:
        raise HTTPException(status_code=404, detail="System not found in graph")
    return result


@router.get("/graph/impact")
def business_impact(
    system_id: str | None = None,
    asset_id: str | None = None,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    start = system_id or asset_id
    if not start:
        raise HTTPException(status_code=400, detail="system_id or asset_id required")
    return graph_from_db(db).business_impact(start)


@router.get("/graph/compliance")
def compliance_inheritance(
    system_id: str = Query(...),
    hops: int = Query(5, ge=1, le=12),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    return graph_from_db(db).compliance_inheritance(system_id, hops=hops)


@router.get("/graph/vendor-path")
def vendor_path(
    system_id: str = Query(...),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    return graph_from_db(db).vendor_path(system_id)


@router.get("/graph/crypto")
def crypto_inventory(
    system_id: str = Query(...),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    return graph_from_db(db).crypto_for_system(system_id)


@router.get("/priorities")
def priorities(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    payload = collect_graph_payload(db)
    ranked = enrich_assets(
        payload["assets"],
        systems=payload["systems"],
        edges=payload["edges"],
        processes=payload["processes"],
        owners=payload["owners"],
    )
    return {"assets": ranked, "total_count": len(ranked)}
