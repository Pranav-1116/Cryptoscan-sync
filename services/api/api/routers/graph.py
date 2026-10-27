"""Dependency graph and blast-radius APIs (Neo4j when configured)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from agility.roadmap import wave_for
from api.dependencies import get_current_user, get_db_session
from api.graph_builder import collect_graph_payload, graph_from_db, sync_graph
from business_context.core.enricher import enrich_assets
from db.repositories.maturity_repository import MaturityRepository
from db.repositories.system_repository import SystemRepository
from graph_engine.core.drift import graph_drift
from graph_engine.core.facade import graph_health
from graph_engine.core.migration import merge_cycle_constraints

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


@router.get("/graph/dependents")
def graph_dependents(
    system_id: str = Query(...),
    hops: int = Query(5, ge=1, le=12),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Reverse blast radius: upstream systems that depend on this one."""
    result = graph_from_db(db).dependents(system_id, hops=hops)
    if result["nodes_visited"] == 0:
        raise HTTPException(status_code=404, detail="System not found in graph")
    return result


@router.get("/graph/path")
def graph_path(
    system_id: str = Query(...),
    target_id: str = Query(...),
    direction: str = Query("downstream", pattern="^(downstream|upstream)$"),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Shortest CALLS path between two systems (200 with reachable=false when none)."""
    result = graph_from_db(db).shortest_path(system_id, target_id, direction=direction)
    if not result["resolved_start"] or not result["resolved_target"]:
        missing = system_id if not result["resolved_start"] else target_id
        raise HTTPException(status_code=404, detail=f"System not found in graph: {missing}")
    return result


@router.get("/graph/hotspots")
def graph_hotspots(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    """Systems ranked by quantum-vulnerable crypto concentration."""
    return graph_from_db(db).crypto_hotspots()


@router.get("/graph/cycles")
def graph_cycles(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    """Strongly-connected dependency cycles (must be migrated together)."""
    return graph_from_db(db).find_cycles()


@router.get("/graph/certificates/exposure")
def graph_certificate_exposure(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    """Expiring/expired certificates mapped to systems and revenue at risk."""
    return graph_from_db(db).certificate_exposure()


@router.get("/graph/stats")
def graph_stats(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    """Graph composition + hygiene (orphans, unlinked assets)."""
    return graph_from_db(db).graph_stats()


@router.get("/graph/drift")
def get_graph_drift(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    """Is the persisted Neo4j graph behind the relational inventory?"""
    from graph_engine.connection.neo4j_driver import get_driver

    return graph_drift(collect_graph_payload(db), driver=get_driver())


@router.get("/graph/migration-waves")
def graph_migration_waves(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    """Readiness waves constrained by dependency cycles: cycle members are
    held to the most conservative wave among their group."""
    graph = graph_from_db(db)
    cycles = graph.find_cycles()["cycles"]
    repo = MaturityRepository(db)
    entries = []
    unscored = 0
    systems, _ = SystemRepository(db).list_systems(page=1, page_size=500)
    for system in systems:
        latest = repo.latest_agility(system.id)
        rationale = None
        if latest and latest.readiness_category:
            wave = wave_for(latest.readiness_category)
            rationale = f"readiness {latest.readiness_score or 0}/100 ({latest.readiness_category})"
        else:
            unscored += 1
            wave = 3
            rationale = "no agility score yet"
        entries.append(
            {
                "system_id": system.id,
                "name": system.name,
                "wave": wave,
                "readiness_category": latest.readiness_category if latest else None,
                "readiness_score": latest.readiness_score if latest else None,
                "agility_score": latest.agility_score if latest else None,
                "unscored": not (latest and latest.readiness_category),
                "rationale": rationale,
            }
        )
    result = merge_cycle_constraints(entries, cycles)
    result["unscored_systems"] = unscored
    return result


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
