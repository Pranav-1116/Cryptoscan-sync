"""Dependency graph and blast-radius APIs."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session
from api.graph_builder import graph_from_db
from business_context.core.enricher import enrich_assets
from db.models.crypto_asset import CryptoAsset
from db.repositories.intelligence_repository import IntelligenceRepository
from db.repositories.system_repository import SystemRepository

router = APIRouter(tags=["graph"])


@router.get("/graph")
def get_graph(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    return graph_from_db(db).to_vis()


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


@router.get("/priorities")
def priorities(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    systems_repo = SystemRepository(db)
    intel = IntelligenceRepository(db)
    systems, _ = systems_repo.list_systems(page=1, page_size=200)
    system_payloads = []
    assets: list[dict] = []
    edges = []
    for system in systems:
        linked = systems_repo.assets_for(system.id)
        system_payloads.append(
            {
                "id": system.id,
                "name": system.name,
                "compliance_scopes": system.compliance_scopes or [],
                "asset_ids": [asset.id for asset in linked],
            }
        )
        for asset in linked:
            payload = asset.to_dict()
            payload["system_id"] = system.id
            assets.append(payload)
        for edge in systems_repo.dependencies_for(system.id):
            edges.append({"parent_id": edge.parent_id, "child_id": edge.child_id})
    if not assets:
        assets = [row.to_dict() for row in db.query(CryptoAsset).limit(200).all()]
    processes = []
    for process in intel.list_processes():
        item = process.to_dict()
        item["system_ids"] = intel.process_system_ids(process.id)
        processes.append(item)
    owners = [row.to_dict() for row in intel.list_owners()]
    ranked = enrich_assets(assets, systems=system_payloads, edges=edges, processes=processes, owners=owners)
    return {"assets": ranked, "total_count": len(ranked)}
