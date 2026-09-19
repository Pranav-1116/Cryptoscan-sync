"""Business-context summary and impact aliases."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session
from api.graph_builder import collect_graph_payload, graph_from_db
from business_context.core.enricher import enrich_assets
from db.repositories.intelligence_repository import IntelligenceRepository

router = APIRouter(prefix="/business-context", tags=["business-context"])


@router.get("")
@router.get("/")
def summary(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    intel = IntelligenceRepository(db)
    processes = []
    for process in intel.list_processes():
        payload = process.to_dict()
        payload["system_ids"] = intel.process_system_ids(process.id)
        processes.append(payload)
    owners = [row.to_dict() for row in intel.list_owners()]
    return {"processes": processes, "owners": owners, "total_count": len(processes)}


@router.get("/impact")
def impact(
    system_id: str | None = Query(None),
    asset_id: str | None = Query(None),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    start = system_id or asset_id
    if not start:
        raise HTTPException(status_code=400, detail="system_id or asset_id required")
    return graph_from_db(db).business_impact(start)


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
