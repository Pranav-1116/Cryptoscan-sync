"""Blast-radius and reachability analysis."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session
from api.graph_builder import graph_from_db

router = APIRouter(prefix="/reachability", tags=["reachability"])


@router.get("/blast-radius")
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


@router.get("/impact")
def business_impact(
    system_id: str = Query(...),
    hops: int = Query(5, ge=1, le=12),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    return graph_from_db(db).business_impact(system_id, hops=hops)


@router.get("/compliance")
def compliance_inheritance(
    system_id: str = Query(...),
    hops: int = Query(5, ge=1, le=12),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    return graph_from_db(db).compliance_inheritance(system_id, hops=hops)


@router.get("/vendor-path")
def vendor_path(
    system_id: str = Query(...),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    return graph_from_db(db).vendor_path(system_id)
