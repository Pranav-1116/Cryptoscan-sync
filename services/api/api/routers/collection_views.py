"""Stored-evidence materialization only. Never authorize or execute collection."""

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session
from api.dependencies import get_current_user, get_db_session
from api.routers.assurance_boundary import Key, author, estate
from api.assurance import collection_views as core, store
from shared_models.collection_views import DriftRequest, SnapshotRequest

router = APIRouter(prefix="/collection", tags=["collection-snapshots"])


@router.post("/snapshots", status_code=201)
def create_snapshot(
    body: SnapshotRequest,
    request: Request,
    ctx=Depends(estate),
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
):
    return core.create_snapshot(db, ctx.tenant_id, body, author(db, request, user), user)


@router.get("/snapshots")
def snapshots(
    cursor: str = Query(default="", max_length=36),
    limit: int = Query(default=10, ge=1, le=20),
    ctx=Depends(estate),
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
):
    return core.listing(db, ctx.tenant_id, cursor, limit)


@router.get("/snapshots/{identifier}")
def snapshot(
    identifier: Key, ctx=Depends(estate), db: Session = Depends(get_db_session), user=Depends(get_current_user)
):
    row, _ = core.read_snapshot(db, ctx.tenant_id, identifier)
    return store.public(row)


@router.post("/metadata-drift", status_code=201)
def create_drift(
    body: DriftRequest,
    request: Request,
    ctx=Depends(estate),
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
):
    return core.create_drift(db, ctx.tenant_id, body, author(db, request, user), user)


@router.get("/metadata-drift/{identifier}")
def drift(identifier: Key, ctx=Depends(estate), db: Session = Depends(get_db_session), user=Depends(get_current_user)):
    return core.read_drift(db, ctx.tenant_id, identifier)
