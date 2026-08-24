"""System inventory and simple dependency edges."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session
from db.models.system import System
from db.repositories.system_repository import SystemRepository

router = APIRouter(prefix="/systems", tags=["systems"])


class SystemCreate(BaseModel):
    name: str
    description: str | None = None
    owner: str | None = None
    environment: str | None = None
    compliance_scopes: list[str] = []


class AttachAsset(BaseModel):
    asset_id: str


class DependencyCreate(BaseModel):
    child_id: str
    relation: str | None = "depends-on"


@router.get("")
def list_systems(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    rows, total = SystemRepository(db).list_systems(page=page, page_size=page_size)
    return {"systems": [row.to_dict() for row in rows], "total_count": total, "page": page, "page_size": page_size}


@router.post("")
def create_system(
    body: SystemCreate,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    repo = SystemRepository(db)
    existing = repo.get_by_name(body.name)
    if existing:
        raise HTTPException(status_code=409, detail="System name already exists")
    row = repo.create(
        System(
            name=body.name,
            description=body.description,
            owner=body.owner,
            environment=body.environment,
            compliance_scopes=body.compliance_scopes,
        )
    )
    return row.to_dict()


@router.get("/{system_id}")
def get_system(
    system_id: str,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    repo = SystemRepository(db)
    row = repo.get_by_id(system_id)
    if row is None:
        raise HTTPException(status_code=404, detail="System not found")
    payload = row.to_dict()
    payload["assets"] = [asset.to_dict() for asset in repo.assets_for(system_id)]
    payload["dependencies"] = [edge.to_dict() for edge in repo.dependencies_for(system_id)]
    return payload


@router.post("/{system_id}/assets")
def attach_asset(
    system_id: str,
    body: AttachAsset,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    repo = SystemRepository(db)
    if repo.get_by_id(system_id) is None:
        raise HTTPException(status_code=404, detail="System not found")
    link = repo.attach_asset(system_id, body.asset_id)
    return link.to_dict()


@router.post("/{system_id}/dependencies")
def add_dependency(
    system_id: str,
    body: DependencyCreate,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    repo = SystemRepository(db)
    if repo.get_by_id(system_id) is None or repo.get_by_id(body.child_id) is None:
        raise HTTPException(status_code=404, detail="System not found")
    edge = repo.add_dependency(system_id, body.child_id, body.relation)
    return edge.to_dict()
