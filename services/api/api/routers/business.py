"""Business processes, owners, vendors, and migration projects."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session
from db.repositories.intelligence_repository import IntelligenceRepository

router = APIRouter(tags=["business"])


class ProcessCreate(BaseModel):
    name: str
    description: str | None = None
    revenue_daily: float = 0
    customer_count: int = 0
    sla_uptime: float | None = None
    executive_sponsor: str | None = None
    process_type: str | None = None
    data_classifications: list[str] | None = None


class OwnerCreate(BaseModel):
    name: str
    email: str | None = None
    role: str | None = None
    department: str | None = None
    escalation_contact: str | None = None


class LinkBody(BaseModel):
    system_id: str
    role: str | None = "PRIMARY"


class VendorCreate(BaseModel):
    name: str
    criticality: str | None = None
    system_id: str | None = None


class MigrationCreate(BaseModel):
    name: str
    system_id: str | None = None
    algorithm_from: str | None = None
    algorithm_to: str | None = None
    status: str = "PLANNED"
    progress: float = 0
    owner: str | None = None
    notes: str | None = None


class MigrationPatch(BaseModel):
    status: str | None = None
    progress: float | None = None
    notes: str | None = None
    owner: str | None = None
    algorithm_to: str | None = None


@router.get("/business/processes")
def list_processes(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    intel = IntelligenceRepository(db)
    rows = []
    for process in intel.list_processes():
        payload = process.to_dict()
        payload["system_ids"] = intel.process_system_ids(process.id)
        rows.append(payload)
    return {"processes": rows}


@router.post("/business/processes")
def create_process(body: ProcessCreate, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    return IntelligenceRepository(db).create_process(**body.model_dump()).to_dict()


@router.post("/business/processes/{process_id}/systems")
def link_process(
    process_id: str, body: LinkBody, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)
):
    return IntelligenceRepository(db).link_process(body.system_id, process_id, body.role).to_dict()


@router.get("/business/owners")
def list_owners(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    return {"owners": [row.to_dict() for row in IntelligenceRepository(db).list_owners()]}


@router.post("/business/owners")
def create_owner(body: OwnerCreate, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    return IntelligenceRepository(db).create_owner(**body.model_dump()).to_dict()


@router.get("/vendors")
def list_vendors(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    intel = IntelligenceRepository(db)
    rows = []
    for vendor in intel.list_vendors():
        payload = vendor.to_dict()
        payload["system_ids"] = intel.vendor_system_ids(vendor.id)
        rows.append(payload)
    return {"vendors": rows}


@router.post("/vendors")
def create_vendor(body: VendorCreate, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    intel = IntelligenceRepository(db)
    vendor = intel.create_vendor(body.name, body.criticality)
    if body.system_id:
        intel.link_vendor(body.system_id, vendor.id)
    return vendor.to_dict()


@router.get("/migrations")
def list_migrations(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    return {"projects": [row.to_dict() for row in IntelligenceRepository(db).list_migrations()]}


@router.post("/migrations")
def create_migration(body: MigrationCreate, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    return IntelligenceRepository(db).create_migration(**body.model_dump()).to_dict()


@router.patch("/migrations/{project_id}")
def update_migration(
    project_id: str, body: MigrationPatch, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)
):
    row = IntelligenceRepository(db).update_migration(project_id, **{k: v for k, v in body.model_dump().items() if v is not None})
    if row is None:
        raise HTTPException(status_code=404, detail="Migration project not found")
    return row.to_dict()
