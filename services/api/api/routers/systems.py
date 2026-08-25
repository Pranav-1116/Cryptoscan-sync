"""System inventory, CMDB import, and per-system scan."""

from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session, get_job_repository
from db.models.system import System
from db.repositories.job_repository import JobRepository
from db.repositories.system_repository import SystemRepository

router = APIRouter(prefix="/systems", tags=["systems"])


class SystemCreate(BaseModel):
    name: str
    description: str | None = None
    owner: str | None = None
    environment: str | None = None
    compliance_scopes: list[str] = []
    scan_target: str | None = None
    scan_branch: str | None = None
    business_unit: str | None = None
    criticality: str | None = None


class AttachAsset(BaseModel):
    asset_id: str


class DependencyCreate(BaseModel):
    child_id: str
    relation: str | None = "depends-on"


class ImportSystemsRequest(BaseModel):
    systems: list[dict] | None = None
    csv: str | None = None


@router.get("")
def list_systems(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    coverage: str | None = None,
    q: str | None = None,
    business_unit: str | None = None,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    repo = SystemRepository(db)
    rows, total = repo.list_systems(
        page=page, page_size=page_size, coverage=coverage, q=q, business_unit=business_unit
    )
    return {
        "systems": [{**row.to_dict(), **{"coverage": repo.catalog_row(row).get("coverage_status")}} for row in rows],
        "total_count": total,
        "page": page,
        "page_size": page_size,
    }


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
    from cbom.coverage import initial_status

    row = repo.create(
        System(
            name=body.name,
            description=body.description,
            owner=body.owner,
            environment=body.environment,
            compliance_scopes=body.compliance_scopes,
            scan_target=body.scan_target,
            scan_branch=body.scan_branch,
            business_unit=body.business_unit,
            criticality=body.criticality,
            coverage_status=initial_status(body.scan_target),
        )
    )
    return row.to_dict()


@router.post("/import")
def import_systems(
    body: ImportSystemsRequest,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    from cbom.coverage import parse_system_import

    try:
        rows = parse_system_import(body.systems if body.systems is not None else body.csv)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if not rows:
        raise HTTPException(status_code=422, detail="No systems in import payload")
    repo = SystemRepository(db)
    created = 0
    updated = 0
    imported = []
    for item in rows[:5000]:
        system, is_new = repo.upsert_imported(item)
        created += int(is_new)
        updated += int(not is_new)
        imported.append(system.to_dict())
    return {
        "created": created,
        "updated": updated,
        "total": created + updated,
        "systems": imported[:50],
        "truncated": len(rows) > 5000,
    }


class SystemUpdate(BaseModel):
    scan_target: str | None = None
    scan_branch: str | None = None
    owner: str | None = None
    environment: str | None = None
    business_unit: str | None = None
    criticality: str | None = None
    description: str | None = None
    compliance_scopes: list[str] | None = None


@router.patch("/{system_id}")
def update_system(
    system_id: str,
    body: SystemUpdate,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    repo = SystemRepository(db)
    row = repo.get_by_id(system_id)
    if row is None:
        raise HTTPException(status_code=404, detail="System not found")
    data = body.model_dump(exclude_unset=True)
    for key, value in data.items():
        setattr(row, key, value)
    if "scan_target" in data:
        from cbom.coverage import initial_status

        if not row.last_scan_id:
            row.coverage_status = initial_status(row.scan_target)
    db.flush()
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
    payload.update({k: v for k, v in repo.catalog_row(row).items() if k not in payload})
    return payload


@router.post("/{system_id}/scan")
def scan_system(
    system_id: str,
    background_tasks: BackgroundTasks,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
    jobs: JobRepository = Depends(get_job_repository),
):
    repo = SystemRepository(db)
    system = repo.get_by_id(system_id)
    if system is None:
        raise HTTPException(status_code=404, detail="System not found")
    target = (system.scan_target or "").strip()
    if not target:
        raise HTTPException(
            status_code=422,
            detail="Set scan_target (git URL or local:// path) before scanning. Algorithms are unknown until a scan produces a CBOM.",
        )
    from api.routers.trigger import enqueue_scan_job

    return enqueue_scan_job(
        jobs,
        background_tasks,
        repo_url=target,
        branch=system.scan_branch or "main",
        triggered_by=user,
        job_type="SYSTEM",
        system_id=system.id,
    )


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
