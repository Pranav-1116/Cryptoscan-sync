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
    vendor_type: str | None = None
    integration_type: str | None = None
    data_classifications: list[str] | None = None
    primary_contact: str | None = None
    security_contact: str | None = None


class QuestionnaireBody(BaseModel):
    transit: str | None = None
    rest: str | None = None
    kms: str | None = None
    pqc: str | None = None
    cbom: str | None = None
    rotation: str | None = None
    vendor_name: str | None = None


class CbomImport(BaseModel):
    sbom: dict


class DocsImport(BaseModel):
    text: str


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
    vendor = intel.create_vendor(
        body.name,
        body.criticality,
        vendor_type=body.vendor_type,
        integration_type=body.integration_type,
        data_classifications=body.data_classifications,
        primary_contact=body.primary_contact,
        security_contact=body.security_contact,
    )
    if body.system_id:
        intel.link_vendor(body.system_id, vendor.id)
    return vendor.to_dict()


@router.get("/vendors/{vendor_id}/questionnaire")
def get_questionnaire(vendor_id: str, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    from vendor_intel.questionnaire import generate_questionnaire

    vendor = IntelligenceRepository(db).get_vendor(vendor_id)
    if vendor is None:
        raise HTTPException(status_code=404, detail="Vendor not found")
    return generate_questionnaire(vendor.name)


@router.post("/vendors/{vendor_id}/questionnaire")
def post_questionnaire(
    vendor_id: str, body: QuestionnaireBody, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)
):
    from datetime import datetime, timezone

    from db.repositories.maturity_repository import MaturityRepository
    from vendor_intel.questionnaire import parse_questionnaire

    intel = IntelligenceRepository(db)
    vendor = intel.get_vendor(vendor_id)
    if vendor is None:
        raise HTTPException(status_code=404, detail="Vendor not found")
    parsed = parse_questionnaire(body.model_dump())
    extra = dict(vendor.extra_json or {})
    extra["questionnaire"] = parsed
    intel.update_vendor(vendor_id, extra_json=extra, last_assessment_date=datetime.now(timezone.utc))
    repo = MaturityRepository(db)
    for item in parsed.get("inventory") or []:
        repo.add_vendor_crypto(vendor_id, **item)
    return parsed


@router.post("/vendors/{vendor_id}/cbom")
def post_vendor_cbom(
    vendor_id: str, body: CbomImport, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)
):
    from db.repositories.maturity_repository import MaturityRepository
    from vendor_intel.sbom_import import import_vendor_cbom

    if IntelligenceRepository(db).get_vendor(vendor_id) is None:
        raise HTTPException(status_code=404, detail="Vendor not found")
    items = import_vendor_cbom(body.sbom)
    stored = MaturityRepository(db).replace_vendor_crypto(vendor_id, items)
    return {"imported": len(stored), "inventory": [row.to_dict() for row in stored]}


@router.post("/vendors/{vendor_id}/docs")
def post_vendor_docs(
    vendor_id: str, body: DocsImport, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)
):
    from db.repositories.maturity_repository import MaturityRepository
    from vendor_intel.docs_extract import extract_crypto_mentions

    vendor = IntelligenceRepository(db).get_vendor(vendor_id)
    if vendor is None:
        raise HTTPException(status_code=404, detail="Vendor not found")
    extracted = extract_crypto_mentions(body.text, vendor=vendor.name)
    repo = MaturityRepository(db)
    for item in extracted.get("inventory") or []:
        repo.add_vendor_crypto(vendor_id, **item)
    return extracted


@router.get("/vendors/{vendor_id}/risk")
def vendor_risk(vendor_id: str, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    from db.repositories.maturity_repository import MaturityRepository
    from vendor_intel.risk import score_vendor

    intel = IntelligenceRepository(db)
    vendor = intel.get_vendor(vendor_id)
    if vendor is None:
        raise HTTPException(status_code=404, detail="Vendor not found")
    inventory = [row.to_dict() for row in MaturityRepository(db).list_vendor_crypto(vendor_id)]
    profile = (vendor.extra_json or {}).get("questionnaire") or {}
    scored = score_vendor(
        inventory=inventory,
        classifications=vendor.data_classifications or [],
        pqc_status=profile.get("pqc_status"),
        cbom_provided=profile.get("cbom_provided"),
        profile=profile,
    )
    scored["vendor_id"] = vendor.id
    scored["vendor"] = vendor.name
    scored["inventory"] = inventory
    return scored


@router.get("/vendor-risks")
def vendor_risks(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    from db.repositories.maturity_repository import MaturityRepository
    from vendor_intel.risk import score_vendor

    intel = IntelligenceRepository(db)
    maturity = MaturityRepository(db)
    rows = []
    for vendor in intel.list_vendors():
        inventory = [row.to_dict() for row in maturity.list_vendor_crypto(vendor.id)]
        profile = (vendor.extra_json or {}).get("questionnaire") or {}
        scored = score_vendor(
            inventory=inventory,
            classifications=vendor.data_classifications or [],
            pqc_status=profile.get("pqc_status"),
            cbom_provided=profile.get("cbom_provided"),
            profile=profile,
        )
        scored["vendor_id"] = vendor.id
        scored["vendor"] = vendor.name
        rows.append(scored)
    return {"vendors": rows, "total_count": len(rows)}


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
