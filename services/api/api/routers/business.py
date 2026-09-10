"""Business processes, owners, vendors, and migration projects."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from datetime import datetime, timezone

from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session
from db.repositories.intelligence_repository import IntelligenceRepository
from db.models.migration_project import MigrationProject

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


class ApiScanBody(BaseModel):
    endpoint: str = Field(..., min_length=3)  # host[:port], port defaults to 443
    timeout: float = 5.0
    scan_ciphers: bool = False
    scan_versions: bool = False


@router.post("/vendors/{vendor_id}/api-scan")
def vendor_api_scan(
    vendor_id: str, body: ApiScanBody, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)
):
    """Discovery method 1: live TLS probe of a vendor endpoint (their crypto for your data).

    Observed directly on the wire, so confidence is HIGH for reachable endpoints;
    unreachable endpoints are reported honestly and store nothing.
    """
    vendor = IntelligenceRepository(db).get_vendor(vendor_id)
    if vendor is None:
        raise HTTPException(status_code=404, detail="Vendor not found")

    from network_scanner.core.scanner import NetworkTlsScanner
    from db.repositories.maturity_repository import MaturityRepository

    result = NetworkTlsScanner(live=True, timeout=body.timeout).scan_hosts(
        [body.endpoint], scan_ciphers=body.scan_ciphers, scan_versions=body.scan_versions
    )
    repo = MaturityRepository(db)
    added = []
    probe_summaries = []
    for finding in result.get("findings") or []:
        crypto = finding.get("crypto") or {}
        meta = finding.get("metadata") or {}
        endpoint_label = finding.get("endpoint") or body.endpoint
        status = finding.get("status") or "UNKNOWN"
        # a failed probe is a finding about reachability, not vendor crypto — store nothing
        if status != "OK":
            probe_summaries.append({"endpoint": endpoint_label, "status": status, "stored": False})
            continue
        algorithm = str(finding.get("algorithm") or crypto.get("algorithm") or "TLS")
        # inventory BOTH the negotiated protocol and the cipher — the registry
        # treats TLS1.0 as disallowed even when its cipher parses as allowed
        algorithm_rows = [
            (
                str(crypto.get("algorithm") or "TLS"),
                f"Data in transit ({endpoint_label}) — protocol",
            ),
            (algorithm, f"Data in transit ({endpoint_label}) — cipher"),
        ]
        for row_algorithm, use_case in algorithm_rows:
            row = repo.add_vendor_crypto(
                vendor_id,
                crypto_use_case=use_case,
                algorithm=row_algorithm,
                key_size=crypto.get("key_size"),
                mode=crypto.get("encryption_mode") or crypto.get("mode"),
                key_management=f"key exchange: {crypto['key_exchange_algorithm']}" if crypto.get("key_exchange_algorithm") else None,
                pqc_ready=str(crypto.get("quantum_impact") or "").upper() in {"NONE", "RESISTANT", "PQC_RESISTANT"},
                discovery_method="API_SCAN",
                confidence=meta.get("confidence") or "HIGH",
                verified_at=datetime.now(timezone.utc),
                source_document=f"tls://{endpoint_label} ({crypto.get('cipher_suite') or 'cipher unknown'})",
            )
            added.append(row.to_dict())
        probe_summaries.append(
            {
                "endpoint": endpoint_label,
                "status": status,
                "stored": True,
                "algorithm": algorithm,
                "tls_version": crypto.get("tls_version"),
                "cipher_suite": crypto.get("cipher_suite"),
                "policy_issues": finding.get("policy_issues") or [],
            }
        )
    return {
        "vendor_id": vendor_id,
        "vendor": vendor.name,
        "endpoint": body.endpoint,
        "inventory_added": len(added),
        "inventory": added,
        "probes": probe_summaries,
        "certificates_seen": len(result.get("certificates") or []),
    }


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


# --------------------------------------------------- migration tracking (W53-54)


class MigrationTaskCreate(BaseModel):
    title: str
    system_id: str | None = None
    asset_id: str | None = None
    evidence_id: str | None = None
    algorithm_from: str | None = None
    algorithm_to: str | None = None
    priority: str = "P2"
    effort: str | None = None
    owner: str | None = None
    external_ref: str | None = None
    due_date: datetime | None = None


class MigrationTaskPatch(BaseModel):
    title: str | None = None
    status: str | None = None
    owner: str | None = None
    blocked_reason: str | None = None
    external_ref: str | None = None
    due_date: datetime | None = None


class AutoProjectRequest(BaseModel):
    scan_id: str
    name: str | None = None
    owner: str | None = None
    system_id: str | None = None


class MilestoneCreate(BaseModel):
    name: str
    target_date: datetime | None = None
    notes: str | None = None


class ExternalSyncRequest(BaseModel):
    updates: list[dict]


def _task_repo(db: Session):
    from db.repositories.migration_task_repository import MigrationTaskRepository

    return MigrationTaskRepository(db)


def _value_error(exc: ValueError) -> HTTPException:
    message = str(exc)
    if "not found" in message:
        return HTTPException(status_code=404, detail=message)
    return HTTPException(status_code=400, detail=message)


@router.post("/migrations/{project_id}/tasks")
def add_migration_task(project_id: str, body: MigrationTaskCreate, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    try:
        row = _task_repo(db).add_task(project_id, source="MANUAL", **body.model_dump())
    except ValueError as exc:
        raise _value_error(exc) from exc
    return row.to_dict()


@router.get("/migrations/{project_id}/tasks")
def list_migration_tasks(project_id: str, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    return {"tasks": [row.to_dict() for row in _task_repo(db).list_tasks(project_id)]}


@router.patch("/migrations/tasks/{task_id}")
def update_migration_task(task_id: str, body: MigrationTaskPatch, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    try:
        row = _task_repo(db).update_task(task_id, **body.model_dump())
    except ValueError as exc:
        raise _value_error(exc) from exc
    if row is None:
        raise HTTPException(status_code=404, detail="Migration task not found")
    return row.to_dict()


@router.post("/migrations/from-scan")
def create_migration_from_scan(body: AutoProjectRequest, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    """Auto-create a migration project + tasks from a scan's remediation advice.

    Tasks come from the deterministic remediation engine over the scan's
    FAIL/WARN findings — one task per suggestion, P0–P3 ordered.
    """
    from db.repositories.evidence_repository import EvidenceRepository
    from db.repositories.scan_repository import ScanRepository
    from remediation.engine import suggest_remediations

    scan = ScanRepository(db).get_by_id(body.scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    findings = [
        {
            "evidence_id": row.id,
            "algorithm": row.algorithm,
            "purpose": row.purpose,
            "mode": row.mode,
            "key_size": row.key_size,
            "file_path": row.file_path,
            "line_number": row.line_number,
            "compliance_status": row.compliance_status,
            "is_hardcoded_key": row.is_hardcoded_key,
        }
        for row in EvidenceRepository(db).get_all_for_scan(body.scan_id)
    ]
    suggestions = suggest_remediations(findings)
    project = IntelligenceRepository(db).create_migration(
        name=body.name or f"PQC migration — {scan.target_location}",
        system_id=body.system_id,
        status="PLANNED",
        owner=body.owner or user,
        notes=f"auto-generated from scan {body.scan_id}",
    )
    repo = _task_repo(db)
    for suggestion in suggestions["suggestions"]:
        location = f"{suggestion.get('file_path') or '?'}"
        if suggestion.get("line_number"):
            location += f":{suggestion['line_number']}"
        repo.add_task(
            project.id,
            source="AUTO",
            system_id=body.system_id,
            evidence_id=str(suggestion.get("evidence_id") or "") or None,
            title=f"[{suggestion['priority']}] Replace {suggestion.get('algorithm') or 'crypto'} at {location} with {suggestion['replace_with']}",
            algorithm_from=suggestion.get("algorithm"),
            algorithm_to=suggestion.get("replace_with"),
            priority=suggestion["priority"],
            effort=suggestion.get("effort"),
            owner=body.owner or user,
        )
    return {
        "project": project.to_dict(),
        "tasks_created": suggestions["count"],
        "by_priority": suggestions["by_priority"],
    }


@router.get("/migrations/{project_id}/progress")
def migration_progress(project_id: str, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    if db.get(MigrationProject, project_id) is None:
        raise HTTPException(status_code=404, detail="Migration project not found")
    return _task_repo(db).progress(project_id)


@router.get("/migrations/{project_id}/forecast")
def migration_forecast(project_id: str, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    if db.get(MigrationProject, project_id) is None:
        raise HTTPException(status_code=404, detail="Migration project not found")
    return _task_repo(db).forecast(project_id)


@router.post("/migrations/{project_id}/milestones")
def add_milestone(project_id: str, body: MilestoneCreate, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    try:
        row = _task_repo(db).add_milestone(project_id, body.name, body.target_date, body.notes)
    except ValueError as exc:
        raise _value_error(exc) from exc
    return row.to_dict()


@router.get("/migrations/{project_id}/milestones")
def list_milestones(project_id: str, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    return {"milestones": [row.to_dict() for row in _task_repo(db).list_milestones(project_id)]}


@router.get("/migrations/{project_id}/export/github-issues")
def export_github_issues(project_id: str, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    """Bulk-importable issue bodies — the honest sync boundary.

    Without live GitHub/JIRA credentials this exports exactly what the
    external tracker needs (title, body, labels); use /sync to push
    status changes back.
    """
    repo = _task_repo(db)
    project = db.get(MigrationProject, project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Migration project not found")
    issues = []
    for task in repo.list_tasks(project_id):
        if task.status in {"DONE", "SKIPPED"}:
            continue
        lines = [
            f"Replace **{task.algorithm_from or 'crypto'}** with **{task.algorithm_to or 'a modern algorithm'}**.",
            "",
            f"- Priority: {task.priority}",
            f"- Effort: {task.effort or 'unknown'}",
            f"- Status: {task.status}",
        ]
        if task.blocked_reason:
            lines.append(f"- Blocked: {task.blocked_reason}")
        lines += ["", "_Generated deterministically by CryptoScan migration tracking._"]
        issues.append(
            {
                "title": task.title,
                "body": "\n".join(lines),
                "labels": ["cryptoscan", f"priority-{task.priority}", f"migration-{project_id[:8]}"],
                "external_id_hint": task.id,
            }
        )
    return {"project": project.to_dict(), "issue_count": len(issues), "issues": issues}


@router.post("/migrations/{project_id}/sync")
def sync_migration(project_id: str, body: ExternalSyncRequest, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    if db.get(MigrationProject, project_id) is None:
        raise HTTPException(status_code=404, detail="Migration project not found")
    return _task_repo(db).sync_external(project_id, body.updates)
