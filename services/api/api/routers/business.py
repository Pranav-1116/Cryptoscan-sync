"""Business processes, owners, vendors, and migration projects."""

from __future__ import annotations

from typing import Any, Literal
from db.tenancy import filtered_get

from fastapi import APIRouter, Depends, HTTPException
from datetime import datetime, timezone

from pydantic import BaseModel, Field
from sqlalchemy import select
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
    profile: dict[str, Any] | None = None


class VendorPatch(BaseModel):
    name: str | None = None
    criticality: str | None = None
    vendor_type: str | None = None
    integration_type: str | None = None
    data_classifications: list[str] | None = None
    primary_contact: str | None = None
    security_contact: str | None = None


class VendorProfileWrite(BaseModel):
    """Envelope for a validated, versioned profile revision.

    The nested document is validated by the shared vendor-intel schema. Keeping
    the envelope separate makes status, provenance, and review metadata
    auditable instead of hiding it inside free-form vendor JSON.
    """
    profile: dict[str, Any]
    status: Literal["DRAFT", "IN_REVIEW", "APPROVED", "EXPIRED"] = "DRAFT"
    source: str = Field(default="operator", min_length=1, max_length=120)
    reviewed_by: str | None = Field(default=None, max_length=160)
    review_notes: str | None = None


class VendorProfileEvidenceWrite(BaseModel):
    evidence_id: str = Field(min_length=1, max_length=160)
    evidence_type: Literal["CONTRACT", "ASSESSMENT", "CERTIFICATION", "QUESTIONNAIRE", "OBSERVED_SCAN", "ATTESTATION", "OTHER"]
    evidence_reference: str = Field(min_length=1, max_length=500)
    status: Literal["PASS", "FAIL", "PENDING", "EXPIRED", "UNAVAILABLE", "UNVERIFIED"] = "UNVERIFIED"
    captured_at: datetime | None = None
    acquired_at: datetime | None = None
    expires_at: datetime | None = None
    issuer: str | None = None
    source_system: str | None = None
    collection_method: Literal["UPLOAD_REFERENCE", "API_REFERENCE", "QUESTIONNAIRE", "OBSERVATION", "ATTESTATION", "OTHER"] = "OTHER"
    collector: str | None = None
    reviewed_by: str | None = None
    content_type: str | None = None
    redaction_status: Literal["NOT_APPLICABLE", "REDACTED", "VERIFIED_NO_SECRETS", "UNKNOWN"] = "UNKNOWN"
    limitations: list[str] = Field(default_factory=list)
    sha256: str | None = Field(default=None, min_length=64, max_length=64)


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
    from db.repositories.vendor_profile_repository import VendorProfileRepository
    from vendor_intel.profile import empty_profile, profile_completeness

    profiles = VendorProfileRepository(db)
    for vendor in intel.list_vendors():
        payload = vendor.to_dict()
        payload["system_ids"] = intel.vendor_system_ids(vendor.id)
        current_profile = profiles.latest(vendor.id)
        payload["vendor_profile"] = {
            "status": current_profile.status if current_profile else "DRAFT",
            "revision": current_profile.revision if current_profile else None,
            "completeness": (
                current_profile.completeness_json
                if current_profile
                else profile_completeness(empty_profile(vendor.name, vendor.id))
            ),
        }
        rows.append(payload)
    return {"vendors": rows}


@router.post("/vendors")
def create_vendor(body: VendorCreate, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    intel = IntelligenceRepository(db)

    # Check the system BEFORE creating the vendor. system_vendors has a
    # foreign key to systems, so an unknown id used to surface as a
    # ForeignKeyViolation and a bare 500 -- a client-supplied value must not
    # read as a server fault. Checking first also avoids the worse outcome:
    # the vendor row is created and committed, then the link fails, leaving
    # an orphan the caller was told nothing about.
    if body.system_id:
        from db.models.system import System

        exists = db.execute(
            select(System.id).where(System.id == body.system_id)
        ).scalars().first()
        if exists is None:
            raise HTTPException(
                status_code=404,
                detail=f"Unknown system_id {body.system_id!r}; create the system first",
            )

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
    result = vendor.to_dict()
    if body.profile is not None:
        from pydantic import ValidationError
        from db.repositories.vendor_profile_repository import VendorProfileRepository
        from vendor_intel.profile import now_utc, parse_profile, profile_completeness, profile_hash

        try:
            profile = parse_profile(body.profile)
        except (ValidationError, ValueError) as exc:
            detail = exc.errors() if isinstance(exc, ValidationError) else str(exc)
            raise HTTPException(status_code=422, detail=detail) from exc
        completeness = profile_completeness(profile)
        revision = VendorProfileRepository(db).create_revision(
            vendor.id,
            schema_version=profile.profile_schema,
            status="DRAFT",
            source="vendor-create",
            profile_json=profile.model_dump(mode="json", by_alias=True),
            completeness_json=completeness,
            content_sha256=profile_hash(profile),
            captured_at=now_utc(),
            created_by=user,
        )
        result["vendor_profile"] = {
            "revision": revision.revision,
            "status": revision.status,
            "completeness": completeness,
        }
    return result


@router.get("/vendors/{vendor_id}/profile/schema")
def vendor_profile_schema(
    vendor_id: str,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    # The schema is generic, but this is still an object-scoped route. Do not
    # let a caller use another tenant's vendor identifier to probe or operate
    # on a vendor profile surface that is not visible in its tenant scope.
    if IntelligenceRepository(db).get_vendor(vendor_id) is None:
        raise HTTPException(status_code=404, detail="Vendor not found")
    from vendor_intel.profile import VendorProfile

    return VendorProfile.model_json_schema(by_alias=True)


@router.post("/vendors/{vendor_id}/profile/validate")
def validate_vendor_profile(
    vendor_id: str,
    body: VendorProfileWrite,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    from pydantic import ValidationError
    from vendor_intel.profile import parse_profile, profile_approval_issues, profile_completeness, profile_hash

    if IntelligenceRepository(db).get_vendor(vendor_id) is None:
        raise HTTPException(status_code=404, detail="Vendor not found")
    try:
        profile = parse_profile(body.profile)
    except (ValidationError, ValueError) as exc:
        detail = exc.errors() if isinstance(exc, ValidationError) else str(exc)
        raise HTTPException(status_code=422, detail=detail) from exc
    completeness = profile_completeness(profile)
    approval_issues = profile_approval_issues(profile)
    return {
        "valid": True,
        "status_allowed": (
            body.status != "APPROVED"
            or (completeness["status"] == "COMPLETE" and not approval_issues and body.reviewed_by == user)
        ),
        "completeness": completeness,
        "approval_issues": approval_issues,
        "content_sha256": profile_hash(profile),
        "persisted": False,
    }


@router.get("/vendors/{vendor_id}/profile")
def get_vendor_profile(vendor_id: str, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    from vendor_intel.profile import empty_profile, profile_completeness
    from db.repositories.vendor_profile_repository import VendorProfileRepository

    vendor = IntelligenceRepository(db).get_vendor(vendor_id)
    if vendor is None:
        raise HTTPException(status_code=404, detail="Vendor not found")
    revision = VendorProfileRepository(db).latest(vendor_id)
    if revision is None:
        profile = empty_profile(vendor.name, vendor.id)
        return {
            "vendor_id": vendor.id,
            "revision": None,
            "persisted": False,
            "status": "DRAFT",
            "profile": profile.model_dump(mode="json", by_alias=True),
            "completeness": profile_completeness(profile),
            "audit": {"source": "system-default", "content_sha256": None},
        }
    return {
        "vendor_id": vendor.id,
        "revision": revision.revision,
        "persisted": True,
        "status": revision.status,
        "profile": revision.profile_json,
        "completeness": revision.completeness_json,
        "audit": {
            "source": revision.source,
            "content_sha256": revision.content_sha256,
            "captured_at": revision.captured_at.isoformat() if revision.captured_at else None,
            "created_by": revision.created_by,
            "reviewed_by": revision.reviewed_by,
            "review_notes": revision.review_notes,
        },
    }


@router.put("/vendors/{vendor_id}/profile")
def put_vendor_profile(
    vendor_id: str,
    body: VendorProfileWrite,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    from pydantic import ValidationError
    from vendor_intel.profile import parse_profile, profile_approval_issues, profile_completeness, profile_hash, now_utc
    from db.repositories.vendor_profile_repository import VendorProfileRepository

    vendor = IntelligenceRepository(db).get_vendor(vendor_id)
    if vendor is None:
        raise HTTPException(status_code=404, detail="Vendor not found")
    try:
        profile = parse_profile(body.profile)
    except (ValidationError, ValueError) as exc:
        detail = exc.errors() if isinstance(exc, ValidationError) else str(exc)
        raise HTTPException(status_code=422, detail=detail) from exc

    completeness = profile_completeness(profile)
    approval_issues = profile_approval_issues(profile)
    if body.status == "APPROVED":
        if completeness["status"] != "COMPLETE" or approval_issues:
            raise HTTPException(
                status_code=422,
                detail={
                    "message": "A profile with missing or unverified evidence cannot be approved",
                    "completeness": completeness,
                    "approval_issues": approval_issues,
                },
            )
        if not body.reviewed_by:
            raise HTTPException(status_code=422, detail="reviewed_by is required for an approved profile")
        if body.reviewed_by != user:
            raise HTTPException(status_code=403, detail="reviewed_by must match the authenticated reviewer")

    revision = VendorProfileRepository(db).create_revision(
        vendor_id,
        schema_version=profile.profile_schema,
        status=body.status,
        source=body.source,
        profile_json=profile.model_dump(mode="json", by_alias=True),
        completeness_json=completeness,
        content_sha256=profile_hash(profile),
        captured_at=now_utc(),
        created_by=user,
        reviewed_by=body.reviewed_by,
        review_notes=body.review_notes,
    )
    return {
        "vendor_id": vendor.id,
        "revision": revision.revision,
        "status": revision.status,
        "profile": revision.profile_json,
        "completeness": revision.completeness_json,
        "audit": {
            "source": revision.source,
            "content_sha256": revision.content_sha256,
            "created_by": revision.created_by,
            "captured_at": revision.captured_at.isoformat() if revision.captured_at else None,
            "reviewed_by": revision.reviewed_by,
        },
    }


@router.post("/vendors/{vendor_id}/profile/evidence")
def append_vendor_profile_evidence(
    vendor_id: str,
    body: VendorProfileEvidenceWrite,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    from pydantic import ValidationError
    from db.repositories.vendor_profile_repository import VendorProfileRepository
    from vendor_intel.profile import empty_profile, now_utc, parse_profile, profile_completeness, profile_hash

    vendor = IntelligenceRepository(db).get_vendor(vendor_id)
    if vendor is None:
        raise HTTPException(status_code=404, detail="Vendor not found")
    repo = VendorProfileRepository(db)
    current = repo.latest(vendor_id)
    try:
        profile = parse_profile(current.profile_json) if current else empty_profile(vendor.name, vendor.id)
        payload = profile.model_dump(mode="json", by_alias=True)
        payload.setdefault("evidence", []).append(body.model_dump(mode="json", exclude_none=True))
        updated = parse_profile(payload)
    except (ValidationError, ValueError) as exc:
        detail = exc.errors() if isinstance(exc, ValidationError) else str(exc)
        raise HTTPException(status_code=422, detail=detail) from exc
    completeness = profile_completeness(updated)
    revision = repo.create_revision(
        vendor_id,
        schema_version=updated.profile_schema,
        status="IN_REVIEW" if current and current.status in {"APPROVED", "EXPIRED"} else current.status if current else "DRAFT",
        source="evidence-ingest",
        profile_json=updated.model_dump(mode="json", by_alias=True),
        completeness_json=completeness,
        content_sha256=profile_hash(updated),
        captured_at=now_utc(),
        created_by=user,
        reviewed_by=None,
        review_notes=f"Evidence appended by {user}",
    )
    return {
        "vendor_id": vendor_id,
        "revision": revision.revision,
        "status": revision.status,
        "evidence_id": body.evidence_id,
        "completeness": completeness,
        "content_sha256": revision.content_sha256,
        "audit": {"created_by": revision.created_by, "captured_at": revision.captured_at.isoformat() if revision.captured_at else None},
    }


@router.delete("/vendors/{vendor_id}/profile")
def expire_vendor_profile(
    vendor_id: str,
    reason: str | None = None,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Expire the current revision without deleting audit history or evidence."""
    from vendor_intel.profile import now_utc
    from db.repositories.vendor_profile_repository import VendorProfileRepository

    if IntelligenceRepository(db).get_vendor(vendor_id) is None:
        raise HTTPException(status_code=404, detail="Vendor not found")
    current = VendorProfileRepository(db).latest(vendor_id)
    if current is None:
        raise HTTPException(status_code=404, detail="Vendor has no persisted profile")
    revision = VendorProfileRepository(db).create_revision(
        vendor_id,
        schema_version=current.schema_version,
        status="EXPIRED",
        source="operator-expire",
        profile_json=current.profile_json,
        completeness_json=current.completeness_json,
        content_sha256=current.content_sha256,
        captured_at=now_utc(),
        created_by=user,
        reviewed_by=user,
        review_notes=reason,
    )
    return {
        "vendor_id": vendor_id,
        "revision": revision.revision,
        "status": revision.status,
        "audit_preserved": True,
        "audit": {"created_by": revision.created_by, "captured_at": revision.captured_at.isoformat() if revision.captured_at else None},
    }


@router.get("/vendors/{vendor_id}/profile/history")
def vendor_profile_history(vendor_id: str, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    from db.repositories.vendor_profile_repository import VendorProfileRepository

    if IntelligenceRepository(db).get_vendor(vendor_id) is None:
        raise HTTPException(status_code=404, detail="Vendor not found")
    return {"vendor_id": vendor_id, "revisions": [row.to_dict() for row in VendorProfileRepository(db).history(vendor_id)]}


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
    from db.repositories.vendor_profile_repository import VendorProfileRepository
    from vendor_intel.profile import empty_profile, parse_profile
    from vendor_intel.profile_risk import assess_profile_risk

    current_profile = VendorProfileRepository(db).latest(vendor.id)
    due_profile = parse_profile(current_profile.profile_json) if current_profile else empty_profile(vendor.name, vendor.id)
    scored["vendor_id"] = vendor.id
    scored["vendor"] = vendor.name
    scored["inventory"] = inventory
    scored["due_diligence"] = assess_profile_risk(
        due_profile,
        crypto_risk=dict(scored),
        profile_status=current_profile.status if current_profile else "DRAFT",
    )
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
        from db.repositories.vendor_profile_repository import VendorProfileRepository
        from vendor_intel.profile import empty_profile, parse_profile
        from vendor_intel.profile_risk import assess_profile_risk

        current_profile = VendorProfileRepository(db).latest(vendor.id)
        due_profile = parse_profile(current_profile.profile_json) if current_profile else empty_profile(vendor.name, vendor.id)
        scored["vendor_id"] = vendor.id
        scored["vendor"] = vendor.name
        scored["due_diligence"] = assess_profile_risk(
            due_profile,
            crypto_risk=dict(scored),
            profile_status=current_profile.status if current_profile else "DRAFT",
        )
        rows.append(scored)
    return {"vendors": rows, "total_count": len(rows)}


@router.get("/vendors/{vendor_id}")
def get_vendor(vendor_id: str, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    from db.repositories.vendor_profile_repository import VendorProfileRepository

    vendor = IntelligenceRepository(db).get_vendor(vendor_id)
    if vendor is None:
        raise HTTPException(status_code=404, detail="Vendor not found")
    current = VendorProfileRepository(db).latest(vendor_id)
    result = vendor.to_dict()
    result["profile"] = {
        "status": current.status if current else "DRAFT",
        "revision": current.revision if current else None,
        "completeness": current.completeness_json if current else None,
    }
    return result


@router.patch("/vendors/{vendor_id}")
def patch_vendor(
    vendor_id: str,
    body: VendorPatch,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    values = {key: value for key, value in body.model_dump(exclude_unset=True).items() if value is not None}
    vendor = IntelligenceRepository(db).update_vendor(vendor_id, **values)
    if vendor is None:
        raise HTTPException(status_code=404, detail="Vendor not found")
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
        for row in EvidenceRepository(db).get_all_for_scan(body.scan_id, include_deleted=False)
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
    if filtered_get(db, MigrationProject, project_id) is None:
        raise HTTPException(status_code=404, detail="Migration project not found")
    return _task_repo(db).progress(project_id)


@router.get("/migrations/{project_id}/forecast")
def migration_forecast(project_id: str, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    if filtered_get(db, MigrationProject, project_id) is None:
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
    project = filtered_get(db, MigrationProject, project_id)
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
    if filtered_get(db, MigrationProject, project_id) is None:
        raise HTTPException(status_code=404, detail="Migration project not found")
    return _task_repo(db).sync_external(project_id, body.updates)
