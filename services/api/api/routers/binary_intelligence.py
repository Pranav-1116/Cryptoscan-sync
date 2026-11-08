"""Binary Intelligence API (docs/binary-intelligence/01_PRODUCT_SPEC.md §12).

Submit authorized artifacts for STATIC analysis — the artifact is never
executed (§14). Findings carry evidence class and usage status; no
finding is never proof of absence; private-key contents are never
responses.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session
from db.repositories.binary_intelligence_repository import (
    BinaryIntelligenceRepository,
)
from binary_intelligence.comparison import compare_findings
from binary_intelligence.pipeline import PROFILES, run_scan
from db.models.binary_intelligence import BinaryArtifact, BinaryScanRun

router = APIRouter(prefix="/binary", tags=["binary-intelligence"])


class ScanRequest(BaseModel):
    """An authorized scan submission. artifact_base64 carries the
    artifact bytes; the request never executes anything."""
    tenant_id: str
    artifact_base64: str = Field(..., description="base64 artifact bytes")
    original_filename: str = "artifact.bin"
    source_type: str = "upload"
    source_location: Optional[str] = None
    scan_profile: str = "standard"


class ArtifactOut(BaseModel):
    artifact_id: str
    sha256: str
    file_size: int
    detected_format: str
    format_reason: str
    original_filename: str
    source_type: str
    source_location: Optional[str] = None
    uploaded_by: str
    received_at: Optional[datetime] = None


class EvidenceOut(BaseModel):
    type: str
    location: str
    description: str
    excerpt: str = ""


class FindingOut(BaseModel):
    finding_id: str
    subject: str
    finding_type: str
    algorithm: str = ""
    variant: str = ""
    operation: str = ""
    mode_or_padding: str = ""
    key_size_bits: Optional[int] = None
    library: str = ""
    detection_method: str = ""
    evidence: List[EvidenceOut] = Field(default_factory=list)
    confidence: str
    usage_status: str
    runtime_confirmed: bool = False
    quantum_vulnerable: bool = False
    pqc_family: bool = False
    limitations: List[str] = Field(default_factory=list)
    scanner_version: str = ""
    signature_database_version: str = ""


class ScanAccepted(BaseModel):
    scan_id: str
    artifact: ArtifactOut
    scan_profile: str
    status: str
    scanner_version: str
    signature_database_version: str
    finding_count: int
    findings: List[FindingOut]
    certificates: List[Dict[str, Any]]
    private_key_events: List[Dict[str, Any]]
    coverage: Dict[str, Any]
    pqc_assessment: Dict[str, Any]
    notes: List[str]


class ScanStatusOut(BaseModel):
    scan_id: str
    artifact_id: str
    artifact_sha256: str
    scan_profile: str
    scanner_version: str
    signature_database_version: str
    status: str
    structural_report: Optional[Dict[str, Any]] = None
    pqc_assessment: Optional[Dict[str, Any]] = None
    scanned_at: Optional[datetime] = None


class FindingListOut(BaseModel):
    artifact_id: str
    findings: List[Dict[str, Any]]
    note: str


class EvidenceListOut(BaseModel):
    finding_id: str
    evidence: List[Dict[str, Any]]
    note: str


def _repo(db: Session) -> BinaryIntelligenceRepository:
    return BinaryIntelligenceRepository(db)


@router.post("/scan", response_model=ScanAccepted, status_code=201)
def submit_scan(body: ScanRequest, response: Response,
                db: Session = Depends(get_db_session),
                user: str = Depends(get_current_user)) -> ScanAccepted:
    """Submit an authorized binary artifact for static analysis. The
    artifact is validated by content, identified by SHA-256 and never
    executed; a deep profile runs standard static analysis and names
    deep analysis as not completed (§12/§14)."""
    try:
        data = base64.b64decode(body.artifact_base64, validate=True)
    except Exception as exc:
        raise HTTPException(
            status_code=422,
            detail="artifact bytes did not decode — content is "
                   "validated, never assumed") from exc
    try:
        result = run_scan(
            tenant_id=body.tenant_id, data=data,
            original_filename=body.original_filename,
            source_type=body.source_type,
            uploaded_by=user,
            source_location=body.source_location,
            profile=body.scan_profile)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    repository = _repo(db)
    registered = repository.register_artifact(result.identity)
    if registered["outcome"] == "existing":
        response.status_code = 200
    repository.record_scan(
        tenant_id=body.tenant_id, scan_id=result.scan_id,
        artifact_id=result.identity.artifact_id,
        artifact_sha256=result.identity.sha256,
        scan_profile=result.profile,
        scanner_version=result.as_dict()["scanner_version"],
        signature_database_version=result.as_dict()["signature_database_version"],
        status=result.status,
        structural_report={
            **result.structural_report,
            "bom": result.bom.as_dict() if result.bom is not None else None},
        pqc_assessment=result.pqc_assessment,
        scanned_at=datetime.now(timezone.utc))
    repository.record_findings(
        tenant_id=body.tenant_id, run_id=result.scan_id,
        findings=result.findings)
    repository.record_coverage(
        tenant_id=body.tenant_id, run_id=result.scan_id,
        coverage=result.coverage)

    payload = result.as_dict()
    return ScanAccepted(
        scan_id=result.scan_id,
        artifact=ArtifactOut(**{
            **result.identity.as_dict(),
            "received_at": result.identity.received_at}),
        scan_profile=result.profile,
        status=result.status,
        scanner_version=payload["scanner_version"],
        signature_database_version=payload["signature_database_version"],
        finding_count=len(result.findings),
        findings=[FindingOut(
            finding_id=f["finding_id"], subject=f["subject"],
            finding_type=f["finding_type"], algorithm=f["algorithm"],
            variant=f["variant"], operation=f["operation"],
            mode_or_padding=f["mode_or_padding"],
            key_size_bits=f["key_size_bits"], library=f["library"],
            detection_method=f["detection_method"],
            evidence=[EvidenceOut(**e) for e in f["evidence"]],
            confidence=f["confidence"], usage_status=f["usage_status"],
            runtime_confirmed=f["runtime_confirmed"],
            quantum_vulnerable=f["quantum_vulnerable"],
            pqc_family=f["pqc_family"], limitations=f["limitations"],
            scanner_version=f["scanner_version"],
            signature_database_version=f["signature_database_version"])
            for f in payload["findings"]],
        certificates=payload["certificates"],
        private_key_events=payload["private_key_events"],
        coverage=payload["coverage"],
        pqc_assessment=payload["pqc_assessment"],
        notes=payload["notes"])


@router.get("/scans/{scan_id}", response_model=ScanStatusOut)
def scan_status(scan_id: str, tenant_id: str = Query(...),
                db: Session = Depends(get_db_session),
                user: str = Depends(get_current_user)) -> ScanStatusOut:
    row = _repo(db).get_scan(tenant_id, scan_id)
    if row is None:
        raise HTTPException(status_code=404, detail="scan not found")
    return ScanStatusOut(**row)


@router.get("/artifacts/{artifact_id}", response_model=ArtifactOut)
def artifact_details(artifact_id: str, tenant_id: str = Query(...),
                     db: Session = Depends(get_db_session),
                     user: str = Depends(get_current_user)) -> ArtifactOut:
    row = _repo(db).get_artifact(tenant_id, artifact_id)
    if row is None:
        raise HTTPException(status_code=404, detail="artifact not found")
    return ArtifactOut(**row)


@router.get("/artifacts/{artifact_id}/findings",
            response_model=FindingListOut)
def artifact_findings(artifact_id: str, tenant_id: str = Query(...),
                      db: Session = Depends(get_db_session),
                      user: str = Depends(get_current_user)
                      ) -> FindingListOut:
    repository = _repo(db)
    if repository.get_artifact(tenant_id, artifact_id) is None:
        raise HTTPException(status_code=404, detail="artifact not found")
    findings = repository.list_findings(tenant_id, artifact_id=artifact_id)
    for finding in findings:
        finding["evidence"] = repository.list_evidence(
            tenant_id, finding_id=finding["finding_id"])
    return FindingListOut(
        artifact_id=artifact_id, findings=findings,
        note="every finding carries its evidence class and usage status; "
             "a function reference is not proof of runtime use (§5), and "
             "no finding is never proof of absence (§7)")


@router.get("/artifacts/{artifact_id}/coverage", response_model=Dict[str, Any])
def artifact_coverage(artifact_id: str, tenant_id: str = Query(...),
                      db: Session = Depends(get_db_session),
                      user: str = Depends(get_current_user)
                      ) -> Dict[str, Any]:
    repository = _repo(db)
    if repository.get_artifact(tenant_id, artifact_id) is None:
        raise HTTPException(status_code=404, detail="artifact not found")
    scans = repository.list_scans_for_artifact(tenant_id, artifact_id)
    if not scans:
        raise HTTPException(status_code=404, detail="no scan runs")
    coverage = repository.get_coverage(tenant_id, scans[-1]["scan_id"])
    return coverage or {}


@router.get("/artifacts/{artifact_id}/evidence",
            response_model=List[Dict[str, Any]])
def artifact_evidence(artifact_id: str, tenant_id: str = Query(...),
                      db: Session = Depends(get_db_session),
                      user: str = Depends(get_current_user)
                      ) -> List[Dict[str, Any]]:
    repository = _repo(db)
    if repository.get_artifact(tenant_id, artifact_id) is None:
        raise HTTPException(status_code=404, detail="artifact not found")
    out: List[Dict[str, Any]] = []
    for finding in repository.list_findings(tenant_id, artifact_id=artifact_id):
        out.extend(repository.list_evidence(
            tenant_id, finding_id=finding["finding_id"]))
    return out


class BomOut(BaseModel):
    artifact_id: str
    bom: Dict[str, Any]
    note: str


class ComparisonOut(BaseModel):
    base_artifact_id: str
    against_artifact_id: str
    deltas: List[Dict[str, Any]]
    summary: Dict[str, int]
    note: str


class RescanRequest(BaseModel):
    tenant_id: str
    artifact_base64: str
    scan_profile: str = "standard"


@router.get("/artifacts/{artifact_id}/bom", response_model=BomOut)
def artifact_bom(artifact_id: str, tenant_id: str = Query(...),
                 db: Session = Depends(get_db_session),
                 user: str = Depends(get_current_user)) -> BomOut:
    """The SBOM/CBOM view of the artifact (§8): components, provides
    and uses relationships with provenance. A `uses` edge appears only
    when evidence supports it — co-occurrence never creates one (§5)."""
    repository = _repo(db)
    if repository.get_artifact(tenant_id, artifact_id) is None:
        raise HTTPException(status_code=404, detail="artifact not found")
    scans = repository.list_scans_for_artifact(tenant_id, artifact_id)
    if not scans:
        raise HTTPException(status_code=404, detail="no scan runs")
    bom = (scans[-1].get("structural_report") or {}).get("bom")
    if bom is None:
        raise HTTPException(status_code=404,
                            detail="no BOM on the latest scan run")
    return BomOut(
        artifact_id=artifact_id, bom=bom,
        note="relationships carry provenance; a library PROVIDES an "
             "algorithm and the application USES it only when evidence "
             "supports the claim (docs/binary-intelligence/"
             "01_PRODUCT_SPEC.md §5)")


@router.get("/artifacts/{artifact_id}/comparison",
            response_model=ComparisonOut)
def artifact_comparison(artifact_id: str, tenant_id: str = Query(...),
                        against_artifact_id: str = Query(...),
                        db: Session = Depends(get_db_session),
                        user: str = Depends(get_current_user)
                        ) -> ComparisonOut:
    """Compare artifact versions (§16 §6): drift of static INDICATORS,
    never drift of behavior — a missing indicator may mean stripping,
    not removal."""
    repository = _repo(db)
    base = repository.get_artifact(tenant_id, artifact_id)
    against = repository.get_artifact(tenant_id, against_artifact_id)
    if base is None or against is None:
        raise HTTPException(status_code=404, detail="artifact not found")
    base_findings = repository.list_findings(tenant_id,
                                             artifact_id=artifact_id)
    against_findings = repository.list_findings(
        tenant_id, artifact_id=against_artifact_id)
    report = compare_findings(
        base_artifact_id=artifact_id, base_sha256=base["sha256"],
        base_findings=base_findings,
        against_artifact_id=against_artifact_id,
        against_sha256=against["sha256"],
        against_findings=against_findings)
    body = report.as_dict()
    return ComparisonOut(
        base_artifact_id=artifact_id,
        against_artifact_id=against_artifact_id,
        deltas=body["deltas"], summary=body["summary"], note=body["note"])


@router.post("/artifacts/{artifact_id}/rescan",
             response_model=ScanAccepted, status_code=201)
def rescan_artifact(artifact_id: str, body: RescanRequest,
                    response: Response,
                    db: Session = Depends(get_db_session),
                    user: str = Depends(get_current_user)) -> ScanAccepted:
    """Rescan the SAME artifact bytes with a (possibly new) profile
    (§12). The platform stores metadata, not blobs — the caller
    resubmits the bytes and the digest must match: a changed artifact
    is a new artifact, never a rescan of this one."""
    repository = _repo(db)
    artifact = repository.get_artifact(body.tenant_id, artifact_id)
    if artifact is None:
        raise HTTPException(status_code=404, detail="artifact not found")
    try:
        import base64 as _b64
        data = _b64.b64decode(body.artifact_base64, validate=True)
    except Exception as exc:
        raise HTTPException(
            status_code=422,
            detail="artifact bytes did not decode — content is "
                   "validated, never assumed") from exc
    import hashlib
    digest = hashlib.sha256(data).hexdigest()
    if digest != artifact["sha256"]:
        raise HTTPException(
            status_code=422,
            detail="digest mismatch — a rescan is for the same bytes; a "
                   "changed artifact is a NEW artifact, never a rescan")
    scan_request = ScanRequest(
        tenant_id=body.tenant_id,
        artifact_base64=body.artifact_base64,
        original_filename=artifact["original_filename"],
        source_type=artifact["source_type"],
        source_location=artifact["source_location"],
        scan_profile=body.scan_profile)
    result = submit_scan(scan_request, response, db=db, user=user)
    response.status_code = 201    # a rescan records a NEW scan run
    return result
