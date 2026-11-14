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

from api.config.settings import get_settings
from api.dependencies import (get_current_user, get_db_session,
                              require_intelligence_writer,
                              require_query_tenant_scope)
from db.repositories.binary_intelligence_repository import (
    BinaryIntelligenceRepository,
)
from binary_intelligence.comparison import compare_findings
from binary_intelligence.drift import (
    build_drift_series, build_estate, build_history,
)
from binary_intelligence.orchestrator import (
    ScanJob, ScanJobQueue, WorkerLimits,
)
from binary_intelligence.pipeline import run_scan

router = APIRouter(prefix="/binary", tags=["binary-intelligence"],
                   dependencies=[Depends(require_query_tenant_scope)])

#: Development-only process-local queue. It cannot survive restart or be
#: shared by API replicas; production async endpoints refuse it until a
#: durable, tenant-isolated artifact handoff and worker claim path exist.
WORKER_QUEUE = ScanJobQueue()
# Inline upload is deliberately below the ingress's 10 MiB body limit. Larger
# artifacts require a bank-approved durable, encrypted handoff; decoding a
# 256 MiB base64 request in the API would exhaust its 1 GiB pod budget first.
MAX_INLINE_BASE64_CHARS = 8 * 1024 * 1024  # at most 6 MiB decoded


def _require_durable_async_backend() -> None:
    """Never acknowledge an undurable Binary job in production.

    Redis alone is not an artifact handoff: raw bytes would still be held
    only in the accepting API process. A real backend needs bounded artifact
    retention, cross-replica claims, retries and cleanup first — which is
    what ``binary_intelligence.durable_queue.DurableScanJobQueue`` provides
    once configured (``configure_durable_queue``). Production refuses the
    process-local queue; development keeps it for local runs and tests.
    """
    if get_settings().is_production and not WORKER_QUEUE.as_dict().get("durable"):
        raise HTTPException(
            status_code=503,
            detail="Binary async jobs unavailable: the process-local queue "
                   "is development-only; no durable artifact-backed worker "
                   "handoff is configured")


def configure_durable_queue(*, limits: Optional[WorkerLimits] = None,
                            lease_seconds: Optional[float] = None,
                            max_attempts: Optional[int] = None) -> None:
    """Install the database-backed job handoff as the module queue.

    Called at app startup when ``BINARY_ASYNC_BACKEND=database``. The durable
    queue runs on the caller's request session (the router passes ``db``
    through), so it tracks the same database as every other write — and a
    worker claiming from another replica shares the table, not a process.
    """
    global WORKER_QUEUE
    from binary_intelligence.durable_queue import DurableScanJobQueue
    kwargs: dict = {}
    if limits is not None:
        kwargs["limits"] = limits
    if lease_seconds is not None:
        kwargs["lease_seconds"] = lease_seconds
    if max_attempts is not None:
        kwargs["max_attempts"] = max_attempts
    WORKER_QUEUE = DurableScanJobQueue(**kwargs)


class ScanRequest(BaseModel):
    """An authorized scan submission. artifact_base64 carries the
    artifact bytes; the request never executes anything."""
    tenant_id: str
    artifact_base64: str = Field(
        ..., max_length=MAX_INLINE_BASE64_CHARS,
        description="bounded inline base64 bytes; larger artifacts need approved storage")
    original_filename: str = "artifact.bin"
    source_type: str = "upload"
    source_location: Optional[str] = None
    scan_profile: str = "standard"


class QueuedJobOut(BaseModel):
    job_id: str
    status: str
    queue: Dict[str, Any]
    note: str


class WorkerStatusOut(BaseModel):
    queue: Dict[str, Any]
    note: str


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


def _require_tenant_scope(tenant_id: str) -> None:
    """Payload tenancy never grants access outside the authenticated scope."""
    from db.tenancy import current_tenant

    scoped = current_tenant()
    if scoped is not None and scoped != tenant_id:
        raise HTTPException(status_code=403,
                            detail="requested tenant does not match the "
                                   "authenticated tenant scope")


@router.post("/scan", response_model=ScanAccepted, status_code=201,
             dependencies=[Depends(require_intelligence_writer)])
def submit_scan(body: ScanRequest, response: Response,
                db: Session = Depends(get_db_session),
                user: str = Depends(get_current_user)) -> ScanAccepted:
    """Submit an authorized binary artifact for static analysis. The
    artifact is validated by content, identified by SHA-256 and never
    executed; a deep profile runs standard static analysis and names
    deep analysis as not completed (§12/§14)."""
    _require_tenant_scope(body.tenant_id)
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

    return _persist(db, body.tenant_id, result, response)


def _persist(db: Session, tenant_id: str, result, response: Response
             ) -> ScanAccepted:
    """Persist one ScanResult: artifact identity, run, findings,
    evidence and coverage — the single write path for sync and worker
    scans alike."""
    repository = _repo(db)
    registered = repository.register_artifact(result.identity)
    if registered["outcome"] == "existing":
        response.status_code = 200
    repository.record_scan(
        tenant_id=tenant_id, scan_id=result.scan_id,
        artifact_id=result.identity.artifact_id,
        artifact_sha256=result.identity.sha256,
        scan_profile=result.profile,
        scanner_version=result.as_dict()["scanner_version"],
        signature_database_version=result.as_dict()["signature_database_version"],
        status=result.status,
        structural_report={
            **result.structural_report,
            "bom": result.bom.as_dict() if result.bom is not None else None,
            "timings": result.timings},
        pqc_assessment=result.pqc_assessment,
        scanned_at=datetime.now(timezone.utc))
    repository.record_findings(
        tenant_id=tenant_id, run_id=result.scan_id,
        findings=result.findings)
    repository.record_coverage(
        tenant_id=tenant_id, run_id=result.scan_id,
        coverage=result.coverage)
    if result.bom is not None:
        repository.record_twin_edges(
            tenant_id=tenant_id, run_id=result.scan_id,
            artifact_id=result.identity.artifact_id,
            artifact_sha256=result.identity.sha256,
            edges=result.bom.relationships)
    # Performance Intelligence integration (§13/§17): scanner
    # measurements with defined units and provenance — never production
    # traffic, never guessed units
    from binary_intelligence.telemetry import scan_metrics
    from db.repositories.performance_repository import PerformanceRepository
    perf = PerformanceRepository(db)
    for metric in scan_metrics(
            tenant_id=tenant_id, scan_id=result.scan_id,
            artifact_id=result.identity.artifact_id, result=result):
        perf.insert_metric(metric)
    # CryptoLog integration (§17 Phase 6): one NOTIFICATION event with
    # evidence references — CryptoLog is not a second evidence store;
    # its evidence level is STATIC, never runtime usage
    from binary_intelligence.telemetry import scan_cryptolog_event
    from db.repositories.cryptolog_repository import CryptoLogRepository
    CryptoLogRepository(db).insert_event(
        scan_cryptolog_event(tenant_id=tenant_id, scan_id=result.scan_id,
                             result=result))

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
    artifact_base64: str = Field(..., max_length=MAX_INLINE_BASE64_CHARS)
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
             response_model=ScanAccepted, status_code=201,
             dependencies=[Depends(require_intelligence_writer)])
def rescan_artifact(artifact_id: str, body: RescanRequest,
                    response: Response,
                    db: Session = Depends(get_db_session),
                    user: str = Depends(get_current_user)) -> ScanAccepted:
    """Rescan the SAME artifact bytes with a (possibly new) profile
    (§12). The platform stores metadata, not blobs — the caller
    resubmits the bytes and the digest must match: a changed artifact
    is a new artifact, never a rescan of this one."""
    _require_tenant_scope(body.tenant_id)
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


@router.get("/worker/status", response_model=WorkerStatusOut)
def worker_status(db: Session = Depends(get_db_session),
                  user: str = Depends(get_current_user)) -> WorkerStatusOut:
    """Development queue introspection; no fake production worker health."""
    _require_durable_async_backend()
    return WorkerStatusOut(
        queue=WORKER_QUEUE.as_dict(db),
        note="measure queue depth, refusals and failure rate — production "
             "operations need the numbers, not vibes (§13)")


@router.post("/scan/async", response_model=QueuedJobOut, status_code=202,
             dependencies=[Depends(require_intelligence_writer)])
def submit_scan_async(body: ScanRequest,
                      db: Session = Depends(get_db_session),
                      user: str = Depends(get_current_user)
                      ) -> QueuedJobOut:
    """Submit for ASYNC processing (§12): the job enters the bounded
    worker queue; a worker executes it via POST /binary/scan/
    jobs/{job_id}/process. Backpressure refuses and counts — never
    silently drops. This queue is development-only; production refuses it
    rather than falsely acknowledging a job that cannot survive restart."""
    _require_tenant_scope(body.tenant_id)
    _require_durable_async_backend()
    import uuid as _uuid
    try:
        data = base64.b64decode(body.artifact_base64, validate=True)
    except Exception as exc:
        raise HTTPException(
            status_code=422,
            detail="artifact bytes did not decode — content is "
                   "validated, never assumed") from exc
    job_id = f"bjob-{_uuid.uuid4().hex[:12]}"
    accepted, reason = WORKER_QUEUE.submit(ScanJob(
        job_id=job_id, tenant_id=body.tenant_id, data=data,
        original_filename=body.original_filename,
        source_type=body.source_type, uploaded_by=user,
        source_location=body.source_location,
        profile=body.scan_profile), db=db)
    if not accepted:
        raise HTTPException(status_code=429, detail=reason)
    return QueuedJobOut(
        job_id=job_id, status="queued",
        queue=WORKER_QUEUE.as_dict(db),
        note="accepted into the bounded worker queue; a worker executes "
             "it via POST /binary/scan/jobs/{job_id}/process (§12)")


@router.post("/scan/jobs/{job_id}/process", response_model=ScanAccepted,
             status_code=201,
             dependencies=[Depends(require_intelligence_writer)])
def process_job(job_id: str, response: Response,
                db: Session = Depends(get_db_session),
                user: str = Depends(get_current_user)) -> ScanAccepted:
    """Execute one queued scan job (§12 asynchronous jobs) and persist
    through the same write path as synchronous scans. Runs under the
    worker's declared limits; the artifact is never executed."""
    _require_durable_async_backend()
    captured: dict = {}

    def _on_result(result) -> None:
        captured["result"] = result

    from db.tenancy import current_tenant

    summary = WORKER_QUEUE.process_job(
        job_id, on_result=_on_result, tenant_id=current_tenant(), db=db)
    if summary is None:
        raise HTTPException(status_code=404, detail="no such queued job")
    if summary["status"] == "failed":
        raise HTTPException(status_code=422, detail=summary["reason"])
    return _persist(db, summary["tenant_id"], captured["result"], response)


class TwinEdgeOut(BaseModel):
    edge_id: str
    run_id: str
    subject: str
    relationship_type: str
    twin_predicate: Optional[str] = None
    object: str
    provenance: str
    evidence_class: str
    limitations: List[str] = Field(default_factory=list)
    observed_at: Optional[str] = None


class TwinEdgesOut(BaseModel):
    artifact_id: str
    edges: List[TwinEdgeOut]
    note: str


@router.get("/artifacts/{artifact_id}/twin", response_model=TwinEdgesOut)
def artifact_twin_edges(artifact_id: str, tenant_id: str = Query(...),
                        db: Session = Depends(get_db_session),
                        user: str = Depends(get_current_user)
                        ) -> TwinEdgesOut:
    """The Digital Twin relationship slice of this artifact (§8): every
    edge carries its provenance and evidence class. An indicator edge
    has NO twin predicate — the twin vocabulary has no 'indicates', and
    inventing one would promote an indicator into a relationship claim
    (§5)."""
    repository = _repo(db)
    if repository.get_artifact(tenant_id, artifact_id) is None:
        raise HTTPException(status_code=404, detail="artifact not found")
    rows = repository.list_twin_edges(tenant_id, artifact_id=artifact_id)
    return TwinEdgesOut(
        artifact_id=artifact_id,
        edges=[TwinEdgeOut(**row) for row in rows],
        note="graph relationships need evidence — edges come from "
             "observed binary evidence with provenance, never from names "
             "or co-occurrence (§8)")


class DriftPointOut(BaseModel):
    artifact_id: str
    sha256: str
    received_at: Optional[str] = None
    original_filename: str
    source_type: str
    source_location: Optional[str] = None
    detected_format: str
    scan_count: int
    delta_vs_previous: Optional[Dict[str, Any]] = None


class DriftSeriesOut(BaseModel):
    subject: str
    points: List[DriftPointOut]
    summary: Dict[str, int]
    limitations: List[str]
    note: str


class HistoryOut(BaseModel):
    artifact_id: str
    runs: List[Dict[str, Any]]
    finding_timeline: List[Dict[str, Any]]
    limitations: List[str]
    note: str


class EstateOut(BaseModel):
    findings_total: int
    by_format: Dict[str, int]
    by_source_type: Dict[str, int]
    by_library: Dict[str, int]
    by_algorithm: Dict[str, int]
    quantum_vulnerable_findings: int
    pqc_family_findings: int
    note: str


@router.get("/drift", response_model=DriftSeriesOut)
def drift_series(tenant_id: str = Query(...),
                 subject: Optional[str] = Query(None),
                 source_location: Optional[str] = Query(None),
                 db: Session = Depends(get_db_session),
                 user: str = Depends(get_current_user)) -> DriftSeriesOut:
    """Version-drift series (§17 Phase 6): artifacts grouped by subject
    (filename / source location), compared consecutively — drift of
    static INDICATORS, never drift of behavior; every delta carries its
    caveat. An on-demand computation; a deployment scheduler can call
    this endpoint on its own cadence."""
    repository = _repo(db)
    artifacts = repository.list_artifact_series(
        tenant_id, original_filename=subject,
        source_location=source_location)
    findings_by_artifact = {}
    for artifact in artifacts:
        findings_by_artifact[artifact["artifact_id"]] = \
            repository.list_findings(tenant_id,
                                     artifact_id=artifact["artifact_id"])
    label = subject or source_location or "(all artifacts)"
    series = build_drift_series(
        subject=label, artifacts=artifacts,
        findings_by_artifact=findings_by_artifact)
    return DriftSeriesOut(**series.as_dict())


@router.get("/artifacts/{artifact_id}/history", response_model=HistoryOut)
def artifact_history(artifact_id: str, tenant_id: str = Query(...),
                     db: Session = Depends(get_db_session),
                     user: str = Depends(get_current_user)) -> HistoryOut:
    """Historical evidence comparison (§17 Phase 6): how findings moved
    across scan runs of ONE immutable artifact — a change between runs
    is a change of scanner, profile or signature database, never of the
    artifact."""
    repository = _repo(db)
    if repository.get_artifact(tenant_id, artifact_id) is None:
        raise HTTPException(status_code=404, detail="artifact not found")
    run_rows = repository.list_scans_for_artifact(tenant_id, artifact_id)
    runs = [{
        "scan_id": row["scan_id"],
        "scan_profile": row["scan_profile"],
        "scanner_version": row["scanner_version"],
        "signature_database_version": row["signature_database_version"],
        "status": row["status"],
        "scanned_at": row.get("scanned_at"),
    } for row in run_rows]
    findings_by_run = {
        row["scan_id"]: repository.list_findings(
            tenant_id, run_id=row["scan_id"])
        for row in run_rows
    }
    history = build_history(artifact_id=artifact_id, runs=runs,
                            findings_by_run=findings_by_run)
    return HistoryOut(**history.as_dict())


@router.get("/estate", response_model=EstateOut)
def estate_view(tenant_id: str = Query(...),
                db: Session = Depends(get_db_session),
                user: str = Depends(get_current_user)) -> EstateOut:
    """Vendor and firmware intelligence (§17 Phase 6): findings grouped
    by format, source, library and algorithm. Grouping is metadata —
    shared names are not proof of common origin (§8); counts are counts
    of RECORDED findings, never of running cryptography."""
    repository = _repo(db)
    rows = repository.list_findings_with_artifacts(tenant_id)
    return EstateOut(**build_estate(findings_with_artifacts=rows))


class FirmwareLeadOut(BaseModel):
    offset: int
    kind: str
    description: str
    validated: bool
    validation_note: str


class FirmwareReportOut(BaseModel):
    tool_name: str
    tool_version: str
    tool_available: bool
    analysis_completed: bool
    leads: List[FirmwareLeadOut]
    carved: List[Dict[str, Any]]
    limitations: List[str]
    notes: List[str]
    note: str


@router.post("/firmware/scan", response_model=FirmwareReportOut, status_code=201,
             dependencies=[Depends(require_intelligence_writer)])
def firmware_scan(body: ScanRequest,
                  db: Session = Depends(get_db_session),
                  user: str = Depends(get_current_user)) -> FirmwareReportOut:
    """Bounded firmware signature analysis (§10/§14): the Binwalk tool
    runs under a hard wall-clock timeout — the artifact itself is never
    executed. Third-party output is validated and normalized into LEADS
   , never definitive evidence; carved contents remain untrusted; a
    missing tool reports the analysis as NOT COMPLETED, never as a
    clean result."""
    _require_tenant_scope(body.tenant_id)
    if get_settings().is_production:
        raise HTTPException(
            status_code=503,
            detail="Firmware analysis unavailable in the production API process; "
                   "a bank-approved isolated parser worker is required")
    from adapters.firmware import analyze_firmware
    try:
        data = base64.b64decode(body.artifact_base64, validate=True)
    except Exception as exc:
        raise HTTPException(
            status_code=422,
            detail="artifact bytes did not decode — content is "
                   "validated, never assumed") from exc
    try:
        report = analyze_firmware(data)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return FirmwareReportOut(**report.as_dict())
