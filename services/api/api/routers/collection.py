"""Universal collection Phase 1. No HTTP handler executes a host command/collector."""

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session
from api.dependencies import get_current_user, get_db_session
from api.routers.assurance_boundary import estate, author, Key
from api.assurance import collection as core, store
from db.models.assurance import AssuranceRevision
from shared_models.collection_coverage import CoverageReport
from shared_models.linux_software import LinuxSoftwareInventory
from shared_models.linux_relationships import LinuxRelationships
from fastapi.responses import JSONResponse
from shared_models.collection import (
    TargetSpec,
    TargetUpdate,
    RevisionRequest,
    JobRequest,
    JobDecision,
    AuthorizeRequest,
)

router = APIRouter(prefix="/collection", tags=["collection"])


@router.get("/collectors")
def collectors(ctx=Depends(estate), user=Depends(get_current_user)):
    core.boundary()
    return {
        "schema_version": "cryptoscan.collector-catalog/v1",
        "collectors": [
            {
                "id": "offline-linux/v1",
                "method": "offline_host",
                "state": "DEVELOPMENT_OFFLINE_ONLY",
                "production_execution_qualified": False,
                "server_execution": False,
                "capabilities": {
                    "SBOM": "PACKAGE_BINARY_MAPPED_PATH_METADATA_NOT_OPERATIONAL_USE",
                    "CBOM": "CERTIFICATE_CONFIG_METADATA",
                    "NBOM": "EXPLICIT_TCP_LISTENER_METADATA_NOT_NEGOTIATED_TLS",
                    "HBOM": "EXPLICIT_KERNEL_DMI_TPM_METADATA_NOT_HARDWARE_ATTESTATION",
                    "VBOM": "UNKNOWN",
                    "TechBOM": "SCOPED_METADATA",
                },
            },
            {
                "id": "offline-oci-metadata/candidate-v1",
                "method": "container",
                "state": "OFFLINE_CANDIDATE_NOT_ADMITTED",
                "production_execution_qualified": False,
                "server_execution": False,
                "capabilities": {
                    "SBOM": "MANIFEST_CONFIG_ARTIFACT_METADATA_NOT_PACKAGE_INVENTORY",
                    "CBOM": "UNKNOWN",
                    "NBOM": "UNKNOWN_DECLARED_PORTS_NOT_LISTENERS",
                    "HBOM": "UNKNOWN",
                    "VBOM": "UNKNOWN",
                    "TechBOM": "SCOPED_ARTIFACT_METADATA",
                },
            },
            {
                "id": "offline-container-content/candidate-v1",
                "method": "container",
                "state": "OFFLINE_CANDIDATE_NOT_ADMITTED",
                "production_execution_qualified": False,
                "server_execution": False,
                "capabilities": {
                    "SBOM": "VERIFIED_LAYERS_AND_DPKG_APK_DATABASE_RECORDS_NOT_COMPLETE_INVENTORY",
                    "CBOM": "UNKNOWN",
                    "NBOM": "UNKNOWN",
                    "HBOM": "UNKNOWN",
                    "VBOM": "UNKNOWN",
                    "TechBOM": "EXACT_PROCESS_CGROUP_MEMBERSHIP_NOT_VERIFIED_IMAGE_DEPLOYMENT",
                },
            },
            {
                "id": "approved-tls-session/candidate-v1",
                "method": "network",
                "state": "OPERATOR_ACTIVE_CANDIDATE_NOT_ADMITTED",
                "production_execution_qualified": False,
                "server_execution": False,
                "active_probe": True,
                "capabilities": {
                    "SBOM": "UNKNOWN",
                    "CBOM": "PINNED_PEER_PUBLIC_METADATA_AND_ONE_SESSION",
                    "NBOM": "ONE_EXACT_NEGOTIATED_TLS_SESSION_NOT_CAPABILITY_SCAN",
                    "HBOM": "UNKNOWN",
                    "VBOM": "UNKNOWN",
                    "TechBOM": "SCOPED_ENDPOINT_SNI_SESSION_REFERENCES",
                },
            },
            {
                "id": "approved-tls13-key-share/candidate-v1",
                "method": "network",
                "state": "OPERATOR_ACTIVE_CANDIDATE_NOT_ADMITTED",
                "production_execution_qualified": False,
                "server_execution": False,
                "active_probe": True,
                "capabilities": {
                    "SBOM": "UNKNOWN",
                    "CBOM": "FINAL_TLS13_SELECTED_GROUP_NOT_PQC_READINESS",
                    "NBOM": "ONE_PINNED_COMPLETED_TLS13_SESSION",
                    "HBOM": "UNKNOWN",
                    "VBOM": "UNKNOWN",
                    "TechBOM": "SCOPED_SESSION_CERTIFICATE_GROUP_REFERENCES",
                },
            },
            *[
                {
                    "method": method,
                    "state": "NOT_ADAPTED_OR_NOT_QUALIFIED",
                    "production_execution_qualified": False,
                    "server_execution": False,
                }
                for method in ["windows", "source", "cloud", "hsm", "hardware", "vendor", "ot"]
            ],
        ],
    }


@router.post("/targets", status_code=201)
def register(
    body: TargetSpec,
    request: Request,
    ctx=Depends(estate),
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
):
    return core.register(db, ctx.tenant_id, body, author(db, request, user), user)


@router.put("/targets/{identifier}")
def update(
    identifier: Key,
    body: TargetUpdate,
    request: Request,
    ctx=Depends(estate),
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
):
    return core.register(
        db,
        ctx.tenant_id,
        body.target,
        author(db, request, user, "assurance.trust"),
        user,
        identifier=identifier,
        expected=body.expected_revision,
    )


@router.post("/targets/{identifier}/authorize")
def authorize(
    identifier: Key,
    body: AuthorizeRequest,
    request: Request,
    ctx=Depends(estate),
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
):
    return core.authorize(db, ctx.tenant_id, identifier, body, author(db, request, user, "assurance.trust"), user)


@router.post("/targets/{identifier}/revoke")
def revoke(
    identifier: Key,
    body: RevisionRequest,
    request: Request,
    ctx=Depends(estate),
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
):
    return core.authorize(
        db, ctx.tenant_id, identifier, body, author(db, request, user, "assurance.trust"), user, revoke=True
    )


@router.get("/targets/{identifier}")
def target(identifier: Key, ctx=Depends(estate), db: Session = Depends(get_db_session), user=Depends(get_current_user)):
    core.boundary()
    return {"history": [store.public(r) for r in core.chain(db, ctx.tenant_id, core.TARGET, identifier)]}


def listing(db, owner, kind, cursor):
    ids = (
        store.rows(db, AssuranceRevision, owner)
        .filter(AssuranceRevision.kind == kind, AssuranceRevision.subject_id > cursor)
        .with_entities(AssuranceRevision.subject_id)
        .distinct()
        .order_by(AssuranceRevision.subject_id)
        .limit(51)
        .all()
    )
    selected = [r[0] for r in ids[:50]]
    return {
        "items": [store.public(core.chain(db, owner, kind, i)[-1]) for i in selected],
        "has_more": len(ids) > 50,
        "next_cursor": selected[-1] if len(ids) > 50 else None,
        "complete_estate_coverage_verified": False,
    }


@router.get("/targets")
def targets(
    cursor: str = Query(default="", max_length=36),
    ctx=Depends(estate),
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
):
    core.boundary()
    return listing(db, ctx.tenant_id, core.TARGET, cursor)


@router.post("/jobs", status_code=201)
def create_job(
    body: JobRequest,
    request: Request,
    ctx=Depends(estate),
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
):
    return core.create_job(db, ctx.tenant_id, body, author(db, request, user), user)


@router.get("/jobs")
def jobs(
    cursor: str = Query(default="", max_length=36),
    ctx=Depends(estate),
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
):
    core.boundary()
    return listing(db, ctx.tenant_id, core.JOB, cursor)


@router.post("/jobs/{identifier}/handoff")
def handoff(
    identifier: Key,
    body: JobDecision,
    request: Request,
    ctx=Depends(estate),
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
):
    return core.transition(db, ctx.tenant_id, identifier, body, author(db, request, user), user, "handoff")


@router.post("/jobs/{identifier}/complete")
def complete(
    identifier: Key,
    body: JobDecision,
    request: Request,
    ctx=Depends(estate),
    db: Session = Depends(get_db_session),
    user=Depends(get_current_user),
):
    return core.transition(db, ctx.tenant_id, identifier, body, author(db, request, user), user, "complete")


@router.get("/jobs/{identifier}")
def job(identifier: Key, ctx=Depends(estate), db: Session = Depends(get_db_session), user=Depends(get_current_user)):
    core.boundary()
    row, _, current = core.resolve_job(db, ctx.tenant_id, identifier)
    try:
        core.admitted(db, ctx.tenant_id, current, row.payload["target_revision"])
        admitted = True
    except Exception as exc:
        from fastapi import HTTPException

        if not isinstance(exc, HTTPException):
            raise
        admitted = False
    return {**store.public(row), "current_authorization_admits_new_work": admitted}


@router.get("/jobs/{identifier}/evidence")
def evidence(
    identifier: Key, ctx=Depends(estate), db: Session = Depends(get_db_session), user=Depends(get_current_user)
):
    return core.evidence(db, ctx.tenant_id, identifier)


@router.get("/jobs/{identifier}/projections")
def projections(
    identifier: Key, ctx=Depends(estate), db: Session = Depends(get_db_session), user=Depends(get_current_user)
):
    return core.projections(db, ctx.tenant_id, identifier)


@router.get("/jobs/{identifier}/coverage")
def coverage(
    identifier: Key, ctx=Depends(estate), db: Session = Depends(get_db_session), user=Depends(get_current_user)
):
    return core.evidence(db, ctx.tenant_id, identifier)["coverage"]


@router.get("/jobs/{identifier}/coverage/surfaces", response_model=CoverageReport)
def surface_coverage(
    identifier: Key, ctx=Depends(estate), db: Session = Depends(get_db_session), user=Depends(get_current_user)
):
    return core.surface_coverage(db, ctx.tenant_id, identifier)


@router.get("/jobs/{identifier}/software/linux", response_model=LinuxSoftwareInventory)
def linux_software(
    identifier: Key, ctx=Depends(estate), db: Session = Depends(get_db_session), user=Depends(get_current_user)
):
    return core.linux_software(db, ctx.tenant_id, identifier)


@router.get("/jobs/{identifier}/relationships/linux", response_model=LinuxRelationships)
def linux_relationships(
    identifier: Key, ctx=Depends(estate), db: Session = Depends(get_db_session), user=Depends(get_current_user)
):
    return core.linux_relationships(db, ctx.tenant_id, identifier)


@router.get("/jobs/{identifier}/software/linux/cyclonedx-1.6", response_class=JSONResponse)
def linux_sbom(
    identifier: Key, ctx=Depends(estate), db: Session = Depends(get_db_session), user=Depends(get_current_user)
):
    return JSONResponse(
        core.linux_sbom(db, ctx.tenant_id, identifier),
        media_type="application/vnd.cyclonedx+json",
        headers={
            "Cache-Control": "private, no-store",
            "Content-Disposition": 'attachment; filename="linux-software.cdx.json"',
            "X-CryptoScan-Validation": "CYCLONEDX_1_6_OFFICIAL_SCHEMA_AND_REFERENCES",
        },
    )


@router.get("/jobs/{identifier}/errors")
def errors(identifier: Key, ctx=Depends(estate), db: Session = Depends(get_db_session), user=Depends(get_current_user)):
    return {"errors": core.evidence(db, ctx.tenant_id, identifier)["errors"], "asset_absence_proven": False}


@router.post("/jobs/{job_id}/enqueue")
def enqueue_job(
    job_id: Key,
    body: RevisionRequest,
    request: Request,
    ctx=Depends(estate),
    user=Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    from api.assurance import host_worker

    actor = author(db, request, user)
    username = user
    return host_worker.enqueue(db, ctx.tenant_id, job_id, body.expected_revision, actor, username)


@router.post("/jobs/{job_id}/cancel")
def cancel_worker_job(
    job_id: Key,
    body: RevisionRequest,
    request: Request,
    ctx=Depends(estate),
    user=Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    from api.assurance import host_worker

    actor = author(db, request, user)
    username = user
    return host_worker.cancel(db, ctx.tenant_id, job_id, body.expected_revision, actor, username)


# Metadata receipt workflow only; no handler dispatches external host execution.
from api.routers.host_qualification import router as qualification_router  # noqa: E402

router.include_router(qualification_router)
