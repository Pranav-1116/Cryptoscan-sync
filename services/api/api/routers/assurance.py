"""Seven evidence-assurance workflows; bounded metadata/bytes, no live acquisition."""
import hashlib
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, Response
from sqlalchemy.orm import Session
from api.dependencies import get_current_user, get_db_session
from api.routers.assurance_boundary import estate, author, Key, new_id
from api.assurance import store, coverage, accuracy, relationships, applicability, adapters, infrastructure
from db.models.assurance import AssuranceRevision, AssuranceBlob
from shared_models.assurance import (Register, CoverageObservation, Sample, Approval, Review, Repeat, Context,
    Relationship, Signer, SupplierUpload, Adapter, AdapterQualification, RedisObjectives, RedisMeasurement, RegressionExecution)
from shared_models.software_identity import scope_key

router = APIRouter(prefix="/assurance", tags=["assurance"])

#: Kind -> permission required to read its retained revisions.
#:
#: These kinds are qualification and trust artefacts: their write routes need a
#: current typed human with ``assurance.trust``/``assurance.review``, and their
#: artefact routes need ``assurance.raw``/``crypto.read``. The generic revision
#: browser is a read path for the same rows, so leaving it on
#: ``get_current_user`` made every one of those stronger checks bypassable with
#: ``?kind=``. Kinds absent from this map stay metadata-only reads.
_KIND_READ_PERMISSION: dict[str, str] = {
    "host_qualification": "crypto.read",
    "supplier_signer": "assurance.trust",
    "adapter_qualification": "assurance.review",
}


def _authorise_kind_read(db: Session, request: Request, user, kind: str) -> None:
    """Gate the revision browser on the same authority as the kind's own routes."""
    permission = _KIND_READ_PERMISSION.get(kind)
    if permission is not None:
        author(db, request, user, permission)


@router.get("/records")
def records(request: Request, kind: str = Query(min_length=1, max_length=30), limit: int = Query(100, ge=1, le=200),
            offset: int = Query(0, ge=0, le=1000000), user=Depends(get_current_user),
            db: Session = Depends(get_db_session), ctx=Depends(estate)):
    _authorise_kind_read(db, request, user, kind)
    query = store.rows(db, AssuranceRevision, ctx.tenant_id).filter_by(kind=kind)
    values = query.order_by(AssuranceRevision.created_at, AssuranceRevision.id).offset(offset).limit(limit + 1).all()
    return {"records": [store.public(r) for r in values[:limit]], "has_more": len(values) > limit,
            "next_offset": offset + limit if len(values) > limit else None, "includes_all_revisions": True}


@router.get("/records/{kind}/{identifier}")
def history(request: Request, kind: Annotated[str, Path(min_length=1, max_length=30)], identifier: Key,
            after_revision: int = Query(0, ge=0), user=Depends(get_current_user),
            db: Session = Depends(get_db_session), ctx=Depends(estate)):
    _authorise_kind_read(db, request, user, kind)
    store.latest(db, ctx.tenant_id, kind, identifier)
    values = store.rows(db, AssuranceRevision, ctx.tenant_id).filter_by(kind=kind, subject_id=identifier).filter(
        AssuranceRevision.revision > after_revision).order_by(AssuranceRevision.revision).limit(201).all()
    return {"revisions": [store.public(r) for r in values[:200]], "has_more": len(values) > 200}


@router.post("/evidence-blobs", status_code=201)
async def evidence_blob(request: Request, evidence_ref: str = Query(min_length=1, max_length=500),
                        user=Depends(get_current_user), db: Session = Depends(get_db_session), ctx=Depends(estate)):
    actor = author(db, request, user)
    if request.headers.get("content-type", "").split(";")[0] != "application/octet-stream":
        raise HTTPException(415, "Send bounded raw application/octet-stream bytes; no remote URLs/file paths")
    data = bytearray()
    async for chunk in request.stream():
        if len(data) + len(chunk) > 1048576:
            raise HTTPException(413, "Quarantine/fixture byte limit is 1048576")
        data.extend(chunk)
    if not data:
        raise HTTPException(422, "Empty evidence blob")
    row = AssuranceBlob(tenant_id=ctx.tenant_id, scope_key=scope_key(ctx.tenant_id), data=bytes(data),
        byte_count=len(data), sha256=hashlib.sha256(data).hexdigest(), created_by=actor)
    db.add(row)
    db.flush()
    receipt = store.append(db, ctx.tenant_id, "evidence_blob", row.id, 0,
        {"blob_id": row.id, "sha256": row.sha256, "byte_count": row.byte_count,
         "evidence_ref": evidence_ref, "state": "UNTRUSTED_QUARANTINED_BYTES_NO_EXECUTION"}, actor)
    return {"blob_id": row.id, "sha256": row.sha256, "byte_count": row.byte_count, "receipt": store.public(receipt)}


@router.get("/evidence-blobs/{identifier}/content")
def blob_content(identifier: Key, request: Request, user=Depends(get_current_user), db: Session = Depends(get_db_session), ctx=Depends(estate)):
    row = store.blob(db, ctx.tenant_id, identifier)
    author(db, request, user, "assurance.raw")
    supplier = store.latest(db, ctx.tenant_id, "supplier_evidence", identifier, required=False)
    if supplier and (supplier.payload["state"] != "APPROVED_OFFLINE_JSON" or adapters.check(db, ctx.tenant_id, supplier.payload)):
        raise HTTPException(409, "Supplier quarantine bytes are not downloadable until current customer/build/trust and bounded-format approval pass")
    return Response(row.data, media_type="application/octet-stream", headers={
        "Content-Disposition": 'attachment; filename="quarantined-evidence.bin"', "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store"})


@router.get("/collections/{identifier}")
def collection(identifier: Key, user=Depends(get_current_user), db: Session = Depends(get_db_session), ctx=Depends(estate)):
    from api.security.partial_progress import summary
    result = summary(db, ctx.tenant_id, identifier, include_observations=True)
    if result is None:
        raise HTTPException(404, "Collection job not found")
    return result


@router.post("/registers", status_code=201)
def create_register(body: Register, request: Request, user=Depends(get_current_user),
                    db: Session = Depends(get_db_session), ctx=Depends(estate)):
    return store.public(coverage.save_register(db, ctx.tenant_id, new_id(), body, author(db, request, user)))


@router.put("/registers/{identifier}")
def revise_register(identifier: Key, body: Register, request: Request, user=Depends(get_current_user),
                    db: Session = Depends(get_db_session), ctx=Depends(estate)):
    store.latest(db, ctx.tenant_id, "estate_register", identifier)
    return store.public(coverage.save_register(db, ctx.tenant_id, identifier, body, author(db, request, user)))


@router.put("/registers/{identifier}/observations/{target_id}")
def coverage_observation(identifier: Key, target_id: Annotated[str, Path(pattern=r"^[a-zA-Z0-9._-]{1,80}$")],
                         body: CoverageObservation, request: Request, user=Depends(get_current_user),
                         db: Session = Depends(get_db_session), ctx=Depends(estate)):
    return store.public(coverage.record(db, ctx.tenant_id, identifier, target_id, body, author(db, request, user)))


@router.get("/registers/{identifier}/coverage")
def coverage_report(identifier: Key, user=Depends(get_current_user), db: Session = Depends(get_db_session), ctx=Depends(estate)):
    return coverage.report(db, ctx.tenant_id, identifier)


@router.post("/relationships", status_code=201)
def propose_relationship(body: Relationship, request: Request, user=Depends(get_current_user),
                         db: Session = Depends(get_db_session), ctx=Depends(estate)):
    return store.public(relationships.save(db, ctx.tenant_id, new_id(), body, author(db, request, user)))


@router.post("/relationships/{identifier}/approve")
def approve_relationship(identifier: Key, body: Approval, request: Request, user=Depends(get_current_user),
                         db: Session = Depends(get_db_session), ctx=Depends(estate)):
    return store.public(relationships.approve(db, ctx.tenant_id, identifier, body, author(db, request, user, "assurance.review")))


@router.get("/applications/{identifier}/trace")
def application_trace(identifier: Key, user=Depends(get_current_user), db: Session = Depends(get_db_session), ctx=Depends(estate)):
    return relationships.trace(db, ctx.tenant_id, identifier)


@router.post("/samples", status_code=201)
def propose_sample(body: Sample, request: Request, user=Depends(get_current_user),
                   db: Session = Depends(get_db_session), ctx=Depends(estate)):
    return store.public(accuracy.propose(db, ctx.tenant_id, new_id(), body, author(db, request, user)))


@router.post("/samples/{identifier}/approve")
def approve_sample(identifier: Key, body: Approval, request: Request, user=Depends(get_current_user),
                   db: Session = Depends(get_db_session), ctx=Depends(estate)):
    return store.public(accuracy.approve(db, ctx.tenant_id, identifier, body, author(db, request, user, "assurance.review")))


@router.get("/samples/{identifier}/workbook")
def workbook(identifier: Key, phase: str = Query("FIRST_PASS", pattern="^(FIRST_PASS|HOLDOUT)$"),
             user=Depends(get_current_user), db: Session = Depends(get_db_session), ctx=Depends(estate)):
    sample = accuracy.approved(db, ctx.tenant_id, identifier)
    source = sample if phase == "FIRST_PASS" else store.latest(db, ctx.tenant_id, "accuracy_repeat", identifier)
    return {"sample_id": identifier, "sample_sha256": source.payload_sha256, "phase": phase,
            "domain_owner": sample.payload["domain_owner"], "scope": sample.payload["scope_description"],
            "units": [u for u in source.payload["units"] if u["split"] == phase], "truth_labels": ["PRESENT", "ABSENT", "UNREVIEWED"],
            "note": "Return truth labels and explanations; TP/FP/misses are calculated from frozen predictions."}


@router.post("/samples/{identifier}/reviews", status_code=201)
def publish_review(identifier: Key, body: Review, request: Request, user=Depends(get_current_user),
                   db: Session = Depends(get_db_session), ctx=Depends(estate)):
    return store.public(accuracy.review(db, ctx.tenant_id, identifier, body, author(db, request, user, "assurance.review")))


@router.post("/samples/{identifier}/repeat", status_code=201)
def repeat_sample(identifier: Key, body: Repeat, request: Request, user=Depends(get_current_user),
                  db: Session = Depends(get_db_session), ctx=Depends(estate)):
    return store.public(accuracy.repeat(db, ctx.tenant_id, identifier, body, author(db, request, user)))


@router.post("/samples/{identifier}/regressions", status_code=201)
def seed_regressions(identifier: Key, request: Request, user=Depends(get_current_user),
                     db: Session = Depends(get_db_session), ctx=Depends(estate)):
    return accuracy.seed_regressions(db, ctx.tenant_id, identifier, author(db, request, user, "assurance.review"))


@router.post("/findings/{identifier}/assessments", status_code=201)
def assessment(identifier: Key, body: Context, request: Request, user=Depends(get_current_user),
               db: Session = Depends(get_db_session), ctx=Depends(estate)):
    return store.public(applicability.assess(db, ctx.tenant_id, identifier, body, author(db, request, user, "assurance.review")))


@router.post("/signers", status_code=201)
def create_signer(body: Signer, request: Request, user=Depends(get_current_user),
                  db: Session = Depends(get_db_session), ctx=Depends(estate)):
    return store.public(adapters.save_signer(db, ctx.tenant_id, new_id(), body, author(db, request, user, "assurance.trust")))


@router.put("/signers/{identifier}")
def revise_signer(identifier: Key, body: Signer, request: Request, user=Depends(get_current_user),
                  db: Session = Depends(get_db_session), ctx=Depends(estate)):
    store.latest(db, ctx.tenant_id, "supplier_signer", identifier)
    return store.public(adapters.save_signer(db, ctx.tenant_id, identifier, body, author(db, request, user, "assurance.trust")))


@router.post("/supplier-evidence", status_code=201)
def supplier_upload(body: SupplierUpload, request: Request, user=Depends(get_current_user),
                    db: Session = Depends(get_db_session), ctx=Depends(estate)):
    return store.public(adapters.upload(db, ctx.tenant_id, body, author(db, request, user)))


@router.post("/supplier-evidence/{identifier}/approve")
def approve_supplier(identifier: Key, body: Approval, request: Request, user=Depends(get_current_user),
                     db: Session = Depends(get_db_session), ctx=Depends(estate)):
    return store.public(adapters.disposition(db, ctx.tenant_id, identifier, body, author(db, request, user, "assurance.review"), True))


@router.post("/supplier-evidence/{identifier}/reject")
def reject_supplier(identifier: Key, body: Approval, request: Request, user=Depends(get_current_user),
                    db: Session = Depends(get_db_session), ctx=Depends(estate)):
    return store.public(adapters.disposition(db, ctx.tenant_id, identifier, body, author(db, request, user, "assurance.review"), False))


@router.post("/adapters", status_code=201)
def create_adapter(body: Adapter, request: Request, user=Depends(get_current_user),
                   db: Session = Depends(get_db_session), ctx=Depends(estate)):
    return store.public(adapters.save_adapter(db, ctx.tenant_id, new_id(), body, author(db, request, user)))


@router.put("/adapters/{identifier}")
def revise_adapter(identifier: Key, body: Adapter, request: Request, user=Depends(get_current_user),
                   db: Session = Depends(get_db_session), ctx=Depends(estate)):
    store.latest(db, ctx.tenant_id, "adapter_manifest", identifier)
    return store.public(adapters.save_adapter(db, ctx.tenant_id, identifier, body, author(db, request, user)))


@router.post("/adapters/{identifier}/qualifications", status_code=201)
def qualify_adapter(identifier: Key, body: AdapterQualification, request: Request, user=Depends(get_current_user),
                    db: Session = Depends(get_db_session), ctx=Depends(estate)):
    return store.public(adapters.qualify(db, ctx.tenant_id, identifier, body, author(db, request, user, "assurance.review")))


@router.get("/adapters/{identifier}")
def adapter_status(identifier: Key, user=Depends(get_current_user), db: Session = Depends(get_db_session), ctx=Depends(estate)):
    return adapters.adapter_status(db, ctx.tenant_id, identifier)


@router.post("/redis-objectives", status_code=201)
def redis_objectives(body: RedisObjectives, request: Request, user=Depends(get_current_user),
                     db: Session = Depends(get_db_session), ctx=Depends(estate)):
    return store.public(infrastructure.objectives(db, ctx.tenant_id, new_id(), body, author(db, request, user, "assurance.trust")))


@router.put("/redis-objectives/{identifier}")
def revise_redis_objectives(identifier: Key, body: RedisObjectives, request: Request, user=Depends(get_current_user),
                            db: Session = Depends(get_db_session), ctx=Depends(estate)):
    store.latest(db, ctx.tenant_id, "redis_objectives", identifier)
    return store.public(infrastructure.objectives(db, ctx.tenant_id, identifier, body, author(db, request, user, "assurance.trust")))


@router.post("/redis-objectives/{identifier}/measurements", status_code=201)
def redis_measurement(identifier: Key, body: RedisMeasurement, request: Request, user=Depends(get_current_user),
                      db: Session = Depends(get_db_session), ctx=Depends(estate)):
    return store.public(infrastructure.measure(db, ctx.tenant_id, identifier, body, author(db, request, user)))


@router.post("/redis-measurements/{identifier}/review")
def review_redis_measurement(identifier: Key, body: Approval, request: Request, user=Depends(get_current_user),
                             db: Session = Depends(get_db_session), ctx=Depends(estate)):
    return store.public(infrastructure.review(db, ctx.tenant_id, identifier, body, author(db, request, user, "assurance.review")))


@router.get("/redis-objectives/{identifier}/qualification")
def redis_qualification(identifier: Key, user=Depends(get_current_user), db: Session = Depends(get_db_session), ctx=Depends(estate)):
    return infrastructure.report(db, ctx.tenant_id, identifier)


@router.post("/regressions/{identifier}/results", status_code=201)
def record_regression_result(identifier: Key, body: RegressionExecution, request: Request, user=Depends(get_current_user),
                             db: Session = Depends(get_db_session), ctx=Depends(estate)):
    return store.public(accuracy.regression_result(db, ctx.tenant_id, identifier, body, author(db, request, user)))


@router.get("/adapters/{identifier}/supplier-evidence/{evidence_id}/observations")
def supplier_observations(identifier: Key, evidence_id: Key, user=Depends(get_current_user),
                          db: Session = Depends(get_db_session), ctx=Depends(estate)):
    return adapters.observations(db, ctx.tenant_id, identifier, evidence_id)


# Operator decisions and independent remediation conditions use the same bounded,
# residency-admitted, exact-estate metadata boundary as the other workflows.
from api.assurance import operator as operator_decisions, remediation as conditions
from shared_models.assurance import RemediationChange, ReportChange, VerifyChange


@router.get("/operator-decisions")
def operator_inbox(offset: int = Query(0, ge=0, le=1000000), limit: int = Query(25, ge=1, le=50),
                   user=Depends(get_current_user), db: Session = Depends(get_db_session), ctx=Depends(estate)):
    return operator_decisions.inbox(db, ctx.tenant_id, offset, limit)


@router.post("/remediation-changes", status_code=201)
def propose_change(body: RemediationChange, request: Request, user=Depends(get_current_user),
                   db: Session = Depends(get_db_session), ctx=Depends(estate)):
    return store.public(conditions.propose(db, ctx.tenant_id, body, author(db, request, user)))


@router.post("/remediation-changes/{identifier}/approve", status_code=201)
def approve_change(identifier: Key, body: Approval, request: Request, user=Depends(get_current_user),
                   db: Session = Depends(get_db_session), ctx=Depends(estate)):
    return store.public(conditions.approve(db, ctx.tenant_id, identifier, body, author(db, request, user, "assurance.review")))


@router.post("/remediation-changes/{identifier}/report-complete", status_code=201)
def report_change(identifier: Key, body: ReportChange, request: Request, user=Depends(get_current_user),
                  db: Session = Depends(get_db_session), ctx=Depends(estate)):
    return store.public(conditions.reported(db, ctx.tenant_id, identifier, body, author(db, request, user)))


@router.post("/remediation-changes/{identifier}/verify", status_code=201)
def verify_change(identifier: Key, body: VerifyChange, request: Request, user=Depends(get_current_user),
                  db: Session = Depends(get_db_session), ctx=Depends(estate)):
    return store.public(conditions.verify(db, ctx.tenant_id, identifier, body, author(db, request, user, "assurance.review")))


from shared_models.assurance import AssignedRemediationTask


@router.post("/remediation-tasks", status_code=201)
def assigned_remediation_task(body: AssignedRemediationTask, request: Request, user=Depends(get_current_user),
                              db: Session = Depends(get_db_session), ctx=Depends(estate)):
    # Explicit exact-owner evidence check even for a platform administrator.
    from db.models.evidence_record import EvidenceRecord
    from api.routers.remediation import create_task, TaskCreateRequest
    author(db, request, user)
    store.exact(db, EvidenceRecord, ctx.tenant_id, body.evidence_id)
    return create_task(TaskCreateRequest(evidence_id=body.evidence_id, owner=body.owner_ref, notes=body.notes), user=user, db=db)


@router.get("/workloads/jobs/{identifier}")
def job_workload(identifier: Key, user=Depends(get_current_user), db: Session = Depends(get_db_session), ctx=Depends(estate)):
    from db.models.scan_job import ScanJob
    from db.models.base import utcnow
    from db.repositories.execution_control import aware
    job = store.exact(db, ScanJob, ctx.tenant_id, identifier)
    return {"job_id": job.id, "estate_id": ctx.tenant_id, "status": job.status,
            "queue_wait_seconds": max(0, (aware(job.started_at or utcnow()) - aware(job.created_at)).total_seconds()),
            "execution_seconds": max(0, (aware(job.completed_at or utcnow()) - aware(job.started_at)).total_seconds()) if job.started_at else None,
            "measurements": (job.progress or {}).get("performance"),
            "measurement_state": "OBSERVED" if (job.progress or {}).get("performance") else "NOT_INSTRUMENTED_OR_LEGACY",
            "capacity_qualified": False}


@router.post("/remediation-changes/{identifier}/revoke", status_code=201)
def revoke_change(identifier: Key, body: Approval, request: Request, user=Depends(get_current_user),
                  db: Session = Depends(get_db_session), ctx=Depends(estate)):
    return store.public(conditions.revoke(db, ctx.tenant_id, identifier, body, author(db, request, user, "assurance.review")))


from api.routers.launch_readiness import router as launch_router
router.include_router(launch_router)
