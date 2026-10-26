"""Exact-estate OCI registry/jobs/intake on the existing assurance revision store.

No handler accesses an image, executes collection, persists operational graph
edges or grants production admission. Target mutex precedes all mutations.
"""

import secrets
from datetime import timedelta
from fastapi import HTTPException
from db.models.assurance import AssuranceRevision
from db.models.base import utcnow
from db.models.system import System
from shared_models.host_collection import digest
from shared_models.oci_collection import OciTarget
from shared_models.oci_intake import OciCaptureBinding, OciJobReturn
from shared_models.oci_projection import materialize_oci
from api.assurance import collection as base, relationships, store

TARGET = "oci_collection_target"
JOB = "oci_collection_job"
EVIDENCE = "oci_collection_evidence"
CONSUMED = "oci_collection_consumed"
TERMINAL = {"COMPLETED", "PARTIAL", "FAILED"}


def chain(db, owner, kind, identifier):
    return base.chain(db, owner, kind, identifier)


def lock_target(db, owner, identifier):
    row = (
        store.rows(db, AssuranceRevision, owner)
        .filter_by(kind=TARGET, subject_id=identifier, revision=1)
        .with_for_update()
        .first()
    )
    if row is None:
        raise HTTPException(404, "OCI target not found")
    store.verify(row)


def save(db, owner, kind, identifier, expected, payload, actor, user, action):
    return base.save(db, owner, kind, identifier, expected, payload, actor, user, "oci." + action)


def system(db, owner, spec):
    row = (
        db.query(System).filter(System.id == spec.system_id, System.tenant_id == owner).with_for_update().one_or_none()
    )
    if row is None:
        raise HTTPException(404, "OCI system not found")
    if not relationships.active(row) or row.environment != spec.environment:
        raise HTTPException(409, "OCI system is inactive or environment changed")


def register(db, owner, spec, actor, user, *, identifier=None, expected=0):
    base.boundary()
    key = store.subject("oci-target/v1", store.scope_key(owner), spec.target_id)
    if identifier is not None:
        lock_target(db, owner, identifier)
        old = chain(db, owner, TARGET, identifier)[-1]
        if old.revision != expected or key != identifier or old.payload["target"]["system_id"] != spec.system_id:
            raise HTTPException(409, "Stable OCI target/system or expected revision changed")
    system(db, owner, spec)
    payload = {
        "schema_version": "cryptoscan.oci-registry-target/v1",
        "state": "REGISTERED",
        "target": spec.model_dump(mode="json"),
        "target_sha256": digest(spec),
        "authorizes_server_collection": False,
        "producer_authenticity_verified": False,
        "production_execution_qualified": False,
    }
    return base.atomic(
        lambda: store.public(save(db, owner, TARGET, key, expected, payload, actor, user, "target.register")), db
    )


def decision(db, owner, identifier, body, actor, user, *, revoke=False):
    base.boundary()
    lock_target(db, owner, identifier)
    row = chain(db, owner, TARGET, identifier)[-1]
    if row.revision != body.expected_revision:
        raise HTTPException(409, "OCI target revision changed")
    spec = OciTarget.model_validate(row.payload["target"])
    if revoke:
        if row.payload["state"] == "REVOKED":
            raise HTTPException(409, "OCI target already revoked")
        state = "REVOKED"
    else:
        if row.payload["state"] != "REGISTERED" or not utcnow() < spec.expires_at <= utcnow() + timedelta(days=1):
            raise HTTPException(409, "OCI target is not a current registration")
        system(db, owner, spec)
        state = "AUTHORIZED"
    payload = {
        **row.payload,
        "state": state,
        "decision_evidence_ref": body.evidence_ref,
        "decision_reason": body.reason,
    }
    return base.atomic(
        lambda: store.public(
            save(
                db,
                owner,
                TARGET,
                identifier,
                row.revision,
                payload,
                actor,
                user,
                "target.revoke" if revoke else "target.authorize",
            )
        ),
        db,
    )


def admitted(db, owner, row, revision):
    spec = OciTarget.model_validate(row.payload["target"])
    if (
        row.revision != revision
        or row.payload["state"] != "AUTHORIZED"
        or row.payload["target_sha256"] != digest(spec)
        or not spec.not_before <= utcnow() < spec.expires_at
    ):
        raise HTTPException(409, "OCI authorization changed, revoked or outside approved window")
    system(db, owner, spec)
    return spec


def create_job(db, owner, body, actor, user):
    base.boundary()
    lock_target(db, owner, body.target_id)
    target = chain(db, owner, TARGET, body.target_id)[-1]
    admitted(db, owner, target, body.expected_target_revision)
    identifier = store.subject("oci-job/v1", store.scope_key(owner), body.target_id, target.payload_sha256)
    payload = {
        "schema_version": "cryptoscan.oci-registry-job/v1",
        "state": "READY",
        "target_id": body.target_id,
        "target_revision": target.revision,
        "target_record_sha256": target.payload_sha256,
        "target_sha256": target.payload["target_sha256"],
        "authorizes_server_collection": False,
        "production_execution_qualified": False,
    }
    return base.atomic(
        lambda: store.public(save(db, owner, JOB, identifier, 0, payload, actor, user, "job.create")), db
    )


def resolve(db, owner, identifier):
    jobs = chain(db, owner, JOB, identifier)
    job = jobs[-1]
    targets = chain(db, owner, TARGET, job.payload["target_id"])
    revision = job.payload["target_revision"]
    if not 1 <= revision <= len(targets):
        raise HTTPException(409, "OCI job target history is incomplete")
    target = targets[revision - 1]
    if (
        target.payload["state"] != "AUTHORIZED"
        or target.payload_sha256 != job.payload["target_record_sha256"]
        or target.payload["target_sha256"] != job.payload["target_sha256"]
    ):
        raise HTTPException(409, "OCI job target commitment mismatch")
    return jobs, target, targets[-1]


def transition(db, owner, identifier, body, actor, user, *, cancel=False):
    base.boundary()
    initial = chain(db, owner, JOB, identifier)[-1]
    lock_target(db, owner, initial.payload["target_id"])
    jobs, target, current = resolve(db, owner, identifier)
    job = jobs[-1]
    if job.revision != body.expected_revision:
        raise HTTPException(409, "OCI job revision changed")
    if cancel:
        if job.payload["state"] not in {"READY", "AWAITING_EVIDENCE"}:
            raise HTTPException(409, "OCI job is terminal")
        payload = {**job.payload, "state": "CANCELLED"}
    else:
        spec = admitted(db, owner, current, target.revision)
        if job.payload["state"] != "READY":
            raise HTTPException(409, "OCI job is not ready")
        # A planned truth workflow cannot bypass its separate review at handoff.
        truth = store.latest(db, owner, "oci_truth_plan", identifier, required=False)
        if truth is not None:
            from api.assurance.oci_truth import reviewer

            if truth.payload.get("state") != "APPROVED":
                raise HTTPException(409, "Planned OCI truth needs separate approval before handoff")
            reviewer(db, owner, truth.created_by)
        binding = OciCaptureBinding(
            job_id=identifier,
            target_id=target.subject_id,
            target_revision=target.revision,
            target_record_sha256=target.payload_sha256,
            target_sha256=digest(spec),
            nonce=secrets.token_hex(32),
            issued_at=utcnow(),
            expires_at=spec.expires_at,
        )
        payload = {
            **job.payload,
            "state": "AWAITING_EVIDENCE",
            "capture_binding": binding.model_dump(mode="json"),
            "binding_sha256": digest(binding),
        }
    return base.atomic(
        lambda: store.public(
            save(
                db,
                owner,
                JOB,
                identifier,
                job.revision,
                payload,
                actor,
                user,
                "job.cancel" if cancel else "job.handoff",
            )
        ),
        db,
    )


def check_capture(job, target, capture):
    binding = capture.binding
    if (
        binding.job_id != job.subject_id
        or binding.target_id != target.subject_id
        or binding.target_revision != target.revision
        or binding.target_record_sha256 != target.payload_sha256
        or binding.target_sha256 != target.payload["target_sha256"]
        or digest(binding) != job.payload.get("binding_sha256")
        or binding.model_dump(mode="json") != job.payload.get("capture_binding")
        or digest(capture.evidence.target) != target.payload["target_sha256"]
    ):
        raise HTTPException(409, "OCI return does not match the exact retained handoff")


def intake(db, owner, identifier, body, actor, user):
    base.boundary()
    initial = chain(db, owner, JOB, identifier)[-1]
    lock_target(db, owner, initial.payload["target_id"])
    jobs, target, current = resolve(db, owner, identifier)
    job = jobs[-1]
    admitted(db, owner, current, target.revision)
    if job.revision != body.expected_revision or job.payload["state"] != "AWAITING_EVIDENCE":
        raise HTTPException(409, "OCI job is not awaiting this evidence revision")
    capture = OciJobReturn.model_validate(body.capture.model_dump())
    check_capture(job, target, capture)
    evidence_sha = digest(capture.evidence)
    if evidence_sha != body.expected_evidence_sha256 or capture.evidence.finished_at > utcnow():
        raise HTTPException(409, "OCI evidence commitment or server-relative timestamp mismatch")
    consumed_id = store.subject("oci-consumed/v1", store.scope_key(owner), evidence_sha)

    def operation():
        consumption = save(
            db,
            owner,
            CONSUMED,
            consumed_id,
            0,
            {"job_id": identifier, "evidence_sha256": evidence_sha},
            actor,
            user,
            "evidence.consume",
        )
        record = save(
            db,
            owner,
            EVIDENCE,
            identifier,
            0,
            {
                "capture": capture.model_dump(mode="json"),
                "capture_sha256": digest(capture),
                "evidence_sha256": evidence_sha,
                "binding_sha256": digest(capture.binding),
                "consumed_id": consumed_id,
                "consumed_record_sha256": consumption.payload_sha256,
            },
            actor,
            user,
            "evidence.intake",
        )
        payload = {
            **job.payload,
            "state": capture.evidence.status,
            "evidence_record_sha256": record.payload_sha256,
            "evidence_sha256": evidence_sha,
            "capture_sha256": digest(capture),
        }
        return store.public(save(db, owner, JOB, identifier, job.revision, payload, actor, user, "job.complete"))

    return base.atomic(operation, db)


def retained(db, owner, identifier):
    base.boundary()
    jobs, target, _ = resolve(db, owner, identifier)
    job = jobs[-1]
    if job.payload["state"] not in TERMINAL:
        raise HTTPException(409, "OCI job has no committed evidence")
    records = chain(db, owner, EVIDENCE, identifier)
    if len(records) != 1 or records[0].payload_sha256 != job.payload["evidence_record_sha256"]:
        raise HTTPException(409, "OCI evidence history commitment mismatch")
    record = records[0]
    try:
        capture = OciJobReturn.model_validate(record.payload["capture"])
    except (ValueError, TypeError, KeyError):
        raise HTTPException(409, "OCI retained evidence structure changed") from None
    check_capture(job, target, capture)
    consumption = chain(db, owner, CONSUMED, record.payload["consumed_id"])
    if (
        len(consumption) != 1
        or consumption[0].payload_sha256 != record.payload["consumed_record_sha256"]
        or consumption[0].payload != {"job_id": identifier, "evidence_sha256": digest(capture.evidence)}
        or digest(capture) != record.payload["capture_sha256"]
        or digest(capture) != job.payload["capture_sha256"]
        or digest(capture.evidence) != record.payload["evidence_sha256"]
        or digest(capture.evidence) != job.payload["evidence_sha256"]
        or digest(capture.binding) != record.payload["binding_sha256"]
        or capture.evidence.status != job.payload["state"]
    ):
        raise HTTPException(409, "OCI retained source/consumption commitment changed")
    return capture


def projections(db, owner, identifier):
    capture = retained(db, owner, identifier)
    return materialize_oci(capture.evidence, digest(capture.evidence)).model_dump(mode="json")


def listing(db, owner, kind, cursor):
    base.boundary()
    keys = (
        store.rows(db, AssuranceRevision, owner)
        .filter(AssuranceRevision.kind == kind, AssuranceRevision.subject_id > cursor)
        .with_entities(AssuranceRevision.subject_id)
        .distinct()
        .order_by(AssuranceRevision.subject_id)
        .limit(51)
        .all()
    )
    selected = [row[0] for row in keys[:50]]
    return {
        "items": [store.public(chain(db, owner, kind, key)[-1]) for key in selected],
        "has_more": len(keys) > 50,
        "next_cursor": selected[-1] if len(keys) > 50 else None,
        "whole_estate_coverage_verified": False,
    }
