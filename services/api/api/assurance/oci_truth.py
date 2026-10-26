"""Separate-human pre-capture truth review on existing OCI jobs and revision store."""

from fastapi import HTTPException
from db.models.user import User
from db.models.tenant import TenantMembership
from db.repositories.execution_control import aware
from api.security.rbac import normalize_roles, PERMISSION_MATRIX
from shared_models.host_collection import digest
from shared_models.oci_truth import OciTruthProposal, compare_image_truth
from api.assurance import collection as base, oci_collection as jobs, store

KIND = "oci_truth_plan"


def reviewer(db, owner, identifier):
    user = db.query(User).filter_by(id=identifier, is_active=True, deleted_at=None).with_for_update().one_or_none()
    roles = set(normalize_roles(user.role_list)) if user else set()
    member = bool(
        user
        and (
            "superadmin" in roles
            or owner is not None
            and db.query(TenantMembership).filter_by(tenant_id=owner, username=user.username).with_for_update().first()
        )
    )
    if not member or not roles & PERMISSION_MATRIX["assurance.review"]:
        raise HTTPException(404, "Current selected-estate truth reviewer not found")
    return user


def ready(db, owner, identifier):
    initial = jobs.chain(db, owner, jobs.JOB, identifier)[-1]
    jobs.lock_target(db, owner, initial.payload["target_id"])
    history, target, current = jobs.resolve(db, owner, identifier)
    job = history[-1]
    spec = jobs.admitted(db, owner, current, target.revision)
    if job.revision != 1 or job.payload["state"] != "READY":
        raise HTTPException(409, "Truth must be committed and reviewed before handoff")
    return job, target, spec


def propose(db, owner, identifier, body, actor, user):
    base.boundary()
    job, target, spec = ready(db, owner, identifier)
    if (
        body.expected_job_revision != job.revision
        or body.target_sha256 != digest(spec)
        or body.target_record_sha256 != target.payload_sha256
        or [x.source for x in body.expected] != spec.inputs
    ):
        raise HTTPException(409, "Truth must account for every exact ordered authorized input")
    reviewer(db, owner, body.reviewer_user_id)
    if body.reviewer_user_id == actor:
        raise HTTPException(409, "Truth proposer cannot be its assigned reviewer")
    payload = {
        "state": "PROPOSED",
        "proposal": body.model_dump(mode="json"),
        "proposal_sha256": digest(body),
        "producer_authenticity_verified": False,
    }
    return base.atomic(
        lambda: store.public(jobs.save(db, owner, KIND, identifier, 0, payload, actor, user, "truth.propose")), db
    )


def approve(db, owner, identifier, body, actor, user):
    base.boundary()
    ready(db, owner, identifier)
    history = jobs.chain(db, owner, KIND, identifier)
    first = history[0]
    plan = OciTruthProposal.model_validate(first.payload["proposal"])
    reviewer(db, owner, actor)
    if (
        len(history) != 1
        or first.payload["state"] != "PROPOSED"
        or body.expected_revision != 1
        or actor != plan.reviewer_user_id
        or actor == first.created_by
    ):
        raise HTTPException(409, "Only the separately assigned human may approve this write-once truth")
    payload = {
        **first.payload,
        "state": "APPROVED",
        "source_revision_sha256": first.payload_sha256,
        "proposed_by": first.created_by,
        "approved_by": actor,
        "decision_reference": body.evidence_ref,
        "decision_reason": body.reason,
    }
    return base.atomic(
        lambda: store.public(jobs.save(db, owner, KIND, identifier, 1, payload, actor, user, "truth.approve")), db
    )


def history(db, owner, identifier):
    base.boundary()
    jobs.resolve(db, owner, identifier)
    return {"history": [store.public(r) for r in jobs.chain(db, owner, KIND, identifier)]}


def reconciliation(db, owner, identifier):
    base.boundary()
    job_history, target, _ = jobs.resolve(db, owner, identifier)
    job = job_history[-1]
    blocked = {
        "schema_version": "cryptoscan.oci-reviewed-truth/v1",
        "job_id": identifier,
        "agreed_metadata_matched": False,
        "identity_separation_verified": False,
        "customer_independent_truth_verified": False,
        "organizational_independence_verified": False,
        "whole_image_software_complete": False,
        "whole_estate_complete": False,
        "source_authenticity_verified": False,
        "bank_production_accepted": False,
        "production_execution_qualified": False,
        "runtime_use": "UNKNOWN",
    }
    if store.latest(db, owner, KIND, identifier, required=False) is None:
        return {**blocked, "verdict": "BLOCKED_NO_PRECOMMITTED_TRUTH"}
    rows = jobs.chain(db, owner, KIND, identifier)
    if len(rows) != 2 or rows[-1].payload["state"] != "APPROVED":
        return {**blocked, "verdict": "BLOCKED_TRUTH_NOT_APPROVED"}
    first, approved = rows
    try:
        plan = OciTruthProposal.model_validate(first.payload["proposal"])
        if (
            approved.payload["proposal"] != first.payload["proposal"]
            or approved.payload["source_revision_sha256"] != first.payload_sha256
            or digest(plan) != first.payload["proposal_sha256"]
            or digest(plan) != approved.payload["proposal_sha256"]
            or first.created_by != approved.payload["proposed_by"]
            or approved.created_by != approved.payload["approved_by"]
            or approved.created_by != plan.reviewer_user_id
            or approved.created_by == first.created_by
            or plan.target_record_sha256 != target.payload_sha256
        ):
            raise ValueError("Changed truth approval")
    except (ValueError, TypeError, KeyError):
        raise HTTPException(409, "Truth proposal/approval commitment mismatch") from None
    try:
        reviewer(db, owner, approved.created_by)
    except HTTPException:
        return {**blocked, "verdict": "BLOCKED_REVIEWER_NO_LONGER_AUTHORIZED"}
    if job.payload["state"] not in jobs.TERMINAL:
        return {**blocked, "verdict": "BLOCKED_NO_ORIGINAL_RETURN"}
    capture = jobs.retained(db, owner, identifier)
    evidence_rows = jobs.chain(db, owner, jobs.EVIDENCE, identifier)
    if approved.created_by == evidence_rows[0].created_by or aware(approved.created_at) > capture.binding.issued_at:
        return {**blocked, "verdict": "BLOCKED_REVIEW_IDENTITY_OR_PRECOMMIT_ORDER"}
    try:
        result = compare_image_truth(plan, capture.evidence)
    except (ValueError, TypeError, KeyError):
        raise HTTPException(409, "Truth/evidence denominator mismatch") from None
    return {
        **blocked,
        **result,
        "identity_separation_verified": True,
        "verdict": "MATCHED_SEPARATELY_REVIEWED_METADATA"
        if result["agreed_metadata_matched"]
        else "BLOCKED_EXPECTED_TRUTH_MISMATCH_OR_GAPS",
        "truth_record_sha256": approved.payload_sha256,
        "expected_truth_source_reference": plan.source_reference,
    }
