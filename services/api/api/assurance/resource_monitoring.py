"""Approved offline resource evidence and traffic-change drafts, never enforcement."""

import secrets
import uuid
from datetime import timedelta
from fastapi import HTTPException
from db.models.assurance import AssuranceRevision
from db.models.base import utcnow
from db.models.system import System
from db.repositories.execution_control import aware
from shared_models.host_collection import digest
from shared_models.resource_monitoring import ResourceAuthorization, ResourceCapture, ResourceScope, resource_report
from api.assurance import collection as base, relationships, store

PLAN = "resource_monitor_plan"
CAPTURE = "resource_monitor_capture"
PROPOSAL = "resource_traffic_proposal"


def lock(db, owner, identifier):
    row = (
        store.rows(db, AssuranceRevision, owner)
        .filter_by(kind=PLAN, subject_id=identifier, revision=1)
        .with_for_update()
        .first()
    )
    if row is None:
        raise HTTPException(404, "Resource scope not found")
    store.verify(row)


def active_system(db, owner, scope):
    system = db.query(System).filter_by(id=scope.system_id, tenant_id=owner).with_for_update().one_or_none()
    if system is None:
        raise HTTPException(404, "Resource system not found")
    if not relationships.active(system) or system.environment != scope.environment:
        raise HTTPException(409, "Resource system/environment is not current")


def create_plan(db, owner, scope, actor, user):
    base.boundary()
    active_system(db, owner, scope)
    if not utcnow() < scope.expires_at <= utcnow() + timedelta(hours=1):
        raise HTTPException(422, "Resource scope must expire within an hour")
    identifier = str(uuid.uuid4())
    return base.atomic(
        lambda: store.public(
            base.save(
                db,
                owner,
                PLAN,
                identifier,
                0,
                {
                    "state": "DRAFT",
                    "scope": scope.model_dump(mode="json"),
                    "scope_sha256": digest(scope),
                    "configuration_change_authorized": False,
                },
                actor,
                user,
                "resource.plan.create",
            )
        ),
        db,
    )


def decision(db, owner, identifier, body, actor, user, revoke=False):
    base.boundary()

    def operation():
        lock(db, owner, identifier)
        row = base.chain(db, owner, PLAN, identifier)[-1]
        if row.revision != body.expected_revision:
            raise HTTPException(409, "Resource scope revision changed")
        scope = ResourceScope.model_validate(row.payload["scope"])
        if revoke:
            if row.payload["state"] != "APPROVED":
                raise HTTPException(409, "Only approved scope can be revoked")
            state = "REVOKED"
        else:
            if row.payload["state"] != "DRAFT" or not scope.not_before <= utcnow() < scope.expires_at:
                raise HTTPException(409, "Scope must be a current draft")
            active_system(db, owner, scope)
            state = "APPROVED"
        return store.public(
            base.save(
                db,
                owner,
                PLAN,
                identifier,
                row.revision,
                {
                    **row.payload,
                    "state": state,
                    "nonce": row.payload.get("nonce") or secrets.token_hex(32),
                    "decision_evidence_ref": body.evidence_ref,
                    "decision_reason": body.reason,
                },
                actor,
                user,
                "resource.plan.revoke" if revoke else "resource.plan.approve",
            )
        )

    return base.atomic(operation, db)


def authorization(row):
    return ResourceAuthorization(
        plan_id=row.subject_id,
        plan_record_sha256=row.payload_sha256,
        scope_sha256=row.payload["scope_sha256"],
        nonce=row.payload["nonce"],
        scope=row.payload["scope"],
    )


def approved(db, owner, identifier):
    rows = base.chain(db, owner, PLAN, identifier)
    row = rows[-1]
    if row.payload["state"] != "APPROVED":
        raise HTTPException(409, "Resource scope is not currently approved")
    auth = authorization(row)
    if not auth.scope.not_before <= utcnow() < auth.scope.expires_at:
        raise HTTPException(409, "Resource scope is outside approved window")
    active_system(db, owner, auth.scope)
    return auth


def intake(db, owner, body, actor, user):
    base.boundary()

    def operation():
        capture = body.capture
        lock(db, owner, capture.authorization.plan_id)
        auth = approved(db, owner, capture.authorization.plan_id)
        if capture.authorization != auth or digest(capture) != body.expected_capture_sha256:
            raise HTTPException(409, "Resource source/approval commitment mismatch")
        approval = base.chain(db, owner, PLAN, auth.plan_id)[1]
        if capture.started_at < aware(approval.created_at):
            raise HTTPException(409, "Capture predates scope approval")
        if capture.finished_at > utcnow():
            raise HTTPException(422, "Future measurements are not retained evidence")
        value = {"capture": capture.model_dump(mode="json"), "report": resource_report(capture)}
        if len(store.encoded(value)) > 131072:
            raise HTTPException(413, "Resource capture exceeds 128 KiB budget")
        identifier = store.subject("resource-capture/v1", store.scope_key(owner), auth.plan_id, capture.capture_id)
        return store.public(base.save(db, owner, CAPTURE, identifier, 0, value, actor, user, "resource.capture.intake"))

    return base.atomic(operation, db)


def retained(db, owner, identifier):
    base.boundary()
    rows = base.chain(db, owner, CAPTURE, identifier)
    if len(rows) != 1:
        raise HTTPException(409, "Resource capture must be write-once")
    row = rows[0]
    try:
        capture = ResourceCapture.model_validate(row.payload["capture"])
        plans = base.chain(db, owner, PLAN, capture.authorization.plan_id)
        if (
            len(plans) < 2
            or plans[1].payload["state"] != "APPROVED"
            or authorization(plans[1]) != capture.authorization
        ):
            raise ValueError("Approval closure changed")
        key = store.subject(
            "resource-capture/v1", store.scope_key(owner), capture.authorization.plan_id, capture.capture_id
        )
        if key != identifier or store.digest(row.payload["report"]) != store.digest(resource_report(capture)):
            raise ValueError("Report changed")
    except (ValueError, TypeError, KeyError):
        raise HTTPException(409, "Resource capture/source/report commitment changed") from None
    return row, capture


def listing(db, owner, kind, cursor, limit=10):
    base.boundary()
    rows = (
        store.rows(db, AssuranceRevision, owner)
        .filter(AssuranceRevision.kind == kind, AssuranceRevision.revision == 1, AssuranceRevision.subject_id > cursor)
        .order_by(AssuranceRevision.subject_id)
        .limit(limit + 1)
        .all()
    )
    values = []
    for initial in rows[:limit]:
        if kind == PLAN:
            row = base.chain(db, owner, PLAN, initial.subject_id)[-1]
            values.append(store.public(row))
        else:
            row, capture = retained(db, owner, initial.subject_id)
            values.append(
                {
                    "capture_id": row.subject_id,
                    "system_id": capture.authorization.scope.system_id,
                    "host_label": capture.authorization.scope.host_label,
                    "finished_at": capture.finished_at.isoformat(),
                    "source_sha256": digest(capture),
                    "provenance": "IMPORTED",
                }
            )
    return {"items": values, "next_cursor": rows[limit - 1].subject_id if len(rows) > limit else None}


def proposal_payload(body, row, capture, reading):
    return {
        "proposal": body.model_dump(mode="json"),
        "source_record_sha256": row.payload_sha256,
        "source_capture_sha256": digest(capture),
        "host_label": capture.authorization.scope.host_label,
        "state": "DRAFT_REQUIRES_DEVICE_ADAPTER_AND_CHANGE_APPROVAL",
        "applied": False,
        "measured_tx_mbps": reading["tx_mbps"],
        "sample_exceeds_proposed_limit": reading["tx_mbps"] > body.egress_limit_mbps,
        "physical_link_capacity_verified": False,
        "management_access_safety_verified": False,
        "rollback_verified": False,
        "enforcement_supported": False,
    }


def propose(db, owner, body, actor, user):
    base.boundary()

    def operation():
        row, capture = retained(db, owner, body.capture_id)
        lock(db, owner, capture.authorization.plan_id)
        approved(db, owner, capture.authorization.plan_id)
        if not timedelta(0) <= utcnow() - capture.finished_at <= timedelta(minutes=5):
            raise HTTPException(409, "Traffic proposal needs a capture no older than five minutes")
        reading = next((n for n in row.payload["report"]["network"] if n["interface"] == body.interface), None)
        if not reading or reading["status"] != "MEASURED":
            raise HTTPException(409, "Traffic proposal needs measured counters for an approved interface")
        value = proposal_payload(body, row, capture, reading)
        return store.public(
            base.save(db, owner, PROPOSAL, str(uuid.uuid4()), 0, value, actor, user, "resource.traffic.propose")
        )

    return base.atomic(operation, db)


def proposal(db, owner, identifier):
    from shared_models.resource_monitoring import TrafficProposal

    base.boundary()
    rows = base.chain(db, owner, PROPOSAL, identifier)
    if len(rows) != 1:
        raise HTTPException(409, "Traffic proposal must be write-once")
    row = rows[0]
    try:
        body = TrafficProposal.model_validate(row.payload["proposal"])
        source, capture = retained(db, owner, body.capture_id)
        reading = next(n for n in source.payload["report"]["network"] if n["interface"] == body.interface)
        if reading["status"] != "MEASURED" or store.digest(row.payload) != store.digest(
            proposal_payload(body, source, capture, reading)
        ):
            raise ValueError("Proposal/source changed")
    except (ValueError, TypeError, KeyError, StopIteration):
        raise HTTPException(409, "Traffic proposal/source commitment changed") from None
    return store.public(row)
