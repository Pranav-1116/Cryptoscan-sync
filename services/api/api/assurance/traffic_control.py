"""Source-bound read-only preflight and separate-human ISOLATED validation review."""

import secrets
import uuid
from datetime import timedelta
from fastapi import HTTPException
from db.models.base import utcnow
from db.repositories.execution_control import aware
from shared_models.host_collection import digest
from shared_models.linux_traffic_control import (
    PreflightSpec,
    TrafficPreflight,
    ValidationChange,
    DrillAuthorization,
    preflight_report,
)
from api.assurance import collection as base, store, resource_monitoring as resources
from api.assurance.oci_truth import reviewer

REQUEST = "traffic_preflight_request"
PREFLIGHT = "linux_traffic_preflight"
CHANGE = "traffic_isolated_validation"


def current_source(db, owner, identifier):
    proposal = resources.proposal(db, owner, identifier)
    _, capture = resources.retained(db, owner, proposal["payload"]["proposal"]["capture_id"])
    resources.lock(db, owner, capture.authorization.plan_id)
    resources.approved(db, owner, capture.authorization.plan_id)
    # Revalidate immutable source/report closure after acquiring the mutable approval lock.
    proposal = resources.proposal(db, owner, identifier)
    if not timedelta(0) <= utcnow() - capture.finished_at <= timedelta(minutes=5):
        raise HTTPException(409, "Preflight/validation needs a current sample no older than five minutes")
    return proposal, capture


def request(db, owner, identifier, body, actor, user):
    base.boundary()

    def operation():
        proposal, capture = current_source(db, owner, identifier)
        if proposal["payload_sha256"] != body.expected_proposal_record_sha256:
            raise HTTPException(409, "Proposal record commitment mismatch")
        selected = proposal["payload"]["proposal"]
        reading = next(n for n in capture.network if n.interface == selected["interface"])
        key = str(uuid.uuid4())
        now = utcnow()
        spec = PreflightSpec(
            request_id=key,
            proposal_id=identifier,
            proposal_record_sha256=proposal["payload_sha256"],
            source_capture_sha256=digest(capture),
            nonce=secrets.token_hex(32),
            system_id=capture.authorization.scope.system_id,
            host_label=capture.authorization.scope.host_label,
            interface=selected["interface"],
            expected_ifindex=reading.second_ifindex,
            expected_boot_id=capture.boot_id,
            expected_network_namespace_inode=capture.network_namespace_inode,
            expected_mount_namespace_inode=capture.mount_namespace_inode,
            egress_limit_mbps=selected["egress_limit_mbps"],
            management_ips=body.management_ips,
            issued_at=now,
            expires_at=min(
                now + timedelta(minutes=5),
                capture.finished_at + timedelta(minutes=5),
                capture.authorization.scope.expires_at,
            ),
        )
        return store.public(
            base.save(
                db,
                owner,
                REQUEST,
                key,
                0,
                {"spec": spec.model_dump(mode="json"), "spec_sha256": digest(spec)},
                actor,
                user,
                "traffic.preflight.request",
            )
        )

    return base.atomic(operation, db)


def request_source(db, owner, identifier, current=False):
    rows = base.chain(db, owner, REQUEST, identifier)
    if len(rows) != 1:
        raise HTTPException(409, "Preflight request is write-once")
    row = rows[0]
    spec = PreflightSpec.model_validate(row.payload["spec"])
    proposal, capture = (
        current_source(db, owner, spec.proposal_id)
        if current
        else (resources.proposal(db, owner, spec.proposal_id), None)
    )
    if capture is None:
        _, capture = resources.retained(db, owner, proposal["payload"]["proposal"]["capture_id"])
    selected = proposal["payload"]["proposal"]
    reading = next(n for n in capture.network if n.interface == selected["interface"])
    if (
        row.subject_id != spec.request_id
        or digest(spec) != row.payload["spec_sha256"]
        or spec.proposal_record_sha256 != proposal["payload_sha256"]
        or spec.source_capture_sha256 != digest(capture)
        or spec.system_id != capture.authorization.scope.system_id
        or spec.host_label != capture.authorization.scope.host_label
        or spec.interface != selected["interface"]
        or spec.egress_limit_mbps != selected["egress_limit_mbps"]
        or spec.expected_ifindex != reading.second_ifindex
        or spec.expected_boot_id != capture.boot_id
        or spec.expected_network_namespace_inode != capture.network_namespace_inode
        or spec.expected_mount_namespace_inode != capture.mount_namespace_inode
    ):
        raise HTTPException(409, "Preflight source closure changed")
    if current and not spec.issued_at <= utcnow() < spec.expires_at:
        raise HTTPException(409, "Preflight/validation request expired")
    return row, spec


def intake(db, owner, identifier, body, actor, user):
    base.boundary()

    def operation():
        row, spec = request_source(db, owner, identifier, True)
        capture = body.capture
        if (
            capture.spec != spec
            or digest(capture) != body.expected_preflight_sha256
            or capture.started_at < aware(row.created_at)
            or capture.finished_at > utcnow()
        ):
            raise HTTPException(409, "Preflight/source/window commitment mismatch")
        return store.public(
            base.save(
                db,
                owner,
                PREFLIGHT,
                identifier,
                0,
                {"capture": capture.model_dump(mode="json"), "report": preflight_report(capture)},
                actor,
                user,
                "traffic.preflight.intake",
            )
        )

    return base.atomic(operation, db)


def retained(db, owner, identifier, current=False):
    base.boundary()
    _, spec = request_source(db, owner, identifier, current)
    rows = base.chain(db, owner, PREFLIGHT, identifier)
    if len(rows) != 1:
        raise HTTPException(409, "Preflight is write-once")
    row = rows[0]
    capture = TrafficPreflight.model_validate(row.payload["capture"])
    if capture.spec != spec or row.payload["report"] != preflight_report(capture):
        raise HTTPException(409, "Preflight/report commitment changed")
    return row, capture


def propose(db, owner, body, actor, user):
    base.boundary()

    def operation():
        row, capture = retained(db, owner, body.preflight_id, True)
        reviewer(db, owner, body.reviewer_user_id)
        if actor == body.reviewer_user_id:
            raise HTTPException(409, "A different human reviewer is required")
        if (
            row.payload_sha256 != body.expected_preflight_record_sha256
            or preflight_report(capture)["isolated_validation_blockers"]
        ):
            raise HTTPException(409, "Exact complete preflight required for isolated validation")
        return store.public(
            base.save(
                db,
                owner,
                CHANGE,
                str(uuid.uuid4()),
                0,
                {
                    "state": "PROPOSED_ISOLATED_VALIDATION",
                    "change": body.model_dump(mode="json"),
                    "real_host_change_authorized": False,
                },
                actor,
                user,
                "traffic.validation.propose",
            )
        )

    return base.atomic(operation, db)


def change_source(db, owner, identifier, current=False):
    rows = base.chain(db, owner, CHANGE, identifier)
    first = rows[0]
    body = ValidationChange.model_validate(first.payload["change"])
    source, capture = retained(db, owner, body.preflight_id, current)
    if (
        source.payload_sha256 != body.expected_preflight_record_sha256
        or preflight_report(capture)["isolated_validation_blockers"]
    ):
        raise HTTPException(409, "Isolated validation source changed")
    if len(rows) > 2 or (
        len(rows) == 2
        and (
            rows[1].payload["change"] != first.payload["change"]
            or rows[1].created_by != body.reviewer_user_id
            or rows[1].created_by == first.created_by
            or rows[1].payload["state"] != "APPROVED_ISOLATED_VALIDATION"
        )
    ):
        raise HTTPException(409, "Separate-human validation review closure changed")
    return rows, body, capture


def approve(db, owner, identifier, body, actor, user):
    base.boundary()

    def operation():
        rows, change, _ = change_source(db, owner, identifier, True)
        first = rows[0]
        reviewer(db, owner, actor)
        if len(rows) != 1 or actor != change.reviewer_user_id or actor == first.created_by:
            raise HTTPException(409, "Only assigned distinct human can approve an unreviewed validation")
        return store.public(
            base.save(
                db,
                owner,
                CHANGE,
                identifier,
                1,
                {**first.payload, "state": "APPROVED_ISOLATED_VALIDATION", "decision": body.model_dump(mode="json")},
                actor,
                user,
                "traffic.validation.approve",
            )
        )

    return base.atomic(operation, db)


def authorization(db, owner, identifier):
    base.boundary()
    rows, change, capture = change_source(db, owner, identifier, True)
    if len(rows) != 2:
        raise HTTPException(409, "Separate-human approval required")
    reviewer(db, owner, change.reviewer_user_id)
    row = rows[-1]
    packet = DrillAuthorization(
        change_id=identifier,
        reviewed_record_sha256=row.payload_sha256,
        preflight_sha256=digest(capture),
        proposal_id=capture.spec.proposal_id,
        egress_limit_mbps=capture.spec.egress_limit_mbps,
        duration_seconds=change.duration_seconds,
        expected_parent_boot_id=capture.boot_id,
        expected_parent_network_namespace_inode=capture.network_namespace_inode,
        expected_parent_mount_namespace_inode=capture.mount_namespace_inode,
        issued_at=max(aware(row.created_at), capture.spec.issued_at),
        expires_at=capture.spec.expires_at,
    )
    if (packet.expires_at - utcnow()).total_seconds() < packet.duration_seconds + 10:
        raise HTTPException(409, "Insufficient remaining drill window; collect a fresh sample")
    return packet
