"""Deployment-specific recovery objectives, retained measurements and review gate."""
from datetime import datetime, timedelta
from fastapi import HTTPException
from db.models.base import utcnow
from db.models.assurance import AssuranceRevision
from shared_models.assurance import REDIS_SCENARIOS, REDIS_ROLES
from shared_models.qualified_export import bounded_json
from db.repositories.execution_control import aware
from . import store


def objectives(db, owner, identifier, body, actor):
    if len(set(body.roles)) != len(body.roles):
        raise HTTPException(422, "Duplicate roles cannot inflate qualification coverage")
    return store.append(db, owner, "redis_objectives", identifier, body.expected_revision,
                        body.model_dump(mode="json", exclude={"expected_revision"}), actor)


def measure(db, owner, identifier, body, actor):
    profile = store.latest(db, owner, "redis_objectives", identifier)
    p = profile.payload
    if body.deployment_id != p["deployment_id"] or body.topology_sha256 != p["topology_sha256"] or body.role not in p["roles"]:
        raise HTTPException(409, "Measurement does not match the approved deployment/topology/consumer scope")
    if body.measured_until > utcnow():
        raise HTTPException(422, "Future measurements are not retained evidence")
    raw = store.blob(db, owner, body.evidence_blob_id)
    try:
        evidence = bounded_json(raw.data)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise HTTPException(422, "Measurement evidence must be bounded JSON, not an unverifiable PASS label") from None
    if not isinstance(evidence, dict) or evidence.get("measurement") != body.model_dump(mode="json", exclude={"evidence_blob_id"}):
        raise HTTPException(409, "Retained measurement evidence and submitted journal/timestamps disagree")
    recovered = set(body.recovered_event_ids)
    lost = [a for a in body.acknowledged if a.event_id not in recovered]
    recovery_seconds = (body.recovered_at - body.fault_at).total_seconds()
    duration = (body.measured_until - body.recovered_at).total_seconds()
    throughput = body.recovery_operations / duration
    passed = (recovery_seconds <= p["max_recovery_seconds"] and len(lost) <= p["max_acknowledged_event_loss"]
              and throughput >= p["minimum_recovery_operations_per_second"] and duration >= p["minimum_measurement_seconds"])
    subject_id = store.subject(identifier, profile.payload_sha256, body.scenario, body.role, body.evidence_blob_id)
    return store.append(db, owner, "redis_measurement", subject_id, 0,
        {"profile_id": identifier, "objectives_sha256": profile.payload_sha256, "measurement": body.model_dump(mode="json"),
         "evidence_sha256": raw.sha256, "recovery_seconds": recovery_seconds,
         "acknowledged_events": len(body.acknowledged), "acknowledged_before_fault": sum(a.acknowledged_at < body.fault_at for a in body.acknowledged),
         "event_loss_applicability": "NOT_APPLICABLE_HEALTH_PING" if body.role == "health" else "MEASURED_ACKNOWLEDGED_STATE",
         "acknowledged_event_loss": len(lost), "lost_event_ids": [a.event_id for a in lost],
         "oldest_lost_ack_before_fault_seconds": max([max(0, (body.fault_at - a.acknowledged_at).total_seconds()) for a in lost], default=0),
         "measurement_seconds": duration, "recovery_operations_per_second": throughput,
         "meets_reported_objectives": passed, "state": "PENDING_INDEPENDENT_HUMAN_REVIEW",
         "measurement_basis": "RETAINED_OPERATOR_DEPLOYMENT_EVIDENCE_NOT_OBSERVED_BY_API",
         "snapshot_after_failover_is_prior_ack_survival_proof": False}, actor)


def review(db, owner, identifier, body, actor):
    measurement = store.latest(db, owner, "redis_measurement", identifier)
    if measurement.created_by == actor or measurement.payload["state"] != "PENDING_INDEPENDENT_HUMAN_REVIEW":
        raise HTTPException(409, "Recovery evidence needs a different human reviewer, once")
    value = measurement.payload
    profile = store.latest(db, owner, "redis_objectives", value["profile_id"])
    if profile.payload_sha256 != value["objectives_sha256"]:
        raise HTTPException(409, "Objectives/topology changed; remeasure the current deployment")
    return store.append(db, owner, "redis_measurement", identifier, body.expected_revision,
        {**value, "state": "REVIEWED", "submitted_by": measurement.created_by,
         "reviewed_by": actor, "review_evidence_ref": body.evidence_ref, "review_reason": body.reason}, actor)


def report(db, owner, identifier):
    profile = store.latest(db, owner, "redis_objectives", identifier)
    history = store.rows(db, AssuranceRevision, owner).filter_by(kind="redis_measurement").filter(
        AssuranceRevision.payload["profile_id"].as_string() == identifier,
        AssuranceRevision.payload["objectives_sha256"].as_string() == profile.payload_sha256).limit(5001).all()
    if len(history) > 5000:
        raise HTTPException(409, "Measurement history exceeds bound; create a new approved qualification campaign")
    newest = {}
    for row in history:
        if row.revision > getattr(newest.get(row.subject_id), "revision", 0):
            newest[row.subject_id] = row
    # A later failure/pending run for a scenario must not be hidden by choosing
    # an older PASS. Current objective revision is part of every receipt.
    cells, ambiguous = {}, set()
    for row in newest.values():
        m = row.payload["measurement"]
        cell = (m["role"], m["scenario"])
        previous = cells.get(cell)
        stamp = aware(datetime.fromisoformat(m["measured_until"]))
        previous_stamp = aware(datetime.fromisoformat(previous.payload["measurement"]["measured_until"])) if previous else None
        if previous_stamp is not None and stamp == previous_stamp and row.subject_id != previous.subject_id:
            ambiguous.add(cell)
        if previous_stamp is None or stamp > previous_stamp:
            cells[cell] = row
            ambiguous.discard(cell)
    matrix = []
    for role in profile.payload["roles"]:
        for scenario in REDIS_SCENARIOS:
            row = cells.get((role, scenario))
            matrix.append({"role": role, "scenario": scenario,
                "measurement_id": row.subject_id if row else None,
                "accepted": bool((role, scenario) not in ambiguous and row and row.payload["state"] == "REVIEWED" and row.payload["meets_reported_objectives"]
                    and aware(datetime.fromisoformat(row.payload["measurement"]["measured_until"])) + timedelta(seconds=profile.payload["max_measurement_age_seconds"]) > utcnow()),
                "state": "AMBIGUOUS_LATEST_MEASUREMENT_ORDER" if (role, scenario) in ambiguous else row.payload["state"] if row else "NOT_MEASURED"})
    accepted = bool(matrix) and all(c["accepted"] for c in matrix)
    return {"objectives": store.public(profile), "matrix": matrix,
            "unqualified_roles": sorted(set(REDIS_ROLES) - set(profile.payload["roles"])),
            "deployment_evidence_meets_objectives": accepted,
            "whole_infrastructure_qualified": accepted and set(profile.payload["roles"]) == set(REDIS_ROLES),
            "qualification_basis": "DEPLOYMENT_SPECIFIC_OPERATOR_MEASUREMENTS_AND_SEPARATE_HUMAN_REVIEW",
            "local_sentinel_promotion_is_deployment_qualification": False}
