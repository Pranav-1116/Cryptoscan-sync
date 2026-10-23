"""Exact-estate independent reports, operational accountability and bounded pilots.

No provider procurement/execution, infrastructure certification, contractual SLA,
live collector authorization or whole-bank acceptance is created by these APIs.
"""

import base64
import hashlib
import json
from datetime import datetime, timedelta
import uuid
from fastapi import HTTPException
from db.models.base import utcnow
from db.models.user import User
from db.models.tenant import TenantMembership
from db.models.assurance import CollectionPhaseReceipt
from db.models.software_supply_chain import SoftwareArtifact, SoftwareDeployment, ReleaseSbomBinding
from db.models.scan import Scan
from db.models.system import System
from db.models.hardware_live import HardwareAsset
from db.models.vendor import Vendor
from db.repositories.execution_control import aware
from shared_models.software_identity import scope_key
from shared_models.launch_assurance import DUTIES
from . import store, remediation, coverage, relationships, adapters


def new_id():
    return str(uuid.uuid4())


def person(db, owner, identifier):
    from api.security.rbac import normalize_roles, PERMISSION_MATRIX

    user = db.query(User).filter_by(id=identifier, is_active=True, deleted_at=None).one_or_none()
    roles = set(normalize_roles(user.role_list)) if user else set()
    member = bool(
        user
        and (
            "superadmin" in roles
            or db.query(TenantMembership).filter_by(tenant_id=owner, username=user.username).first() is not None
        )
    )
    if not user or not member or not roles & PERMISSION_MATRIX["assurance.operate"]:
        raise HTTPException(404, "Active accountable selected-estate human not found")
    return user


def fresh(value):
    return aware(datetime.fromisoformat(value)) > utcnow()


def active_identity(db, model, owner, identifier):
    row = store.exact(db, model, owner, identifier)
    if not relationships.active(row):
        raise HTTPException(409, "Referenced identity/evidence is inactive or expired")
    return row


def engagement(db, owner, body, actor):
    artifact = active_identity(db, SoftwareArtifact, owner, body.artifact_id)
    if body.expires_at <= utcnow():
        raise HTTPException(422, "Engagement expiry must be in the future")
    try:
        key = base64.b64decode(body.public_key_base64, validate=True)
        if len(key) != 32:
            raise ValueError()
    except ValueError:
        raise HTTPException(422, "A strict-base64 32-byte Ed25519 assessor public key is required") from None
    blobs = {
        name: store.blob(db, owner, getattr(body, name)).sha256
        for name in ("independence_declaration_blob_id", "scope_blob_id", "deployment_manifest_blob_id")
    }
    scope = {
        **body.model_dump(mode="json"),
        "artifact_digest": artifact.digest,
        "blob_sha256": blobs,
        "estate_scope": scope_key(owner),
        "policy_binding": remediation.policy_binding(db, owner),
    }
    return store.append(
        db,
        owner,
        "security_engagement",
        new_id(),
        0,
        {
            "scope": scope,
            "scope_sha256": store.digest(scope),
            "state": "PROPOSED",
            "independence": "UNREVIEWED_EXTERNAL_ASSERTION",
            "certification": False,
        },
        actor,
    )


def engagement_current(db, owner, row):
    scope = row.payload["scope"]
    return (
        row.payload["state"] == "APPROVED"
        and fresh(scope["expires_at"])
        and scope["policy_binding"] == remediation.policy_binding(db, owner)
        and not (scope["policy_binding"] or {}).get("stopped", False)
    )


def review_engagement(db, owner, identifier, body, actor, withdraw=False):
    row = store.latest(db, owner, "security_engagement", identifier)
    if (
        row.payload["state"] == "WITHDRAWN"
        or not withdraw
        and (
            row.payload["state"] != "PROPOSED"
            or row.created_by == actor
            or not fresh(row.payload["scope"]["expires_at"])
        )
    ):
        raise HTTPException(409, "Current proposed scope needs a different authorized reviewer")
    if withdraw:
        return store.append(
            db,
            owner,
            "security_engagement",
            identifier,
            body.expected_revision,
            {
                **row.payload,
                "state": "WITHDRAWN",
                "withdrawn_by": actor,
                "withdrawn_at": utcnow().isoformat(),
                "withdrawal_evidence_ref": body.evidence_ref,
                "withdrawal_reason": body.reason,
            },
            actor,
        )
    return store.append(
        db,
        owner,
        "security_engagement",
        identifier,
        body.expected_revision,
        {
            **row.payload,
            "state": "APPROVED",
            "reviewed_by": actor,
            "approved_at": utcnow().isoformat(),
            "review_evidence_ref": body.evidence_ref,
            "review_reason": body.reason,
            "independence": "CUSTOMER_REVIEWED_EXTERNAL_ASSERTION_NOT_ACCREDITATION",
        },
        actor,
    )


def report(db, owner, identifier, body, actor):
    eng = store.latest(db, owner, "security_engagement", identifier)
    p = body.payload.model_dump(mode="json")
    scope = eng.payload["scope"]
    old = store.latest(db, owner, "security_report", identifier, required=False)
    if not engagement_current(db, owner, eng):
        raise HTTPException(409, "Approved, unexpired, current engagement required")
    if (
        p["engagement_id"] != identifier
        or p["engagement_revision"] != eng.revision
        or p["estate_scope"] != scope_key(owner)
        or p["scope_sha256"] != eng.payload["scope_sha256"]
        or p["environment_ref"] != scope["environment_ref"]
        or p["sequence"] != body.expected_revision + 1
        or body.expected_revision != (old.revision if old else 0)
    ):
        raise HTTPException(409, "Signed report scope/estate/revision/sequence disagrees with approved engagement")
    artifact = active_identity(db, SoftwareArtifact, owner, p["artifact_id"])
    if p["artifact_digest"] != artifact.digest:
        raise HTTPException(409, "Signed artifact digest mismatch")
    if not old and (
        p["artifact_id"] != scope["artifact_id"]
        or p["deployment_manifest_sha256"] != scope["blob_sha256"]["deployment_manifest_blob_id"]
    ):
        raise HTTPException(409, "Initial report must cover the approved baseline release/deployment")
    start, end = body.payload.started_at, body.payload.ended_at
    if (
        not aware(datetime.fromisoformat(eng.payload["approved_at"])) <= start <= end <= utcnow()
        or old
        and start <= aware(datetime.fromisoformat(old.payload["report"]["ended_at"]))
    ):
        raise HTTPException(409, "Report interval is invalid, future-dated or older than the retained report")
    blob = store.blob(db, owner, p["report_blob_id"])
    if blob.sha256 != p["report_sha256"]:
        raise HTTPException(409, "External report bytes disagree with signed checksum")
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature

        Ed25519PublicKey.from_public_bytes(base64.b64decode(scope["public_key_base64"], validate=True)).verify(
            base64.b64decode(body.signature_base64, validate=True), store.encoded(p)
        )
    except (ValueError, InvalidSignature):
        raise HTTPException(422, "Assessor signature does not verify over canonical report bytes") from None
    expected = {c["case_id"] for c in scope["cases"]}
    cases = {c["case_id"]: c["outcome"] for c in p["cases"]}
    if set(cases) != expected or len(cases) != len(p["cases"]):
        raise HTTPException(422, "Every scoped case needs exactly one explicit outcome; missing is not passed")
    refs = [f["finding_ref"] for f in p["findings"]]
    retests = {r["finding_id"]: r for r in p["retests"]}
    if len(set(refs)) != len(refs) or len(retests) != len(p["retests"]):
        raise HTTPException(422, "Duplicate finding/retest identities")
    prior_ids = set(old.payload["finding_ids"] if old else [])
    discovered = {store.subject(identifier, ref) for ref in refs}
    if discovered & retests.keys() or set(retests) - prior_ids or prior_ids - discovered - retests.keys():
        raise HTTPException(422, "Every prior finding needs a disposition; no unknown or duplicate retests")
    baseline = (
        p["artifact_id"] == scope["artifact_id"]
        and p["deployment_manifest_sha256"] == scope["blob_sha256"]["deployment_manifest_blob_id"]
    )
    if not baseline:
        intended = False
        for fid in retests:
            f = store.latest(db, owner, "security_finding", fid)
            change = f.payload.get("change") or {}
            intended |= bool(
                change.get("approved_by")
                and change.get("completed_at")
                and change.get("replacement_artifact_id") == p["artifact_id"]
                and change.get("deployment_manifest_sha256") == p["deployment_manifest_sha256"]
            )
        if not intended:
            raise HTTPException(
                409, "Changed report release/deployment needs an explicitly approved and reported finding change"
            )
    identifiers = sorted(prior_ids | discovered)
    if len(identifiers) > 200:
        raise HTTPException(409, "Engagement exceeds 200 findings; split and reapprove scope")
    updates = []
    failed_cases = set()
    for f in p["findings"]:
        if (
            len(set(f["case_ids"])) != len(f["case_ids"])
            or not set(f["case_ids"]) <= expected
            or any(cases[c] != "FAILED" for c in f["case_ids"])
        ):
            raise HTTPException(422, "Finding cases must belong to scope and have FAILED outcomes")
        failed_cases.update(f["case_ids"])
        fid = store.subject(identifier, f["finding_ref"])
        before = store.latest(db, owner, "security_finding", fid, required=False)
        if before and set(before.payload["finding"]["case_ids"]) != set(f["case_ids"]):
            raise HTTPException(
                409,
                "Rediscovery cannot redefine a tracked finding's cases; use a new finding reference and explicitly disposition the original",
            )
        updates.append(
            (
                fid,
                before.revision if before else 0,
                {
                    "engagement_id": identifier,
                    "finding": f,
                    "state": "OPEN",
                    "condition": "PRESENT",
                    "origin_report_sequence": p["sequence"],
                    "owner_user_id": None,
                    "change": None,
                },
            )
        )
    for fid, result in retests.items():
        finding = store.latest(db, owner, "security_finding", fid)
        if (
            finding.payload["engagement_id"] != identifier
            or finding.payload_sha256 != result["expected_finding_sha256"]
        ):
            raise HTTPException(409, "Retest does not bind the current finding/change revision")
        value = finding.payload
        change = value.get("change") or {}
        if result["outcome"] == "RESOLVED":
            if (
                value["state"] not in {"REPORTED_COMPLETE", "RETEST_INCONCLUSIVE", "RETEST_RECORDED_RESOLVED"}
                or not change.get("approved_by")
                or not change.get("completed_at")
                or aware(datetime.fromisoformat(change["completed_at"])) >= start
                or change["replacement_digest"] != p["artifact_digest"]
                or change["replacement_artifact_id"] != p["artifact_id"]
                or change["deployment_manifest_sha256"] != p["deployment_manifest_sha256"]
                or any(cases[c] != "PASSED" for c in value["finding"]["case_ids"])
            ):
                raise HTTPException(
                    409,
                    "Resolved retest needs approved/reported change, intended replacement, later test and all finding cases passed",
                )
        if result["outcome"] == "PRESENT":
            failed_cases.update(c for c in value["finding"]["case_ids"] if cases[c] == "FAILED")
            if not any(cases[c] == "FAILED" for c in value["finding"]["case_ids"]):
                raise HTTPException(422, "Present condition needs a failed finding case")
        state = (
            "RETEST_RECORDED_RESOLVED"
            if result["outcome"] == "RESOLVED"
            else "OPEN"
            if result["outcome"] == "PRESENT"
            else "RETEST_INCONCLUSIVE"
        )
        updates.append(
            (
                fid,
                finding.revision,
                {
                    **value,
                    "state": state,
                    "condition": result["outcome"],
                    "retest_report_sequence": p["sequence"],
                    "retest_evidence_ref": result["evidence_ref"],
                },
            )
        )
    if {c for c, v in cases.items() if v == "FAILED"} - failed_cases:
        raise HTTPException(422, "Every failed case needs a tracked finding")
    row = store.append(
        db,
        owner,
        "security_report",
        identifier,
        body.expected_revision,
        {
            "report": p,
            "signature_base64": body.signature_base64,
            "finding_ids": identifiers,
            "origin_verified": True,
            "independence": eng.payload["independence"],
            "certification": False,
            "imported_by": actor,
        },
        actor,
        commit=False,
    )
    for fid, rev, payload in updates:
        store.append(db, owner, "security_finding", fid, rev, payload, actor, commit=False)
    db.commit()
    return row


def finding_action(db, owner, identifier, body, actor, action):
    row = store.latest(db, owner, "security_finding", identifier)
    p = row.payload
    eng = store.latest(db, owner, "security_engagement", p["engagement_id"])
    if not engagement_current(db, owner, eng):
        raise HTTPException(409, "Engagement authority expired/withdrawn/changed")
    if action == "plan":
        if p["state"] == "RETEST_RECORDED_RESOLVED":
            raise HTTPException(409, "Resolved finding needs an assessor-reported recurrence before a new plan")
        person(db, owner, body.owner_user_id)
        artifact = active_identity(db, SoftwareArtifact, owner, body.replacement_artifact_id)
        manifest = store.blob(db, owner, body.deployment_manifest_blob_id)
        value = {
            **p,
            "state": "CHANGE_PROPOSED",
            "owner_user_id": body.owner_user_id,
            "change": {
                **body.model_dump(mode="json", exclude={"expected_revision"}),
                "proposed_by": actor,
                "replacement_digest": artifact.digest,
                "deployment_manifest_sha256": manifest.sha256,
            },
        }
    elif action == "approve":
        if p["state"] != "CHANGE_PROPOSED" or actor in {p["change"]["proposed_by"], p["owner_user_id"]}:
            raise HTTPException(409, "Change needs a different reviewer, not its proposer or owner")
        value = {
            **p,
            "state": "CHANGE_APPROVED",
            "change": {
                **p["change"],
                "approved_by": actor,
                "approved_at": utcnow().isoformat(),
                "approval_ref": body.evidence_ref,
                "approval_reason": body.reason,
            },
        }
    else:
        if p["state"] != "CHANGE_APPROVED" or actor != p["owner_user_id"]:
            raise HTTPException(409, "Only the assigned owner may report an approved action complete")
        person(db, owner, actor)
        if not aware(datetime.fromisoformat(p["change"]["approved_at"])) <= body.completed_at <= utcnow():
            raise HTTPException(422, "Action time must follow approval and not be future-dated")
        evidence = store.blob(db, owner, body.evidence_blob_id)
        value = {
            **p,
            "state": "REPORTED_COMPLETE",
            "change": {
                **p["change"],
                "completed_at": body.completed_at.isoformat(),
                "completion_blob_id": evidence.id,
                "completion_sha256": evidence.sha256,
                "reported_by": actor,
            },
        }
    return store.append(db, owner, "security_finding", identifier, body.expected_revision, value, actor)


def security_status(db, owner, identifier):
    eng = store.latest(db, owner, "security_engagement", identifier)
    latest = store.latest(db, owner, "security_report", identifier, required=False)
    issues = []
    if not engagement_current(db, owner, eng):
        issues.append("ENGAGEMENT_NOT_CURRENT_APPROVED")
    if not latest:
        issues.append("INDEPENDENT_REPORT_NOT_OBTAINED")
    findings = store.latest_many(db, owner, "security_finding", latest.payload["finding_ids"] if latest else [])
    if latest and set(findings) != set(latest.payload["finding_ids"]):
        issues.append("TRACKED_FINDING_RECORD_MISSING")
    try:
        for name, sha in eng.payload["scope"]["blob_sha256"].items():
            if store.blob(db, owner, eng.payload["scope"][name]).sha256 != sha:
                issues.append("SCOPE_EVIDENCE_DIGEST_CHANGED")
        if latest:
            report_payload = latest.payload["report"]
            if store.blob(db, owner, report_payload["report_blob_id"]).sha256 != report_payload["report_sha256"]:
                issues.append("REPORT_EVIDENCE_DIGEST_CHANGED")
    except HTTPException:
        issues.append("SCOPE_OR_REPORT_EVIDENCE_UNAVAILABLE_OR_CORRUPT")
    for f in findings.values():
        if f.payload["state"] != "RETEST_RECORDED_RESOLVED":
            issues.append("UNRESOLVED_OR_UNTESTED_FINDING:" + f.subject_id)
    if latest:
        r = latest.payload["report"]
        active_identity(db, SoftwareArtifact, owner, r["artifact_id"])
        if (
            aware(datetime.fromisoformat(r["ended_at"]))
            + timedelta(seconds=eng.payload["scope"]["report_max_age_seconds"])
            <= utcnow()
        ):
            issues.append("INDEPENDENT_REPORT_STALE")
    if latest and any(c["outcome"] != "PASSED" for c in latest.payload["report"]["cases"]):
        issues.append("FAILED_OR_UNTESTED_CASES")
    return {
        "engagement_id": identifier,
        "engagement_revision": eng.revision,
        "scope_sha256": eng.payload["scope_sha256"],
        "report_revision": latest.revision if latest else None,
        "issues": issues,
        "state": "SCOPED_SIGNED_TEST_RECORDS_COMPLETE" if not issues else "BLOCKED",
        "findings": [store.public(f) for f in findings.values()],
        "certified": False,
        "independence": eng.payload["independence"],
        "limit": "Signature proves report origin/integrity, not assessor competence, genuine independence or accreditation",
    }


def assignment(db, owner, body, actor):
    person(db, owner, body.owner_user_id)
    person(db, owner, body.backup_user_id)
    if body.owner_user_id == body.backup_user_id or body.review_due_at <= utcnow():
        raise HTTPException(422, "Distinct primary/backup and future review deadline required")
    blob = store.blob(db, owner, body.procedure_blob_id)
    return store.append(
        db,
        owner,
        "operating_assignment",
        store.subject("duty", body.duty),
        body.expected_revision,
        {
            **body.model_dump(mode="json", exclude={"expected_revision"}),
            "procedure_sha256": blob.sha256,
            "acknowledged_user_ids": [],
            "state": "AWAITING_OWNER_ACKNOWLEDGEMENT",
        },
        actor,
    )


def acknowledge(db, owner, identifier, body, actor):
    row = store.latest(db, owner, "operating_assignment", identifier)
    p = row.payload
    person(db, owner, actor)
    if (
        actor not in {p["owner_user_id"], p["backup_user_id"]}
        or actor in p["acknowledged_user_ids"]
        or not fresh(p["review_due_at"])
    ):
        raise HTTPException(409, "Current designated primary/backup must acknowledge once")
    ids = [*p["acknowledged_user_ids"], actor]
    return store.append(
        db,
        owner,
        "operating_assignment",
        identifier,
        body.expected_revision,
        {
            **p,
            "acknowledged_user_ids": ids,
            "state": "ACKNOWLEDGED" if len(ids) == 2 else p["state"],
            "last_ack_ref": body.evidence_ref,
            "last_ack_reason": body.reason,
        },
        actor,
    )


def operating_interval(started_at, ended_at, assigned_at, now):
    """One interval rule at intake and current read, including clock rollback."""
    return aware(assigned_at) <= aware(started_at) <= aware(ended_at) <= now


def exercise(db, owner, identifier, body, actor):
    row = store.latest(db, owner, "operating_assignment", identifier)
    p = row.payload
    person(db, owner, actor)
    if (
        row.revision != body.assignment_revision
        or p["state"] != "ACKNOWLEDGED"
        or not fresh(p["review_due_at"])
        or actor not in {p["owner_user_id"], p["backup_user_id"]}
    ):
        raise HTTPException(409, "Current acknowledged assignment and designated operator required")
    if not operating_interval(body.started_at, body.ended_at, row.created_at, utcnow()):
        raise HTTPException(422, "Exercise interval invalid/future-dated")
    blob = store.blob(db, owner, body.evidence_blob_id)
    if (
        body.measured_recovery_seconds is not None
        and body.measured_recovery_seconds > (body.ended_at - body.started_at).total_seconds()
    ):
        raise HTTPException(422, "Measured recovery exceeds exercise interval")
    return store.append(
        db,
        owner,
        "operating_exercise",
        identifier,
        body.expected_revision,
        {
            **body.model_dump(mode="json", exclude={"expected_revision"}),
            "assignment_sha256": row.payload_sha256,
            "evidence_sha256": blob.sha256,
            "performed_by": actor,
            "state": "REPORTED_NOT_REVIEWED",
        },
        actor,
    )


def review_exercise(db, owner, identifier, body, actor):
    row = store.latest(db, owner, "operating_exercise", identifier)
    assignment = store.latest(db, owner, "operating_assignment", identifier)
    p = row.payload
    if (
        p["state"] != "REPORTED_NOT_REVIEWED"
        or actor == p["performed_by"]
        or assignment.payload_sha256 != p["assignment_sha256"]
        or p["outcome"] != "PASSED"
    ):
        raise HTTPException(409, "Passed evidence under unchanged assignment needs a different reviewer")
    return store.append(
        db,
        owner,
        "operating_exercise",
        identifier,
        body.expected_revision,
        {
            **p,
            "state": "REVIEWED_EXERCISE_ASSERTION",
            "reviewed_by": actor,
            "review_evidence_ref": body.evidence_ref,
            "review_reason": body.reason,
            "independent_runtime_proof": False,
        },
        actor,
    )


def operations_status(db, owner):
    now = utcnow()
    ids = [store.subject("duty", d) for d in DUTIES]
    assignments = store.latest_many(db, owner, "operating_assignment", ids)
    exercises = store.latest_many(db, owner, "operating_exercise", ids)
    result = []
    for duty, key in zip(DUTIES, ids):
        a, e = assignments.get(key), exercises.get(key)
        issues = []
        if not a:
            issues.append("UNASSIGNED")
        else:
            p = a.payload
            try:
                if store.blob(db, owner, p["procedure_blob_id"]).sha256 != p["procedure_sha256"]:
                    issues.append("PROCEDURE_EVIDENCE_DIGEST_CHANGED")
                if e and store.blob(db, owner, e.payload["evidence_blob_id"]).sha256 != e.payload["evidence_sha256"]:
                    issues.append("EXERCISE_EVIDENCE_DIGEST_CHANGED")
            except HTTPException:
                issues.append("PROCEDURE_OR_EXERCISE_EVIDENCE_UNAVAILABLE_OR_CORRUPT")
            for uid in (p["owner_user_id"], p["backup_user_id"]):
                try:
                    person(db, owner, uid)
                except HTTPException:
                    issues.append("OWNER_OR_BACKUP_NO_LONGER_ACTIVE")
            if p["state"] != "ACKNOWLEDGED":
                issues.append("OWNER_ACKNOWLEDGEMENT_MISSING")
            if not fresh(p["review_due_at"]):
                issues.append("PROCEDURE_REVIEW_OVERDUE")
            if not e or e.payload["assignment_sha256"] != a.payload_sha256:
                issues.append("CURRENT_ASSIGNMENT_EXERCISE_MISSING")
            elif (
                e.payload["state"] != "REVIEWED_EXERCISE_ASSERTION"
                or not operating_interval(datetime.fromisoformat(e.payload["started_at"]),
                    datetime.fromisoformat(e.payload["ended_at"]), a.created_at, now)
                or aware(datetime.fromisoformat(e.payload["ended_at"]))
                + timedelta(seconds=p["exercise_max_age_seconds"])
                <= now
            ):
                issues.append("EXERCISE_FAILED_UNREVIEWED_OR_STALE")
        result.append(
            {
                "duty": duty,
                "issues": issues,
                "assignment": store.public(a) if a else None,
                "exercise": store.public(e) if e else None,
            }
        )
    return {
        "duties": result,
        "all_owner_reviewed_records_current": all(not r["issues"] for r in result),
        "sla_authorized": False,
        "reason": "Contracts/SLOs require demonstrated site capability, capacity and legal approval; reviewed exercise assertions alone do not establish an SLA",
    }


def validate_pilot(db, owner, payload):
    p = payload
    person(db, owner, p["customer_owner_user_id"])
    person(db, owner, p["technical_owner_user_id"])
    if p["customer_owner_user_id"] == p["technical_owner_user_id"]:
        raise HTTPException(422, "Customer and technical owner must be distinct")
    store.exact(db, System, owner, p["system_id"])
    artifact = active_identity(db, SoftwareArtifact, owner, p["artifact_id"])
    binding = active_identity(db, ReleaseSbomBinding, owner, p["sbom_binding_id"])
    deployment = active_identity(db, SoftwareDeployment, owner, p["deployment_id"])
    if (
        binding.artifact_id != artifact.id
        or deployment.artifact_id != artifact.id
        or deployment.system_id != p["system_id"]
    ):
        raise HTTPException(409, "SBOM, deployment, artifact and application must identify the same release")
    source = store.exact(db, Scan, owner, p["source_scan_id"])
    if (
        source.status != "COMPLETED"
        or not source.scan_end
        or aware(source.scan_end) > utcnow()
        or not (source.statistics or {}).get("file_observation_receipts")
    ):
        raise HTTPException(409, "Completed observed source scan required")
    register = store.latest(db, owner, "estate_register", p["register_id"])
    if not any(
        t["system_id"] == p["system_id"] and t["kind"] == "SOURCE" and t["target_ref"] == source.target_location
        for t in register.payload["targets"]
    ):
        raise HTTPException(409, "Pilot source/application must belong to the independent expected-target register")
    required_targets = {
        ("DEPLOYMENT", deployment.id),
        ("HARDWARE", p["hardware_id"]),
        ("SUPPLIER", p["supplier_evidence_id"]),
    }
    registered = {(t["kind"], t["target_ref"]) for t in register.payload["targets"] if t["system_id"] == p["system_id"]}
    if not required_targets <= registered:
        raise HTTPException(
            409,
            "Register must explicitly include this application's deployment, hardware and supplier evidence identities",
        )
    tls = remediation.certificate(db, owner, p["tls_run_id"], p["tls_endpoint"])
    ssh = store.exact(db, CollectionPhaseReceipt, owner, p["ssh_receipt_id"])
    if ssh.phase != "host_keys" or ssh.state != "COMPLETED" or ssh.observation_succeeded is not True:
        raise HTTPException(409, "Successful SSH host-key receipt required, not just an open port")
    if (
        not ssh.started_at
        or not ssh.observation
        or hashlib.sha256(
            json.dumps(ssh.observation, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        ).hexdigest()
        != ssh.observation_sha256
        or aware(ssh.started_at) > utcnow()
        or aware(ssh.updated_at) > utcnow()
    ):
        raise HTTPException(409, "SSH observation integrity/timing unavailable")
    from db.models.scan_job import ScanJob

    ssh_job = store.exact(db, ScanJob, owner, ssh.job_id)
    if ssh_job.status != "COMPLETED":
        raise HTTPException(409, "SSH collector job not complete")
    for endpoint, permission in ((p["tls_endpoint"], p["tls_permission_ref"]), (ssh.endpoint, p["ssh_permission_ref"])):
        if not any(
            t["kind"] == "ENDPOINT"
            and t["system_id"] == p["system_id"]
            and t["target_ref"] == endpoint
            and t["permission_ref"] == permission
            for t in register.payload["targets"]
        ):
            raise HTTPException(409, "Both exact pilot endpoints must be in the same application register")
    hardware = active_identity(db, HardwareAsset, owner, p["hardware_id"])
    if not hardware.manufacturer or not hardware.model or not (hardware.firmware or hardware.crypto_capabilities):
        raise HTTPException(409, "Hardware manufacturer/model and firmware or cryptographic metadata required")
    vendor = active_identity(db, Vendor, owner, p["vendor_id"])
    supplier = store.latest(db, owner, "supplier_evidence", p["supplier_evidence_id"])
    if (
        supplier.payload["artifact_id"] != artifact.id
        or supplier.payload["state"] != "APPROVED_OFFLINE_JSON"
        or supplier.payload["manifest"]["vendor"] != vendor.name
        or adapters.check(db, owner, supplier.payload)
    ):
        raise HTTPException(409, "Current approved signed supplier evidence for the exact release required")
    change = store.latest(db, owner, "remediation_change", p["remediation_change_id"])
    if change.payload["kind"] == "SOURCE_SITE":
        if change.payload["before"]["scan_id"] != source.id:
            raise HTTPException(409, "Remediation baseline must be this pilot source scan")
    elif change.payload["endpoint"] != p["tls_endpoint"]:
        raise HTTPException(409, "Certificate remediation must address this pilot endpoint")
    eng = store.latest(db, owner, "security_engagement", p["engagement_id"])
    if eng.payload["scope"]["artifact_id"] != artifact.id:
        raise HTTPException(409, "Independent security engagement must bind pilot release")
    proof_blob = store.blob(db, owner, p["source_build_binding_blob_id"])
    return {
        "artifact_digest": artifact.digest,
        "sbom_sha256": binding.sbom_sha256,
        "register_revision": register.revision,
        "source_manifest": source.manifest_hash,
        "source_build_binding_sha256": proof_blob.sha256,
        "tls": tls,
        "ssh_receipt_id": ssh.id,
        "hardware_id": hardware.id,
        "hardware_metadata": {
            "manufacturer": hardware.manufacturer,
            "model": hardware.model,
            "firmware": hardware.firmware,
            "crypto_capabilities": hardware.crypto_capabilities,
        },
        "vendor_id": vendor.id,
        "vendor_name": vendor.name,
        "ssh_observation_sha256": ssh.observation_sha256,
        "supplier_sha256": supplier.payload_sha256,
        "relationship_limit": "Source/build, deployed release, endpoint/service and hardware/supplier associations are explicit customer assertions, not inferred runtime relationships",
    }


def pilot(db, owner, identifier, body, actor):
    p = body.model_dump(mode="json", exclude={"expected_revision"})
    if body.expires_at <= utcnow():
        raise HTTPException(422, "Pilot expiry must be in the future")
    if body.expected_revision:
        store.latest(db, owner, "customer_pilot", identifier)
    snapshot = validate_pilot(db, owner, p)
    return store.append(
        db,
        owner,
        "customer_pilot",
        identifier,
        body.expected_revision,
        {
            **p,
            "state": "PROPOSED",
            "snapshot": snapshot,
            "proposed_by": actor,
            "whole_bank_visibility": False,
            "commercial_acceptance": False,
        },
        actor,
    )


def pilot_status(db, owner, identifier):
    row = store.latest(db, owner, "customer_pilot", identifier)
    p = row.payload
    issues = []
    try:
        observed = validate_pilot(db, owner, p)
        if observed != p["snapshot"]:
            issues.append("PILOT_EVIDENCE_OR_REGISTER_CHANGED")
    except HTTPException as exc:
        issues.append("EVIDENCE_UNAVAILABLE_OR_CHANGED:" + str(exc.detail))
    if not fresh(p["expires_at"]):
        issues.append("PILOT_EXPIRED")
    tls = p["snapshot"]["tls"]
    ssh = store.exact(db, CollectionPhaseReceipt, owner, p["ssh_receipt_id"])
    cutoff = utcnow() - timedelta(seconds=p["evidence_max_age_seconds"])
    if aware(datetime.fromisoformat(tls["completed_at"])) <= cutoff or aware(ssh.updated_at) <= cutoff:
        issues.append("ENDPOINT_OBSERVATIONS_STALE")
    change = store.latest(db, owner, "remediation_change", p["remediation_change_id"], required=False)
    proof = store.latest(
        db, owner, "condition_proof", store.subject(p["remediation_change_id"], "condition_proof"), required=False
    )
    if (
        not change
        or not remediation.current(db, owner, change)
        or not proof
        or proof.payload["result"] != "VERIFIED"
        or proof.payload["change_sha256"] != change.payload_sha256
        or not proof.payload.get("after")
        or not remediation.observation_current(db, owner, change, proof.payload["after"])
        or aware(datetime.fromisoformat(proof.payload["after"]["completed_at"]))
        + timedelta(seconds=change.payload["freshness_seconds"])
        <= utcnow()
    ):
        issues.append("CURRENT_INDEPENDENT_REMEDIATION_PROOF_MISSING")
    security = security_status(db, owner, p["engagement_id"])
    if security["issues"]:
        issues.append("INDEPENDENT_SECURITY_RECORDS_INCOMPLETE")
    operations = operations_status(db, owner)
    if not operations["all_owner_reviewed_records_current"]:
        issues.append("OPERATIONAL_OWNERSHIP_OR_EXERCISES_INCOMPLETE")
    try:
        report = coverage.report(db, owner, p["register_id"])
        coverage_available = True
    except HTTPException as exc:
        if exc.status_code not in {404, 409, 503}:
            raise
        # Counts are UNKNOWN, not zero, when a dependency cannot be verified.
        issues.append("COVERAGE_UNAVAILABLE_OR_CHANGED")
        report, coverage_available = {"targets": [], "counts": None}, False
    unresolved = [t["target_id"] for t in report["targets"] if t["state"] != "OBSERVED"]
    # External-export register entries have no automatic receipt adapter. Disclose
    # them rather than manufacturing OBSERVED records for a document assertion.
    source_targets = [
        t
        for t in report["targets"]
        if t["system_id"] == p["system_id"]
        and t["kind"] == "SOURCE"
        and t["target_ref"] == store.exact(db, Scan, owner, p["source_scan_id"]).target_location
    ]
    ssh_targets = [
        t
        for t in report["targets"]
        if t["system_id"] == p["system_id"]
        and t["kind"] == "ENDPOINT"
        and t["target_ref"] == ssh.endpoint
        and t["method"].startswith("SSH_")
    ]
    if not source_targets or not ssh_targets or any(t["state"] != "OBSERVED" for t in source_targets + ssh_targets):
        issues.append("SOURCE_OR_SSH_REGISTER_COVERAGE_NOT_CURRENT")
    from db.models.scan_job import ScanJob

    for target in source_targets:
        receipt = target.get("receipt") or {}
        job = store.exact(db, ScanJob, owner, receipt.get("job_id")) if receipt.get("job_id") else None
        if not job or job.scan_id != p["source_scan_id"]:
            issues.append("SOURCE_COVERAGE_DOES_NOT_BIND_SELECTED_SCAN")
    if any((t.get("receipt") or {}).get("job_id") != ssh.job_id for t in ssh_targets):
        issues.append("SSH_COVERAGE_DOES_NOT_BIND_SELECTED_RECEIPT")
    fingerprint = store.digest(
        {
            "snapshot": p["snapshot"],
            "security": security,
            "operations": operations,
            "proof_sha256": proof.payload_sha256 if proof else None,
            "coverage": [
                {"target_id": t["target_id"], "state": t["state"], "receipt": t["receipt"]} for t in report["targets"]
            ],
        }
    )
    if p.get("technical_review_snapshot_sha256") != fingerprint:
        issues.append("CURRENT_TECHNICAL_OWNER_REVIEW_MISSING")
    return {
        "pilot_id": identifier,
        "revision": row.revision,
        "state": p["state"],
        "issues": issues,
        "evidence_loop_ready": not issues,
        "commercial_acceptance_current": not issues
        and p["state"] == "CUSTOMER_ACCEPTED_BOUNDED"
        and p.get("acceptance_snapshot_sha256") == fingerprint,
        "gate_snapshot_sha256": fingerprint,
        "whole_bank_visibility": False,
        "sla_authorized": False,
        "security": security,
        "coverage_counts": report["counts"],
        "coverage_available": coverage_available,
        "unresolved_targets": unresolved,
        "exclusions": p["exclusions"],
        "limits": p["snapshot"]["relationship_limit"],
    }


def accept_pilot(db, owner, identifier, body, actor):
    row = store.latest(db, owner, "customer_pilot", identifier)
    p = row.payload
    if p["state"] != "TECHNICALLY_REVIEWED" or actor != p["customer_owner_user_id"] or actor == p["proposed_by"]:
        raise HTTPException(409, "A different designated customer owner must accept the bounded pilot")
    status = pilot_status(db, owner, identifier)
    if status["issues"]:
        raise HTTPException(
            409, {"reason": "Pilot has unresolved evidence/operating/security gates", "issues": status["issues"]}
        )
    return store.append(
        db,
        owner,
        "customer_pilot",
        identifier,
        body.expected_revision,
        {
            **p,
            "state": "CUSTOMER_ACCEPTED_BOUNDED",
            "accepted_by": actor,
            "accepted_at": utcnow().isoformat(),
            "acceptance_evidence_ref": body.evidence_ref,
            "acceptance_reason": body.reason,
            "acceptance_snapshot_sha256": status["gate_snapshot_sha256"],
            "commercial_acceptance": True,
        },
        actor,
    )


def review_pilot(db, owner, identifier, body, actor):
    row = store.latest(db, owner, "customer_pilot", identifier)
    p = row.payload
    if actor != p["technical_owner_user_id"]:
        raise HTTPException(409, "Only the designated technical owner may review this pilot")
    status = pilot_status(db, owner, identifier)
    blockers = [i for i in status["issues"] if i != "CURRENT_TECHNICAL_OWNER_REVIEW_MISSING"]
    if blockers:
        raise HTTPException(409, {"reason": "Pilot evidence gates incomplete", "issues": blockers})
    return store.append(
        db,
        owner,
        "customer_pilot",
        identifier,
        body.expected_revision,
        {
            **p,
            "state": "TECHNICALLY_REVIEWED",
            "technical_review_by": actor,
            "technical_review_ref": body.evidence_ref,
            "technical_review_reason": body.reason,
            "technical_review_snapshot_sha256": status["gate_snapshot_sha256"],
        },
        actor,
    )
