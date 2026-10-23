"""Approved predicates, independent observations, retained proofs. Never ticket truth."""
from datetime import datetime, timedelta
import uuid
from fastapi import HTTPException
from db.models.base import utcnow
from db.models.remediation_task import RemediationTask, RemediationVerification
from db.models.scan import Scan
from db.models.scan_job import ScanJob
from db.models.evidence_record import EvidenceRecord
from db.models.network_scan_run import NetworkScanRun
from db.models.execution_control import EstateExecutionPolicy
from db.repositories.execution_control import aware
from . import store


def policy_binding(db, owner):
    rows = db.query(EstateExecutionPolicy).filter_by(tenant_id=owner).all()
    if len(rows) > 1:
        raise HTTPException(409, "Ambiguous estate policy")
    row = rows[0] if rows else None
    return {"id": row.id, "revision": row.revision, "contract_sha256": store.digest(row.contract), "stopped": row.stopped} if row else None


_UNSET = object()


def live_findings(db, owner, findings):
    # The entire bounded comparison contributed to the verdict. Never turn a
    # withdrawn member into clean absence by silently filtering the snapshot.
    if not findings or len(findings) > 5000:
        return False
    identifiers = {f.get("evidence_id") for f in findings}
    if None in identifiers or len(identifiers) != len(findings):
        return False
    return db.query(EvidenceRecord.id).filter(
        EvidenceRecord.tenant_id == owner, EvidenceRecord.id.in_(identifiers),
        EvidenceRecord.deleted_at.is_(None)).count() == len(identifiers)


def exact_algorithm(finding, expected):
    actual = str(finding.get("algorithm") or "").upper()
    expected = expected.upper()
    if actual == expected:
        return True
    # The real normalizer retains SHA-2 as family SHA2 + digest bits. Do not
    # mistake that representation for absence of an explicitly approved
    # SHA-256 (or accept another SHA-2 width as equivalent). Preserve raw proof
    # snapshots and commitments; this only compares the existing predicate.
    bits = finding.get("key_size")
    return actual == "SHA2" and type(bits) is int and bits in {224, 256, 384, 512} and expected == f"SHA-{bits}"


def lock_source_evidence(db, owner, before, after):
    """Serialize positive publication with soft withdrawal of either snapshot.

    The task lock alone does not protect evidence rows. Lock the bounded union
    in a stable order, then recheck deletion state using scalar columns (not a
    possibly cached ORM identity). PostgreSQL retains these locks until the
    proof/task transaction commits. A later withdrawal invalidates current
    eligibility without rewriting the retained historical proof.
    """
    identifiers = {f.get("evidence_id") for snapshot in (before, after)
                   for f in (snapshot or {}).get("findings", [])}
    if not identifiers or None in identifiers or len(identifiers) > 10000:
        return False
    rows = db.query(EvidenceRecord.id, EvidenceRecord.deleted_at).filter(
        EvidenceRecord.tenant_id == owner, EvidenceRecord.id.in_(identifiers)
    ).order_by(EvidenceRecord.id).with_for_update().all()
    return len(rows) == len(identifiers) and all(row.deleted_at is None for row in rows)


def observation_current(db, owner, row, after):
    return (row.payload["kind"] != "SOURCE_SITE"
            or bool(after and live_findings(db, owner, after.get("findings"))))


def current(db, owner, row, binding=_UNSET, assignment=_UNSET):
    if row.payload["state"] == "REVOKED":
        return False
    if row.payload["kind"] == "SOURCE_SITE" and not live_findings(db, owner, row.payload["before"].get("findings")):
        return False
    if row.payload["kind"] == "SOURCE_SITE" and row.payload["state"] != "PROPOSED":
        if assignment is _UNSET:
            assignment = store.latest(db, owner, "remediation_assignment", row.payload["task_id"], required=False)
        if not assignment or assignment.payload["change_id"] != row.subject_id:
            return False
    return (aware(datetime.fromisoformat(row.payload["expires_at"])) > utcnow()
            and row.payload["policy_binding"] == (policy_binding(db, owner) if binding is _UNSET else binding)
            and not (row.payload["policy_binding"] or {}).get("stopped", False))



def locked_task(db, owner, identifier):
    task = db.query(RemediationTask).filter_by(tenant_id=owner, id=identifier).with_for_update().one_or_none()
    if task is None:
        raise HTTPException(404, "Referenced evidence/identity not found")
    return task

def source(db, owner, scan_id, task):
    scan = store.exact(db, Scan, owner, scan_id)
    jobs = db.query(ScanJob).filter_by(tenant_id=owner, scan_id=scan.id, status="COMPLETED", job_type="MANUAL").limit(2).all()
    if (scan.status != "COMPLETED" or not scan.scan_end or len(jobs) != 1
            or scan.target_location != task.target_location or jobs[0].target_repo != task.target_location
            or not jobs[0].started_at or not jobs[0].completed_at):
        raise HTTPException(409, "Completed source scan and exact durable job binding required")
    receipts = [r for r in (scan.statistics or {}).get("file_observation_receipts", [])
                if r.get("file") == task.original_finding.get("file_path")]
    if len(receipts) != 1 or receipts[0].get("parser_completed") is not True:
        raise HTTPException(409, "Exact original-file parser receipt required; disappearance is not resolution")
    sha = receipts[0].get("sha256")
    if not isinstance(sha, str) or len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha):
        raise HTTPException(409, "Source content checksum unavailable")
    if not aware(jobs[0].started_at) <= aware(scan.scan_start) <= aware(scan.scan_end) <= aware(jobs[0].completed_at) <= utcnow():
        raise HTTPException(409, "Invalid or future-dated source/job observation interval")
    observations = db.query(EvidenceRecord).filter_by(tenant_id=owner, scan_id=scan.id).order_by(EvidenceRecord.id).limit(5001).all()
    if len(observations) > 5000:
        raise HTTPException(409, "Comparison exceeds bounded verifier; partition the target, do not truncate proof")
    if any(r.deleted_at is not None for r in observations):
        raise HTTPException(409, "Retracted observations cannot establish a current source comparison; collect again")
    from api.routers.remediation import _finding_snapshot
    return {"scan_id": scan.id, "job_id": jobs[0].id, "started_at": aware(scan.scan_start).isoformat(),
            "completed_at": aware(scan.scan_end).isoformat(), "job_started_at": aware(jobs[0].started_at).isoformat(),
            "job_completed_at": aware(jobs[0].completed_at).isoformat(), "manifest_hash": scan.manifest_hash,
            "scanner_id": scan.scanner_id, "scanner_version": scan.scanner_version,
            "receipt": receipts[0], "findings": [_finding_snapshot(r) for r in observations]}


def certificate(db, owner, run_id, endpoint):
    run = store.exact(db, NetworkScanRun, owner, run_id)
    result = run.result or {}
    collection = result.get("collection") or {}
    job = store.exact(db, ScanJob, owner, collection.get("job_id"))
    if (collection.get("schema") != "cryptoscan.network-collection/1" or run.target_kind != "hosts" or collection.get("kind") != "hosts" or result.get("live") is not True
            or job.job_type != "NETWORK_SCAN" or job.status != "COMPLETED"
            or not job.started_at or not job.completed_at):
        raise HTTPException(409, "Completed live TLS collector and durable job required, not renewal inventory")
    if not aware(job.started_at) <= aware(job.completed_at) <= utcnow():
        raise HTTPException(409, "Invalid or future-dated collector interval")
    probes = [p for p in result.get("probes", []) if p.get("endpoint") == endpoint]
    if len(probes) != 1 or probes[0].get("status") != "OK":
        raise HTTPException(409, "One successful observation of the exact intended endpoint required")
    if not (probes[0].get("metadata") or {}).get("certificate_hostname"):
        raise HTTPException(409, "Observed SNI/certificate-hostname identity unavailable")
    chain = probes[0].get("certificates") or []
    cert = chain[0] if chain else {}
    fp = cert.get("fingerprint_sha256")
    if not isinstance(fp, str) or len(fp) != 64 or any(c not in "0123456789abcdef" for c in fp):
        raise HTTPException(409, "Observed certificate SHA256 unavailable")
    return {"network_run_id": run.id, "job_id": job.id, "endpoint": endpoint,
            "started_at": aware(job.started_at).isoformat(), "completed_at": aware(job.completed_at).isoformat(),
            "fingerprint_sha256": fp, "probe": probes[0], "collection": collection,
            "connection_identity": {k: (probes[0].get("metadata") or {}).get(k) for k in ("certificate_hostname", "starttls")},
            "limits": "Endpoint identity only; not chain trust, revocation, all load-balancer nodes or all client paths"}


def propose(db, owner, body, actor):
    if not utcnow() < body.expires_at:
        raise HTTPException(422, "Approval expiry must be in the future")
    payload = body.model_dump(mode="json")
    if body.kind == "SOURCE_SITE":
        task = store.exact(db, RemediationTask, owner, body.task_id)
        if not task.owner or task.owner != body.owner_ref:
            raise HTTPException(409, "An assigned task owner matching the change owner is required")
        finding = task.original_finding
        if (not finding.get("file_path") or not finding.get("line_number") or finding.get("purpose") in {None, "", "UNKNOWN"}
                or finding.get("algorithm") in {None, "", "UNKNOWN"}):
            raise HTTPException(409, "Known original file/line/purpose/algorithm required for this predicate")
        before = source(db, owner, task.scan_id, task)
        if not any(f["evidence_id"] == task.evidence_id and f == task.original_finding for f in before["findings"]):
            raise HTTPException(409, "Retained finding snapshot does not match original source evidence")
        payload["original_finding"] = task.original_finding
    else:
        before = certificate(db, owner, body.before_run_id, body.endpoint)
        if before["fingerprint_sha256"] == body.expected_fingerprint_sha256:
            raise HTTPException(422, "Replacement identity must differ from the original")
    if aware(datetime.fromisoformat(before["completed_at"])) > utcnow():
        raise HTTPException(409, "Future-dated baseline")
    payload.update(state="PROPOSED", before=before, policy_binding=policy_binding(db, owner),
                   predicate_version="condition/1", scope_limit="Only the explicit predicate; not whole-estate risk closure")
    return store.append(db, owner, "remediation_change", str(uuid.uuid4()), 0, payload, actor)


def approve(db, owner, identifier, body, actor):
    row = store.latest(db, owner, "remediation_change", identifier)
    if row.payload["state"] != "PROPOSED" or not current(db, owner, row):
        raise HTTPException(409, "Change is not proposed or its authority/expiry is stale")
    if actor == row.created_by:
        raise HTTPException(409, "Independent reviewer must approve the proposed condition")
    payload = {**row.payload, "state": "APPROVED", "approved_at": utcnow().isoformat(),
               "approved_by": actor, "approval_evidence_ref": body.evidence_ref, "approval_reason": body.reason}
    approved = store.append(db, owner, "remediation_change", identifier, body.expected_revision, payload, actor, commit=False)
    if payload["kind"] == "SOURCE_SITE":
        task = locked_task(db, owner, payload["task_id"])
        if task.owner != payload["owner_ref"]:
            raise HTTPException(409, "Assigned task owner changed")
        old = store.latest(db, owner, "remediation_assignment", task.id, required=False)
        store.append(db, owner, "remediation_assignment", task.id, old.revision if old else 0,
                     {"change_id": identifier, "owner_ref": payload["owner_ref"]}, actor, commit=False)
        task.status = "ACCEPTED"
    db.commit()
    return approved


def reported(db, owner, identifier, body, actor):
    row = store.latest(db, owner, "remediation_change", identifier)
    if row.payload["state"] != "APPROVED" or not current(db, owner, row):
        raise HTTPException(409, "A current approved change is required")
    if not aware(datetime.fromisoformat(row.payload["approved_at"])) <= body.completed_at <= utcnow():
        raise HTTPException(422, "Completion must be after approval and not in the future")
    reported = store.append(db, owner, "remediation_change", identifier, body.expected_revision,
        {**row.payload, "state": "REPORTED_COMPLETE", "completed_at": body.completed_at.isoformat(),
         "completion_evidence_ref": body.evidence_ref, "reported_by": actor}, actor, commit=False)
    if row.payload["kind"] == "SOURCE_SITE":
        task = locked_task(db, owner, row.payload["task_id"])
        if not current(db, owner, row) or task.owner != row.payload["owner_ref"] or task.status != "ACCEPTED":
            raise HTTPException(409, "Assigned accepted task required to report work")
        task.status, task.completed_at, task.completed_by = "COMPLETED", body.completed_at, actor
    db.commit()
    return reported


def verify(db, owner, identifier, body, actor):
    row = store.latest(db, owner, "remediation_change", identifier)
    p = row.payload
    if row.revision != body.expected_revision or p["state"] != "REPORTED_COMPLETE":
        raise HTTPException(409, "Reload the reported-complete approved change before verification")
    proof_id = store.subject(identifier, "condition_proof")
    old_proof = store.latest(db, owner, "condition_proof", proof_id, required=False)
    if body.expected_proof_revision != (old_proof.revision if old_proof else 0):
        raise HTTPException(409, "Reload current condition proof revision before retrying verification")
    result, reason, after, task = "INCONCLUSIVE", "No usable independent observation", None, None
    try:
        if p["kind"] == "SOURCE_SITE":
            task = locked_task(db, owner, p["task_id"])
        if not current(db, owner, row):
            raise HTTPException(409, "Approval expired or estate authority changed; re-propose/re-approve")
        if p["kind"] == "SOURCE_SITE":
            task = locked_task(db, owner, p["task_id"])
            if task.original_finding != p["original_finding"] or task.owner != p["owner_ref"]:
                raise HTTPException(409, "Task owner or original condition changed")
            after = source(db, owner, body.rescan_id, task)
        else:
            after = certificate(db, owner, body.rescan_id, p["endpoint"])
        cutoff = aware(datetime.fromisoformat(p["completed_at"]))
        start, end = (aware(datetime.fromisoformat(after[k])) for k in ("started_at", "completed_at"))
        if (after["job_id"] == p["before"]["job_id"] or not cutoff < start <= end <= utcnow()
                or "job_started_at" in after and not cutoff < aware(datetime.fromisoformat(after["job_started_at"])) <= start
                or "job_completed_at" in after and not end <= aware(datetime.fromisoformat(after["job_completed_at"])) <= utcnow()):
            raise HTTPException(409, "Observation must independently start after reported change, finish, and not be future-dated")
        if end + timedelta(seconds=p["freshness_seconds"]) <= utcnow():
            raise HTTPException(409, "Observation exceeds approved freshness window; collect again")
        if p["kind"] == "TLS_CERTIFICATE":
            if after["connection_identity"] != p["before"]["connection_identity"]:
                raise HTTPException(409, "SNI/STARTTLS identity changed; not the approved endpoint observation")
            result = "VERIFIED" if after["fingerprint_sha256"] == p["expected_fingerprint_sha256"] else "FAILED"
            reason = "Exact endpoint replacement SHA256 " + ("observed" if result == "VERIFIED" else "not observed")
        else:
            from remediation.verification import verify_remediation
            verdict = verify_remediation(p["original_finding"], {"replace_with": p["expected_algorithm"]}, after["findings"], p["before"]["findings"])
            result, reason = verdict["result"], verdict["reason"]
            f = p["original_finding"]
            site = [x for x in after["findings"] if x["file_path"] == f["file_path"] and x["line_number"] == f["line_number"]
                    and x["purpose"] == f["purpose"] and exact_algorithm(x, p["expected_algorithm"])]
            if result == "VERIFIED" and (len(site) != 1 or site[0]["compliance_status"] != "PASS"
                    or after["receipt"]["sha256"] == p["before"]["receipt"]["sha256"]):
                result, reason = "INCONCLUSIVE", "Expected compliant replacement at exact file/line/purpose and changed source content required"
    except HTTPException as exc:
        # Failed lookups do not become successful fixes. Do not reveal foreign IDs.
        reason = "Independent observation unavailable" if exc.status_code == 404 else str(exc.detail)
    if result == "VERIFIED" and p["kind"] == "SOURCE_SITE" and not lock_source_evidence(db, owner, p["before"], after):
        result, reason = "INCONCLUSIVE", "Source evidence was withdrawn before proof publication"
    if result == "VERIFIED" and (not current(db, owner, row) or not observation_current(db, owner, row, after)):
        result, reason = "INCONCLUSIVE", "Approval or source evidence changed or expired during verification"
    proof = store.append(db, owner, "condition_proof", proof_id, body.expected_proof_revision,
        {"change_id": identifier, "change_revision": row.revision, "change_sha256": row.payload_sha256,
         "predicate_version": p["predicate_version"], "result": result, "reason": reason,
         "requested_rescan_id": body.rescan_id, "before": p["before"], "after": after,
         "observed_at": utcnow().isoformat(), "scope_limit": p["scope_limit"]}, actor, commit=False)
    if task is not None and current(db, owner, row):
        db.add(RemediationVerification(tenant_id=owner, task_id=task.id, rescan_id=after["scan_id"] if after else None,
            result=result, reason=reason, comparison={"condition_proof_id": proof.subject_id, "change_id": identifier,
                "before": p["before"], "after": after}, verified_by=actor, verified_at=utcnow()))
        from remediation.verification import apply_result_to_status
        task.status = apply_result_to_status(result)
    db.commit()
    return proof


def revoke(db, owner, identifier, body, actor):
    row = store.latest(db, owner, "remediation_change", identifier)
    if row.payload["state"] not in {"PROPOSED", "APPROVED", "REPORTED_COMPLETE"}:
        raise HTTPException(409, "Change already revoked")
    return store.append(db, owner, "remediation_change", identifier, body.expected_revision,
        {**row.payload, "state": "REVOKED", "revoked_at": utcnow().isoformat(),
         "revoked_by": actor, "revocation_reason": body.reason, "revocation_evidence_ref": body.evidence_ref}, actor)
