"""Registered denominators independent of discoveries; freshness from SQL receipts."""
from datetime import datetime, timedelta
from fastapi import HTTPException
from db.models.base import utcnow
from db.models.scan import Scan
from db.models.scan_job import ScanJob
from db.models.assurance import CollectionPhaseReceipt
from db.models.system import System
from db.repositories.execution_control import aware
from . import store


def save_register(db, owner, identifier, body, actor):
    for target in body.targets:
        if target.system_id:
            store.exact(db, System, owner, target.system_id)
    return store.append(db, owner, "estate_register", identifier, body.expected_revision,
                        body.model_dump(mode="json", exclude={"expected_revision"}), actor)


def record(db, owner, register_id, target_id, body, actor):
    register = store.latest(db, owner, "estate_register", register_id)
    target = next((t for t in register.payload["targets"] if t["target_id"] == target_id), None)
    if not target:
        raise HTTPException(404, "Registered target not found")
    identifier = store.subject(register_id, target_id)
    old = store.latest(db, owner, "coverage_observation", identifier, required=False)
    success_at = old.payload.get("last_successful_at") if old and old.payload["target_sha256"] == store.digest(target) else None
    attempted_at = None
    if old and old.payload["target_sha256"] == store.digest(target) and old.payload.get("last_attempted_at"):
        attempted_at = aware(datetime.fromisoformat(old.payload["last_attempted_at"]))
    state = body.outcome
    scope_complete = None
    if body.outcome == "RECEIPT":
        if not body.job_id:
            raise HTTPException(422, "RECEIPT requires a durable job")
        job = store.exact(db, ScanJob, owner, body.job_id)
        attempted_at = aware(job.started_at or job.created_at)
        if attempted_at > utcnow() or job.status in {"QUEUED", "DEFERRED"}:
            raise HTTPException(409, "Job has not attempted collection")
        if target["method"] == "LOCAL_SOURCE":
            if job.target_repo != target["target_ref"] or job.job_type != "MANUAL" or not target["target_ref"].startswith("/"):
                raise HTTPException(409, "Receipt does not identify this registered source/method")
            if job.status == "COMPLETED" and job.scan_id:
                scan = store.exact(db, Scan, owner, job.scan_id)
                if scan.status != "COMPLETED" or scan.target_location != target["target_ref"] or not scan.scan_end:
                    raise HTTPException(409, "Scan completion/target disagrees with the job")
                if not (scan.statistics or {}).get("file_observation_receipts"):
                    raise HTTPException(409, "No parsed source-file receipt; an empty or legacy completed job is not fresh source evidence")
                state, success_at = "OBSERVED", aware(scan.scan_end).isoformat()
                # A successful local source run is not proof that every expected
                # repo/file/export/deployment was present in the target register.
                scope_complete = None
            else:
                state = "BLOCKED"
        elif target["method"].startswith("SSH_"):
            required = {"host_keys", "kex"} if target["method"] == "SSH_HOST_KEYS_KEX" else {"host_keys"}
            phases = db.query(CollectionPhaseReceipt).filter_by(job_id=job.id, tenant_id=owner, endpoint=target["target_ref"]).all()
            phases = [p for p in phases if p.phase in required]
            if {p.phase for p in phases} != required:
                raise HTTPException(409, "No exact endpoint/phase receipt for this collection method")
            scope_complete = all(p.state == "COMPLETED" for p in phases)
            state = "OBSERVED" if scope_complete and all(p.observation_succeeded is True for p in phases) else "BLOCKED"
            attempted = [p for p in phases if p.state not in {"NOT_ATTEMPTED", "REFUSED"}]
            if not attempted:
                raise HTTPException(409, "Receipt records refusal, not an attempted observation")
            if any(not p.started_at for p in attempted):
                raise HTTPException(409, "Phase attempt start provenance is unavailable")
            attempted_at = max(aware(p.started_at) for p in attempted)
            if state == "OBSERVED":
                success_at = max(aware(p.updated_at) for p in phases).isoformat()
        else:
            raise HTTPException(409, "External export needs a qualified import-to-target binding; not inferred from a job")
    elif body.job_id:
        raise HTTPException(422, "Blocked/unsupported declarations must not masquerade as job receipts")
    if success_at and aware(datetime.fromisoformat(success_at)) > utcnow():
        raise HTTPException(409, "A future-dated receipt cannot establish freshness")
    if old and attempted_at and old.payload.get("last_attempted_at") and aware(datetime.fromisoformat(old.payload["last_attempted_at"])) > attempted_at:
        raise HTTPException(409, "Older attempts cannot overwrite the current coverage outcome")
    return store.append(db, owner, "coverage_observation", identifier, body.expected_revision,
        {"register_id": register_id, "register_revision": register.revision, "target_id": target_id,
         "target_sha256": store.digest(target), "state": state,
         "last_attempted_at": attempted_at.isoformat() if attempted_at else None, "last_successful_at": success_at,
         "reported_at": utcnow().isoformat(),
         "collection_complete": scope_complete, "job_id": body.job_id,
         "assertion": "SQL_RECEIPT" if body.outcome == "RECEIPT" else "OPERATOR_DECLARED",
         "evidence_ref": body.evidence_ref, "reason": body.reason}, actor)


def report(db, owner, identifier):
    register = store.latest(db, owner, "estate_register", identifier)
    targets = register.payload["targets"]
    observations = store.latest_many(db, owner, "coverage_observation", [store.subject(identifier, t["target_id"]) for t in targets])
    counts = dict.fromkeys(["OBSERVED", "STALE", "BLOCKED", "UNSUPPORTED", "NOT_ATTEMPTED"], 0)
    by_kind, result = {}, []
    now = utcnow()
    for target in targets:
        row = observations.get(store.subject(identifier, target["target_id"]))
        value = row.payload if row and row.payload["target_sha256"] == store.digest(target) else None
        state = value["state"] if value else "NOT_ATTEMPTED"
        expires_at = None
        if value and value.get("last_successful_at"):
            from datetime import datetime
            expires_at = aware(datetime.fromisoformat(value["last_successful_at"])) + timedelta(seconds=target["freshness_seconds"])
            if state == "OBSERVED" and now >= expires_at:
                state = "STALE"
        counts[state] += 1
        kind = by_kind.setdefault(target["kind"], {"registered": 0, **dict.fromkeys(counts, 0)})
        kind["registered"] += 1
        kind[state] += 1
        result.append({**target, "state": state, "expires_at": expires_at.isoformat() if expires_at else None,
                       "last_attempted_at": value.get("last_attempted_at") if value else None,
                       "last_successful_at": value.get("last_successful_at") if value else None,
                       "receipt": value})
    return {"register_id": identifier, "revision": register.revision, "registered_targets": len(targets),
            "register_completeness": register.payload["completeness"],
            "scope_description": register.payload["scope_description"],
            "completeness_evidence_ref": register.payload["completeness_evidence_ref"],
            "whole_bank_verified": False, "denominator_basis": "REGISTERED_TARGETS_ONLY_NOT_DISCOVERED_ASSETS",
            "completeness_basis": "OWNER_ATTESTATION_NOT_INDEPENDENT_VERIFICATION", "counts": counts,
            "by_kind": by_kind, "targets": result, "as_of": now.isoformat()}
