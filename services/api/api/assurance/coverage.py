"""Registered denominators independent of discoveries; freshness from SQL receipts."""
from datetime import datetime, timedelta
from pathlib import PurePosixPath
from fastapi import HTTPException
from db.models.base import utcnow
from db.models.scan import Scan
from db.models.scan_job import ScanJob
from db.models.assurance import CollectionPhaseReceipt
from db.models.system import System
from db.repositories.execution_control import aware
from . import store


# Same bound as the source scanner's primary-file receipt collector. A receipt
# validates observed primary files, never all files/imports or the whole estate.
_MAX_SOURCE_RECEIPTS = 1000


def _source_completion(job, scan, target_ref, now):
    """Validate current SQL identity, interval and actual parsed-file evidence.

    Used both at intake and on current reads so legacy/invalidated receipts
    cannot remain a green coverage claim merely because their history is intact.
    """
    if (job is None or scan is None or job.scan_id != scan.id
            or job.status != "COMPLETED" or job.job_type != "MANUAL"
            or job.target_repo != target_ref or not target_ref.startswith("/") or scan.status != "COMPLETED"
            or scan.target_location != target_ref
            or not job.started_at or not job.completed_at or not scan.scan_start or not scan.scan_end):
        raise HTTPException(409, "Completed source scan and exact durable job binding required")
    if not aware(job.started_at) <= aware(scan.scan_start) <= aware(scan.scan_end) <= aware(job.completed_at) <= now:
        raise HTTPException(409, "Invalid or future-dated source/job observation interval")
    stats = scan.statistics if isinstance(scan.statistics, dict) else {}
    receipts = stats.get("file_observation_receipts")
    if not isinstance(receipts, list) or not 1 <= len(receipts) <= _MAX_SOURCE_RECEIPTS:
        raise HTTPException(409, "Bounded parsed source-file receipts required")
    files, parsed = set(), False
    for receipt in receipts:
        if not isinstance(receipt, dict):
            raise HTTPException(409, "Invalid source-file receipt")
        name, sha = receipt.get("file"), receipt.get("sha256")
        if (not isinstance(name, str) or not name or "\x00" in name
                or PurePosixPath(name).is_absolute() or ".." in PurePosixPath(name).parts
                or PurePosixPath(name).as_posix() != name or name == "." or name in files
                or not isinstance(sha, str) or len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha)
                or type(receipt.get("parser_completed")) is not bool):
            raise HTTPException(409, "Source-file identity, checksum and parser outcome must be unambiguous")
        files.add(name)
        parsed |= receipt["parser_completed"] is True
    if not parsed:
        raise HTTPException(409, "No completed source-file parser receipt; an empty or legacy completed job is not fresh source evidence")
    return aware(scan.scan_end)


def _current_source_jobs(db, owner, targets, observations, identifier):
    """Batch current proof lookup; no per-target SQL growth for a register."""
    job_ids = set()
    for target in targets:
        row = observations.get(store.subject(identifier, target["target_id"]))
        if (target["method"] == "LOCAL_SOURCE" and row and row.payload["state"] == "OBSERVED"
                and row.payload["target_sha256"] == store.digest(target)):
            job_ids.add(row.payload.get("job_id"))
    job_ids.discard(None)
    if not job_ids:
        return {}, {}
    jobs = {j.id: j for j in db.query(ScanJob).filter(ScanJob.tenant_id == owner, ScanJob.id.in_(job_ids)).all()}
    scan_ids = {j.scan_id for j in jobs.values() if j.scan_id}
    scans = {s.id: s for s in db.query(Scan).filter(Scan.tenant_id == owner, Scan.id.in_(scan_ids)).all()} if scan_ids else {}
    return jobs, scans


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
                completed = _source_completion(job, scan, target["target_ref"], utcnow())
                state, success_at = "OBSERVED", completed.isoformat()
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
    jobs, scans = _current_source_jobs(db, owner, targets, observations, identifier)
    for target in targets:
        row = observations.get(store.subject(identifier, target["target_id"]))
        value = row.payload if row and row.payload["target_sha256"] == store.digest(target) else None
        state = value["state"] if value else "NOT_ATTEMPTED"
        if state == "OBSERVED" and target["method"] == "LOCAL_SOURCE":
            job = jobs.get(value.get("job_id"))
            scan = scans.get(job.scan_id) if job else None
            completed = _source_completion(job, scan, target["target_ref"], now)
            if (value.get("assertion") != "SQL_RECEIPT"
                    or value.get("last_successful_at") != completed.isoformat()
                    or value.get("last_attempted_at") != aware(job.started_at).isoformat()):
                raise HTTPException(409, "Current source receipt disagrees with retained coverage; record a new valid observation")
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
