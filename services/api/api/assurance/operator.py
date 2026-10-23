"""Bounded decision read model, exact estate, no aggregate risk score or hidden scope."""
from datetime import datetime, timedelta
from sqlalchemy import func, select
from db.models.base import utcnow
from db.models.assurance import AssuranceRevision
from db.models.remediation_task import RemediationTask
from db.models.scan_job import ScanJob
from db.models.execution_control import ScanApproval, ExecutionAttempt
from db.repositories.execution_control import aware
from shared_models.software_identity import scope_key
from . import store, coverage, remediation


def latest_page(db, owner, kind, offset, limit):
    sub = select(AssuranceRevision.subject_id, func.max(AssuranceRevision.revision).label("rev")).where(
        AssuranceRevision.tenant_id == owner, AssuranceRevision.scope_key == scope_key(owner),
        AssuranceRevision.kind == kind).group_by(AssuranceRevision.subject_id).subquery()
    rows = store.rows(db, AssuranceRevision, owner).join(sub, (AssuranceRevision.subject_id == sub.c.subject_id)
        & (AssuranceRevision.revision == sub.c.rev)).filter(AssuranceRevision.kind == kind).order_by(
            AssuranceRevision.created_at.desc(), AssuranceRevision.id.desc()).offset(offset).limit(limit + 1).all()
    for row in rows:
        store.verify(row)
    return rows[:limit], len(rows) > limit


def inbox(db, owner, offset=0, limit=25):
    now = utcnow()
    sections = {}
    def page(name, model, query, encode):
        rows = query.order_by(model.created_at.desc(), model.id.desc()).offset(offset).limit(limit + 1).all()
        sections[name] = {"items": [encode(r) for r in rows[:limit]], "has_more": len(rows) > limit,
                          "next_offset": offset + limit if len(rows) > limit else None}
    binding = remediation.policy_binding(db, owner)
    task_rows = db.query(RemediationTask).filter(RemediationTask.tenant_id == owner).order_by(
        RemediationTask.created_at.desc(), RemediationTask.id.desc()).offset(offset).limit(limit + 1).all()
    assignments = store.latest_many(db, owner, "remediation_assignment", [t.id for t in task_rows[:limit]])
    changes = store.latest_many(db, owner, "remediation_change", [a.payload["change_id"] for a in assignments.values()])
    proofs = store.latest_many(db, owner, "condition_proof", [store.subject(c.subject_id, "condition_proof") for c in changes.values()])
    items = []
    for t in task_rows[:limit]:
        assignment = assignments.get(t.id)
        change = changes.get(assignment.payload["change_id"]) if assignment else None
        proof = proofs.get(store.subject(change.subject_id, "condition_proof")) if change else None
        observed = bool(t.status == "VERIFIED" and t.owner and change and proof
            and remediation.current(db, owner, change, binding, assignment) and proof.payload["result"] == "VERIFIED"
            and proof.payload.get("after") and remediation.observation_current(db, owner, change, proof.payload["after"])
            and aware(datetime.fromisoformat(proof.payload["after"]["completed_at"]))
                + timedelta(seconds=change.payload["freshness_seconds"]) > now)
        items.append({"id": t.id, "status": t.status, "priority": t.priority, "owner": t.owner or "UNASSIGNED",
            "needs_attention": not observed, "current_condition_verified": observed,
            "condition_proof_id": proof.subject_id if proof else None, "proof_revision": proof.revision if proof else 0,
            "condition_expires_at": (aware(datetime.fromisoformat(proof.payload["after"]["completed_at"]))
                + timedelta(seconds=change.payload["freshness_seconds"])).isoformat() if change and proof and proof.payload.get("after") else None,
            "evidence": {"scan_id": t.scan_id, "evidence_id": t.evidence_id, "finding": t.original_finding},
            "reported_complete": t.completed_at is not None,
            "next_action": "Review scoped retained condition proof; not whole-estate closure" if observed else
                "Assign owner and review current approval/proof; historical task label alone is not current resolution",
            "evidence_freshness": "NOT_ESTABLISHED_BY_TASK_STATUS", "verification_route": "/api/v1/assurance/remediation-changes"})
    sections["tasks"] = {"items": items, "has_more": len(task_rows) > limit,
                         "next_offset": offset + limit if len(task_rows) > limit else None}
    jobs = db.query(ScanJob).filter(ScanJob.tenant_id == owner, ScanJob.status.in_(["FAILED", "UNKNOWN", "DEFERRED", "QUEUED", "RUNNING"]))
    page("jobs", ScanJob, jobs, lambda j: {
        "id": j.id, "status": j.status, "target": j.target_repo, "owner": j.triggered_by,
        "queue_wait_seconds": max(0, (aware(j.started_at or now) - aware(j.created_at)).total_seconds()),
        "execution_seconds": max(0, (aware(j.completed_at or now) - aware(j.started_at)).total_seconds()) if j.started_at else None,
        "stage": (j.progress or {}).get("current_stage"), "error": j.error_message,
        "next_action": "Reconcile external outcome before any retry" if j.status == "UNKNOWN" else
            "Inspect failure and collection coverage; retry only through the original admitted route" if j.status == "FAILED" else
            "Inspect admission, queue and lease; do not assume observation succeeded"})
    def approval(a):
        contract = a.contract or {}
        try:
            expired = aware(datetime.fromisoformat(contract["expires_at"])) <= now
        except (KeyError, TypeError, ValueError):
            expired = True
        reasons = (["REVOKED"] if a.revoked_at else []) + (["EXPIRED_OR_UNKNOWN_EXPIRY"] if expired else [])
        if not binding or binding["revision"] != a.policy_revision or binding["stopped"]:
            reasons.append("POLICY_CHANGED_OR_STOPPED_OR_MISSING")
        if isinstance(contract.get("max_requests"), int) and a.requests_used >= contract["max_requests"]:
            reasons.append("REQUEST_ALLOWANCE_EXHAUSTED")
        try:
            if aware(datetime.fromisoformat(contract["not_before"])) > now:
                reasons.append("NOT_YET_VALID")
        except (KeyError, TypeError, ValueError):
            reasons.append("UNKNOWN_START_WINDOW")
        return {"id": a.id, "owner": a.approved_by, "expires_at": contract.get("expires_at"),
                "admission_eligibility": "NOT_ESTABLISHED_BY_SUMMARY_CREDENTIAL_AND_SCOPE_CHECKS_STILL_REQUIRED",
                "stale_reasons": reasons, "next_action": "Obtain fresh approval; never replay the old grant" if reasons else "Use only within exact approved scope"}
    page("approvals", ScanApproval, db.query(ScanApproval).filter(ScanApproval.tenant_id == owner), approval)
    page("executions", ExecutionAttempt, db.query(ExecutionAttempt).filter(
        ExecutionAttempt.tenant_id == owner, ExecutionAttempt.status.in_(["RUNNING", "UNKNOWN"])), lambda a: {
            "id": a.id, "job_id": a.job_id, "status": a.status, "checkpoint": a.checkpoint,
            "heartbeat_at": aware(a.heartbeat_at).isoformat(), "deadline_at": aware(a.deadline_at).isoformat(),
            "deadline_exceeded": aware(a.deadline_at) <= now, "owner": "execution-operator",
            "next_action": "Inspect durable outcome and fence before recovery; deadline is not proof of cancellation"})
    for kind, name in [("remediation_change", "changes"), ("condition_proof", "proofs")]:
        rows, more = latest_page(db, owner, kind, offset, limit)
        assignments = store.latest_many(db, owner, "remediation_assignment", [r.payload["task_id"] for r in rows if r.payload.get("task_id")]) if kind == "remediation_change" else {}
        proof_changes = store.latest_many(db, owner, "remediation_change", [r.payload["change_id"] for r in rows]) if kind == "condition_proof" else {}
        proof_assignments = store.latest_many(db, owner, "remediation_assignment", [c.payload["task_id"] for c in proof_changes.values() if c.payload.get("task_id")])
        items = []
        for r in rows:
            p = r.payload
            if kind == "remediation_change":
                items.append({"id": r.subject_id, "revision": r.revision, "state": p["state"], "kind": p["kind"],
                    "owner": p["owner_ref"], "change_ref": p["change_ref"], "criteria": p["verification_criteria"],
                    "approval_current": remediation.current(db, owner, r, binding, assignments.get(p.get("task_id"))), "expires_at": p["expires_at"],
                    "condition": {k: p.get(k) for k in ("task_id", "endpoint", "expected_algorithm", "expected_fingerprint_sha256")},
                    "evidence_sha256": r.payload_sha256, "next_action": "Independent rescan then verify; report alone is not closure"})
            else:
                change = proof_changes.get(p["change_id"])
                after = p.get("after")
                expires = (aware(datetime.fromisoformat(after["completed_at"])) + timedelta(seconds=change.payload["freshness_seconds"])) if change and after else None
                is_current = bool(change and expires and expires > now
                    and remediation.current(db, owner, change, binding, proof_assignments.get(change.payload.get("task_id")))
                    and remediation.observation_current(db, owner, change, after))
                items.append({"freshness_state": "WITHIN_APPROVED_WINDOW" if is_current else "STALE_OR_UNAVAILABLE",
                    "condition_expires_at": expires.isoformat() if expires else None,
                    "proof_revision": r.revision, "id": r.subject_id, "change_id": p["change_id"], "change_revision": p["change_revision"],
                    "result": p["result"], "reason": p["reason"], "observed_at": p["observed_at"],
                    "scope_limit": p["scope_limit"], "evidence_sha256": r.payload_sha256})
        sections[name] = {"items": items, "has_more": more, "next_offset": offset + limit if more else None}
    # Five registers per page; all counts are for their independently registered denominators.
    rows, more = latest_page(db, owner, "estate_register", offset, min(limit, 5))
    reports = []
    for r in rows:
        report = coverage.report(db, owner, r.subject_id)
        targets = report.pop("targets")
        report["attention_targets"] = [t for t in targets if t["state"] != "OBSERVED"][:25]
        report["targets_shown"] = len(report["attention_targets"])
        report["full_report_url"] = f"/api/v1/assurance/registers/{r.subject_id}/coverage"
        reports.append(report)
    sections["coverage"] = {"items": reports, "has_more": more, "next_offset": offset + min(limit, 5) if more else None}
    return {"schema": "cryptoscan.operator-decisions/1", "estate_id": owner, "as_of": now.isoformat(),
            "sections": sections, "page_is_whole_estate": False, "offset": offset,
            "uncertainty": "No register means unknown coverage, not zero risk. Source receipts do not establish whole-bank completeness.",
            "reconciliation": "Full SQL read on each poll; replay gaps require refresh, never optimistic completion",
            "cache_policy": "No shared or persistent response cache; all predicates and authority re-evaluated"}
