"""Automated remediation suggestions: template library, rendered fixes, fix-branch payloads.

Advisory only — compliance verdicts come solely from the policy engine.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from db.tenancy import filtered_get

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session, require_auditor
from api.events.platform_events import emit_platform_event
from db.models.remediation_task import RemediationTask, RemediationVerification
from db.models.scan import Scan
from db.repositories.remediation_repository import (
    RemediationTaskRepository,
    RemediationVerificationRepository,
)

router = APIRouter(prefix="/remediation", tags=["remediation"])


class FixBranchRequest(BaseModel):
    evidence_id: str = Field(..., min_length=1)
    language: str = "python"


def _templates_lib():
    from remediation import templates

    return templates


@router.get("/templates")
def list_templates(user: str = Depends(get_current_user)):
    lib = _templates_lib()
    return {
        "templates": lib.template_catalog(),
        "template_count": len(lib.template_ids()),
        "snippet_count": lib.snippet_count(),
        "languages": lib.languages(),
        "guides": sorted(lib._GUIDES),
    }


@router.get("/templates/{rule_id}")
def template_detail(rule_id: str, user: str = Depends(get_current_user)):
    lib = _templates_lib()
    rendered = lib.render(rule_id, "python")
    if rendered is None:
        raise HTTPException(status_code=404, detail=f"no template for rule '{rule_id}'")
    return rendered


@router.get("/scans/{scan_id}/suggestions")
def scan_suggestions(
    scan_id: str,
    language: str = "python",
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Deterministic suggestions for a scan, each with the rendered fix."""
    from db.repositories.evidence_repository import EvidenceRepository
    from db.repositories.scan_repository import ScanRepository
    from remediation.engine import suggest_remediations

    if ScanRepository(db).get_by_id(scan_id) is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    findings = [
        {
            "evidence_id": row.id,
            "algorithm": row.algorithm,
            "purpose": row.purpose,
            "mode": row.mode,
            "key_size": row.key_size,
            "file_path": row.file_path,
            "line_number": row.line_number,
            "compliance_status": row.compliance_status,
            "is_hardcoded_key": row.is_hardcoded_key,
        }
        for row in EvidenceRepository(db).get_all_for_scan(scan_id, include_deleted=False)
    ]
    report = suggest_remediations(findings)
    lib = _templates_lib()
    for suggestion in report["suggestions"]:
        rendered = lib.render(suggestion["rule"], language)
        if rendered is not None:
            suggestion["fix"] = rendered
        else:
            suggestion["fix"] = None  # manual-review: no template, honest
    report["language"] = language
    return report


@router.post("/fix-branch")
def fix_branch(
    body: FixBranchRequest,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Generate a fix-branch payload for one finding (no push happens here)."""
    from remediation.engine import _rule_for, _normalize
    from remediation.templates import fix_branch_payload

    from db.models.evidence_record import EvidenceRecord

    row = filtered_get(db, EvidenceRecord, body.evidence_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Evidence record not found")
    if row.deleted_at is not None:
        # retracted evidence must not generate new fix suggestions
        raise HTTPException(status_code=409, detail="Evidence record is retracted (soft-deleted)")
    finding = {
        "algorithm": row.algorithm,
        "purpose": row.purpose,
        "mode": row.mode,
        "key_size": row.key_size,
        "file_path": row.file_path,
        "line_number": row.line_number,
        "compliance_status": row.compliance_status,
        "is_hardcoded_key": row.is_hardcoded_key,
    }
    rule = _rule_for(finding) or {
        "rule": "manual-review",
        "replace_with": "review",
        "guidance": "Review this primitive against the current policy pack.",
        "category": "UNKNOWN",
        "priority": "P3",
        "effort": "low",
    }
    suggestion = {
        **finding,
        "algorithm": _normalize(finding.get("algorithm")) if finding.get("algorithm") else finding.get("algorithm"),
        "rule": rule["rule"],
        "category": rule["category"],
        "priority": rule["priority"],
        "replace_with": rule["replace_with"],
        "evidence_id": row.id,
    }
    return fix_branch_payload(suggestion, language=body.language)


# --------------------------------------------------------------------------- #
# Task tracking + evidence-based verification (audit 62 / GAP-006)
# --------------------------------------------------------------------------- #
# Suggestions say what to do; tasks prove it got done. A task snapshots the
# non-compliant finding at creation, and completion automatically verifies the
# remediation against rescan evidence — VERIFIED / PARTIAL / FAILED /
# REGRESSION / INCONCLUSIVE — instead of trusting a human "done" checkbox.
# The comparison itself lives in remediation.verification (pure, testable).


class TaskCreateRequest(BaseModel):
    evidence_id: str = Field(..., min_length=1)
    owner: str | None = None
    notes: str | None = None


class TaskCompleteRequest(BaseModel):
    rescan_id: str | None = None
    notes: str | None = None


class TaskVerifyRequest(BaseModel):
    rescan_id: str | None = None


def _task_repo(db: Session) -> RemediationTaskRepository:
    return RemediationTaskRepository(db)


def _verification_repo(db: Session) -> RemediationVerificationRepository:
    return RemediationVerificationRepository(db)


def _finding_snapshot(row) -> dict[str, Any]:
    return {
        "evidence_id": row.id,
        "algorithm": row.algorithm,
        "purpose": row.purpose,
        "mode": row.mode,
        "key_size": row.key_size,
        "file_path": row.file_path,
        "line_number": row.line_number,
        "compliance_status": row.compliance_status,
        "is_hardcoded_key": bool(row.is_hardcoded_key),
    }


def _rule_snapshot(finding: dict[str, Any]) -> dict[str, Any]:
    from remediation.engine import _rule_for

    return _rule_for(finding) or {
        "rule": "manual-review", "replace_with": "review",
        "category": "UNKNOWN", "priority": "P3", "effort": "low",
    }


def _task_out(task: RemediationTask, latest: RemediationVerification | None = None) -> dict[str, Any]:
    out = task.to_dict(exclude={"original_finding"})
    out["original_finding"] = task.original_finding
    if latest is not None:
        out["latest_verification"] = {
            "id": latest.id, "result": latest.result, "reason": latest.reason,
            "rescan_id": latest.rescan_id, "verified_by": latest.verified_by,
            "verified_at": latest.verified_at.isoformat() if latest.verified_at else None,
        }
    return out


def _verification_out(row: RemediationVerification) -> dict[str, Any]:
    out = row.to_dict()
    if isinstance(out.get("verified_at"), datetime):
        out["verified_at"] = out["verified_at"].isoformat()
    return out


@router.post("/tasks")
def create_task(
    body: TaskCreateRequest,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Track the remediation of one finding; snapshots it for later proof."""
    from db.models.evidence_record import EvidenceRecord

    row = filtered_get(db, EvidenceRecord, body.evidence_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Evidence record not found")
    if row.deleted_at is not None:
        raise HTTPException(status_code=409, detail="Evidence record is retracted (soft-deleted)")
    scan = filtered_get(db, Scan, row.scan_id)
    if scan is None:
        raise HTTPException(status_code=400, detail="Owning scan not found — cannot track verification target")
    finding = _finding_snapshot(row)
    rule = _rule_snapshot(finding)
    task = _task_repo(db).create(RemediationTask(
        evidence_id=row.id,
        scan_id=row.scan_id,
        rule_id=rule["rule"],
        category=rule.get("category"),
        priority=rule.get("priority"),
        replace_with=rule.get("replace_with"),
        original_finding=finding,
        target_location=scan.target_location,
        status="PROPOSED",
        owner=body.owner,
        notes=body.notes,
        created_by=user,
    ))
    emit_platform_event(
        "remediation.task_created",
        f"Remediation task proposed for {finding.get('algorithm')} at "
        f"{finding.get('file_path')}:{finding.get('line_number')} (rule {rule['rule']})",
        {"task_id": task.id, "evidence_id": row.id, "scan_id": row.scan_id,
         "rule": rule["rule"], "status": task.status},
        target_name="remediation",
    )
    return _task_out(task)


@router.get("/tasks")
def list_tasks(
    status: str | None = None,
    scan_id: str | None = None,
    owner: str | None = None,
    page: int = 1,
    page_size: int = 50,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    tasks, total = _task_repo(db).list_tasks(
        status=status, scan_id=scan_id, owner=owner, page=page, page_size=page_size)
    verifications = _verification_repo(db)
    return {
        "tasks": [_task_out(t, verifications.latest_for_task(t.id)) for t in tasks],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get("/tasks/{task_id}")
def get_task(
    task_id: str,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    task = filtered_get(db, RemediationTask, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    return _task_out(task, _verification_repo(db).latest_for_task(task.id))


@router.post("/tasks/{task_id}/accept")
def accept_task(
    task_id: str,
    user: str = Depends(require_auditor),
    db: Session = Depends(get_db_session),
):
    task = filtered_get(db, RemediationTask, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    if task.status != "PROPOSED":
        raise HTTPException(status_code=409, detail=f"Task in status {task.status}; only PROPOSED tasks can be accepted")
    task.status = "ACCEPTED"
    db.commit()
    emit_platform_event(
        "remediation.task_accepted",
        f"Remediation task {task.id} accepted for work by {user}",
        {"task_id": task.id, "status": task.status, "accepted_by": user},
        target_name="remediation",
    )
    return _task_out(task, _verification_repo(db).latest_for_task(task.id))


def _run_verification(
    db: Session, task: RemediationTask, rescan_id: str | None, user: str,
) -> RemediationVerification:
    """Compare the task's finding against rescan evidence; persist the proof."""
    from db.repositories.evidence_repository import EvidenceRepository
    from remediation.verification import verify_remediation

    evidence_repo = EvidenceRepository(db)
    rule = {"rule": task.rule_id, "replace_with": task.replace_with,
            "category": task.category, "priority": task.priority}

    rescan: Scan | None = None
    if rescan_id:
        rescan = filtered_get(db, Scan, rescan_id)
        if rescan is None:
            raise HTTPException(status_code=404, detail="Rescan not found")
        if task.target_location and rescan.target_location != task.target_location:
            raise HTTPException(
                status_code=400,
                detail="Rescan target does not match the task's target — verification compares like with like")
    elif task.target_location:
        # proof must be newer evidence than the finding came from: the latest
        # completed scan of the same target after the ORIGINAL scan (falling
        # back to task creation when the original scan row was pruned)
        original_scan = filtered_get(db, Scan, task.scan_id)
        after = original_scan.scan_start if original_scan is not None else task.created_at
        rescan = _task_repo(db).latest_completed_scan_after(task.target_location, after)

    rescan_findings = None
    if rescan is not None:
        rescan_findings = [_finding_snapshot(r) for r in evidence_repo.get_all_for_scan(rescan.id)]
        if not rescan_findings:
            rescan_findings = None  # scan produced nothing → INCONCLUSIVE, not "fixed"

    original_findings = [_finding_snapshot(r) for r in evidence_repo.get_all_for_scan(task.scan_id)]
    if not original_findings:
        original_findings = None  # pruned: fall back to file-scoped regression checks

    verdict = verify_remediation(
        task.original_finding, rule, rescan_findings, original_findings)
    if rescan is not None and rescan_findings is None:
        verdict["reason"] = (
            "rescan produced no evidence for the target — scan may have failed "
            "or scanned nothing") + f" (rescan {rescan.id})"

    verification = _verification_repo(db).create(RemediationVerification(
        task_id=task.id,
        rescan_id=rescan.id if rescan is not None else rescan_id,
        result=verdict["result"],
        reason=verdict["reason"],
        comparison={
            **verdict["comparison"],
            "rule": rule,
            "rescan_status": rescan.status if rescan is not None else None,
        },
        verified_by=user,
        verified_at=datetime.now(timezone.utc),
    ))
    from remediation.verification import apply_result_to_status

    task.status = apply_result_to_status(verdict["result"])
    db.commit()
    emit_platform_event(
        "remediation.task_verified",
        f"Remediation task {task.id} verification: {verdict['result']}",
        {"task_id": task.id, "result": verdict["result"], "reason": verdict["reason"],
         "rescan_id": verification.rescan_id, "task_status": task.status,
         "verified_by": user},
        target_name="remediation",
    )
    return verification


@router.post("/tasks/{task_id}/complete")
def complete_task(
    task_id: str,
    body: TaskCompleteRequest,
    user: str = Depends(require_auditor),
    db: Session = Depends(get_db_session),
):
    """Mark the work done — verification runs automatically against the
    latest rescan of the same target (or the given ``rescan_id``)."""
    task = filtered_get(db, RemediationTask, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    if task.status not in ("ACCEPTED", "PROPOSED"):
        raise HTTPException(status_code=409, detail=f"Task in status {task.status}; only ACCEPTED tasks can be completed")
    task.status = "COMPLETED"
    task.completed_at = datetime.now(timezone.utc)
    task.completed_by = user
    if body.notes:
        task.notes = (task.notes or "") + f"\n{body.notes}"
    db.commit()
    emit_platform_event(
        "remediation.task_completed",
        f"Remediation task {task.id} marked completed by {user}; verifying against rescan evidence",
        {"task_id": task.id, "status": task.status, "rescan_id": body.rescan_id},
        target_name="remediation",
    )
    verification = _run_verification(db, task, body.rescan_id, user)
    return _task_out(task, verification)


@router.post("/tasks/{task_id}/verify")
def verify_task(
    task_id: str,
    body: TaskVerifyRequest,
    user: str = Depends(require_auditor),
    db: Session = Depends(get_db_session),
):
    """Re-run verification (e.g. after a fresh rescan) — appends a new proof."""
    task = filtered_get(db, RemediationTask, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    if task.status not in ("COMPLETED", "VERIFIED", "PARTIAL", "FAILED", "REGRESSION"):
        raise HTTPException(status_code=409, detail=f"Task in status {task.status}; complete it before verifying")
    verification = _run_verification(db, task, body.rescan_id, user)
    return _task_out(task, verification)


@router.get("/verifications")
def list_verifications(
    task_id: str | None = None,
    result: str | None = None,
    page: int = 1,
    page_size: int = 50,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    rows, total = _verification_repo(db).list_verifications(
        task_id=task_id, result=result, page=page, page_size=page_size)
    return {
        "verifications": [_verification_out(r) for r in rows],
        "total": total,
        "page": page,
        "page_size": page_size,
    }
