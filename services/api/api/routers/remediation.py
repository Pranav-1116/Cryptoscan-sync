"""Automated remediation suggestions: template library, rendered fixes, fix-branch payloads.

Advisory only — compliance verdicts come solely from the policy engine.
"""

from __future__ import annotations

from db.tenancy import filtered_get

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session

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
        for row in EvidenceRepository(db).get_all_for_scan(scan_id)
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
