"""Findings endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session, get_evidence_repository
from api.schemas.finding_schemas import FindingListResponse, FindingResponse
from api.security.evidence_projection import project_finding
from db.repositories.evidence_repository import EvidenceRepository

router = APIRouter(tags=["findings"])


def _to_response(row, include_raw: bool = False) -> FindingResponse:
    finding_data, redacted = project_finding(row.finding_data) if include_raw else (None, False)
    return FindingResponse(
        evidence_id=row.id,
        scan_id=row.scan_id,
        algorithm=row.algorithm,
        key_size=row.key_size,
        mode=row.mode,
        padding=row.padding,
        purpose=row.purpose,
        confidence=row.confidence,
        is_hardcoded_key=row.is_hardcoded_key,
        file_path=row.file_path,
        line_number=row.line_number,
        class_name=row.class_name,
        method_name=row.method_name,
        compliance_status=row.compliance_status,
        content_hash=row.content_hash,
        chain_hash=row.chain_hash,
        normalized_crypto=row.normalized_crypto,
        policy_evaluation=row.policy_evaluation,
        finding_data=finding_data,
        redacted_projection=redacted,
        created_at=getattr(row, "created_at", None),
        updated_at=getattr(row, "updated_at", None),
    )


@router.get("/scans/{scan_id}/findings", response_model=FindingListResponse)
def list_findings(
    scan_id: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    algorithm: str | None = None,
    compliance_status: str | None = None,
    hardcoded_only: bool = False,
    user: str = Depends(get_current_user),
    repo: EvidenceRepository = Depends(get_evidence_repository),
):
    rows, total = repo.list_for_scan(
        scan_id,
        algorithm=algorithm,
        compliance_status=compliance_status,
        hardcoded_only=hardcoded_only,
        page=page,
        page_size=page_size,
    )
    return FindingListResponse(
        findings=[_to_response(r) for r in rows],
        total_count=total,
        page=page,
        page_size=page_size,
    )


@router.get("/findings", response_model=FindingListResponse)
def list_all_findings(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    algorithm: str | None = None,
    compliance_status: str | None = None,
    scan_id: str | None = Query(None, description="Restrict to a single scan"),
    user: str = Depends(get_current_user),
    repo: EvidenceRepository = Depends(get_evidence_repository),
):
    rows, total = repo.list_all(
        algorithm=algorithm,
        compliance_status=compliance_status,
        scan_id=scan_id,
        page=page,
        page_size=page_size,
    )
    return FindingListResponse(
        findings=[_to_response(r) for r in rows],
        total_count=total,
        page=page,
        page_size=page_size,
    )


# --------------------------------------------------------------------------- #
# Observation conflicts (audit 50) — disagreement between observers, surfaced
# --------------------------------------------------------------------------- #

@router.get("/findings/conflicts")
def finding_conflicts(
    scan_id: str = Query(..., description="Scan whose observations are checked against each other"),
    compare_scan_id: str | None = Query(
        None, description="Optional second scan: conflicts between the two scans instead"),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Where observers of the same site disagree: algorithm, parameters, or verdict.

    Within one scan this is scanner-vs-scanner disagreement; with
    ``compare_scan_id`` it is scan-vs-scan (the honest replacement for
    "trust the newest"). Conflicts are reported, never auto-resolved —
    resolution is a human/policy decision, this endpoint just refuses to
    keep the disagreement invisible.
    """
    from normalization.conflicts import detect_conflicts, detect_cross_scan_conflicts

    from db.models.scan import Scan

    def _view(row) -> dict:
        return {
            "algorithm": row.algorithm,
            "key_size": row.key_size,
            "mode": row.mode,
            "file_path": row.file_path,
            "line_number": row.line_number,
            "compliance_status": row.compliance_status,
            "scanner_ids": (row.scanner_ids or []) if hasattr(row, "scanner_ids") else [],
        }

    def _scan_exists(scan_id_value: str) -> bool:
        return db.execute(
            select(Scan).where(Scan.id == scan_id_value).limit(1)
        ).scalars().first() is not None

    if not _scan_exists(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")

    repo = EvidenceRepository(db)
    baseline = [_view(r) for r in repo.get_all_for_scan(scan_id)]
    if compare_scan_id:
        if not _scan_exists(compare_scan_id):
            raise HTTPException(status_code=404, detail="Comparison scan not found")
        current = [_view(r) for r in repo.get_all_for_scan(compare_scan_id)]
        conflicts = detect_cross_scan_conflicts(
            baseline, current, baseline_scan_id=scan_id, current_scan_id=compare_scan_id)
    else:
        conflicts = detect_conflicts(baseline)

    by_type: dict[str, int] = {}
    for c in conflicts:
        by_type[c["conflict_type"]] = by_type.get(c["conflict_type"], 0) + 1
    return {
        "scan_id": scan_id,
        "compare_scan_id": compare_scan_id,
        "conflicts": conflicts,
        "conflict_count": len(conflicts),
        "by_type": by_type,
    }


@router.get("/findings/{evidence_id}", response_model=FindingResponse)
def get_finding(
    evidence_id: str,
    user: str = Depends(get_current_user),
    repo: EvidenceRepository = Depends(get_evidence_repository),
):
    row = repo.get_by_id(evidence_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return _to_response(row, include_raw=True)

