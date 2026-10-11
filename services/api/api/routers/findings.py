"""Findings endpoints."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from functools import lru_cache
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.dependencies import (
    get_current_user,
    get_db_session,
    get_evidence_repository,
    require_auditor,
)
from api.schemas.finding_schemas import FindingListResponse, FindingResponse
from api.security.evidence_projection import project_finding
from db.repositories.evidence_repository import EvidenceRepository

router = APIRouter(tags=["findings"])
logger = logging.getLogger(__name__)


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
        deleted_at=getattr(row, "deleted_at", None),
        deleted_by=getattr(row, "deleted_by", None),
        delete_reason=getattr(row, "delete_reason", None),
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

@router.get("/findings/corroboration")
def finding_corroboration(
    scan_id: str = Query(..., description="Scan whose observations are checked for agreement"),
    compare_scan_id: str | None = Query(
        None, description="Optional second scan: agreement across the two scans instead"),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Where independent observers of the same site AGREE (audit 49 P1#5).

    The complementary surface to /findings/conflicts: same normalized
    algorithm and parameters, observed by >= 2 distinct scanners, with a
    tier-aware *suggested* confidence uplift — annotation only, recorded
    confidence is never rewritten. Retracted evidence never corroborates.
    """
    from normalization.corroboration import corroboration_summary

    from db.models.scan import Scan

    def _scan_exists(scan_id_value: str) -> bool:
        return db.execute(
            select(Scan).where(Scan.id == scan_id_value).limit(1)
        ).scalars().first() is not None

    if not _scan_exists(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")
    repo = EvidenceRepository(db)

    def _view(row) -> dict:
        # same observer resolution as the scorecard surface: provenance
        # and finding-source identity become the scanner id so
        # independence is judged on real observer names
        from normalization.calibration import UNATTRIBUTED, detector_key

        base = {
            "algorithm": row.algorithm,
            "key_size": row.key_size,
            "mode": row.mode,
            "file_path": row.file_path,
            "line_number": row.line_number,
            "compliance_status": row.compliance_status,
            "scanner_ids": (row.scanner_ids or []) if hasattr(row, "scanner_ids") else [],
            "provenance": row.provenance,
            "finding_data": row.finding_data,
        }
        key = detector_key(base)
        if key != UNATTRIBUTED:
            base["scanner_ids"] = [key]
        return base

    # retracted evidence must not corroborate either
    baseline = [_view(r) for r in repo.get_all_for_scan(scan_id, include_deleted=False)]
    if compare_scan_id:
        if not _scan_exists(compare_scan_id):
            raise HTTPException(status_code=404, detail="Comparison scan not found")
        current = [_view(r) for r in repo.get_all_for_scan(compare_scan_id, include_deleted=False)]
        # cross-scan corroboration: stamp which scan each view came from
        # so observers from the two scans stay distinct even when both
        # fall back to unknown-observer
        for view in baseline:
            view.setdefault("scan_ids", [scan_id])
        for view in current:
            view.setdefault("scan_ids", [compare_scan_id])
        observations = baseline + current
    else:
        observations = baseline

    summary = corroboration_summary(observations)
    summary["scan_id"] = scan_id
    summary["compare_scan_id"] = compare_scan_id
    return summary


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
    # retracted (soft-deleted) evidence must not manufacture conflicts
    baseline = [_view(r) for r in repo.get_all_for_scan(scan_id, include_deleted=False)]
    if compare_scan_id:
        if not _scan_exists(compare_scan_id):
            raise HTTPException(status_code=404, detail="Comparison scan not found")
        current = [_view(r) for r in repo.get_all_for_scan(compare_scan_id, include_deleted=False)]
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


@router.get("/findings/detectors/scorecards")
def detector_scorecards(
    scan_limit: int = Query(25, ge=1, le=200,
                            description="How many most-recent scans calibrate over"),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Per-detector calibration scorecards (audit 49 P0#4, round 28).

    Production has no labeled ground truth, so calibration is measured
    through the two honest proxies the platform records: retractions
    (soft-deleted evidence — operator-judged false positives) and
    authority losses (the non-preferred side of decisive observation
    conflicts under the 6-tier hierarchy). Annotation only — recorded
    confidence is never rewritten.

    Tombstones COUNT (they are the retraction signal) but never feed
    conflict detection, so a retraction cannot manufacture a conflict.
    """
    from normalization.calibration import (UNATTRIBUTED, detector_key,
                                           detector_scorecards as score)
    from normalization.conflicts import detect_conflicts

    from db.models.scan import Scan

    scan_rows = db.execute(
        select(Scan).order_by(Scan.scan_start.desc()).limit(scan_limit)
    ).scalars().all()
    if not scan_rows:
        return {"detectors": [], "detector_count": 0, "tier_counts": {},
                "scans_considered": 0, "observations": 0,
                "method": {"note": "no scans yet — nothing to calibrate"}}

    repo = EvidenceRepository(db)

    def _view(row) -> dict:
        # EvidenceRecord has no scanner_ids column — the observer identity
        # lives in the provenance / finding-source JSON. Resolve it once so
        # both the scorecard grouping and the conflict detector see the
        # same observer name (authority tokens read scanner_ids).
        base = {
            "algorithm": row.algorithm,
            "key_size": row.key_size,
            "mode": row.mode,
            "file_path": row.file_path,
            "line_number": row.line_number,
            "compliance_status": row.compliance_status,
            "scanner_ids": (row.scanner_ids or []) if hasattr(row, "scanner_ids") else [],
            "provenance": row.provenance,
            "finding_data": row.finding_data,
            "deleted": row.deleted_at is not None,
        }
        key = detector_key(base)
        if key != UNATTRIBUTED:
            base["scanner_ids"] = [key]
        return base

    views: list[dict] = []
    conflicts: list[dict] = []
    for scan in scan_rows:
        # tombstones included: retraction is the FP proxy being measured
        views.extend(_view(r) for r in repo.get_all_for_scan(scan.id, include_deleted=True))
        # tombstones excluded: retracted evidence must not manufacture conflicts
        live = [_view(r) for r in repo.get_all_for_scan(scan.id, include_deleted=False)]
        conflicts.extend(detect_conflicts(live))

    result = score(views, conflicts)
    result["scans_considered"] = len(scan_rows)
    result["observations"] = len(views)
    return result


@lru_cache(maxsize=1)
def _corpus_benchmark() -> tuple:
    """Run the labeled accuracy corpus once per process (hermetic, deterministic)."""
    import importlib.util
    import sys
    from pathlib import Path

    bench = Path(__file__).resolve().parents[4] / "scripts" / "accuracy_benchmark.py"
    spec = importlib.util.spec_from_file_location("accuracy_benchmark_runtime", bench)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["accuracy_benchmark_runtime"] = mod
    spec.loader.exec_module(mod)
    report = mod.run()
    return (report,)


@router.get("/findings/detectors/labeled-calibration")
def labeled_detector_calibration(
    user: str = Depends(get_current_user),
):
    """Labeled ground-truth calibration (audits 49 P0#4 + 52, round 34).

    Per-detector TP/FP/precision measured against the hand-labeled
    accuracy corpus — every case carries the exact algorithm families a
    correct scanner must report, and hard negatives label any report as a
    false positive. Misses stay scanner-level (which detector *should*
    have seen a family is a coverage question, so per-detector recall is
    never fabricated).

    Deliberately separate from `GET /findings/detectors/scorecards`:
    that surface calibrates over production traffic through honest
    proxies (retractions, authority losses); this one measures against
    fixed ground truth. Both views, not either alone.
    """
    from scanner.labeled_calibration import labeled_detector_metrics

    report = _corpus_benchmark()[0]
    calibration = labeled_detector_metrics(report.get("cases") or [])
    calibration["corpus_overall"] = report.get("overall")
    return calibration


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


class SoftDeleteRequest(BaseModel):
    """Retraction request: a reason is mandatory (audit trail, report 15 §6.2)."""

    reason: str = Field(..., min_length=3, description="Why this finding is being retracted")


@router.post("/findings/{evidence_id}/soft-delete", response_model=FindingResponse)
def soft_delete_finding(
    evidence_id: str,
    body: SoftDeleteRequest,
    user: str = Depends(require_auditor),
    repo: EvidenceRepository = Depends(get_evidence_repository),
    db: Session = Depends(get_db_session),
):
    """Retract one finding without breaking the scan's hash chain.

    Marks the evidence row as a tombstone (deleted_at / deleted_by /
    delete_reason). Chain verification and exports still see the row — the
    chain it committed to stays intact — while consumption surfaces
    (listings, CBOM generation, conflicts, drift, remediation suggestions)
    stop counting it. Auditor-only. Deleting an already-retracted row
    returns 409 with the existing tombstone info.
    """
    row = repo.get_by_id(evidence_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    if row.deleted_at is not None:
        raise HTTPException(
            status_code=409,
            detail=f"Finding already retracted by {row.deleted_by} at {row.deleted_at.isoformat()}",
        )
    row.deleted_at = datetime.now(timezone.utc)
    row.deleted_by = user[:100]
    row.delete_reason = body.reason
    try:
        from db.repositories.user_repository import UserRepository

        UserRepository(db).audit(
            user,
            "evidence.soft_delete",
            target_type="evidence",
            target_id=str(row.id),
            detail={"scan_id": row.scan_id, "reason": body.reason},
        )
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("evidence_soft_delete_audit_failed", extra={"evidence_id": evidence_id})
        raise HTTPException(status_code=503, detail="Evidence retraction audit is unavailable")
    return _to_response(row, include_raw=True)


@router.post("/findings/{evidence_id}/restore", response_model=FindingResponse)
def restore_finding(
    evidence_id: str,
    user: str = Depends(require_auditor),
    repo: EvidenceRepository = Depends(get_evidence_repository),
    db: Session = Depends(get_db_session),
):
    """Reverse a retraction: clears the tombstone, the row re-enters consumption.

    The retraction's audit entry stays in the hash-chained log — undoing a
    tombstone remains visible as a past action. Auditor-only. 409 if the
    finding is not currently retracted.
    """
    row = repo.get_by_id(evidence_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    if row.deleted_at is None:
        raise HTTPException(status_code=409, detail="Finding is not retracted")
    prior = {"deleted_at": row.deleted_at.isoformat(), "deleted_by": row.deleted_by}
    row.deleted_at = None
    row.deleted_by = None
    row.delete_reason = None
    try:
        from db.repositories.user_repository import UserRepository

        UserRepository(db).audit(
            user,
            "evidence.restore",
            target_type="evidence",
            target_id=str(row.id),
            detail={"scan_id": row.scan_id, "prior_tombstone": prior},
        )
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("evidence_restore_audit_failed", extra={"evidence_id": evidence_id})
        raise HTTPException(status_code=503, detail="Evidence restore audit is unavailable")
    return _to_response(row, include_raw=True)

