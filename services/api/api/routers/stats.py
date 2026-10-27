"""Dashboard summary stats."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session
from db.models.evidence_record import EvidenceRecord
from db.models.scan import Scan
from db.repositories.drift_repository import DriftRepository
from db.repositories.evidence_repository import EvidenceRepository

router = APIRouter(prefix="/stats", tags=["stats"])


@router.get("/summary")
def summary(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    # One pass over each table instead of four separate COUNTs: the
    # evidence table is unbounded (every scan appends rows) and this endpoint
    # is polled by several dashboards.
    total_scans = db.execute(select(func.count()).select_from(Scan)).scalar_one()
    total_findings, compliant, failed = db.execute(
        select(
            func.count(),
            func.sum(case((EvidenceRecord.compliance_status == "PASS", 1), else_=0)),
            func.sum(case((EvidenceRecord.compliance_status == "FAIL", 1), else_=0)),
        )
    ).one()
    coverage = {}
    try:
        from db.repositories.system_repository import SystemRepository

        coverage = SystemRepository(db).coverage_summary()
    except Exception:
        coverage = {}
    return {
        "total_scans": int(total_scans),
        "total_findings": int(total_findings or 0),
        "compliant": int(compliant or 0),
        "non_compliant": int(failed or 0),
        "open_drift": DriftRepository(db).open_counts_by_severity(),
        "algorithms": EvidenceRepository(db).algorithm_breakdown(),
        "coverage": coverage,
    }
