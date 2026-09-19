"""Dashboard summary stats."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
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
    total_scans = db.execute(select(func.count()).select_from(Scan)).scalar_one()
    total_findings = db.execute(select(func.count()).select_from(EvidenceRecord)).scalar_one()
    compliant = db.execute(
        select(func.count()).select_from(EvidenceRecord).where(EvidenceRecord.compliance_status == "PASS")
    ).scalar_one()
    failed = db.execute(
        select(func.count()).select_from(EvidenceRecord).where(EvidenceRecord.compliance_status == "FAIL")
    ).scalar_one()
    coverage = {}
    try:
        from db.repositories.system_repository import SystemRepository

        coverage = SystemRepository(db).coverage_summary()
    except Exception:
        coverage = {}
    return {
        "total_scans": int(total_scans),
        "total_findings": int(total_findings),
        "compliant": int(compliant),
        "non_compliant": int(failed),
        "open_drift": DriftRepository(db).open_counts_by_severity(),
        "algorithms": EvidenceRepository(db).algorithm_breakdown(),
        "coverage": coverage,
    }
