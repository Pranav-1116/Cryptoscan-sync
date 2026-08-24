"""
Statistics router.
Aggregated metrics for the dashboard home page.
"""
from __future__ import annotations

import logging
from typing import Annotated, Dict, List

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from api.dependencies import get_current_user, get_db_session
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/stats", tags=["statistics"])


# ---------------------------------------------------------------------------
# Response Schemas
# ---------------------------------------------------------------------------

class AlgorithmStat(BaseModel):
    algorithm: str
    total_findings: int
    compliant: int
    non_compliant: int
    compliance_pct: float


class DriftSeverityStat(BaseModel):
    severity: str
    open_count: int


class SummaryStatsResponse(BaseModel):
    total_scans: int
    total_findings: int
    compliant_findings: int
    non_compliant_findings: int
    compliance_percentage: float
    open_drift_events: int
    critical_drift_events: int
    high_drift_events: int
    medium_drift_events: int
    algorithm_breakdown: List[AlgorithmStat]
    drift_by_severity: List[DriftSeverityStat]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get(
    "/summary",
    response_model=SummaryStatsResponse,
    summary="Get dashboard summary statistics",
)
async def get_summary_stats(
    current_user: Annotated[str, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db_session),
) -> SummaryStatsResponse:
    """
    Return aggregated statistics for the dashboard home page.
    Queries are optimised with indexed columns (compliance_status, algorithm).
    """
    # Total scans
    result = await db.execute(text("SELECT COUNT(*) FROM scans WHERE status = 'COMPLETED'"))
    total_scans: int = result.scalar() or 0

    # Finding counts
    result = await db.execute(text("""
        SELECT
            COUNT(*) AS total,
            COUNT(*) FILTER (WHERE compliance_status = 'PASS') AS compliant,
            COUNT(*) FILTER (WHERE compliance_status = 'FAIL') AS non_compliant
        FROM evidence_records
    """))
    row = result.fetchone()
    total_findings = row.total or 0
    compliant = row.compliant or 0
    non_compliant = row.non_compliant or 0
    compliance_pct = round((compliant / total_findings * 100) if total_findings > 0 else 0.0, 1)

    # Drift events
    result = await db.execute(text("""
        SELECT
            COUNT(*) FILTER (WHERE resolution_status = 'OPEN') AS open_total,
            COUNT(*) FILTER (WHERE resolution_status = 'OPEN' AND severity = 'CRITICAL') AS critical,
            COUNT(*) FILTER (WHERE resolution_status = 'OPEN' AND severity = 'HIGH') AS high,
            COUNT(*) FILTER (WHERE resolution_status = 'OPEN' AND severity = 'MEDIUM') AS medium
        FROM drift_events
    """))
    drift_row = result.fetchone()

    # Algorithm breakdown (top 10)
    result = await db.execute(text("""
        SELECT
            algorithm,
            COUNT(*) AS total,
            COUNT(*) FILTER (WHERE compliance_status = 'PASS') AS compliant,
            COUNT(*) FILTER (WHERE compliance_status = 'FAIL') AS non_compliant
        FROM evidence_records
        WHERE algorithm IS NOT NULL
        GROUP BY algorithm
        ORDER BY total DESC
        LIMIT 10
    """))
    algorithm_rows = result.fetchall()

    algorithm_breakdown = [
        AlgorithmStat(
            algorithm=row.algorithm,
            total_findings=row.total,
            compliant=row.compliant,
            non_compliant=row.non_compliant,
            compliance_pct=round(
                (row.compliant / row.total * 100) if row.total > 0 else 0.0, 1
            ),
        )
        for row in algorithm_rows
    ]

    # Drift by severity
    result = await db.execute(text("""
        SELECT severity, COUNT(*) AS open_count
        FROM drift_events
        WHERE resolution_status = 'OPEN'
        GROUP BY severity
        ORDER BY
            CASE severity
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM' THEN 3
                WHEN 'INFO' THEN 4
                ELSE 5
            END
    """))
    drift_rows = result.fetchall()
    drift_by_severity = [
        DriftSeverityStat(severity=row.severity, open_count=row.open_count)
        for row in drift_rows
    ]

    return SummaryStatsResponse(
        total_scans=total_scans,
        total_findings=total_findings,
        compliant_findings=compliant,
        non_compliant_findings=non_compliant,
        compliance_percentage=compliance_pct,
        open_drift_events=drift_row.open_total or 0,
        critical_drift_events=drift_row.critical or 0,
        high_drift_events=drift_row.high or 0,
        medium_drift_events=drift_row.medium or 0,
        algorithm_breakdown=algorithm_breakdown,
        drift_by_severity=drift_by_severity,
    )