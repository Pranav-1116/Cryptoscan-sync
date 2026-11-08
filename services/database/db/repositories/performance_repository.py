"""Performance metric repository (docs/performance/01_PRODUCT_SPEC.md).

Idempotent ingestion at the schema level: a duplicate metric_id reports
its accepted identity (DUPLICATE) and never creates a second row. Reads
are tenant-scoped; missing/stale telemetry carries no value and is never
reconstructed as zero on the way out.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Mapping, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models.performance import (
    PerformanceCollectorHealth, PerformanceMetric as PerformanceMetricRow,
    PerformanceMetricDefinition,
)
from shared_models.performance_metrics import (
    NO_VALUE_QUALITIES, PerformanceMetric,
)

INSERTED = "inserted"
DUPLICATE = "duplicate"


def row_to_metric(row: PerformanceMetricRow) -> PerformanceMetric:
    return PerformanceMetric(
        metric_id=row.metric_id,
        tenant_id=row.tenant_id or "",
        asset_id=row.asset_id,
        metric_name=row.metric_name,
        metric_type=row.metric_type,
        metric_value=row.metric_value,
        unit=row.unit,
        source_id=row.source_id,
        observed_at=row.observed_at,
        interval_seconds=row.interval_seconds,
        labels=row.labels or {},
        evidence_id=row.evidence_id,
        quality_status=row.quality_status,
    )


class PerformanceRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    # -- ingestion ------------------------------------------------------
    def insert_metric(self, metric: PerformanceMetric) -> Dict[str, Any]:
        existing = self.db.execute(
            select(PerformanceMetricRow).where(
                PerformanceMetricRow.metric_id == metric.metric_id)
        ).scalar_one_or_none()
        if existing is not None:
            return {
                "outcome": DUPLICATE,
                "accepted_id": existing.metric_id,
                "note": "idempotent ingestion: the accepted identity stands",
            }
        row = PerformanceMetricRow(
            metric_id=metric.metric_id,
            tenant_id=metric.tenant_id,
            asset_id=metric.asset_id,
            metric_name=metric.metric_name,
            metric_type=metric.metric_type.value,
            metric_value=metric.metric_value,
            unit=metric.unit,
            source_id=metric.source_id,
            observed_at=metric.observed_at,
            interval_seconds=metric.interval_seconds,
            labels=dict(metric.labels),
            evidence_id=metric.evidence_id,
            quality_status=metric.quality_status.value,
        )
        self.db.add(row)
        self.db.commit()
        return {
            "outcome": INSERTED,
            "accepted_id": metric.metric_id,
            "note": "ingested with its unit, source and observation timestamp",
        }

    # -- reads ----------------------------------------------------------
    def get_metric(self, tenant_id: str,
                   metric_id: str) -> Optional[PerformanceMetric]:
        row = self.db.execute(
            select(PerformanceMetricRow).where(
                PerformanceMetricRow.metric_id == metric_id,
                PerformanceMetricRow.tenant_id == tenant_id,
            )
        ).scalar_one_or_none()
        return row_to_metric(row) if row else None

    def query_metrics(self, tenant_id: str, *,
                      metric_name: Optional[str] = None,
                      asset_id: Optional[str] = None,
                      window_start: Optional[datetime] = None,
                      window_end: Optional[datetime] = None,
                      limit: int = 200) -> List[PerformanceMetric]:
        stmt = select(PerformanceMetricRow).where(
            PerformanceMetricRow.tenant_id == tenant_id)
        if metric_name is not None:
            stmt = stmt.where(PerformanceMetricRow.metric_name == metric_name)
        if asset_id is not None:
            stmt = stmt.where(PerformanceMetricRow.asset_id == asset_id)
        if window_start is not None:
            stmt = stmt.where(PerformanceMetricRow.observed_at >= window_start)
        if window_end is not None:
            stmt = stmt.where(PerformanceMetricRow.observed_at <= window_end)
        stmt = stmt.order_by(PerformanceMetricRow.observed_at).limit(limit)
        return [row_to_metric(r) for r in self.db.execute(stmt).scalars()]

    def collector_health(self, tenant_id: str) -> List[Dict[str, Any]]:
        rows = self.db.execute(
            select(PerformanceCollectorHealth).where(
                PerformanceCollectorHealth.tenant_id == tenant_id)
        ).scalars().all()
        return [
            {
                "collector_id": r.collector_id,
                "status": r.status,
                "last_report_at": r.last_report_at,
                "detail": r.detail,
            }
            for r in rows
        ]
