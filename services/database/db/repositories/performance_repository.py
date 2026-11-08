"""Performance metric repository (docs/performance/01_PRODUCT_SPEC.md).

Idempotent ingestion at the schema level: a duplicate metric_id reports
its accepted identity (DUPLICATE) and never creates a second row. Reads
are tenant-scoped; missing/stale telemetry carries no value and is never
reconstructed as zero on the way out.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models.performance import (
    PerformanceAggregate, PerformanceAlert, PerformanceAsset,
    PerformanceBaseline, PerformanceBenchmarkRun,
    PerformanceCapacityForecast, PerformanceCollectorHealth,
    PerformanceIncident, PerformanceMetric as PerformanceMetricRow,
    PerformanceMetricDefinition, PerformanceSloPolicy,
)
from shared_models.performance_metrics import (
    NO_VALUE_QUALITIES, PerformanceMetric,
)

INSERTED = "inserted"
DUPLICATE = "duplicate"


def _aware(value: Optional[datetime]) -> Optional[datetime]:
    """SQLite hands back naive datetimes; the contract requires the
    timezone. UTC is the storage convention — attach it rather than
    pretend the instant is unknown."""
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


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
        observed_at=_aware(row.observed_at),
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

    # -- engine stores ---------------------------------------------------
    def register_asset(self, tenant_id: str, asset_id: str, *,
                       identity_source: str = "digital-twin",
                       seen_at: Optional[datetime] = None) -> Dict[str, Any]:
        """Link an asset_id to its Digital Twin identity — a reference,
        never invented attributes (§3.6: reuse asset identity)."""
        stamp = seen_at or datetime.now(timezone.utc)
        existing = self.db.execute(
            select(PerformanceAsset).where(
                PerformanceAsset.tenant_id == tenant_id,
                PerformanceAsset.asset_id == asset_id)
        ).scalar_one_or_none()
        if existing is None:
            existing = PerformanceAsset(
                tenant_id=tenant_id, asset_id=asset_id,
                identity_source=identity_source,
                first_seen_at=stamp, last_seen_at=stamp)
            self.db.add(existing)
        else:
            existing.last_seen_at = stamp
        self.db.commit()
        return {
            "asset_id": existing.asset_id,
            "identity_source": existing.identity_source,
            "first_seen_at": existing.first_seen_at,
            "last_seen_at": existing.last_seen_at,
        }

    def asset_reference(self, tenant_id: str,
                        asset_id: str) -> Optional[Dict[str, Any]]:
        row = self.db.execute(
            select(PerformanceAsset).where(
                PerformanceAsset.tenant_id == tenant_id,
                PerformanceAsset.asset_id == asset_id)
        ).scalar_one_or_none()
        if row is None:
            return None
        return {
            "asset_id": row.asset_id,
            "identity_source": row.identity_source,
            "first_seen_at": row.first_seen_at,
            "last_seen_at": row.last_seen_at,
        }

    def insert_benchmark_run(self, tenant_id: str, run) -> Dict[str, Any]:
        """A controlled benchmark run is stored in its own table — it is
        never written to performance_metrics and never mixed into
        observed aggregates (§2.F)."""
        existing = self.db.execute(
            select(PerformanceBenchmarkRun).where(
                PerformanceBenchmarkRun.run_id == run.run_id)
        ).scalar_one_or_none()
        if existing is not None:
            return {"outcome": DUPLICATE, "accepted_id": existing.run_id}
        row = PerformanceBenchmarkRun(
            tenant_id=tenant_id,
            run_id=run.run_id,
            measurement_kind=run.measurement_kind,
            approved=1 if run.approved else 0,
            method=run.method.model_dump(),
            results=[r.model_dump() for r in run.results],
            executed_at=run.executed_at,
        )
        self.db.add(row)
        self.db.commit()
        return {"outcome": INSERTED, "accepted_id": run.run_id}

    def list_benchmark_runs(self, tenant_id: str, *,
                            limit: int = 50) -> List[Dict[str, Any]]:
        rows = self.db.execute(
            select(PerformanceBenchmarkRun).where(
                PerformanceBenchmarkRun.tenant_id == tenant_id)
            .order_by(PerformanceBenchmarkRun.executed_at.desc())
            .limit(limit)
        ).scalars()
        return [
            {
                "run_id": r.run_id,
                "measurement_kind": r.measurement_kind,
                "approved": bool(r.approved),
                "method": r.method,
                "results": r.results,
                "executed_at": r.executed_at,
            }
            for r in rows
        ]

    def insert_alert(self, tenant_id: str, alert: Dict[str, Any]
                     ) -> Dict[str, Any]:
        row = PerformanceAlert(
            tenant_id=tenant_id,
            metric_name=alert["metric_name"],
            severity=alert["severity"],
            severity_factors=alert.get("severity_factors"),
            proven=alert.get("proven"),
            not_proven=alert.get("not_proven"),
            supporting_measurements=alert.get("supporting_measurements"),
            window_start=alert["window_start"],
            window_end=alert["window_end"],
            raised_at=datetime.now(timezone.utc),
        )
        self.db.add(row)
        self.db.commit()
        return {"outcome": INSERTED, "accepted_id": row.id}

    def list_alerts(self, tenant_id: str, *,
                    metric_name: Optional[str] = None,
                    limit: int = 50) -> List[Dict[str, Any]]:
        stmt = select(PerformanceAlert).where(
            PerformanceAlert.tenant_id == tenant_id)
        if metric_name is not None:
            stmt = stmt.where(PerformanceAlert.metric_name == metric_name)
        stmt = stmt.order_by(PerformanceAlert.raised_at.desc()).limit(limit)
        return [
            {
                "alert_id": r.id,
                "metric_name": r.metric_name,
                "severity": r.severity,
                "severity_factors": r.severity_factors,
                "proven": r.proven,
                "not_proven": r.not_proven,
                "supporting_measurements": r.supporting_measurements,
                "window_start": r.window_start,
                "window_end": r.window_end,
                "raised_at": r.raised_at,
            }
            for r in self.db.execute(stmt).scalars()
        ]

    def insert_baseline(self, tenant_id: str, baseline) -> Dict[str, Any]:
        row = PerformanceBaseline(
            tenant_id=tenant_id,
            metric_name=baseline.metric_name,
            asset_id=baseline.asset_id,
            window_start=baseline.window_start,
            window_end=baseline.window_end,
            method=baseline.method,
            sample_count=baseline.sample_count,
            median=baseline.median, p95=baseline.p95, mad=baseline.mad,
        )
        self.db.add(row)
        self.db.commit()
        return {"outcome": INSERTED, "accepted_id": row.id}

    def insert_forecast(self, tenant_id: str, forecast: Dict[str, Any],
                        *, window_start: datetime,
                        window_end: datetime) -> Dict[str, Any]:
        row = PerformanceCapacityForecast(
            tenant_id=tenant_id,
            metric_name=forecast["metric_name"],
            method=forecast["method"],
            status=forecast["status"],
            sample_count=forecast.get("sample_count") or 0,
            growth_per_second=forecast.get("growth_per_second"),
            estimated_seconds_to_exhaustion=forecast.get(
                "estimated_seconds_to_exhaustion"),
            disclaimer=forecast.get("disclaimer")
            or "forecast, not fact — recorded as computed, never as a promise",
            window_start=window_start,
            window_end=window_end,
        )
        self.db.add(row)
        self.db.commit()
        return {"outcome": INSERTED, "accepted_id": row.id}

    def list_slo_policies(self, tenant_id: str) -> List[Dict[str, Any]]:
        rows = self.db.execute(
            select(PerformanceSloPolicy).where(
                PerformanceSloPolicy.tenant_id == tenant_id)
        ).scalars()
        return [
            {
                "policy_key": r.policy_key,
                "metric_name": r.metric_name,
                "objective": r.objective,
                "window_seconds": r.window_seconds,
                "comparator": r.comparator,
            }
            for r in rows
        ]
