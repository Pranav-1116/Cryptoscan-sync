"""Performance metric repository (docs/performance/01_PRODUCT_SPEC.md).

Idempotent ingestion at the schema level: a duplicate metric_id reports
its accepted identity (DUPLICATE) and never creates a second row. Reads
are tenant-scoped; missing/stale telemetry carries no value and is never
reconstructed as zero on the way out.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

import sqlalchemy as sa
from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models.performance import (
    PerformanceAlert, PerformanceAsset,
    PerformanceBaseline, PerformanceBenchmarkRun,
    PerformanceCapacityForecast, PerformanceCollectorHealth,
    PerformanceCaptureReceipt, PerformanceMetric as PerformanceMetricRow,
    PerformanceMetricDefinition, PerformanceSloPolicy,
)
from shared_models.performance_metrics import (
    PerformanceMetric,
)

INSERTED = "inserted"
DUPLICATE = "duplicate"
CONFLICT = "conflict"


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
    def insert_metric(self, metric: PerformanceMetric, *,
                      commit: bool = True) -> Dict[str, Any]:
        existing = self.db.execute(
            select(PerformanceMetricRow).where(
                PerformanceMetricRow.tenant_id == metric.tenant_id,
                PerformanceMetricRow.metric_id == metric.metric_id)
        ).scalar_one_or_none()
        if existing is not None:
            if row_to_metric(existing).model_dump() != metric.model_dump():
                return {"outcome": CONFLICT, "accepted_id": existing.metric_id,
                        "note": "metric_id already belongs to a different observation; "
                                "the original was not overwritten"}
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
        if commit:
            self.db.commit()
        else:
            self.db.flush()  # detect within-capture duplicates before the receipt commits
        return {
            "outcome": INSERTED,
            "accepted_id": metric.metric_id,
            "note": "ingested with its unit, source and observation timestamp",
        }

    def get_capture_receipt(self, tenant_id: str,
                            receipt_id: str) -> Optional[PerformanceCaptureReceipt]:
        return self.db.scalar(select(PerformanceCaptureReceipt).where(
            PerformanceCaptureReceipt.tenant_id == tenant_id,
            PerformanceCaptureReceipt.receipt_id == receipt_id))

    def add_capture_receipt(self, **fields: Any) -> PerformanceCaptureReceipt:
        row = PerformanceCaptureReceipt(**fields)
        self.db.add(row)
        self.db.flush()
        return row

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
                      source_id: Optional[str] = None,
                      window_start: Optional[datetime] = None,
                      window_end: Optional[datetime] = None,
                      limit: int = 200) -> List[PerformanceMetric]:
        stmt = select(PerformanceMetricRow).where(
            PerformanceMetricRow.tenant_id == tenant_id)
        if metric_name is not None:
            stmt = stmt.where(PerformanceMetricRow.metric_name == metric_name)
        if asset_id is not None:
            stmt = stmt.where(PerformanceMetricRow.asset_id == asset_id)
        if source_id is not None:
            stmt = stmt.where(PerformanceMetricRow.source_id == source_id)
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
                            limit: int = 50,
                            after: Optional[Tuple[datetime, str]] = None
                            ) -> List[Dict[str, Any]]:
        stmt = select(PerformanceBenchmarkRun).where(
            PerformanceBenchmarkRun.tenant_id == tenant_id)
        if after is not None:
            cursor_time, cursor_id = after
            stmt = stmt.where(sa.or_(
                PerformanceBenchmarkRun.executed_at < cursor_time,
                sa.and_(PerformanceBenchmarkRun.executed_at == cursor_time,
                        PerformanceBenchmarkRun.run_id < cursor_id)))
        rows = self.db.execute(
            stmt.order_by(PerformanceBenchmarkRun.executed_at.desc(),
                          PerformanceBenchmarkRun.run_id.desc())
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

    def get_benchmark_run(self, tenant_id: str, run_id: str) -> Optional[Dict[str, Any]]:
        row = self.db.scalar(select(PerformanceBenchmarkRun).where(
            PerformanceBenchmarkRun.tenant_id == tenant_id,
            PerformanceBenchmarkRun.run_id == run_id))
        if row is None:
            return None
        return {"run_id": row.run_id, "measurement_kind": row.measurement_kind,
                "approved": bool(row.approved), "method": row.method or {},
                "results": row.results or [], "executed_at": _aware(row.executed_at)}

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

    # --- metric definitions (§5: performance_metric_definitions) -------

    def sync_metric_definitions(self, tenant_id: str,
                                definitions: Sequence[Any],
                                ) -> Dict[str, Any]:
        """Idempotently register the taxonomy as definitions rows. A
        metric is defined before it is ingested — a guessed unit is not
        a defined unit. Re-running the sync inserts nothing twice."""
        inserted = 0
        existing = {row.metric_name: row
                    for row in self.db.scalars(
                        select(PerformanceMetricDefinition).where(
                            PerformanceMetricDefinition.tenant_id
                            == tenant_id))}
        for definition in definitions:
            if definition.name in existing:
                continue
            self.db.add(PerformanceMetricDefinition(
                tenant_id=tenant_id,
                metric_name=definition.name,
                domain=definition.domain,
                unit=definition.unit,
                metric_type=definition.metric_type.value,
                description=definition.what_it_tells))
            inserted += 1
        self.db.commit()
        return {"registered": len(existing) + inserted, "inserted": inserted}

    def list_metric_definitions(self, tenant_id: str,
                               *, domain: Optional[str] = None
                               ) -> List[Dict[str, Any]]:
        stmt = select(PerformanceMetricDefinition).where(
            PerformanceMetricDefinition.tenant_id == tenant_id)
        if domain:
            stmt = stmt.where(PerformanceMetricDefinition.domain == domain)
        rows = self.db.scalars(
            stmt.order_by(PerformanceMetricDefinition.metric_name))
        return [{
            "metric_name": row.metric_name,
            "domain": row.domain,
            "unit": row.unit,
            "metric_type": row.metric_type,
            "description": row.description,
        } for row in rows]

    # --- collector health (§9: stale collectors are detected) ---------

    def record_collector_report(self, tenant_id: str, collector_id: str,
                                *, status: str,
                                last_report_at: Optional[datetime] = None,
                                detail: Optional[str] = None
                                ) -> Dict[str, Any]:
        """Upsert one collector's heartbeat. Idempotent per collector."""
        row = self.db.scalars(
            select(PerformanceCollectorHealth).where(
                PerformanceCollectorHealth.tenant_id == tenant_id,
                PerformanceCollectorHealth.collector_id == collector_id
            )).first()
        if row is None:
            row = PerformanceCollectorHealth(
                tenant_id=tenant_id, collector_id=collector_id,
                status=status, last_report_at=last_report_at,
                detail=detail)
            self.db.add(row)
        else:
            row.status = status
            row.last_report_at = last_report_at or row.last_report_at
            row.detail = detail
        self.db.commit()
        return {"collector_id": collector_id, "status": status}

    def list_collector_health(self, tenant_id: str, *,
                              stale_after_seconds: float,
                              now: datetime) -> List[Dict[str, Any]]:
        """Every collector with its status. A collector that has not
        reported within ``stale_after_seconds`` is named STALE — its
        missing telemetry is never interpreted as zero."""
        from datetime import timedelta
        cutoff = now - timedelta(seconds=stale_after_seconds)
        rows = self.db.scalars(
            select(PerformanceCollectorHealth).where(
                PerformanceCollectorHealth.tenant_id == tenant_id).order_by(
                PerformanceCollectorHealth.collector_id))
        out: List[Dict[str, Any]] = []
        for row in rows:
            reported = _aware(row.last_report_at)
            effective = row.status
            if reported is not None and reported < cutoff:
                effective = "stale"
            elif reported is None:
                effective = "unknown"
            out.append({
                "collector_id": row.collector_id,
                "status": effective,
                "last_report_at": reported,
                "detail": row.detail,
                "stale": effective == "stale",
                "note": "a stale collector is detected and named — its "
                        "missing metrics are never read as zero",
            })
        return out

    def query_samples_cursor(self, tenant_id: str, *, metric_name: Optional[str],
                             asset_id: Optional[str],
                             window_start: Optional[datetime],
                             window_end: Optional[datetime],
                             after: Optional[Tuple[datetime, str]],
                             limit: int) -> List[PerformanceMetric]:
        """Raw samples in (observed_at, metric_id) order, resuming
        strictly after the cursor. A cursor is an exact position in that
        order — rows are never skipped or repeated across pages."""
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
        if after is not None:
            cursor_time, cursor_id = after
            stmt = stmt.where(sa.or_(
                PerformanceMetricRow.observed_at > cursor_time,
                sa.and_(PerformanceMetricRow.observed_at == cursor_time,
                        PerformanceMetricRow.metric_id > cursor_id)))
        stmt = stmt.order_by(PerformanceMetricRow.observed_at,
                             PerformanceMetricRow.metric_id).limit(limit)
        return [row_to_metric(r) for r in self.db.execute(stmt).scalars()]
