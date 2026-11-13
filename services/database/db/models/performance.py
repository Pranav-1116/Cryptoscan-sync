"""Performance engine storage (docs/performance/01_PRODUCT_SPEC.md, §5).

PostgreSQL holds configuration, metadata, alert state and references;
high-volume samples move to a time-series store when real deployment
volume justifies it (§4). The schema keeps the two apart by design: this
module defines the metric rows, the metric definitions registry and
collector health that Phase 1 (foundation) requires.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import JSON, DateTime, Float, Index, String, Text, text
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.tenancy import TenantScoped


class PerformanceMetric(BaseModel, TenantScoped):
    """One measurement row — the §5 `performance_metrics` field table."""

    __tablename__ = "performance_metrics"

    metric_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    asset_id: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    metric_name: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    metric_type: Mapped[str] = mapped_column(String(20), nullable=False)
    metric_value: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    unit: Mapped[str] = mapped_column(String(32), nullable=False)
    source_id: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                  nullable=False, index=True)
    interval_seconds: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    labels: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    evidence_id: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    quality_status: Mapped[str] = mapped_column(String(20), nullable=False)

    __table_args__ = (
        Index("ix_performance_metrics_tenant_name_observed",
              "tenant_id", "metric_name", "observed_at"),
        Index("uq_performance_metrics_tenant_metric_id", "tenant_id",
              "metric_id", unique=True),
        Index("uq_performance_metrics_platform_metric_id", "metric_id",
              unique=True, postgresql_where=text("tenant_id IS NULL"),
              sqlite_where=text("tenant_id IS NULL")),
    )


class PerformanceCaptureReceipt(BaseModel, TenantScoped):
    """Public signature metadata for a bank-retained exporter snapshot.

    Raw exporter bytes and signing private keys are never stored here. The
    digest and detached signature let an auditor match the bank's original.
    """

    __tablename__ = "performance_capture_receipts"
    __table_args__ = (
        Index("uq_performance_capture_tenant_receipt", "tenant_id", "receipt_id",
              unique=True),
        Index("uq_performance_capture_platform_receipt", "receipt_id", unique=True,
              postgresql_where=text("tenant_id IS NULL"),
              sqlite_where=text("tenant_id IS NULL")),
    )

    receipt_id: Mapped[str] = mapped_column(String(64), nullable=False)
    asset_ref: Mapped[str] = mapped_column(String(120), nullable=False)
    source_id: Mapped[str] = mapped_column(String(120), nullable=False)
    source_type: Mapped[str] = mapped_column(String(32), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    previous_observed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    payload_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    previous_sha256: Mapped[Optional[str]] = mapped_column(String(64))
    authorization_ref: Mapped[str] = mapped_column(String(120), nullable=False)
    provenance_state: Mapped[str] = mapped_column(String(40), nullable=False)
    key_id: Mapped[Optional[str]] = mapped_column(String(120))
    issuer: Mapped[Optional[str]] = mapped_column(String(120))
    signature: Mapped[Optional[str]] = mapped_column(String(128))
    accepted_count: Mapped[int] = mapped_column(nullable=False, default=0)
    duplicate_count: Mapped[int] = mapped_column(nullable=False, default=0)
    rejected_count: Mapped[int] = mapped_column(nullable=False, default=0)


class PerformanceMetricDefinition(BaseModel, TenantScoped):
    """The taxonomy registry row: a metric is defined before it is
    ingested — a guessed unit is not a defined unit."""

    __tablename__ = "performance_metric_definitions"

    metric_name: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    domain: Mapped[str] = mapped_column(String(40), nullable=False)
    unit: Mapped[str] = mapped_column(String(32), nullable=False)
    metric_type: Mapped[str] = mapped_column(String(20), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)

    __table_args__ = (
        Index("ix_performance_metric_definitions_tenant_name",
              "tenant_id", "metric_name", unique=True),
    )


class PerformanceCollectorHealth(BaseModel, TenantScoped):
    """Collector health (§9): a stale collector is detected and named —
    its missing telemetry is never interpreted as zero."""

    __tablename__ = "performance_collector_health"

    collector_id: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    last_report_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True)
    detail: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    __table_args__ = (
        Index("ix_performance_collector_health_tenant_collector",
              "tenant_id", "collector_id", unique=True),
    )


class PerformanceAsset(BaseModel, TenantScoped):
    """Digital Twin asset reference (§5): the performance engine links
    ``asset_id`` to the Digital Twin — it never becomes a second asset
    registry with invented attributes."""

    __tablename__ = "performance_assets"

    asset_id: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    identity_source: Mapped[str] = mapped_column(String(40), nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                    nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                   nullable=False)

    __table_args__ = (
        Index("ix_performance_assets_tenant_asset",
              "tenant_id", "asset_id", unique=True),
    )


class PerformanceAggregate(BaseModel, TenantScoped):
    """Stored aggregate over raw samples — provenance carries the window
    and the delivered/unknown counts so a stored figure never hides its
    coverage."""

    __tablename__ = "performance_aggregates"

    metric_name: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    asset_id: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                   nullable=False)
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                 nullable=False)
    sample_count: Mapped[int] = mapped_column(nullable=False)
    value_count: Mapped[int] = mapped_column(nullable=False)
    unknown_count: Mapped[int] = mapped_column(nullable=False)
    average: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    p95: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    __table_args__ = (
        Index("ix_performance_aggregates_tenant_name_window",
              "tenant_id", "metric_name", "window_start"),
    )


class PerformanceBaseline(BaseModel, TenantScoped):
    __tablename__ = "performance_baselines"

    metric_name: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    asset_id: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                   nullable=False)
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                 nullable=False)
    method: Mapped[str] = mapped_column(String(80), nullable=False)
    sample_count: Mapped[int] = mapped_column(nullable=False)
    median: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    p95: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    mad: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    __table_args__ = (
        Index("ix_performance_baselines_tenant_name_window",
              "tenant_id", "metric_name", "window_start"),
    )


class PerformanceAlert(BaseModel, TenantScoped):
    """An alert row stores what is proven AND what is not proven, with
    its computed severity and the supporting measurements."""

    __tablename__ = "performance_alerts"

    metric_name: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    severity_factors: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    proven: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    not_proven: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    supporting_measurements: Mapped[Optional[dict]] = mapped_column(JSON,
                                                                   nullable=True)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                   nullable=False)
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                 nullable=False)
    raised_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                nullable=False)

    __table_args__ = (
        Index("ix_performance_alerts_tenant_name_raised",
              "tenant_id", "metric_name", "raised_at"),
    )


class PerformanceIncident(BaseModel, TenantScoped):
    __tablename__ = "performance_incidents"

    incident_key: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    alert_ids: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    summary: Mapped[str] = mapped_column(Text, nullable=False)

    __table_args__ = (
        Index("ix_performance_incidents_tenant_key",
              "tenant_id", "incident_key", unique=True),
    )


class PerformanceSloPolicy(BaseModel, TenantScoped):
    __tablename__ = "performance_slo_policies"

    policy_key: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    metric_name: Mapped[str] = mapped_column(String(120), nullable=False)
    objective: Mapped[float] = mapped_column(Float, nullable=False)
    window_seconds: Mapped[int] = mapped_column(nullable=False)
    comparator: Mapped[str] = mapped_column(String(8), nullable=False)

    __table_args__ = (
        Index("ix_performance_slo_policies_tenant_key",
              "tenant_id", "policy_key", unique=True),
    )


class PerformanceCapacityForecast(BaseModel, TenantScoped):
    """A stored forecast keeps its disclaimer: forecast, not fact."""

    __tablename__ = "performance_capacity_forecasts"

    metric_name: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    method: Mapped[str] = mapped_column(String(80), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    sample_count: Mapped[int] = mapped_column(nullable=False)
    growth_per_second: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    estimated_seconds_to_exhaustion: Mapped[Optional[float]] = mapped_column(
        Float, nullable=True)
    disclaimer: Mapped[str] = mapped_column(Text, nullable=False)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                   nullable=False)
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                 nullable=False)

    __table_args__ = (
        Index("ix_performance_capacity_forecasts_tenant_name",
              "tenant_id", "metric_name"),
    )


class PerformanceBenchmarkRun(BaseModel, TenantScoped):
    """Controlled benchmark results (§2.F) — their own table, never
    mixed into observed production metrics."""

    __tablename__ = "performance_benchmark_runs"

    run_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True,
                                        index=True)
    measurement_kind: Mapped[str] = mapped_column(String(40), nullable=False)
    approved: Mapped[int] = mapped_column(nullable=False)
    method: Mapped[dict] = mapped_column(JSON, nullable=False)
    results: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    executed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("ix_performance_benchmark_runs_tenant_run",
              "tenant_id", "run_id", unique=True),
    )
