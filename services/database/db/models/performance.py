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

from sqlalchemy import JSON, DateTime, Float, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.tenancy import TenantScoped


class PerformanceMetric(BaseModel, TenantScoped):
    """One measurement row — the §5 `performance_metrics` field table."""

    __tablename__ = "performance_metrics"

    metric_id: Mapped[str] = mapped_column(String(64), nullable=False,
                                           unique=True, index=True)
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
    )


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
