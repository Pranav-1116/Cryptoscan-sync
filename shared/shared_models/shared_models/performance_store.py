"""Session-only performance metric store (docs/performance/01_PRODUCT_SPEC.md).

Phase 1 collection contracts: idempotent ingestion (a duplicate
metric_id reports its accepted identity, never a second row),
tenant-isolated reads (a tenant never sees another tenant's metrics),
and honest aggregation — missing and stale telemetry is reported as
unknown coverage and never averaged in as a zero.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from shared_models.performance_metrics import (
    NO_VALUE_QUALITIES,
    PerformanceMetric,
    QualityStatus,
)

INSERTED = "inserted"
DUPLICATE = "duplicate"


@dataclass(frozen=True)
class AggregateResult:
    """An aggregate is only as honest as its coverage.

    `average` is computed over the values the sources actually delivered.
    `unknown_count` names the missing/stale samples that carry no value —
    they are never averaged in as zeros, and coverage says so.
    """

    metric_name: str
    window_start: datetime
    window_end: datetime
    sample_count: int
    value_count: int
    unknown_count: int
    average: Optional[float]
    minimum: Optional[float]
    maximum: Optional[float]

    @property
    def coverage(self) -> str:
        if self.sample_count == 0:
            return "no samples"
        if self.value_count == 0:
            return "unknown — no delivered values in window"
        if self.unknown_count:
            return (
                f"partial — {self.value_count}/{self.sample_count} samples "
                f"delivered values; {self.unknown_count} unknown (never zero)"
            )
        return "complete"


class MetricRepository:
    """A tenant-scoped, idempotent in-memory store for Phase 1."""

    def __init__(self) -> None:
        self._rows: Dict[Tuple[str, str], PerformanceMetric] = {}
        self._label_budget: Dict[Tuple[str, str, str], set] = {}

    # -- ingestion ------------------------------------------------------
    def accept(self, metric: PerformanceMetric) -> Tuple[str, str]:
        """Idempotent ingestion. Returns (outcome, accepted_id): a
        duplicate metric_id within a tenant reports the accepted identity
        and never creates a second row."""
        key = (metric.tenant_id, metric.metric_id)
        if key in self._rows:
            return DUPLICATE, self._rows[key].metric_id
        for label_key, label_value in metric.labels.items():
            bucket = self._label_budget.setdefault(
                (metric.tenant_id, metric.metric_name, label_key), set())
            if label_value not in bucket and len(bucket) >= 256:
                raise ValueError(
                    f"bounded cardinality: label {label_key!r} already has "
                    "256 distinct values for this tenant and metric — "
                    "bounded cardinality is a success criterion "
                    "(docs/performance/01_PRODUCT_SPEC.md §10)")
            bucket.add(label_value)
        self._rows[key] = metric
        return INSERTED, metric.metric_id

    def accept_many(self, metrics: Iterable[PerformanceMetric]
                    ) -> List[Tuple[str, str]]:
        return [self.accept(metric) for metric in metrics]

    # -- reads ----------------------------------------------------------
    def get(self, tenant_id: str, metric_id: str) -> Optional[PerformanceMetric]:
        """Tenant-isolated read: another tenant's metric is None here,
        never a leak."""
        return self._rows.get((tenant_id, metric_id))

    def query(self, tenant_id: str, *, metric_name: Optional[str] = None,
              asset_id: Optional[str] = None,
              window_start: Optional[datetime] = None,
              window_end: Optional[datetime] = None) -> List[PerformanceMetric]:
        rows = [row for (tid, _), row in self._rows.items() if tid == tenant_id]
        if metric_name is not None:
            rows = [r for r in rows if r.metric_name == metric_name]
        if asset_id is not None:
            rows = [r for r in rows if r.asset_id == asset_id]
        if window_start is not None:
            rows = [r for r in rows if r.observed_at >= window_start]
        if window_end is not None:
            rows = [r for r in rows if r.observed_at <= window_end]
        return sorted(rows, key=lambda r: (r.observed_at, r.metric_id))

    def aggregate(self, tenant_id: str, metric_name: str, *,
                  window_start: datetime,
                  window_end: datetime) -> AggregateResult:
        """Average over delivered values only. Missing/stale samples are
        counted as unknown — never drawn as a quiet zero that drags an
        average toward a lie."""
        rows = self.query(tenant_id, metric_name=metric_name,
                          window_start=window_start, window_end=window_end)
        delivered = [r.metric_value for r in rows
                     if r.quality_status not in NO_VALUE_QUALITIES
                     and r.metric_value is not None]
        unknown = sum(1 for r in rows
                      if r.quality_status in NO_VALUE_QUALITIES
                      or r.metric_value is None)
        average = sum(delivered) / len(delivered) if delivered else None
        return AggregateResult(
            metric_name=metric_name,
            window_start=window_start,
            window_end=window_end,
            sample_count=len(rows),
            value_count=len(delivered),
            unknown_count=unknown,
            average=average,
            minimum=min(delivered) if delivered else None,
            maximum=max(delivered) if delivered else None,
        )

    def __len__(self) -> int:
        return len(self._rows)
