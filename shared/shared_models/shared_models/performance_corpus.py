"""Deterministic SYNTHETIC performance metric corpus (Phase 8 qualification,
docs/performance/01_PRODUCT_SPEC.md §10).

Every corpus row is labelled SYNTHETIC at the source: source_id
'synthetic-corpus' and label synthetic=1. A synthetic measurement never
masquerades as an observation from a real system — synthetic results
never qualify a real-environment act (§2.F: observed production
performance and controlled measurements stay separate; this corpus is
neither).
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from typing import List

from shared_models.performance_metrics import (
    PerformanceMetric, QualityStatus,
)
from shared_models.performance_taxonomy import definition_for

SCHEMA = "cryptoscan.performance-synthetic-corpus/1"
SYNTHETIC_SOURCE = "synthetic-corpus"
#: a fixed past instant keeps the corpus deterministic AND valid —
#: a measurement is never pre-dated into the future.
CORPUS_EPOCH = datetime(2026, 11, 1, 0, 0, 0, tzinfo=timezone.utc)

#: (metric_name, base value, jitter) — every name is in the taxonomy and
#: every unit is the taxonomy's unit, never a guess.
_TEMPLATES = (
    ("cpu.utilization_pct", 37.5, 12.0),
    ("ram.utilization_pct", 61.0, 9.0),
    ("disk.utilization_pct", 72.0, 3.0),
    ("disk.iops", 450.0, 120.0),
    ("disk.throughput_mbps", 84.0, 25.0),
    ("system.load", 2.4, 0.8),
    ("storage.used_bytes", 773_094_113_280.0, 5e8),
    ("network.rtt_ms", 42.0, 15.0),
    ("network.throughput_mbps", 840.0, 160.0),
    ("network.jitter_ms", 3.2, 1.4),
    ("api.requests_per_sec", 1250.0, 300.0),
    ("api.latency_p95_ms", 180.0, 40.0),
    ("api.error_rate_pct", 0.2, 0.15),
    ("db.connections_active", 34.0, 10.0),
    ("db.query_time_ms", 12.5, 5.0),
    ("crypto.tls_handshake_ms", 35.0, 12.0),
    ("crypto.hsm_operation_latency_ms", 8.0, 2.5),
    ("k8s.pod_restarts", 0.0, 1.0),
    ("capacity.utilization_pct", 72.0, 3.0),
)


def generate_corpus(count: int, *, seed: int = 20261108,
                    tenant_id: str = "tenant_synthetic",
                    id_prefix: str = "corpus"
                    ) -> List[PerformanceMetric]:
    """A deterministic corpus: same arguments, same rows, every time."""
    rng = random.Random(seed)
    rows: List[PerformanceMetric] = []
    for index in range(count):
        name, base, jitter = _TEMPLATES[index % len(_TEMPLATES)]
        definition = definition_for(name)
        value = round(max(0.0, base + rng.uniform(-jitter, jitter)), 3)
        rows.append(PerformanceMetric(
            metric_id=f"{id_prefix}-{index:06d}",
            tenant_id=tenant_id,
            asset_id=f"asset-{(index % 7) + 1:03d}",
            metric_name=name,
            metric_type=definition.metric_type,
            metric_value=value,
            unit=definition.unit,
            source_id=SYNTHETIC_SOURCE,
            observed_at=CORPUS_EPOCH + timedelta(minutes=index % 240),
            interval_seconds=60.0,
            labels={"synthetic": "1", "corpus": SCHEMA.split("/")[-1]},
            quality_status=QualityStatus.VALID,
        ))
    return rows


def missing_row(index: int, *, tenant_id: str = "tenant_synthetic",
                quality: QualityStatus = QualityStatus.STALE
                ) -> PerformanceMetric:
    """A corpus row whose source did NOT deliver a value — unknown
    telemetry, never a fabricated zero."""
    return PerformanceMetric(
        metric_id=f"corpus-missing-{index:06d}",
        tenant_id=tenant_id,
        asset_id=f"asset-{(index % 7) + 1:03d}",
        metric_name="api.latency_p95_ms",
        metric_type=definition_for("api.latency_p95_ms").metric_type,
        metric_value=None,
        unit=definition_for("api.latency_p95_ms").unit,
        source_id=SYNTHETIC_SOURCE,
        observed_at=CORPUS_EPOCH + timedelta(minutes=index % 240),
        interval_seconds=60.0,
        labels={"synthetic": "1", "corpus": SCHEMA.split("/")[-1]},
        quality_status=quality,
    )
