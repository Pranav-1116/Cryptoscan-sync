"""Performance collector translators (docs/performance/01_PRODUCT_SPEC.md,
§3.2 and roadmap Phases 2–4).

External exporter payloads — Node Exporter (infrastructure and storage),
PostgreSQL Exporter (database), OTLP (applications) — become
``PerformanceMetric`` rows here. The rule every translator obeys: it
never invents a value and never guesses a unit. A family it cannot map
is REFUSED with its reason and counted, never silently dropped and never
fabricated into the taxonomy.

Rate-derived metrics (utilization percentages) need two samples. One
sample yields no value — a percentage computed from a single reading
would be invented, so the row is emitted with ``missing`` quality and no
value at all.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Mapping, Optional, Tuple

from shared_models.performance_metrics import (
    PerformanceMetric, QualityStatus,
)
from shared_models.performance_taxonomy import definition_for

#: raw family -> (taxonomy metric name, unit scale function name)
#: The mapped unit MUST equal the taxonomy unit (checked at translation).
NODE_EXPORTER_MAP: Dict[str, str] = {
    "node_memory_MemTotal_bytes": "storage.capacity_bytes",
    "node_memory_MemAvailable_bytes": "storage.available_bytes",
    "node_filesystem_size_bytes": "storage.capacity_bytes",
    "node_filesystem_avail_bytes": "storage.available_bytes",
    "node_disk_read_bytes_total": "disk.throughput_mbps",
    "node_disk_written_bytes_total": "disk.throughput_mbps",
    "node_disk_reads_completed_total": "disk.iops",
    "node_disk_writes_completed_total": "disk.iops",
    "node_load1": "system.load",
    "node_procs_running": "process.health",
}

#: rate-derived families: computed only across two snapshots
NODE_RATE_MAP: Dict[str, str] = {
    "node_cpu_seconds_total": "cpu.utilization_pct",
    "node_memory_MemAvailable_bytes@rate": "ram.utilization_pct",
}

POSTGRES_EXPORTER_MAP: Dict[str, str] = {
    "pg_stat_activity_count": "db.connections_active",
    "pg_settings_max_connections": "db.connections_idle",
    "pg_stat_database_tup_returned": "db.query_throughput",
    "pg_stat_database_xact_commit": "db.transactions_per_sec",
    "pg_stat_database_deadlocks": "db.deadlocks",
    "pg_database_size_bytes": "db.size_bytes",
    "pg_replication_lag_seconds": "db.replication_lag_seconds",
    "pg_stat_database_blks_hit": "db.cache_hit_ratio",
}

OTLP_MAP: Dict[str, str] = {
    "http.server.request.duration": "api.latency_p50_ms",
    "http.server.active_requests": "api.concurrent_requests",
    "http.server.error.rate": "api.error_rate_pct",
    "process.cpu.utilization": "cpu.utilization_pct",
    "process.memory.usage": "container.memory_bytes",
}

UNIT_SCALE = {
    # raw counter seconds -> reported as ms or percent via rate
    "bytes_to_mbps": lambda value, interval: (
        None if not interval else (value * 8 / interval / 1_000_000)),
}


@dataclass
class TranslationResult:
    """What a translator produced — and everything it refused."""

    metrics: List[PerformanceMetric] = field(default_factory=list)
    refused: List[Dict[str, str]] = field(default_factory=list)

    @property
    def refused_count(self) -> int:
        return len(self.refused)


def _unit_of(metric_name: str) -> Optional[str]:
    try:
        return definition_for(metric_name).unit
    except KeyError:
        return None


def _refuse(refused: List[Dict[str, str]], family: str, reason: str) -> None:
    refused.append({"raw_family": family, "reason": reason})


def _sample_rows(payload: Mapping[str, Any]) -> List[Tuple[str, float, Dict[str, str]]]:
    """Normalize an exporter payload to (family, value, labels) rows."""
    rows: List[Tuple[str, float, Dict[str, str]]] = []
    for family, samples in (payload.get("metrics") or {}).items():
        for sample in samples or []:
            try:
                value = float(sample.get("value"))
            except (TypeError, ValueError):
                continue
            rows.append((family, value, dict(sample.get("labels") or {})))
    return rows


def translate_node_exporter(payload: Mapping[str, Any], *,
                            asset_id: str, tenant_id: str, source_id: str,
                            observed_at: datetime,
                            previous: Optional[Mapping[str, Any]] = None,
                            interval_seconds: Optional[float] = None
                            ) -> TranslationResult:
    """Node Exporter payload -> infrastructure and storage metrics.

    ``previous`` is the prior payload snapshot: without it, rate-derived
    utilization is emitted as MISSING telemetry (no value), never a
    guessed percentage.
    """
    result = TranslationResult()
    previous_rows: Dict[Tuple[str, str], float] = {}
    if previous:
        for family, value, labels in _sample_rows(previous):
            previous_rows[(family, labels.get("cpu") or labels.get("device")
                           or labels.get("mountpoint") or "")] = value
    seen_keys = set()

    # CPU utilization = 1 - idle-delta/total-delta per cpu, summed over the
    # modes both snapshots share. One snapshot, or a counter that did not
    # move, is unknown telemetry: no value, quality named.
    cpu_now = _cpu_rows(_sample_rows(payload))
    cpu_prev = _cpu_rows(_sample_rows(previous)) if previous else {}
    for cpu, (idle_now, total_now) in sorted(cpu_now.items()):
        prev = cpu_prev.get(cpu)
        metric_id = _metric_id(source_id, "node_cpu_seconds_total",
                               {"cpu": cpu}, observed_at)
        if prev is None:
            result.metrics.append(_metric(
                metric_name="cpu.utilization_pct", value=None,
                quality=QualityStatus.MISSING, unit="percent",
                asset_id=asset_id, tenant_id=tenant_id,
                source_id=source_id, observed_at=observed_at,
                metric_id=metric_id, labels={"cpu": cpu}))
            continue
        idle_prev, total_prev = prev
        delta_total = total_now - total_prev
        delta_idle = idle_now - idle_prev
        if delta_total <= 0 or delta_idle < 0:
            result.metrics.append(_metric(
                metric_name="cpu.utilization_pct", value=None,
                quality=QualityStatus.STALE, unit="percent",
                asset_id=asset_id, tenant_id=tenant_id,
                source_id=source_id, observed_at=observed_at,
                metric_id=metric_id, labels={"cpu": cpu}))
            continue
        utilized = max(0.0, min(1.0, 1.0 - delta_idle / delta_total))
        result.metrics.append(_metric(
            metric_name="cpu.utilization_pct",
            value=round(utilized * 100, 2), quality=QualityStatus.VALID,
            unit="percent", asset_id=asset_id, tenant_id=tenant_id,
            source_id=source_id, observed_at=observed_at,
            metric_id=metric_id, labels={"cpu": cpu},
            interval_seconds=interval_seconds))

    for family, value, labels in _sample_rows(payload):
        if family == "node_cpu_seconds_total":
            continue  # handled above
        mapped = NODE_EXPORTER_MAP.get(family)
        if mapped is None:
            _refuse(result.refused, family,
                    "not in the verified translator map — a unit is never guessed")
            continue
        unit = _unit_of(mapped)
        if unit is None:
            _refuse(result.refused, family,
                    f"mapped name {mapped!r} is not in the metric taxonomy")
            continue
        metric_id = _metric_id(source_id, family, labels, observed_at)
        if metric_id in seen_keys:
            continue
        seen_keys.add(metric_id)
        result.metrics.append(_metric(
            metric_name=mapped, value=value, quality=QualityStatus.VALID,
            unit=unit, asset_id=asset_id, tenant_id=tenant_id,
            source_id=source_id, observed_at=observed_at,
            metric_id=metric_id, labels=labels,
            interval_seconds=interval_seconds))
    return result


def translate_postgres_exporter(payload: Mapping[str, Any], *,
                                asset_id: str, tenant_id: str,
                                source_id: str, observed_at: datetime,
                                interval_seconds: Optional[float] = None
                                ) -> TranslationResult:
    """PostgreSQL Exporter payload -> database metrics. Query parameters
    and customer records are never collected — only the statistic rows
    the exporter exposes (§2.E)."""
    result = TranslationResult()
    seen = set()
    for family, value, labels in _sample_rows(payload):
        mapped = POSTGRES_EXPORTER_MAP.get(family)
        if mapped is None:
            _refuse(result.refused, family,
                    "not in the verified translator map — a unit is never guessed")
            continue
        unit = _unit_of(mapped)
        if unit is None:
            _refuse(result.refused, family,
                    f"mapped name {mapped!r} is not in the metric taxonomy")
            continue
        metric_id = _metric_id(source_id, family, labels, observed_at)
        if metric_id in seen:
            continue
        seen.add(metric_id)
        result.metrics.append(_metric(
            metric_name=mapped, value=value, quality=QualityStatus.VALID,
            unit=unit, asset_id=asset_id, tenant_id=tenant_id,
            source_id=source_id, observed_at=observed_at,
            metric_id=metric_id, labels=labels,
            interval_seconds=interval_seconds))
    return result


def translate_otlp(payload: Mapping[str, Any], *, asset_id: str,
                   tenant_id: str, source_id: str, observed_at: datetime,
                   interval_seconds: Optional[float] = None
                   ) -> TranslationResult:
    """OTLP metrics payload -> application metrics. An OTLP family
    outside the verified map is refused with its reason — an instrument
    name is not a license to guess a unit."""
    result = TranslationResult()
    seen = set()
    for family, value, labels in _sample_rows(payload):
        mapped = OTLP_MAP.get(family)
        if mapped is None:
            _refuse(result.refused, family,
                    "not in the verified translator map — a unit is never guessed")
            continue
        unit = _unit_of(mapped)
        if unit is None:
            _refuse(result.refused, family,
                    f"mapped name {mapped!r} is not in the metric taxonomy")
            continue
        metric_id = _metric_id(source_id, family, labels, observed_at)
        if metric_id in seen:
            continue
        seen.add(metric_id)
        result.metrics.append(_metric(
            metric_name=mapped, value=value, quality=QualityStatus.VALID,
            unit=unit, asset_id=asset_id, tenant_id=tenant_id,
            source_id=source_id, observed_at=observed_at,
            metric_id=metric_id, labels=labels,
            interval_seconds=interval_seconds))
    return result


def _cpu_rows(rows: List[Tuple[str, float, Dict[str, str]]]
              ) -> Dict[str, Tuple[float, float]]:
    """Per-cpu (idle delta base, total) sums from node_cpu_seconds_total."""
    out: Dict[str, Tuple[float, float]] = {}
    for family, value, labels in rows:
        if family != "node_cpu_seconds_total":
            continue
        cpu = labels.get("cpu") or "all"
        idle, total = out.get(cpu, (0.0, 0.0))
        if labels.get("mode") == "idle":
            idle += value
        total += value
        out[cpu] = (idle, total)
    return out


_UNSAFE = re.compile(r"[^A-Za-z0-9._:-]")


def _metric_id(source_id: str, family: str, labels: Mapping[str, str],
               observed_at: datetime) -> str:
    label_part = "-".join(f"{k}-{v}" for k, v in sorted(labels.items()))[:40]
    stamp = observed_at.strftime("%Y%m%dT%H%M%S%f")
    raw = f"{source_id}.{family}.{label_part}.{stamp}"
    return _UNSAFE.sub("-", raw)[:64]


def _metric(*, metric_name: str, value: Optional[float], quality: QualityStatus,
            unit: Optional[str], asset_id: str, tenant_id: str, source_id: str,
            observed_at: datetime, metric_id: str,
            labels: Mapping[str, str],
            interval_seconds: Optional[float] = None) -> PerformanceMetric:
    return PerformanceMetric(
        metric_id=metric_id, tenant_id=tenant_id, asset_id=asset_id,
        metric_name=metric_name,
        metric_type=definition_for(metric_name).metric_type.value,
        metric_value=value, unit=unit or definition_for(metric_name).unit,
        source_id=source_id, observed_at=observed_at,
        interval_seconds=interval_seconds, labels=dict(labels),
        quality_status=quality)
