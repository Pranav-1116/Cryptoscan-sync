"""Performance domain views (docs/performance/01_PRODUCT_SPEC.md, §2 and §6).

Read-side intelligence over ingested metrics: the overview tiles and the
domain views (network, storage, applications, databases, cryptography,
infrastructure, per-asset). Every view is computed from raw delivered
samples on read — deterministic and reproducible — and every gap is
named: a domain with no telemetry reports ``unknown``, never zeros.

The bandwidth/throughput distinction (§2.C) is structural here: a
bandwidth capacity figure is never presented as an observed throughput.
"""

from __future__ import annotations

from datetime import datetime
from statistics import median
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

from shared_models.performance_metrics import (
    NO_VALUE_QUALITIES, PerformanceMetric,
)
from shared_models.performance_taxonomy import domain_of

MAX_QUERY_WINDOW_DAYS = 31


def _percentile(values: Sequence[float], fraction: float) -> Optional[float]:
    """Nearest-rank percentile over delivered values — deterministic,
    reproducible, and documented as the aggregation method."""
    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, int((len(ordered) * fraction) + 0.999999))
    return ordered[min(rank, len(ordered)) - 1]


def _delivered(rows: Iterable[PerformanceMetric]) -> List[float]:
    return [r.metric_value for r in rows
            if r.quality_status not in NO_VALUE_QUALITIES
            and r.metric_value is not None]


def _unknown_count(rows: Sequence[PerformanceMetric]) -> int:
    return sum(1 for r in rows
               if r.quality_status in NO_VALUE_QUALITIES
               or r.metric_value is None)


def summarize_metric(rows: Sequence[PerformanceMetric]) -> Dict[str, Any]:
    """A metric summary whose coverage is part of its answer: averages
    and percentiles cover delivered values only, unknowns are named."""
    delivered = _delivered(rows)
    unknown = _unknown_count(rows)
    if not rows:
        state = "no samples"
    elif not delivered:
        state = "unknown — no delivered values"
    elif unknown:
        state = f"partial — {len(delivered)}/{len(rows)} delivered"
    else:
        state = "complete"
    return {
        "sample_count": len(rows),
        "value_count": len(delivered),
        "unknown_count": unknown,
        "coverage": state,
        "average": (sum(delivered) / len(delivered)) if delivered else None,
        "minimum": min(delivered) if delivered else None,
        "maximum": max(delivered) if delivered else None,
        "p50": _percentile(delivered, 0.50),
        "p95": _percentile(delivered, 0.95),
        "p99": _percentile(delivered, 0.99),
    }


def window_check(window_start: Optional[datetime],
                 window_end: Optional[datetime]) -> None:
    """Query windows are bounded (§6): a larger window is refused with
    its reason, never silently truncated."""
    if window_start is None or window_end is None:
        raise ValueError(
            "window_start and window_end are required — a query without a "
            "time range would claim unbounded history")
    if window_end <= window_start:
        raise ValueError("window_end must be after window_start")
    span = (window_end - window_start).total_seconds()
    if span > MAX_QUERY_WINDOW_DAYS * 86400:
        raise ValueError(
            f"query window exceeds {MAX_QUERY_WINDOW_DAYS} days — bounded "
            "query windows are a design rule (docs/performance/"
            "01_PRODUCT_SPEC.md §6); narrow the range")


def _rows_by_name(rows: Sequence[PerformanceMetric]) -> Dict[str, List[PerformanceMetric]]:
    by_name: Dict[str, List[PerformanceMetric]] = {}
    for row in rows:
        by_name.setdefault(row.metric_name, []).append(row)
    return by_name


def domain_view(rows: Sequence[PerformanceMetric], domain: str,
                ) -> Dict[str, Any]:
    """One monitoring domain (§2 A–H) as named metric summaries."""
    by_name = _rows_by_name(rows)
    metrics: Dict[str, Any] = {}
    for name in sorted(by_name):
        if domain_of(name) != domain:
            continue
        metrics[name] = summarize_metric(by_name[name])
    if metrics:
        note = "summaries cover delivered values; unknowns are named, never zero"
    else:
        note = (f"no telemetry for domain {domain!r} in this window — "
                "absence is unknown, never zero")
    return {"domain": domain, "metrics": metrics, "note": note}


def storage_view(rows: Sequence[PerformanceMetric]) -> Dict[str, Any]:
    """Storage intelligence (§2.B): capacity, used, available,
    utilization — and an exhaustion estimate only when growth is
    measurable, never invented."""
    by_name = _rows_by_name(rows)
    summary = {name: summarize_metric(values)
               for name, values in sorted(by_name.items())
               if domain_of(name) == "storage"}
    capacity = _latest(by_name.get("storage.capacity_bytes", []))
    used = _latest(by_name.get("storage.used_bytes", []))
    available = _latest(by_name.get("storage.available_bytes", []))
    utilization = _latest(by_name.get("storage.utilization_pct", []))
    if capacity is not None and used is None and available is not None:
        used = capacity - available  # derived, and labelled as such
    tiles = {
        "capacity_bytes": _tile(capacity, "bytes"),
        "used_bytes": _tile(used, "bytes",
                            derived=capacity is not None and used is not None),
        "available_bytes": _tile(available, "bytes"),
        "utilization_pct": _tile(utilization, "percent"),
    }
    return {
        "tiles": tiles,
        "metrics": summary,
        "note": "values are the latest delivered samples in the window; "
                "an absent tile is unknown, never zero",
    }


def network_view(rows: Sequence[PerformanceMetric]) -> Dict[str, Any]:
    """Network performance (§2.C). Bandwidth capacity and actual
    throughput are separate tiles — a 10 Gbps interface does not mean
    applications are transferring 10 Gbps."""
    by_name = _rows_by_name(rows)
    summary = {name: summarize_metric(values)
               for name, values in sorted(by_name.items())
               if domain_of(name) == "network"}
    return {
        "bandwidth_capacity_mbps": _tile(
            _latest(by_name.get("network.bandwidth_mbps", [])), "Mbps"),
        "observed_throughput_mbps": _tile(
            _latest(by_name.get("network.throughput_mbps", [])), "Mbps"),
        "rtt_ms": summarize_metric(by_name.get("network.rtt_ms", []))
        if "network.rtt_ms" in by_name else None,
        "metrics": summary,
        "note": "bandwidth capacity and actual throughput are different: "
                "capacity is never presented as observed throughput",
    }


def application_view(rows: Sequence[PerformanceMetric]) -> Dict[str, Any]:
    """Application and API performance (§2.D): RPS, p50/p95/p99, error
    and timeout rates — percentiles over delivered values."""
    by_name = _rows_by_name(rows)
    summary = {name: summarize_metric(values)
               for name, values in sorted(by_name.items())
               if domain_of(name) == "applications"}
    return {
        "requests_per_sec": _tile(
            _latest(by_name.get("api.requests_per_sec", [])), "requests/sec"),
        "latency_p50_ms": _tile(_latest(by_name.get("api.latency_p50_ms", [])), "ms"),
        "latency_p95_ms": _tile(_latest(by_name.get("api.latency_p95_ms", [])), "ms"),
        "latency_p99_ms": _tile(_latest(by_name.get("api.latency_p99_ms", [])), "ms"),
        "error_rate_pct": _tile(
            _latest(by_name.get("api.error_rate_pct", [])), "percent"),
        "metrics": summary,
        "note": "percentiles are computed from delivered samples in the "
                "window; missing telemetry is unknown, never zero",
    }


def database_view(rows: Sequence[PerformanceMetric]) -> Dict[str, Any]:
    """Database performance (§2.E): connections, query time, throughput
    — statistics only; query parameters and customer records are never
    collected."""
    by_name = _rows_by_name(rows)
    summary = {name: summarize_metric(values)
               for name, values in sorted(by_name.items())
               if domain_of(name) == "database"}
    return {
        "connections_active": _tile(
            _latest(by_name.get("db.connections_active", [])), "count"),
        "query_time_ms": summarize_metric(by_name.get("db.query_time_ms", []))
        if "db.query_time_ms" in by_name else None,
        "metrics": summary,
        "note": "statistics only — query parameters and customer records "
                "are never collected (docs/performance/01_PRODUCT_SPEC.md §2.E)",
    }


def cryptography_view(rows: Sequence[PerformanceMetric]) -> Dict[str, Any]:
    """Cryptographic performance (§2.F): TLS, certificates, HSM, KMS —
    observed production measurements only. Controlled benchmark results
    live in the benchmark runs and are never mixed in here."""
    by_name = _rows_by_name(rows)
    summary = {name: summarize_metric(values)
               for name, values in sorted(by_name.items())
               if domain_of(name) == "cryptography"}
    return {
        "tls_handshake_ms": summarize_metric(
            by_name.get("crypto.tls_handshake_ms", []))
        if "crypto.tls_handshake_ms" in by_name else None,
        "hsm_operation_latency_ms": summarize_metric(
            by_name.get("crypto.hsm_operation_latency_ms", []))
        if "crypto.hsm_operation_latency_ms" in by_name else None,
        "metrics": summary,
        "measurement_kind": "observed-production",
        "note": "observed production performance only — a controlled "
                "benchmark result is never presented as production traffic "
                "performance (docs/performance/01_PRODUCT_SPEC.md §2.F)",
    }


def overview(rows: Sequence[PerformanceMetric]) -> Dict[str, Any]:
    """The overview tiles (§7). Each tile is either a computed figure
    from delivered samples or ``unknown`` — never a zero filler."""
    by_name = _rows_by_name(rows)
    storage_pct = _latest(by_name.get("storage.utilization_pct", []))
    if storage_pct is None:
        capacity = _latest(by_name.get("storage.capacity_bytes", []))
        used = _latest(by_name.get("storage.used_bytes", []))
        if capacity and used is not None:
            storage_pct = round(used / capacity * 100, 1)
    return {
        "storage_usage_pct": _tile(storage_pct, "percent"),
        "network_throughput_mbps": _tile(
            _latest(by_name.get("network.throughput_mbps", [])), "Mbps"),
        "api_p95_latency_ms": _tile(
            _latest(by_name.get("api.latency_p95_ms", [])), "ms"),
        "requests_per_sec": _tile(
            _latest(by_name.get("api.requests_per_sec", [])), "requests/sec"),
        "note": "tiles show delivered values only; an unknown tile is "
                "unknown, never zero",
    }


def _latest(rows: Sequence[PerformanceMetric]) -> Optional[float]:
    delivered = [r for r in rows
                 if r.quality_status not in NO_VALUE_QUALITIES
                 and r.metric_value is not None]
    if not delivered:
        return None
    return max(delivered, key=lambda r: r.observed_at).metric_value


def _tile(value: Optional[float], unit: str, *, derived: bool = False
          ) -> Dict[str, Any]:
    if value is None:
        return {"value": None, "unit": unit, "state": "unknown",
                "note": "no delivered telemetry in window — unknown, never zero"}
    return {"value": value, "unit": unit, "state": "known",
            "derived": derived}
