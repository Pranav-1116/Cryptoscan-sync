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
from typing import Any, Dict, Iterable, List, Optional, Sequence

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
        # the UI brief's twelve measurements (docs/performance/03_UI_SPEC.md
        # §5) — undelivered families are unknown tiles, never zero fillers
        "jitter_ms": _tile(_latest(by_name.get("network.jitter_ms", [])), "ms"),
        "packet_loss_pct": _tile(
            _latest(by_name.get("network.packet_loss_pct", [])), "percent"),
        "retransmissions": _tile(
            _latest(by_name.get("network.tcp_retransmissions", [])), "count"),
        "dns_resolution_ms": _tile(
            _latest(by_name.get("network.dns_resolution_ms", [])), "ms"),
        "connection_establish_ms": _tile(
            _latest(by_name.get("network.connection_establish_ms", [])), "ms"),
        "tcp_connections": _tile(
            _latest(by_name.get("network.connections", [])), "count"),
        "interface_errors": _tile(
            _latest(by_name.get("network.interface_errors", [])), "count"),
        "tunnel_health": _tile(
            _latest(by_name.get("network.tunnel_health", [])), "state"),
        "tls_handshake_ms": _tile(
            _latest(by_name.get("crypto.tls_handshake_ms", [])), "ms"),
        "load_balancer_response_ms": _tile(None, "ms"),
        "metrics": summary,
        "cipher_suite_note": (
            "network telemetry can establish that a connection exists or "
            "measure its performance — it does not automatically reveal the "
            "negotiated TLS cipher suite; that requires an appropriate "
            "authorized endpoint or protocol observation"),
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
    # the ten categories (docs/performance/03_UI_SPEC.md §6) — measured
    # families where delivered, named gaps where no collector exists, and
    # PQC kept benchmark-only (no production PQC telemetry is collected)
    def _cat(names, gap_basis=""):
        metrics = {name: summarize_metric(by_name[name])
                   for name in names if name in by_name}
        return {"state": "measured" if metrics else "not_collected",
                "metrics": metrics,
                "basis": "" if metrics else gap_basis}

    by_label: Dict[str, Dict[str, List[PerformanceMetric]]] = {}
    for row in rows:
        labels = row.labels or {}
        for key, bucket in (("algorithm", "algorithms"),
                            ("provider", "libraries"), ("library", "libraries")):
            label_value = labels.get(key)
            if label_value:
                by_label.setdefault(bucket, {}).setdefault(
                    str(label_value), []).append(row)
    labelled = {
        bucket: {name: summarize_metric(vals)
                 for name, vals in sorted(items.items())}
        for bucket, items in by_label.items()
    }
    categories = {
        "tls": _cat(("crypto.tls_handshake_ms",
                     "crypto.tls_negotiation_failures"),
                    "no TLS telemetry is stored in the window"),
        "encryption": {
            "state": "not_collected", "metrics": {},
            "basis": ("encryption throughput and operation latency have no "
                      "dedicated collector family — a named gap, never zeros"),
        },
        "decryption": {
            "state": "not_collected", "metrics": {},
            "basis": ("decryption throughput and operation latency have no "
                      "dedicated collector family — a named gap, never zeros"),
        },
        "signatures": _cat(("crypto.sign_latency_ms", "crypto.verify_latency_ms"),
                           "no signing or verification telemetry is stored in the window"),
        "keygen": _cat(("crypto.keygen_duration_ms",),
                       "no key-generation telemetry is stored in the window"),
        "algorithms": {
            "state": "measured" if labelled.get("algorithms") else "not_collected",
            "metrics": labelled.get("algorithms", {}),
            "basis": ("" if labelled.get("algorithms") else
                      "no algorithm-attributed telemetry is stored in the window"),
        },
        "libraries": {
            "state": "measured" if labelled.get("libraries") else "not_collected",
            "metrics": labelled.get("libraries", {}),
            "basis": ("" if labelled.get("libraries") else
                      "no provider-attributed telemetry is stored in the window"),
        },
        "pqc": {
            "state": "benchmark-only", "metrics": {},
            "basis": ("ML-KEM and ML-DSA performance is benchmark-only here "
                      "— no production PQC telemetry is collected"),
        },
        "errors": _cat(("crypto.provider_errors",),
                       "no provider-error telemetry is stored in the window"),
        "resources": {
            "state": "not_collected", "metrics": {},
            "basis": ("CPU consumption and memory overhead of cryptographic "
                      "operations have no collector family — a named gap"),
        },
    }
    return {
        "tls_handshake_ms": summarize_metric(
            by_name.get("crypto.tls_handshake_ms", []))
        if "crypto.tls_handshake_ms" in by_name else None,
        "hsm_operation_latency_ms": summarize_metric(
            by_name.get("crypto.hsm_operation_latency_ms", []))
        if "crypto.hsm_operation_latency_ms" in by_name else None,
        "metrics": summary,
        "categories": categories,
        "measurement_kind": "observed-production",
        "note": "observed production performance only — a controlled "
                "benchmark result is never presented as production traffic "
                "performance (docs/performance/01_PRODUCT_SPEC.md §2.F)",
    }


def _service_rows(rows: Sequence[PerformanceMetric]) -> List[Dict[str, Any]]:
    """Per-service figures for the landing table. One row per asset that
    delivered any api.* telemetry; missing columns stay None (unknown)."""
    by_asset: Dict[str, List[PerformanceMetric]] = {}
    for row in rows:
        if (row.metric_name or "").startswith("api."):
            by_asset.setdefault(row.asset_id, []).append(row)
    out: List[Dict[str, Any]] = []
    for asset_id, arows in sorted(by_asset.items()):
        by_name: Dict[str, List[PerformanceMetric]] = {}
        for row in arows:
            by_name.setdefault(row.metric_name, []).append(row)
        out.append({
            "service": asset_id,
            "p95_latency_ms": _latest(by_name.get("api.latency_p95_ms", [])),
            "error_rate_pct": _latest(by_name.get("api.error_rate_pct", [])),
            "requests_per_sec": _latest(by_name.get("api.requests_per_sec", [])),
            "sample_count": len(arows),
        })
    return out


def overview(rows: Sequence[PerformanceMetric]) -> Dict[str, Any]:
    """The overview tiles (§7). Each tile is either a computed figure
    from delivered samples or ``unknown`` — never a zero filler.

    The headline set carries the UI brief's four cards (CPU, memory,
    application p95, error rate) beside the estate tiles."""
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
        "cpu_utilization_pct": _tile(
            _latest(by_name.get("cpu.utilization_pct", [])), "percent"),
        "memory_utilization_pct": _tile(
            _latest(by_name.get("ram.utilization_pct", [])), "percent"),
        "app_p95_latency_ms": _tile(
            _latest(by_name.get("api.latency_p95_ms", [])), "ms"),
        "error_rate_pct": _tile(
            _latest(by_name.get("api.error_rate_pct", [])), "percent"),
        "services": _service_rows(rows),
        "note": "tiles show delivered values only; an unknown tile is "
                "unknown, never zero",
    }


#: Infrastructure families (UI spec §2). The eight interface tabs read one
#: workspace projection: categories, per-server inventory and honest gaps.
_INFRA_FAMILIES = {
    "cpu": ("cpu.utilization_pct", "system.load"),
    "memory": ("ram.utilization_pct",),
    "storage": ("storage.capacity_bytes", "storage.used_bytes",
                "storage.available_bytes", "storage.utilization_pct",
                "storage.growth_bytes"),
    "disk": ("disk.utilization_pct", "disk.iops", "disk.throughput_mbps",
             "disk.latency_ms"),
    "processes": ("process.health",),
    "containers": ("container.cpu_pct", "container.memory_bytes",
                   "container.network_throughput_mbps"),
    "kubernetes": ("k8s.pod_restarts", "k8s.resource_quota_pct"),
}


def infrastructure_workspace(
        rows: Sequence[PerformanceMetric],
        link_by_asset: Dict[str, Optional[str]] | None = None,
) -> Dict[str, Any]:
    """The Infrastructure Performance workspace (UI spec §2): the eight
    interface tabs read this one projection.

    ``link_by_asset`` carries VERIFIED canonical refs (tech-spine lookups
    performed by the caller) — an asset without a verified link stays
    unlinked; the engine never invents asset identities. Virtualization and
    environmental hardware telemetry have no metric families in the
    taxonomy, so those tabs report a named collection gap — never zeros."""
    by_name = _rows_by_name(rows)
    links = link_by_asset or {}

    categories: Dict[str, Any] = {}
    for category, names in _INFRA_FAMILIES.items():
        metrics = {name: summarize_metric(by_name[name])
                   for name in names if name in by_name}
        categories[category] = {
            "state": "measured" if metrics else "not_collected",
            "metrics": metrics,
            "basis": ("" if metrics else
                      f"no {category} telemetry is stored in the window"),
        }
    categories["virtualization"] = {
        "state": "not_collected",
        "metrics": {},
        "basis": ("virtualization telemetry (CPU ready, memory ballooning, "
                  "host contention) has no authorized collector — a named "
                  "gap, not a healthy host"),
    }

    per_asset: Dict[str, List[PerformanceMetric]] = {}
    for row in rows:
        per_asset.setdefault(row.asset_id, []).append(row)
    inventory: List[Dict[str, Any]] = []
    for asset_id, arows in sorted(per_asset.items()):
        names: Dict[str, List[PerformanceMetric]] = {}
        for row in arows:
            names.setdefault(row.metric_name, []).append(row)
        observed = [r.observed_at for r in arows]
        inventory.append({
            "asset_id": asset_id,
            "link": links.get(asset_id),
            "link_state": ("linked" if links.get(asset_id)
                           else "not established"),
            "cpu_pct": _latest(names.get("cpu.utilization_pct", [])),
            "memory_pct": _latest(names.get("ram.utilization_pct", [])),
            "load": _latest(names.get("system.load", [])),
            "disk_latency_ms": _latest(names.get("disk.latency_ms", [])),
            "families": sorted(names.keys()),
            "samples": len(arows),
            "last_observed": max(observed).isoformat() if observed else None,
        })

    trends = {name: summarize_metric(by_name[name])
              for name in sorted(by_name)
              if name in ("cpu.utilization_pct", "ram.utilization_pct",
                          "system.load", "disk.iops", "disk.latency_ms",
                          "disk.throughput_mbps")}

    return {
        "categories": categories,
        "inventory": inventory,
        "trends": trends,
        "hardware_health": {
            "state": "measured" if "process.health" in by_name else "not_collected",
            "metrics": ({"process.health": summarize_metric(by_name["process.health"])}
                        if "process.health" in by_name else {}),
            "basis": ("environmental telemetry (temperature, fans, power "
                      "supplies) has no authorized collector — reported as a "
                      "gap, never as healthy readings"),
        },
        "note": "one workspace projection for the eight interface tabs — "
                "delivered telemetry only; a gap is named, never filled with "
                "zeros",
    }


#: Endpoint attribution keys accepted from delivered labels. Only these
#: controlled attribute keys are projected — request payloads are never
#: read, and redaction rules govern any trace collection.
_ENDPOINT_KEYS = ("endpoint", "path", "url", "operation")


def application_workspace(rows: Sequence[PerformanceMetric]) -> Dict[str, Any]:
    """Application Performance (UI spec §3): the ten headline metrics,
    per-service and per-endpoint performance, and the eight capabilities
    each as measured or as a named gap. Distributed traces and request
    waterfalls have no authorized collector here — the gap is named and
    the collection contract (controlled attributes and redaction; payment
    credentials, authorization tokens and sensitive request payloads are
    never collected) governs what could ever be collected."""
    by_name = _rows_by_name(rows)

    def tile_for(name: str, unit: str) -> Dict[str, Any]:
        return _tile(_latest(by_name.get(name, [])), unit)

    queue_tile = _tile(None, "count")
    queue_tile["note"] = ("queue depth has no authorized collector — "
                          "unknown, never zero")
    metrics = {
        "requests_per_sec": tile_for("api.requests_per_sec", "requests/sec"),
        "throughput_bytes": tile_for("api.throughput_bytes", "bytes"),
        "latency_p50_ms": tile_for("api.latency_p50_ms", "ms"),
        "latency_p95_ms": tile_for("api.latency_p95_ms", "ms"),
        "latency_p99_ms": tile_for("api.latency_p99_ms", "ms"),
        "error_rate_pct": tile_for("api.error_rate_pct", "percent"),
        "timeout_rate_pct": tile_for("api.timeout_rate_pct", "percent"),
        "availability_pct": tile_for("availability.uptime_pct", "percent"),
        "queue_depth": queue_tile,
        "saturation": tile_for("saturation.indicator", "ratio"),
    }

    per_asset: Dict[str, List[PerformanceMetric]] = {}
    for row in rows:
        if (row.metric_name or "").startswith("api.") or row.metric_name == "availability.uptime_pct":
            per_asset.setdefault(row.asset_id, []).append(row)
    services: List[Dict[str, Any]] = []
    for asset_id, arows in sorted(per_asset.items()):
        names: Dict[str, List[PerformanceMetric]] = {}
        for row in arows:
            names.setdefault(row.metric_name, []).append(row)
        observed = [r.observed_at for r in arows]
        services.append({
            "service": asset_id,
            "p50_latency_ms": _latest(names.get("api.latency_p50_ms", [])),
            "p95_latency_ms": _latest(names.get("api.latency_p95_ms", [])),
            "p99_latency_ms": _latest(names.get("api.latency_p99_ms", [])),
            "error_rate_pct": _latest(names.get("api.error_rate_pct", [])),
            "timeout_rate_pct": _latest(names.get("api.timeout_rate_pct", [])),
            "requests_per_sec": _latest(names.get("api.requests_per_sec", [])),
            "samples": len(arows),
            "last_observed": max(observed).isoformat() if observed else None,
        })

    endpoints: List[Dict[str, Any]] = []
    for row in rows:
        labels = row.labels or {}
        endpoint = next((str(labels[k]) for k in _ENDPOINT_KEYS if labels.get(k)), None)
        if endpoint is None:
            continue
        endpoints.append({
            "service": row.asset_id,
            "endpoint": endpoint,
            "metric_name": row.metric_name,
            "latest": row.metric_value,
            "unit": row.unit,
            "observed_at": row.observed_at.isoformat(),
        })
    endpoints.sort(key=lambda e: (e["service"], e["endpoint"], e["metric_name"]))

    def capability(delivered: bool, gap_basis: str, ok_basis: str) -> Dict[str, str]:
        return {"state": "measured" if delivered else "not_collected",
                "basis": ok_basis if delivered else gap_basis}

    capabilities = {
        "service_level": capability(
            bool(services), "no service telemetry is stored in the window",
            "per-service percentiles computed from delivered samples"),
        "api_endpoints": capability(
            bool(endpoints),
            "no endpoint-attributed telemetry is stored in the window",
            "endpoint rows project controlled label keys only"),
        "distributed_tracing": capability(
            False, "distributed tracing has no authorized collector — trace "
                   "collection is governed by controlled attributes and "
                   "redaction; payment credentials, authorization tokens and "
                   "sensitive request payloads are never collected",
            ""),
        "request_waterfall": capability(
            False, "a request waterfall is drawn from traces — no traces are "
                   "stored, so no waterfall is drawn", ""),
        "slow_transactions": capability(
            False, "transaction records have no authorized collector — a slow "
                   "transaction cannot be named without stored transactions", ""),
        "dependency_latency": capability(
            False, "dependency links carry no latency measurements in this "
                   "window — a link is not a latency", ""),
        "regression": capability(
            "performance.regression_ms" in by_name,
            "no regression measurements are stored in the window",
            "regression measurements compared against the recorded baseline"),
        "slo": capability(
            "slo.compliance_pct" in by_name,
            "no SLO compliance measurements are stored in the window — "
            "policies are tracked separately and a policy is not proof of "
            "compliance",
            "compliance measurements compared against the stated policies"),
    }

    return {
        "metrics": metrics,
        "services": services,
        "endpoints": endpoints,
        "capabilities": capabilities,
        "regression": (summarize_metric(by_name["performance.regression_ms"])
                       if "performance.regression_ms" in by_name else None),
        "note": "percentiles are computed from delivered samples in the "
                "window; missing telemetry is unknown, never zero",
    }


#: Database metric areas (UI spec §4): measured families per area and the
#: measurements with NO collector — named as gaps, never zeros.
_DB_AREAS = {
    "connections": (("db.connections_active", "db.connections_idle",
                     "db.pool_utilization_pct"),
                    ("waiting connections", "connection exhaustion")),
    "queries": (("db.query_time_ms", "db.query_throughput"),
                ("slow query count",)),
    "locks": (("db.lock_waits", "db.deadlocks"), ("blocking",)),
    "cache": (("db.cache_hit_ratio",), ("buffer utilization",)),
    "storage": (("db.size_bytes",), ("database growth", "database IOPS")),
    "replication": (("db.replication_lag_seconds",), ("replication status",)),
    "transactions": (("db.transactions_per_sec",),
                     ("commit rate", "rollback rate")),
    "backup": (("db.backup_duration_seconds",),
               ("backup status", "backup age")),
    "availability": (("availability.uptime_pct",), ("connection failures",)),
}

#: Database adapter platforms (UI spec §4). The engine ships a dedicated
#: postgres_exporter translator and a generic OTLP ingest path — other
#: platforms are named scope with no dedicated adapter, never claimed.
_DB_ADAPTERS = (
    {"platform": "PostgreSQL", "adapter": "postgres_exporter",
     "state": "adapter available"},
    {"platform": "MySQL", "adapter": None,
     "state": "no dedicated adapter — generic OTLP ingest only"},
    {"platform": "Microsoft SQL Server", "adapter": None,
     "state": "no dedicated adapter — generic OTLP ingest only"},
    {"platform": "Oracle", "adapter": None,
     "state": "no dedicated adapter — generic OTLP ingest only"},
)


def database_workspace(
        rows: Sequence[PerformanceMetric],
        collectors: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Database Performance (UI spec §4): the nine areas over delivered
    db.* telemetry, per-database rows and the adapter panel. The
    collection contract is statistics only: query fingerprints and
    normalized statistics, never SQL statements containing customer data
    (docs/performance/03_UI_SPEC.md §4)."""
    by_name = _rows_by_name(rows)

    areas: Dict[str, Any] = {}
    for area, (names, missing) in _DB_AREAS.items():
        metrics = {name: summarize_metric(by_name[name])
                   for name in names if name in by_name}
        areas[area] = {
            "state": "measured" if metrics else "not_collected",
            "metrics": metrics,
            "missing": list(missing),
        }

    per_asset: Dict[str, List[PerformanceMetric]] = {}
    for row in rows:
        if (row.metric_name or "").startswith("db.") or row.metric_name == "availability.uptime_pct":
            per_asset.setdefault(row.asset_id, []).append(row)
    databases: List[Dict[str, Any]] = []
    for asset_id, arows in sorted(per_asset.items()):
        names: Dict[str, List[PerformanceMetric]] = {}
        platform = None
        for row in arows:
            names.setdefault(row.metric_name, []).append(row)
            labels = row.labels or {}
            if platform is None:
                platform = (labels.get("platform") or labels.get("engine")
                            or labels.get("database"))
        observed = [r.observed_at for r in arows]
        databases.append({
            "database": asset_id,
            "platform": platform or "not recorded",
            "connections_active": _latest(names.get("db.connections_active", [])),
            "query_time_ms": _latest(names.get("db.query_time_ms", [])),
            "size_bytes": _latest(names.get("db.size_bytes", [])),
            "replication_lag_seconds": _latest(
                names.get("db.replication_lag_seconds", [])),
            "samples": len(arows),
            "last_observed": max(observed).isoformat() if observed else None,
        })

    return {
        "areas": areas,
        "databases": databases,
        "adapters": list(_DB_ADAPTERS),
        "collectors": collectors or [],
        "note": "statistics only — the collection contract is query "
                "fingerprints and normalized statistics; query parameters "
                "and customer records are never collected, and SQL "
                "statements containing customer data are never collected",
    }


#: HSM/KMS metric families (UI spec §7). Read-only projections of stored
#: telemetry — the collector rule (vendor-supported, read-only, no key
#: material, no interference) governs collection and is not narrated here.
_HSM_METRICS = (
    "crypto.hsm_operation_latency_ms", "crypto.hsm_queue_depth",
    "crypto.hsm_utilization_pct", "crypto.sign_latency_ms",
    "crypto.verify_latency_ms", "crypto.keygen_duration_ms",
    "crypto.provider_errors", "crypto.kms_response_ms",
    "cloud.kms_service_latency_ms",
)


def hsm_view(rows: Sequence[PerformanceMetric]) -> Dict[str, Any]:
    """HSM & KMS performance (UI spec §7): per-device rows plus the
    measured families. Unknowns stay unknown; key material never appears
    because only metric rows are read."""
    by_name = _rows_by_name(rows)
    families = {name: summarize_metric(by_name.get(name, []))
                for name in _HSM_METRICS if name in by_name}
    def _trend(metric_rows: Sequence[PerformanceMetric]) -> List[Dict[str, Any]]:
        """Hour-bucketed trend over DELIVERED values only — a bucket with
        no data is null, never a fabricated flat point."""
        buckets: Dict[str, List[float]] = {}
        for row in metric_rows:
            if (row.quality_status in NO_VALUE_QUALITIES
                    or row.metric_value is None):
                continue
            buckets.setdefault(row.observed_at.strftime("%Y-%m-%dT%H"),
                               []).append(row.metric_value)
        return [{"bucket": hour, "value": round(sum(vals) / len(vals), 3),
                 "samples": len(vals)}
                for hour, vals in sorted(buckets.items())]

    per_device: Dict[str, Dict[str, List[PerformanceMetric]]] = {}
    for row in rows:
        if row.metric_name not in _HSM_METRICS:
            continue
        per_device.setdefault(row.asset_id, {}).setdefault(
            row.metric_name, []).append(row)
    devices: List[Dict[str, Any]] = []
    for device_id, by_metric in sorted(per_device.items()):
        flat = [r for rs in by_metric.values() for r in rs]
        op_rows = by_metric.get("crypto.hsm_operation_latency_ms", [])
        avail_rows = [r for r in rows
                      if r.asset_id == device_id
                      and r.metric_name == "availability.uptime_pct"]
        devices.append({
            "device": device_id,
            "operation_latency_ms": _latest(op_rows),
            "p95_latency_ms": _percentile(
                [r.metric_value for r in op_rows
                 if r.quality_status not in NO_VALUE_QUALITIES
                 and r.metric_value is not None], 0.95),
            "queue_depth": _latest(by_metric.get("crypto.hsm_queue_depth", [])),
            "utilization_pct": _latest(
                by_metric.get("crypto.hsm_utilization_pct", [])),
            "provider_errors": _latest(
                by_metric.get("crypto.provider_errors", [])),
            "availability_pct": _latest(avail_rows),
            "operations_per_sec": None,
            "samples": len(flat),
            "last_observed": max((r.observed_at for r in flat), default=None),
            "trend": _trend(op_rows),
        })
    for entry in devices:
        entry["last_observed"] = (entry["last_observed"].isoformat()
                                  if entry["last_observed"] else None)

    def _measure(names, gap_basis):
        found = {name: summarize_metric(by_name[name])
                 for name in names if name in by_name}
        return {"state": "measured" if found else "not_collected",
                "metrics": found, "basis": "" if found else gap_basis}

    measurements = {
        "availability": _measure(("availability.uptime_pct",),
                                 "no HSM availability telemetry is stored in the window"),
        "throughput": {"state": "not_collected", "metrics": {},
                       "basis": ("request throughput has no counter family "
                                 "— unknown, never zero")},
        "sign_latency": _measure(("crypto.sign_latency_ms",),
                                 "no signing telemetry is stored in the window"),
        "verify_latency": _measure(("crypto.verify_latency_ms",),
                                   "no verification telemetry is stored in the window"),
        "encrypt_latency": {"state": "not_collected", "metrics": {},
                            "basis": ("encrypt latency has no dedicated "
                                      "collector family — a named gap")},
        "decrypt_latency": {"state": "not_collected", "metrics": {},
                            "basis": ("decrypt latency has no dedicated "
                                      "collector family — a named gap")},
        "keygen_latency": _measure(("crypto.keygen_duration_ms",),
                                   "no key-generation telemetry is stored in the window"),
        "queue_saturation": _measure(("crypto.hsm_queue_depth",
                                      "crypto.hsm_utilization_pct"),
                                     "no queue or saturation telemetry is stored in the window"),
        "session_utilization": {"state": "not_collected", "metrics": {},
                                "basis": ("session utilization has no "
                                          "collector family — a named gap")},
        "provider_errors": _measure(("crypto.provider_errors",),
                                    "no provider-error telemetry is stored in the window"),
        "failover": {"state": "not_collected", "metrics": {},
                     "basis": ("failover status has no collector family "
                               "— a named gap")},
        "firmware_changes": {"state": "not_collected", "metrics": {},
                             "basis": ("firmware and configuration changes "
                                       "are not performance telemetry here "
                                       "— a named gap")},
        "kms_latency": _measure(("crypto.kms_response_ms",
                                 "cloud.kms_service_latency_ms"),
                                "no KMS latency telemetry is stored in the window"),
        "kms_throttling": {"state": "not_collected", "metrics": {},
                           "basis": ("KMS throttling has no collector "
                                     "family — a named gap")},
    }
    return {
        "devices": devices,
        "families": families,
        "measurements": measurements,
        "measurement_kind": "observed-production",
        "note": "vendor-supported read-only management and performance "
                "interfaces only — key material is never collected and HSM "
                "operations are never interfered with",
    }


def workload_view(rows: Sequence[PerformanceMetric]) -> Dict[str, Any]:
    """Workload & transaction intelligence (UI spec §8): business-facing
    throughput and latency joined to the estate metrics — with the
    causation rule enforced: a time correlation is reported as correlation,
    never as cause, until timestamps and traces establish it."""
    by_name = _rows_by_name(rows)
    workload = {name: summarize_metric(values)
                for name, values in sorted(by_name.items())
                if name in ("api.requests_per_sec", "api.requests_total",
                            "api.latency_p50_ms", "api.latency_p95_ms",
                            "api.latency_p99_ms", "api.error_rate_pct",
                            "api.timeout_rate_pct", "api.throughput_bytes",
                            "db.transactions_per_sec", "db.query_throughput",
                            "crypto.tls_handshake_ms",
                            "crypto.hsm_operation_latency_ms")}
    candidates = []
    tls = _latest(by_name.get("crypto.tls_handshake_ms", []))
    app_p95 = _latest(by_name.get("api.latency_p95_ms", []))
    if tls is not None and app_p95 is not None:
        candidates.append({
            "question": "does TLS handshake time contribute to application latency?",
            "tls_handshake_ms": tls,
            "app_p95_latency_ms": app_p95,
            "causation": "unproven",
            "basis": ("a time correlation alone never proves causation — "
                      "timestamps and traces must correlate before causation "
                      "is suggested"),
        })
    # business workload categories (docs/performance/03_UI_SPEC.md §8) —
    # attributed from delivered labels only; unlabelled traffic is never
    # claimed as a business workload
    workload_keys = ("workload", "transaction_type", "business_unit")

    def _matches(row, pattern):
        labels = row.labels or {}
        return any(pattern in str(labels.get(k, "")).lower()
                   for k in workload_keys)

    categories: Dict[str, Any] = {}
    for category, pattern in (("payments", "payment"), ("authentication", "auth"),
                              ("card", "card"), ("batch", "batch")):
        cat_rows = [r for r in rows if _matches(r, pattern)]
        metrics = {}
        for row in cat_rows:
            metrics.setdefault(row.metric_name, []).append(row)
        categories[category] = {
            "state": "measured" if cat_rows else "not_collected",
            "metrics": {name: summarize_metric(vals)
                        for name, vals in sorted(metrics.items())},
            "basis": ("" if cat_rows else
                      f"no {category} workload telemetry is labelled in the "
                      "window — workload performance is not inferred from "
                      "infrastructure metrics"),
        }

    def _measured(names, gap_basis):
        found = {name: summarize_metric(by_name[name])
                 for name in names if name in by_name}
        return {"state": "measured" if found else "not_collected",
                "metrics": found, "basis": "" if found else gap_basis}

    measurements = {
        "payment_throughput": categories["payments"],
        "authentication_performance": categories["authentication"],
        "card_authorization_latency": categories["card"],
        "batch_duration": categories["batch"],
        "database_transaction_time": _measured(
            ("db.transactions_per_sec", "db.query_time_ms"),
            "no database transaction telemetry is stored in the window"),
        "crypto_overhead_per_transaction": {
            "state": "not_collected", "metrics": {},
            "basis": ("cryptographic overhead per transaction has no "
                      "collector family — it is never inferred from crypto "
                      "latency alone, a named gap"),
        },
        "queue_backlogs": {
            "state": "not_collected", "metrics": {},
            "basis": "queue depth has no collector family — a named gap",
        },
    }

    # peak vs off-peak from delivered request series — labelled derived,
    # computed from real samples only
    peak_offpeak: Dict[str, Any] = {"state": "not_collected", "basis": (
        "no request series is labelled in the window — peak and off-peak "
        "cannot be compared without delivered samples")}
    req_rows = [r for r in by_name.get("api.requests_per_sec", [])
                if r.quality_status not in NO_VALUE_QUALITIES
                and r.metric_value is not None]
    if req_rows:
        buckets: Dict[str, List[float]] = {}
        for row in req_rows:
            buckets.setdefault(row.observed_at.strftime("%Y-%m-%dT%H"),
                               []).append(row.metric_value)
        means = {hour: sum(vals) / len(vals) for hour, vals in buckets.items()}
        if len(means) >= 2:
            peak_hour = max(means, key=lambda h: means[h])
            offpeak = {h: v for h, v in means.items() if h != peak_hour}
            offpeak_mean = sum(offpeak.values()) / len(offpeak)
            peak_offpeak = {
                "state": "derived",
                "peak_bucket": peak_hour,
                "peak_value": round(means[peak_hour], 3),
                "offpeak_mean": round(offpeak_mean, 3),
                "buckets": [{"bucket": h, "value": round(v, 3)}
                            for h, v in sorted(means.items())],
                "basis": ("derived from the window's delivered request "
                          "samples — derived figures are labelled derived"),
            }

    return {
        "workload_metrics": workload,
        "categories": categories,
        "measurements": measurements,
        "peak_offpeak": peak_offpeak,
        "correlation_candidates": candidates,
        "causation": "unproven",
        "note": "workload performance meets business workloads here; the "
                "engine reports correlation candidates only — it must "
                "correlate timestamps and traces before suggesting causation",
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
