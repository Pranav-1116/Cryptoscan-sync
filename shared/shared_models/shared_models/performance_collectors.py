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

import hashlib
import math
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Mapping, Optional, Tuple

from shared_models.performance_metrics import (
    PerformanceMetric, QualityStatus,
)
from shared_models.performance_taxonomy import definition_for

# Gauges whose raw unit and meaning match the registry exactly. Memory is
# RAM, not filesystem storage; cumulative disk counters are not rates.
NODE_EXPORTER_MAP: Dict[str, str] = {
    "node_filesystem_size_bytes": "storage.capacity_bytes",
    "node_filesystem_avail_bytes": "storage.available_bytes",
    "node_load1": "system.load",
}
NODE_DISK_COUNTERS: Dict[str, tuple[str, str, float]] = {
    "node_disk_read_bytes_total": ("disk.throughput_mbps", "read", 1_000_000.0),
    "node_disk_written_bytes_total": ("disk.throughput_mbps", "write", 1_000_000.0),
    "node_disk_reads_completed_total": ("disk.iops", "read", 1.0),
    "node_disk_writes_completed_total": ("disk.iops", "write", 1.0),
}

POSTGRES_EXPORTER_MAP: Dict[str, str] = {
    "pg_stat_database_deadlocks": "db.deadlocks",  # cumulative counter, not a rate
    "pg_database_size_bytes": "db.size_bytes",
    "pg_replication_lag_seconds": "db.replication_lag_seconds",
}
POSTGRES_DERIVED = frozenset({
    "pg_stat_database_xact_commit", "pg_stat_database_xact_rollback",
    "pg_stat_database_blks_hit", "pg_stat_database_blks_read",
})
POSTGRES_UNSUPPORTED = {
    "pg_settings_max_connections": "connection capacity is not idle connections",
    "pg_stat_database_tup_returned": "tuples returned are not queries/sec",
}

OTLP_MAP: Dict[str, str] = {
    "http.server.active_requests": "api.concurrent_requests",
    "process.memory.usage": "container.memory_bytes",
}
OTLP_UNSUPPORTED = {
    "http.server.request.duration": "a histogram point is not p50; an approved quantile aggregation is required",
    "http.server.error.rate": "source unit unspecified; error fraction is not a percentage without a contract",
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


def _sample_rows(payload: Mapping[str, Any],
                 refused: Optional[List[Dict[str, str]]] = None
                 ) -> List[Tuple[str, float, Dict[str, str]]]:
    """Normalize exporter rows; malformed/nonfinite values are named refusals."""
    rows: List[Tuple[str, float, Dict[str, str]]] = []
    source = payload.get("metrics") or {}
    if not isinstance(source, Mapping):
        if refused is not None:
            _refuse(refused, "metrics", "exporter metrics must be a mapping")
        return rows
    for family, samples in source.items():
        if not isinstance(samples, list):
            if refused is not None:
                _refuse(refused, str(family), "sample family must be a list")
            continue
        for sample in samples:
            if not isinstance(sample, Mapping):
                if refused is not None:
                    _refuse(refused, str(family), "sample is not a mapping")
                continue
            try:
                value = float(sample.get("value"))
                if not math.isfinite(value):
                    raise ValueError("non-finite")
                labels = sample.get("labels") or {}
                if not isinstance(labels, Mapping) or not all(
                        isinstance(k, str) and isinstance(v, str)
                        for k, v in labels.items()):
                    raise ValueError("labels are not bounded strings")
            except (TypeError, ValueError):
                if refused is not None:
                    _refuse(refused, str(family), "sample has no finite numeric value or bounded labels")
                continue
            rows.append((str(family), value, dict(labels)))
    return rows


def _index(rows: List[Tuple[str, float, Dict[str, str]]],
           refused: Optional[List[Dict[str, str]]] = None
           ) -> Dict[Tuple[str, Tuple[Tuple[str, str], ...]], float]:
    out: Dict[Tuple[str, Tuple[Tuple[str, str], ...]], float] = {}
    duplicates: set[Tuple[str, Tuple[Tuple[str, str], ...]]] = set()
    for family, value, labels in rows:
        key = family, tuple(sorted(labels.items()))
        if key in out or key in duplicates:
            duplicates.add(key)
            out.pop(key, None)
            if refused is not None:
                _refuse(refused, family, "duplicate labelled counter snapshot is ambiguous")
        else:
            out[key] = value
    return out


def _emit(result: TranslationResult, *, metric_name: str,
          family: str, value: Optional[float], quality: QualityStatus,
          asset_id: str, tenant_id: str, source_id: str, observed_at: datetime,
          labels: Mapping[str, str], interval_seconds: Optional[float] = None,
          ) -> None:
    try:
        result.metrics.append(_metric(
            metric_name=metric_name, value=value, quality=quality,
            unit=_unit_of(metric_name), asset_id=asset_id, tenant_id=tenant_id,
            source_id=source_id, observed_at=observed_at,
            metric_id=_metric_id(source_id, family, labels, observed_at,
                                 tenant_id=tenant_id, asset_id=asset_id),
            labels=labels, interval_seconds=interval_seconds))
    except (KeyError, ValueError) as exc:
        _refuse(result.refused, family,
                f"source sample refused by the metric contract ({type(exc).__name__})")


def _rate(value: float, previous: Optional[float], interval: Optional[float]
          ) -> Tuple[Optional[float], QualityStatus]:
    if previous is None or interval is None or not math.isfinite(interval) or interval <= 0:
        return None, QualityStatus.MISSING
    if value < previous:
        return None, QualityStatus.STALE
    return (value - previous) / interval, QualityStatus.VALID


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
    current = _sample_rows(payload, result.refused)
    prior = _index(_sample_rows(previous, result.refused), result.refused) if previous else {}
    seen_keys = set()

    # CPU needs exactly the same modes on each core in both snapshots. A reset
    # in ANY mode or a missing idle mode cannot be hidden by the summed total.
    cpu_now = _cpu_rows(current)
    cpu_prev = _cpu_rows(_sample_rows(previous)) if previous else {}
    seen_modes: set[tuple[str, str]] = set()
    duplicate_cpus: set[str] = set()
    for family, _, labels in current:
        if family == "node_cpu_seconds_total":
            key = (labels.get("cpu") or "all", labels.get("mode") or "")
            if key in seen_modes:
                duplicate_cpus.add(key[0])
            seen_modes.add(key)
    for cpu, modes in sorted(cpu_now.items()):
        earlier = cpu_prev.get(cpu)
        quality, utilization = QualityStatus.MISSING, None
        if cpu in duplicate_cpus:
            _refuse(result.refused, "node_cpu_seconds_total",
                    "duplicate per-core/mode counter refused")
        if earlier and cpu not in duplicate_cpus and "idle" in modes and set(modes) == set(earlier):
            deltas = {mode: value - earlier[mode] for mode, value in modes.items()}
            total = sum(deltas.values())
            if any(delta < 0 for delta in deltas.values()) or total <= 0:
                quality = QualityStatus.STALE
            else:
                quality = QualityStatus.VALID
                utilization = round((1 - deltas["idle"] / total) * 100, 2)
        _emit(result, metric_name="cpu.utilization_pct",
              family="node_cpu_seconds_total", value=utilization,
              quality=quality, asset_id=asset_id, tenant_id=tenant_id,
              source_id=source_id, observed_at=observed_at,
              labels={"cpu": cpu}, interval_seconds=interval_seconds)

    memory = _index([row for row in current if row[0] in {
        "node_memory_MemTotal_bytes", "node_memory_MemAvailable_bytes"}],
        result.refused)
    available_keys = {labels for family, labels in memory
                      if family == "node_memory_MemAvailable_bytes"}
    total_keys = {labels for family, labels in memory
                  if family == "node_memory_MemTotal_bytes"}
    for label_key in sorted(available_keys | total_keys):
        total = memory.get(("node_memory_MemTotal_bytes", label_key))
        available = memory.get(("node_memory_MemAvailable_bytes", label_key))
        valid = total is not None and total > 0 and available is not None \
            and 0 <= available <= total
        _emit(result, metric_name="ram.utilization_pct",
              family="node_memory_utilization", value=round(
                  (1 - available / total) * 100, 2) if valid else None,
              quality=QualityStatus.VALID if valid else QualityStatus.MISSING,
              asset_id=asset_id, tenant_id=tenant_id, source_id=source_id,
              observed_at=observed_at, labels=dict(label_key))

    for family, value, labels in current:
        if family == "node_cpu_seconds_total" or family in {
                "node_memory_MemTotal_bytes", "node_memory_MemAvailable_bytes"}:
            continue
        key = (family, tuple(sorted(labels.items())))
        if key in seen_keys:
            _refuse(result.refused, family, "duplicate labelled exporter sample refused")
            continue
        seen_keys.add(key)
        if family in NODE_DISK_COUNTERS:
            mapped, direction, scale = NODE_DISK_COUNTERS[family]
            if "direction" in labels:
                _refuse(result.refused, family, "collector direction label conflicts with source family")
                continue
            rate, quality = _rate(value, prior.get(key), interval_seconds)
            _emit(result, metric_name=mapped, family=family,
                  value=round(rate / scale, 6) if rate is not None else None,
                  quality=quality, asset_id=asset_id, tenant_id=tenant_id,
                  source_id=source_id, observed_at=observed_at,
                  labels={**labels, "direction": direction},
                  interval_seconds=interval_seconds)
        elif family in NODE_EXPORTER_MAP:
            _emit(result, metric_name=NODE_EXPORTER_MAP[family], family=family,
                  value=value, quality=QualityStatus.VALID,
                  asset_id=asset_id, tenant_id=tenant_id, source_id=source_id,
                  observed_at=observed_at, labels=labels,
                  interval_seconds=interval_seconds)
        else:
            _refuse(result.refused, family,
                    "not in the verified translator map — a unit is never guessed")
    return result


def translate_postgres_exporter(payload: Mapping[str, Any], *,
                                asset_id: str, tenant_id: str,
                                source_id: str, observed_at: datetime,
                                interval_seconds: Optional[float] = None,
                                previous: Optional[Mapping[str, Any]] = None
                                ) -> TranslationResult:
    """PostgreSQL Exporter payload -> database metrics. Query parameters
    and customer records are never collected — only the statistic rows
    the exporter exposes (§2.E)."""
    result = TranslationResult()
    current = _sample_rows(payload, result.refused)
    now = _index(current, result.refused)
    before = _index(_sample_rows(previous, result.refused), result.refused) if previous else {}
    seen = set()
    for family, value, labels in current:
        key = family, tuple(sorted(labels.items()))
        if key in seen:
            _refuse(result.refused, family, "duplicate labelled exporter sample refused")
            continue
        seen.add(key)
        if family == "pg_stat_activity_count":
            state = labels.get("state", "").lower()
            mapped = {"active": "db.connections_active",
                      "idle": "db.connections_idle"}.get(state)
            if not mapped:
                _refuse(result.refused, family,
                        "connection state must be active or idle; an unlabeled count is neither")
                continue
            _emit(result, metric_name=mapped, family=family,
                  value=value, quality=QualityStatus.VALID,
                  asset_id=asset_id, tenant_id=tenant_id, source_id=source_id,
                  observed_at=observed_at, labels=labels)
        elif family in POSTGRES_EXPORTER_MAP:
            mapped = POSTGRES_EXPORTER_MAP[family]
            _emit(result, metric_name=mapped, family=family,
                  value=value, quality=QualityStatus.VALID,
                  asset_id=asset_id, tenant_id=tenant_id, source_id=source_id,
                  observed_at=observed_at, labels=labels)
        elif family in POSTGRES_DERIVED:
            continue  # paired with its companion counter below
        elif family in POSTGRES_UNSUPPORTED:
            _refuse(result.refused, family, POSTGRES_UNSUPPORTED[family])
        else:
            _refuse(result.refused, family,
                    "not in the verified translator map — a unit is never guessed")

    def _labels_for(*families: str) -> set[Tuple[Tuple[str, str], ...]]:
        return {labels for family, labels in now if family in families}

    for label_key in sorted(_labels_for("pg_stat_database_xact_commit",
                                        "pg_stat_database_xact_rollback")):
        commit = now.get(("pg_stat_database_xact_commit", label_key))
        rollback = now.get(("pg_stat_database_xact_rollback", label_key))
        old_commit = before.get(("pg_stat_database_xact_commit", label_key))
        old_rollback = before.get(("pg_stat_database_xact_rollback", label_key))
        quality, value = QualityStatus.MISSING, None
        if commit is not None and rollback is not None:
            cr, cq = _rate(commit, old_commit, interval_seconds)
            rr, rq = _rate(rollback, old_rollback, interval_seconds)
            if cq == rq == QualityStatus.VALID:
                quality, value = QualityStatus.VALID, round(cr + rr, 6)
            elif QualityStatus.STALE in (cq, rq):
                quality = QualityStatus.STALE
        _emit(result, metric_name="db.transactions_per_sec",
              family="pg_stat_database_xact_total", value=value,
              quality=quality, asset_id=asset_id, tenant_id=tenant_id,
              source_id=source_id, observed_at=observed_at,
              labels=dict(label_key), interval_seconds=interval_seconds)

    for label_key in sorted(_labels_for("pg_stat_database_blks_hit",
                                        "pg_stat_database_blks_read")):
        hit = now.get(("pg_stat_database_blks_hit", label_key))
        read = now.get(("pg_stat_database_blks_read", label_key))
        old_hit = before.get(("pg_stat_database_blks_hit", label_key))
        old_read = before.get(("pg_stat_database_blks_read", label_key))
        quality, ratio = QualityStatus.MISSING, None
        if None not in (hit, read, old_hit, old_read):
            delta_hit, delta_read = hit - old_hit, read - old_read
            if delta_hit < 0 or delta_read < 0:
                quality = QualityStatus.STALE
            elif delta_hit + delta_read > 0:
                quality = QualityStatus.VALID
                ratio = round(delta_hit / (delta_hit + delta_read), 6)
        _emit(result, metric_name="db.cache_hit_ratio",
              family="pg_stat_database_cache_hit_ratio", value=ratio,
              quality=quality, asset_id=asset_id, tenant_id=tenant_id,
              source_id=source_id, observed_at=observed_at,
              labels=dict(label_key), interval_seconds=interval_seconds)
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
    for family, value, labels in _sample_rows(payload, result.refused):
        key = family, tuple(sorted(labels.items()))
        if key in seen:
            _refuse(result.refused, family, "duplicate labelled exporter sample refused")
            continue
        seen.add(key)
        if family == "process.cpu.utilization":
            if not 0 <= value <= 1:
                _refuse(result.refused, family,
                        "OTLP utilization must be a finite fraction in [0,1] before percent conversion")
                continue
            _emit(result, metric_name="cpu.utilization_pct", family=family,
                  value=round(value * 100, 4), quality=QualityStatus.VALID,
                  asset_id=asset_id, tenant_id=tenant_id, source_id=source_id,
                  observed_at=observed_at, labels=labels,
                  interval_seconds=interval_seconds)
        elif family in OTLP_MAP:
            _emit(result, metric_name=OTLP_MAP[family], family=family,
                  value=value, quality=QualityStatus.VALID,
                  asset_id=asset_id, tenant_id=tenant_id, source_id=source_id,
                  observed_at=observed_at, labels=labels,
                  interval_seconds=interval_seconds)
        else:
            _refuse(result.refused, family, OTLP_UNSUPPORTED.get(
                family, "not in the verified translator map — a unit is never guessed"))
    return result


def _cpu_rows(rows: List[Tuple[str, float, Dict[str, str]]]
              ) -> Dict[str, Dict[str, float]]:
    """Exact per-core/mode counters; missing modes never become zeroes."""
    out: Dict[str, Dict[str, float]] = {}
    for family, value, labels in rows:
        if family == "node_cpu_seconds_total" and labels.get("mode"):
            out.setdefault(labels.get("cpu") or "all", {})[labels["mode"]] = value
    return out


_UNSAFE = re.compile(r"[^A-Za-z0-9._:-]")


def _metric_id(source_id: str, family: str, labels: Mapping[str, str],
               observed_at: datetime, *, tenant_id: str, asset_id: str) -> str:
    label_part = "-".join(f"{k}-{v}" for k, v in sorted(labels.items()))
    stamp = observed_at.strftime("%Y%m%dT%H%M%S%f")
    raw = f"{source_id}.{family}.{label_part}.{stamp}"
    # metric_id is globally unique in PostgreSQL, so identical exporter names
    # and timestamps in two banks or on two assets must never alias each other.
    identity = f"{tenant_id}|{asset_id}|{raw}"
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
    return f"{_UNSAFE.sub('-', raw)[:47]}-{digest}"


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


# --- cAdvisor (containers, §2G / §4) --------------------------------

_CADVISOR_FAMILY_MAP = {
    "container_memory_working_set_bytes": "container.memory_bytes",
}

_CADVISOR_RATE_DERIVED = {
    "container_cpu_usage_seconds_total",
    "container_network_receive_bytes_total",
    "container_network_transmit_bytes_total",
    "container_cpu_cfs_throttled_periods_total",
}


def _gauge_translation(payload: Mapping[str, Any], *, family_map: Mapping[str, str],
                       rate_derived: set, asset_id: str, tenant_id: str,
                       source_id: str, observed_at: datetime,
                       interval_seconds: float, mapping_table: str
                       ) -> TranslationResult:
    """Shared gauge mapping: documented table in, refusals out —
    rate-derived counters need two snapshots and unknown families are
    never guessed."""
    result = TranslationResult()
    for family, value, labels in _sample_rows(payload):
        mapped = family_map.get(family)
        if mapped is None:
            if family in rate_derived:
                _refuse(result.refused, family,
                        "rate-derived counter — two snapshots are "
                        "required; a rate is never guessed from one sample")
            else:
                _refuse(result.refused, family,
                        f"not in the {mapping_table} mapping table — "
                        "a unit is never guessed")
            continue
        metric_id = _metric_id(source_id, family, labels, observed_at,
                               tenant_id=tenant_id, asset_id=asset_id)
        try:
            metric = _metric(metric_name=mapped, value=value,
                             quality=QualityStatus.VALID,
                             unit=_unit_of(mapped), asset_id=asset_id,
                             tenant_id=tenant_id, source_id=source_id,
                             observed_at=observed_at, metric_id=metric_id,
                             labels=labels,
                             interval_seconds=interval_seconds)
        except ValueError as exc:
            _refuse(result.refused, family, str(exc))
            continue
        result.metrics.append(metric)
    return result


def translate_cadvisor(payload: Mapping[str, Any], *, asset_id: str,
                       tenant_id: str, source_id: str,
                       observed_at: datetime, interval_seconds: float = 60.0,
                       ) -> TranslationResult:
    """Translate a cAdvisor scrape (§2G). Gauge families map through the
    documented table; rate-derived CPU/network counters are refused with
    their reason — a rate needs two snapshots, never one."""
    return _gauge_translation(
        payload, family_map=_CADVISOR_FAMILY_MAP,
        rate_derived=_CADVISOR_RATE_DERIVED, asset_id=asset_id,
        tenant_id=tenant_id, source_id=source_id, observed_at=observed_at,
        interval_seconds=interval_seconds, mapping_table="cAdvisor")


# --- kube-state-metrics (§2G / §4) ----------------------------------

_KUBE_STATE_FAMILY_MAP = {
    "kube_pod_container_status_restarts_total": "k8s.pod_restarts",
    "kube_pod_status_phase": "process.health",
}


def translate_kube_state_metrics(payload: Mapping[str, Any], *, asset_id: str,
                                 tenant_id: str, source_id: str,
                                 observed_at: datetime,
                                 interval_seconds: float = 60.0,
                                 ) -> TranslationResult:
    """Translate a kube-state-metrics scrape (§2G). Restart counts and
    pod phases map through the documented table; unknown families are
    refused, never guessed."""
    return _gauge_translation(
        payload, family_map=_KUBE_STATE_FAMILY_MAP,
        rate_derived=set(), asset_id=asset_id,
        tenant_id=tenant_id, source_id=source_id, observed_at=observed_at,
        interval_seconds=interval_seconds,
        mapping_table="kube-state-metrics")


# --- Windows Exporter (§4) ------------------------------------------

_WINDOWS_FAMILY_MAP = {
    "windows_logical_disk_size_bytes": "storage.capacity_bytes",
    "windows_logical_disk_free_bytes": "storage.available_bytes",
}

_WINDOWS_RATE_DERIVED = {
    "windows_cpu_time_total",
    "windows_net_bytes_received_total",
    "windows_net_bytes_sent_total",
}


def translate_windows_exporter(payload: Mapping[str, Any], *, asset_id: str,
                               tenant_id: str, source_id: str,
                               observed_at: datetime,
                               interval_seconds: float = 60.0,
                               ) -> TranslationResult:
    """Translate a Windows Exporter scrape (§4). Disk gauges map through
    the documented table; CPU time and network byte counters are
    rate-derived and refused."""
    return _gauge_translation(
        payload, family_map=_WINDOWS_FAMILY_MAP,
        rate_derived=_WINDOWS_RATE_DERIVED, asset_id=asset_id,
        tenant_id=tenant_id, source_id=source_id, observed_at=observed_at,
        interval_seconds=interval_seconds,
        mapping_table="Windows Exporter")


# --- SNMPv3 network telemetry (§3 / §4) -----------------------------

_SNMP_FAMILY_MAP = {
    "ifOperStatus": "network.tunnel_health",
    "ifInErrors": "network.interface_errors",
    "ifSpeed": "network.bandwidth_mbps",
}

#: SNMP raw units and their documented conversion. ifSpeed is bits/sec;
#: the metric's unit is Mbps, so the value is divided by a documented
#: factor — the conversion is declared here, never guessed.
_SNMP_UNIT_CONVERSIONS = {
    "ifSpeed": 1_000_000.0,
}

_SNMP_RATE_DERIVED = {
    "ifHCInOctets",
    "ifHCOutOctets",
    "ifInOctets",
    "ifOutOctets",
}


def translate_snmp(payload: Mapping[str, Any], *, asset_id: str,
                   tenant_id: str, source_id: str,
                   observed_at: datetime, interval_seconds: float = 60.0,
                   ) -> TranslationResult:
    """Translate SNMPv3 network telemetry (§3/§4). Interface state,
    errors and link capacity map with documented unit conversions;
    octet counters are rate-derived and refused — throughput is never
    guessed from one sample."""
    result = TranslationResult()
    for family, value, labels in _sample_rows(payload):
        mapped = _SNMP_FAMILY_MAP.get(family)
        if mapped is None:
            if family in _SNMP_RATE_DERIVED:
                _refuse(result.refused, family,
                        "rate-derived counter — two snapshots are "
                        "required; throughput is never guessed from one "
                        "sample")
            else:
                _refuse(result.refused, family,
                        "not in the SNMP mapping table — a unit is "
                        "never guessed")
            continue
        divisor = _SNMP_UNIT_CONVERSIONS.get(family, 1.0)
        metric_id = _metric_id(source_id, family, labels, observed_at,
                               tenant_id=tenant_id, asset_id=asset_id)
        try:
            metric = _metric(metric_name=mapped, value=value / divisor,
                             quality=QualityStatus.VALID,
                             unit=_unit_of(mapped), asset_id=asset_id,
                             tenant_id=tenant_id, source_id=source_id,
                             observed_at=observed_at, metric_id=metric_id,
                             labels=labels, interval_seconds=interval_seconds)
        except ValueError as exc:
            _refuse(result.refused, family, str(exc))
            continue
        result.metrics.append(metric)
    return result
