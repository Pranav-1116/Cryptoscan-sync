"""Performance metric taxonomy (docs/performance/01_PRODUCT_SPEC.md, §2).

The named metrics of the eight monitoring domains, each with its unit,
type and domain. The success criterion "every metric has a defined unit,
source and timestamp" starts here: a metric outside the taxonomy is not
silently accepted with a guessed unit — it is refused until defined.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Tuple

from shared_models.performance_metrics import MetricType


@dataclass(frozen=True)
class MetricDefinition:
    name: str
    domain: str
    unit: str
    metric_type: MetricType
    what_it_tells: str


def _d(name, domain, unit, metric_type, what):
    return MetricDefinition(name, domain, unit, MetricType(metric_type), what)


#: the eight domains (§2 A–H)
DOMAINS = (
    "infrastructure", "storage", "network", "applications",
    "database", "cryptography", "container_cloud", "capacity",
)

DEFINITIONS: Tuple[MetricDefinition, ...] = (
    # A. infrastructure
    _d("cpu.utilization_pct", "infrastructure", "percent", "gauge",
       "How much processor capacity is being used"),
    _d("ram.utilization_pct", "infrastructure", "percent", "gauge",
       "Memory usage and available memory"),
    _d("disk.utilization_pct", "infrastructure", "percent", "gauge",
       "Storage capacity consumed"),
    _d("disk.iops", "infrastructure", "ops/sec", "gauge",
       "Read/write operations per second"),
    _d("disk.throughput_mbps", "infrastructure", "MB/s", "gauge",
       "MB/s read and written"),
    _d("disk.latency_ms", "infrastructure", "ms", "histogram",
       "Time taken for storage operations"),
    _d("process.health", "infrastructure", "state", "gauge",
       "Running, stopped or unhealthy processes"),
    _d("system.load", "infrastructure", "load", "gauge",
       "Overall system workload"),
    # B. storage
    _d("storage.capacity_bytes", "storage", "bytes", "gauge",
       "Total storage capacity"),
    _d("storage.used_bytes", "storage", "bytes", "gauge",
       "Used storage"),
    _d("storage.available_bytes", "storage", "bytes", "gauge",
       "Available storage"),
    _d("storage.utilization_pct", "storage", "percent", "gauge",
       "Filesystem utilization"),
    _d("storage.growth_bytes", "storage", "bytes", "counter",
       "Log and evidence storage growth"),
    _d("storage.exhaustion_eta_seconds", "storage", "seconds", "gauge",
       "Estimated time until capacity exhaustion"),
    # C. network
    _d("network.bandwidth_mbps", "network", "Mbps", "gauge",
       "Interface bandwidth capacity — never the same as throughput"),
    _d("network.throughput_mbps", "network", "Mbps", "gauge",
       "Actual throughput (Mbps/Gbps)"),
    _d("network.rtt_ms", "network", "ms", "histogram",
       "Round-trip time (RTT)"),
    _d("network.jitter_ms", "network", "ms", "gauge", "Jitter"),
    _d("network.packet_loss_pct", "network", "percent", "gauge",
       "Packet loss"),
    _d("network.tcp_retransmissions", "network", "count", "counter",
       "TCP retransmissions"),
    _d("network.connections", "network", "count", "gauge",
       "Connection count"),
    _d("network.connection_establish_ms", "network", "ms", "histogram",
       "Connection establishment time"),
    _d("network.dns_resolution_ms", "network", "ms", "histogram",
       "DNS resolution time"),
    _d("network.interface_errors", "network", "count", "counter",
       "Network interface errors"),
    _d("network.tunnel_health", "network", "state", "gauge",
       "VPN/IPsec tunnel health"),
    # D. applications and API
    _d("api.requests_per_sec", "applications", "requests/sec", "gauge",
       "Incoming request rate"),
    _d("api.requests_total", "applications", "count", "counter",
       "Request volume over a time window"),
    _d("api.latency_p50_ms", "applications", "ms", "histogram",
       "Median response time"),
    _d("api.latency_p95_ms", "applications", "ms", "histogram",
       "95% of requests finish within this time"),
    _d("api.latency_p99_ms", "applications", "ms", "histogram",
       "99% of requests finish within this time"),
    _d("api.error_rate_pct", "applications", "percent", "gauge",
       "Percentage of failed requests"),
    _d("api.timeout_rate_pct", "applications", "percent", "gauge",
       "Percentage of requests timing out"),
    _d("api.concurrent_requests", "applications", "count", "gauge",
       "Requests being processed simultaneously"),
    _d("api.throughput_bytes", "applications", "bytes", "counter",
       "Amount of data processed over time"),
    # E. database
    _d("db.connections_active", "database", "count", "gauge",
       "Active connections"),
    _d("db.connections_idle", "database", "count", "gauge",
       "Idle connections"),
    _d("db.query_time_ms", "database", "ms", "histogram",
       "Query execution time — never query parameters"),
    _d("db.query_throughput", "database", "queries/sec", "gauge",
       "Query throughput"),
    _d("db.transactions_per_sec", "database", "transactions/sec", "gauge",
       "Transaction rate"),
    _d("db.deadlocks", "database", "count", "counter", "Deadlocks"),
    _d("db.lock_waits", "database", "count", "counter", "Lock waits"),
    _d("db.cache_hit_ratio", "database", "ratio", "gauge",
       "Cache hit ratio"),
    _d("db.size_bytes", "database", "bytes", "gauge",
       "Database size and growth"),
    _d("db.replication_lag_seconds", "database", "seconds", "gauge",
       "Replication lag"),
    _d("db.pool_utilization_pct", "database", "percent", "gauge",
       "Connection pool utilization"),
    _d("db.backup_duration_seconds", "database", "seconds", "histogram",
       "Backup and restore performance"),
    # F. cryptography
    _d("crypto.tls_handshake_ms", "cryptography", "ms", "histogram",
       "TLS handshake duration"),
    _d("crypto.tls_negotiation_failures", "cryptography", "count",
       "counter", "TLS negotiation failures"),
    _d("crypto.cert_validation_ms", "cryptography", "ms", "histogram",
       "Certificate validation duration"),
    _d("crypto.hsm_operation_latency_ms", "cryptography", "ms",
       "histogram", "HSM operation latency"),
    _d("crypto.hsm_queue_depth", "cryptography", "count", "gauge",
       "HSM queue depth and utilization"),
    _d("crypto.kms_response_ms", "cryptography", "ms", "histogram",
       "KMS API response time"),
    _d("crypto.sign_latency_ms", "cryptography", "ms", "histogram",
       "Signing operation latency"),
    _d("crypto.verify_latency_ms", "cryptography", "ms", "histogram",
       "Verification operation latency"),
    _d("crypto.keygen_duration_ms", "cryptography", "ms", "histogram",
       "Key-generation duration"),
    _d("crypto.provider_errors", "cryptography", "count", "counter",
       "Cryptographic provider errors"),
    # G. container and cloud
    _d("container.cpu_pct", "container_cloud", "percent", "gauge",
       "Docker container CPU"),
    _d("container.memory_bytes", "container_cloud", "bytes", "gauge",
       "Docker container memory"),
    _d("container.network_throughput_mbps", "container_cloud", "Mbps",
       "gauge", "Container network throughput"),
    _d("k8s.pod_restarts", "container_cloud", "count", "counter",
       "Kubernetes pod health and restarts"),
    _d("k8s.resource_quota_pct", "container_cloud", "percent", "gauge",
       "Resource quota consumption"),
    _d("cloud.kms_service_latency_ms", "container_cloud", "ms",
       "histogram", "KMS service latency"),
    # H. capacity and reliability
    _d("capacity.utilization_pct", "capacity", "percent", "gauge",
       "Capacity utilization trends"),
    _d("capacity.growth_rate_pct", "capacity", "percent", "gauge",
       "Resource growth rates"),
    _d("availability.uptime_pct", "capacity", "percent", "gauge",
       "Availability and uptime"),
    _d("slo.compliance_pct", "capacity", "percent", "gauge",
       "Service-level objective (SLO) compliance"),
    _d("saturation.indicator", "capacity", "ratio", "gauge",
       "Saturation and bottleneck indicators"),
    _d("capacity.exhaustion_eta_seconds", "capacity", "seconds", "gauge",
       "Forecasted resource exhaustion"),
    _d("performance.regression_ms", "capacity", "ms", "gauge",
       "Performance regression"),
)

_BY_NAME: Dict[str, MetricDefinition] = {d.name: d for d in DEFINITIONS}


def definition_for(metric_name: str) -> MetricDefinition:
    """Look a metric up in the taxonomy.

    A metric outside the taxonomy is not silently accepted with a guessed
    unit — refuse it until it is defined (success criterion: every metric
    has a defined unit).
    """
    definition = _BY_NAME.get(metric_name)
    if definition is None:
        raise KeyError(
            f"{metric_name!r} is not in the metric taxonomy — define it "
            "(name, domain, unit, type) before ingesting; a guessed unit "
            "is not a defined unit")
    return definition


def domain_of(metric_name: str) -> str:
    return definition_for(metric_name).domain
