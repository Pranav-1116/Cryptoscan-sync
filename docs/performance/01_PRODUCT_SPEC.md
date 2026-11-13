# ZELNX Performance Intelligence — Product Specification

> **Status: PRODUCT SPECIFICATION (requirements source).** Source: the
> product owner's brief, 2026-11-07. This document is the requirements
> source for the ZELNX Performance Intelligence engine, the same way
> `docs/cryptolog/01_PRODUCT_SPEC.md` is for CryptoLog. Every rule stated
> here is binding on the implementation: missing telemetry is marked
> unknown or stale, never zero; benchmark results are never presented as
> production traffic performance; a time correlation alone never proves
> causation; all figures in the brief's illustrations are fictional
> examples. Scope lives in the document below, verbatim.

---

Infrastructure • Network • Application • Database • Cryptographic Performance

The engine should answer questions such as:

- How much storage is available, used and growing?
- What is the network bandwidth and actual throughput?
- What is the network latency between systems?
- How many requests are applications receiving?
- How many requests succeed or fail?
- What are API response times: p50, p95 and p99?
- What are CPU, RAM and disk I/O utilization?
- How are databases performing?
- Are TLS handshakes slow?
- Is an HSM or KMS introducing latency?
- Did a cryptographic configuration change affect performance?

## 2. What the engine should monitor

Eight monitoring domains.

### A. Infrastructure performance

| Metric           | What it tells you                         |
| ---------------- | ----------------------------------------- |
| CPU utilization  | How much processor capacity is being used |
| RAM utilization  | Memory usage and available memory         |
| Disk utilization | Storage capacity consumed                 |
| Disk IOPS        | Read/write operations per second          |
| Disk throughput  | MB/s read and written                     |
| Disk latency     | Time taken for storage operations         |
| Process health   | Running, stopped or unhealthy processes   |
| System load      | Overall system workload                   |

### B. Storage intelligence

Monitor:

- Total storage capacity.
- Used and available storage.
- Filesystem utilization.
- Database storage consumption.
- Object storage consumption.
- Log and evidence storage growth.
- Backup storage consumption.
- Storage read/write throughput.
- Storage latency.
- Estimated time until capacity exhaustion.

Example:

    Storage overview
    # 720 GB — 72% used
    # 1 TB Total / 720 GB Used / 280 GB Available

Illustrative dashboard values, not live measurements.

### C. Network performance

Monitor:

- Inbound and outbound bandwidth.
- Actual throughput (Mbps/Gbps).
- Round-trip time (RTT).
- Latency and jitter.
- Packet loss.
- TCP retransmissions.
- Connection count.
- Connection establishment time.
- DNS resolution time.
- Network interface errors.
- VPN/IPsec tunnel health.

Important: bandwidth capacity and actual throughput are different. A
10 Gbps interface does not mean applications are currently transferring
data at 10 Gbps.

### D. Application and API performance

| Metric                    | Meaning                                 |
| ------------------------- | --------------------------------------- |
| Requests per second (RPS) | Incoming request rate                   |
| Total requests            | Request volume over a time window       |
| p50 latency               | Median response time                    |
| p95 latency               | 95% of requests finish within this time |
| p99 latency               | 99% of requests finish within this time |
| Error rate                | Percentage of failed requests           |
| Timeout rate              | Percentage of requests timing out       |
| Concurrent requests       | Requests being processed simultaneously |
| Throughput                | Amount of data processed over time      |

For example, an API might receive 1,000 requests/second, with p95
latency of 180 ms and an error rate of 0.2%.

### E. Database performance

Monitor PostgreSQL and other supported database systems:

- Active and idle connections.
- Query execution time.
- Slow queries.
- Query throughput.
- Transaction rate.
- Deadlocks.
- Lock waits.
- Cache hit ratio.
- Database size and growth.
- Replication lag.
- Connection pool utilization.
- Backup and restore performance.

For banks, monitor performance without collecting query parameters or
sensitive customer records by default.

### F. Cryptographic performance

This is where the engine becomes especially valuable to CryptoScan.

Measure, when the underlying provider exposes the metrics:

- TLS handshake duration.
- TLS negotiation failures.
- Certificate validation duration.
- HSM operation latency.
- HSM queue depth and utilization.
- KMS API response time.
- Signing operation latency.
- Verification operation latency.
- Key-generation duration.
- Cryptographic provider errors.
- Algorithm-specific benchmark results.

Keep two measurements separate:

1. Observed production performance: measurements from actual monitored
   operations.
2. Controlled benchmark performance: results from approved tests in a
   controlled environment.

Never present a benchmark result as actual production traffic
performance.

### G. Container and cloud performance

Monitor:

- Docker container CPU and memory.
- Kubernetes pod health and restarts.
- Container network throughput.
- Pod resource requests and limits.
- Cloud compute utilization.
- Cloud storage utilization.
- Cloud network throughput.
- KMS service latency.
- Resource quota consumption.

### H. Capacity and reliability intelligence

The engine should calculate:

- Capacity utilization trends.
- Resource growth rates.
- Availability and uptime.
- Service-level objective (SLO) compliance.
- Saturation and bottleneck indicators.
- Forecasted resource exhaustion.
- Performance regression.
- Service degradation.

## 3. Recommended architecture

Build this as a separate engine, reusing CryptoScan's existing
authentication, evidence, asset identity, Digital Twin, database and API
infrastructure wherever possible.

    1. Authorized monitoring sources
       Servers • Applications • Network • Databases • HSM/KMS • Cloud • Containers
    2. Collectors and telemetry adapters
       OS metrics • SNMP • OpenTelemetry • Prometheus exporters • Vendor APIs
    3. Performance ingestion gateway
       Authentication • Validation • Tenant isolation • Rate limits • Deduplication
    4. Processing and intelligence
       Normalization • Aggregation • Baselines • Anomaly detection • Correlation
    5. Performance data storage
       PostgreSQL — Metadata, configuration, alerts, policies
       Time-series store — Metric samples and historical trends
       Object storage — Reports and approved diagnostic artifacts
       Redis — Cache and short-lived coordination
    6. CryptoScan intelligence integration
       Digital Twin • CryptoLog • Six BOMs • Threat Intelligence • PQC Migration
    7. Performance Intelligence dashboard
       Live monitoring • Historical trends • Alerts • Reports • Capacity planning

## 4. Technology choices

| Layer                       | Recommended technology                                   |
| --------------------------- | -------------------------------------------------------- |
| Metrics collection          | Prometheus exporters                                     |
| Application instrumentation | OpenTelemetry                                            |
| Network monitoring          | SNMPv3, approved network telemetry                       |
| Linux monitoring            | Node Exporter                                            |
| Windows monitoring          | Windows Exporter                                         |
| Database                    | PostgreSQL Exporter                                      |
| Containers                  | cAdvisor                                                 |
| Kubernetes                  | kube-state-metrics                                       |
| Metrics storage             | Prometheus initially; VictoriaMetrics or Thanos at scale |
| Dashboards                  | Custom CryptoScan UI                                     |
| Visualization               | Grafana for internal engineering if useful               |
| Background processing       | Existing worker infrastructure                           |
| Long-term archive           | MinIO / S3-compatible storage                            |

Do not immediately introduce Kafka, a large observability stack and
several new databases. The local development machine has 8 GB RAM. Start
with lightweight collectors, Prometheus and the existing PostgreSQL. Add
a scalable time-series backend when real deployment volume justifies it.

## 5. Data model and metric structure

Every measurement should use a consistent structure.

Suggested `performance_metrics` fields:

| Field              | Purpose                                |
| ------------------ | -------------------------------------- |
| `metric_id`        | Unique measurement ID                  |
| `tenant_id`        | Bank/customer boundary                 |
| `asset_id`         | Linked Digital Twin asset              |
| `metric_name`      | e.g. `network.rtt_ms`                  |
| `metric_type`      | Gauge, counter or histogram            |
| `metric_value`     | Numeric value                          |
| `unit`             | ms, bytes, Mbps, percent, requests/sec |
| `source_id`        | Collector or exporter                  |
| `observed_at`      | Actual observation time                |
| `interval_seconds` | Collection interval                    |
| `labels`           | Bounded dimensions                     |
| `evidence_id`      | Optional provenance reference          |
| `quality_status`   | Valid, stale, partial, missing         |

Recommended additional tables:

- `performance_assets`
- `performance_metric_definitions`
- `performance_metric_samples`
- `performance_aggregates`
- `performance_baselines`
- `performance_alerts`
- `performance_incidents`
- `performance_slo_policies`
- `performance_capacity_forecasts`
- `performance_collector_health`
- `performance_benchmark_runs`

Do not put every high-frequency metric into ordinary PostgreSQL rows
indefinitely. Use a time-series database for high-volume samples and
PostgreSQL for configuration, metadata, alert state and references.

## 6. API design

Suggested API namespace:

| Method | Endpoint                                | Purpose                     |
| ------ | --------------------------------------- | --------------------------- |
| POST   | `/api/v1/performance/ingest`            | Receive metrics             |
| POST   | `/api/v1/performance/ingest/batch`      | Batch ingestion             |
| GET    | `/api/v1/performance/overview`          | Overall performance         |
| GET    | `/api/v1/performance/assets/{asset_id}` | Asset metrics               |
| GET    | `/api/v1/performance/network`           | Network metrics             |
| GET    | `/api/v1/performance/storage`           | Storage metrics             |
| GET    | `/api/v1/performance/applications`      | Application metrics         |
| GET    | `/api/v1/performance/databases`         | Database metrics            |
| GET    | `/api/v1/performance/cryptography`      | Crypto performance          |
| GET    | `/api/v1/performance/alerts`            | Performance alerts          |
| GET    | `/api/v1/performance/baselines`         | Performance baselines       |
| GET    | `/api/v1/performance/capacity`          | Capacity analysis           |
| GET    | `/api/v1/performance/reports`           | Reports                     |
| POST   | `/api/v1/performance/benchmarks`        | Start approved benchmark    |
| GET    | `/api/v1/performance/health`            | Collector and engine health |

All query APIs should support time ranges, cursor pagination, tenant
authorization and sensible maximum query windows.

## 7. Frontend dashboard design

A new navigation section: ZELNX Performance Intelligence. All dashboard
values and alerts in the brief are fictional examples, not measurements
from any infrastructure.

Recommended screens:

1. Performance Overview
2. Infrastructure Monitoring
3. Storage Intelligence
4. Network Intelligence
5. Application Performance
6. Database Performance
7. Cryptographic Performance
8. Cloud and Container Performance
9. Performance Alerts
10. Capacity Planning
11. Benchmark Lab
12. Historical Reports
13. Collector Health
14. SLO and SLA Management

## 8. The most important feature: connect Performance Engine to Digital Twin

This is where ZELNX differentiates from a generic monitoring dashboard.

Scenario: a bank changes its TLS configuration from one cipher suite to
another. The system records:

1. CryptoScan detects the configuration change with evidence.
2. NBOM records the relevant network configuration or negotiation
   observation.
3. CryptoLog records the cryptographic change event.
4. Performance Engine measures handshake duration before and after the
   change.
5. Digital Twin identifies the affected services and dependencies.
6. Intelligence correlates the observations and presents the impact.

Rules that govern the presentation:

- Correlation detected — causation unproven. A time correlation alone
  does not prove that the TLS change caused the latency increase. Other
  possible causes still need investigation.

This supports PQC migration **as measured context inside the Digital Twin
simulation**. The Performance Engine never selects a migration wave or
predicts the future candidate's production latency from historical data.
Benchmark approved implementations and compare their performance in a controlled
environment — RSA versus ML-DSA signing and verification; ECDH versus
ML-KEM key establishment; classical versus supported hybrid TLS
negotiation; different HSM providers and firmware versions; different
cryptographic library versions. Benchmark results must include hardware,
software, provider, algorithm parameters, test methodology, concurrency
and sample count. Never assume a particular PQC algorithm will always be
slower or faster.

## 9. Security and operational requirements

Mandatory design principles:

- Read-only collection by default.
- No unauthorized active network testing.
- No production stress testing without explicit approval.
- No customer payloads, passwords, tokens or private keys in metrics.
- Use SNMPv3 and authenticated telemetry wherever supported.
- Tenant isolation on every metric, query and alert.
- Restrict metric labels to prevent unbounded cardinality.
- Protect collector credentials with the bank's secret manager.
- Use bounded queues and backpressure.
- Detect stale collectors instead of interpreting missing metrics as zero.
- Preserve measurement timestamps and source provenance.
- Audit configuration changes and benchmark execution.
- Define retention and aggregation policies.

A performance engine is not automatically a load-testing engine.
Production load testing is a separately authorized capability with strict
safety controls.

## 10. Implementation roadmap

Eight phases:

| Phase                       | Deliverables                                                        |
| --------------------------- | ------------------------------------------------------------------- |
| 1. Foundation               | Metric taxonomy, schema, asset identity, collection contracts       |
| 2. Infrastructure           | CPU, RAM, disk, storage and process metrics                         |
| 3. Network                  | Bandwidth, throughput, RTT, jitter, packet loss                     |
| 4. Applications and DB      | RPS, p95/p99, errors, database queries and connections              |
| 5. Crypto performance       | TLS, certificates, HSM, KMS and controlled benchmarks               |
| 6. Intelligence             | Baselines, regression detection, alerts, capacity forecasts         |
| 7. Integration and UI       | Digital Twin, CryptoLog, six BOMs and dashboard                     |
| 8. Enterprise qualification | Security tests, load tests, retention, recovery and bank validation |

### Initial success criteria

Measurable acceptance targets before implementation:

- Every metric has a defined unit, source and timestamp.
- No cross-tenant metric access.
- Missing telemetry is marked unknown or stale, not zero.
- Metric ingestion is idempotent.
- High-cardinality inputs are bounded.
- Historical aggregates match raw measurements within defined tolerances.
- Collection overhead is measured on representative bank systems.
- Performance alerts include supporting measurements.
- Benchmark results are reproducible.

## 11. How it fits into the ZELNX product

    # ZELNX Platform
    Core intelligence foundation:
      Digital Twin • Evidence Engine • Asset Discovery • Identity & Relationships
      Discovery and inventory: SBOM • CBOM • HBOM • NBOM • VBOM • TechBOM
    Intelligence engines:
      CryptoLog • Performance Engine • Threat Intelligence • PQC Migration Engine
      Risk & Compliance • Simulation Engine
    Enterprise operations:
      Governance • Audit & Reporting • Monitoring • Access Control
