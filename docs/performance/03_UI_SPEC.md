# Performance Intelligence — UI Specification

> **Status: UI SPECIFICATION (screen brief).** Source: the product owner's
> brief, 2026-10-16 ("save this into new file start to build"). This is the
> UI layer over the engine requirements in `01_PRODUCT_SPEC.md` and the
> qualification harness in `02_QUALIFICATION_REPORT.md`. Every rule stated
> here is binding on the implementation: production values come from actual
> authorized telemetry; absent telemetry renders unknown, never zero;
> benchmark results are never production traffic performance; correlation
> never upgrades to causation; all figures in the brief's layouts are
> fictional illustrations. The rules govern the product and are not drawn
> on screen.

---

## 1. Performance Overview UI — main landing page

The screen a bank infrastructure team, application owner or security
engineer sees first.

Header controls: environment (e.g. Production) · time range (e.g. last 24
hours) · business unit (e.g. all business units).

Headline metrics (four KPI cards):

| Metric | Meaning |
|---|---|
| CPU utilization | estate CPU utilisation against thresholds |
| Memory utilization | estate memory utilisation |
| Application p95 latency | representative application latency |
| Error rate | failed requests as a percentage |

Sections:

- **Infrastructure trends** — CPU and memory utilisation over time.
- **Service performance** — per-service table: service, p95 latency, errors.
- **Performance alerts** — warning and critical performance conditions
  (e.g. memory pressure; a cryptographic operation queue exceeding an
  approved threshold).

### 1a. Live Systems — servers reporting through Cryptava agents

A compact table at the top of the Overview, and a dedicated **Live Systems** view.
There is one card per server whose Cryptava agent is activated:

* `LIVE`, `STALE` or `NO SAMPLES YET`;
* when the last signed sample arrived;
* the scope (whole machine, or the server's own processes);
* CPU, memory, disk used/free, disk I/O, network throughput;
* link capacity, labelled as capacity;
* connections and retransmits, process health;
* TLS handshake time per listener, with protocol and cipher;
* HSM response time where configured.

CPU, memory, network and TLS have a short trend. Every unread figure is listed as
`unknown · <metric> — <reason>`. The page polls every 15 s, and the time range
defaults to *follow live (last 30 min)*.

Source and rules: `05_CRYPTAVA_LIVE_SYSTEMS.md`.

## 2. Infrastructure Performance UI — computing infrastructure

| Category | Measurements |
|---|---|
| CPU | Utilization, load, cores, frequency, saturation |
| Memory | Used, available, cache, swap, pressure |
| Storage | Capacity, IOPS, throughput, latency |
| Disk | Read/write latency, queue depth, utilization |
| Processes | Resource usage, restarts, failures |
| Virtualization | VM CPU ready, memory ballooning, host contention |
| Containers | CPU throttling, memory limits, restarts |
| Kubernetes | Pod health, node pressure, scheduling latency |

Interface tabs: Infrastructure Overview · Server Inventory · CPU & Memory ·
Storage Performance · Virtualization · Container Performance · Hardware
Health · Historical Trends.

> The user can select a server and open its TechBOM record, dependencies
> and Digital Twin history.

## 3. Application Performance UI — bank applications and services

| Metric | Meaning |
|---|---|
| RPS | Requests per second |
| Throughput | Amount of data processed |
| p50 latency | Median response time |
| p95 latency | 95th percentile response time |
| p99 latency | 99th percentile response time |
| Error rate | Failed requests as a percentage |
| Timeout rate | Requests exceeding timeout |
| Availability | Service availability over a defined period |
| Queue depth | Waiting work |
| Saturation | How close a service is to resource limits |

Advanced capabilities: service-level performance · API endpoint
performance · distributed transaction tracing · request waterfall
visualization · slow transaction detection · service dependency latency ·
performance regression comparison · SLA/SLO tracking.

> **Working rule (not UI copy).** Distributed traces use controlled
> attributes and redaction. Never collect payment credentials, authorization
> tokens or sensitive request payloads.

## 4. Database Performance UI — banking infrastructure

| Area | Metrics |
|---|---|
| Connections | Active, idle, waiting, connection exhaustion |
| Queries | Execution time, slow queries, throughput |
| Locks | Lock waits, deadlocks, blocking |
| Cache | Cache hit ratio, buffer utilization |
| Storage | Database size, growth, IOPS |
| Replication | Lag, replication status |
| Transactions | Commit rate, rollback rate |
| Backup | Duration, status, backup age |
| Availability | Uptime, connection failures |

Database-specific adapters for PostgreSQL, MySQL, Microsoft SQL Server,
Oracle and other approved platforms.

> **Working rule (not UI copy).** For sensitive banking systems, collect
> query fingerprints and normalized statistics rather than SQL statements
> containing customer data.

## 5. Network Performance UI — communication between systems

Metrics: bandwidth and throughput · round-trip time · jitter · packet loss ·
retransmissions · DNS resolution time · connection establishment time · TCP
connection state · network interface errors · VPN/IPsec tunnel health ·
TLS handshake latency · load-balancer response time.

> **Working rule (not UI copy).** Network telemetry can establish that a
> connection exists or measure its performance. It does not automatically
> reveal the negotiated TLS cipher suite — that requires an appropriate
> authorized endpoint or protocol observation.

## 6. Cryptographic Performance UI — ZELNX differentiation

One of the most important parts of Performance Intelligence: focused
cryptographic operation performance, not just CPU and network latency.

| Category | Measurement |
|---|---|
| TLS | Handshake latency, handshake success/failure |
| Encryption | Throughput, operation latency |
| Decryption | Throughput, operation latency |
| Digital signatures | Signing and verification latency |
| Key generation | Operation duration and success |
| Algorithms | Performance by algorithm and implementation |
| Crypto libraries | Provider/library performance |
| PQC | ML-KEM and ML-DSA benchmark performance |
| Errors | Provider errors and operation failures |
| Resources | CPU consumption and memory overhead |

**Cryptographic Benchmark Laboratory** — controlled benchmark results:
operation type, test environment, algorithm → mean latency table with a bar
comparison. Benchmark metadata must accompany any comparison:

- CPU and architecture
- Operating system and kernel
- Library/provider version
- Algorithm and parameter set
- Key size
- Message/payload size
- Number of iterations
- Warm-up period
- Concurrency
- Mean, median, p95 and p99
- Test date and environment

> **Working rule (not UI copy).** Never compare two algorithms without
> recording the hardware, implementation, key parameters, payload size and
> benchmark conditions. Separate controlled benchmarks from production
> telemetry. Do not run intrusive performance tests against live bank HSMs
> without explicit approval.

## 7. HSM & KMS Performance UI — dedicated workspace

Measures: HSM availability and health · request throughput · sign/verify
latency · encrypt/decrypt latency · key generation latency · queue depth
and saturation · session utilization · provider errors · failover status ·
firmware and configuration changes · KMS API latency and throttling.

**HSM performance detail:** per-device record with operations per second,
p95 latency, queue utilization, availability, and an operation latency
trend.

> **Working rule (not UI copy).** The collector uses vendor-supported,
> read-only management and performance interfaces. Never collect key
> material or interfere with HSM operations.

## 8. Workload & Transaction Intelligence

Where infrastructure and application performance meet business workloads:
payment transaction throughput · authentication request performance · card
authorization latency · batch processing duration · database transaction
time · cryptographic operation overhead per transaction · peak and
off-peak performance · queue backlogs.

> **Working rule (not UI copy).** The system may investigate whether
> increased TLS handshake time contributes to payment API latency — but it
> must correlate timestamps and traces before suggesting causation.

## 9. Capacity & Forecasting UI

Answers: will current infrastructure handle future workload? when will
storage capacity become insufficient? which servers regularly experience
CPU saturation? what happens to HSM performance at peak transaction volume?
how much capacity will a PQC migration require?

Features: CPU and memory capacity planning · storage growth forecasting ·
network bandwidth planning · database growth projections · HSM capacity
and throughput forecasting · transaction peak modelling · PQC migration
resource estimates · capacity threshold alerts.

> **Working rule (not UI copy).** Predictions display the observation
> period, data coverage, assumptions and uncertainty. A forecast is not a
> guaranteed future result.

---

## Visual references (look only, never data)

AppDynamics AI Application Performance Dashboard (Dribbble), Logz.io (G2),
Better Stack, Motadata Linux Server Monitoring, Blockbridge/Grafana, Ceph
Block Performance Monitoring, Datadog APM, Splunk APM, New Relic
Transaction 360, Grafana Cloud Database Observability, Xitoring PostgreSQL
Monitoring, Obkio, IBM Networking Maps, Utimaco 360 HSM Monitoring,
nShield Docs dashboard, ML-KEM vs X25519 comparative analysis, VMware
OpManager Nexus, time-series forecasting references, Control Seat gallery.
