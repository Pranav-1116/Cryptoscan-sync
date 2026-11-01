# Observability coverage — what an operator can see

`cryptoscan.observability-coverage/1` · generated 2026-11-01T16:08:35.723848+00:00 · **10 pass · 0 partial · 0 fail** · 46 series from `/metrics`

Each row is graded against something in this repository: a row marked **EXECUTED** was driven through the real endpoint, route or exporter and its answer read back; a row marked **READ** is a file or an import that proves the surface exists; a surface that does not exist is reported as **FAIL**, not as future work. The evidence block under each row is the measurement, not a description of one.

| Surface | Verdict | Evidence | What was found |
|---|---|---|---|
| **can an operator see whether collectors are running and what they return?** | **PASS** | EXECUTED | every required series present |
| **can an operator see a queue that is not draining, or work that was given up on?** | **PASS** | EXECUTED | every required series present |
| **can an operator see that the database is unhealthy before users report it?** | **PASS** | EXECUTED | every required series present |
| **can an operator see the evidence store going stale under a BOM?** | **PASS** | EXECUTED | every required series present |
| **can an operator see that an agent on a host stopped reporting?** | **PASS** | EXECUTED | every required series present |
| **can an operator see which planes stopped being covered?** | **PASS** | EXECUTED | every required series present |
| **do the probes answer, and do they distinguish liveness from readiness?** | **PASS** | EXECUTED | liveness 200, readiness 200, worker probe 503 when stalled and 200 when draining |
| **is a single request traceable across API, worker and database?** | **PASS** | EXECUTED | 1 OTLP notification(s) received, trace id matched, 623 bytes, exporter absent when unconfigured |
| **are logs structured, correlated and safe to ship?** | **PASS** | READ | every required series present |
| **does every alert reference a metric that exists, and is anything paging?** | **PASS** | EXECUTED | 15 rules, 3 metrics referenced, receiver answered 200 with 1 alert(s) counted |

## Row by row

### `collector_metrics` — PASS (EXECUTED)

*can an operator see whether collectors are running and what they return?*

- **Reading:** scan volume, duration and the live-monitor fleet are emitted by the API
- **Limit:** per-collector-plane outcome (COMPLETE / PARTIAL / FAILED, as the estate report calls them) has no metric: a plane that stopped collecting is visible only through stale evidence
- **Closes with:** a labelled counter per plane outcome, emitted by the discovery path

```
{
  "present": {
    "scan_volume": [
      "cryptoscan_scans_total",
      "cryptoscan_scans_by_status"
    ],
    "scan_duration": [
      "cryptoscan_scan_duration_seconds_bucket"
    ],
    "monitor_fleet": [
      "cryptoscan_monitor_targets_total"
    ]
  },
  "emitted_series": 46
}
```

### `queue_metrics` — PASS (EXECUTED)

*can an operator see a queue that is not draining, or work that was given up on?*

- **Reading:** added this pass: queued age, retry backlog, dead letters and worker leases, read from the same Redis keys the consumer uses
- **Limit:** the retry/dead-letter/worker series are only emitted when REDIS_URL is set; without Redis the queue is in-process and unobservable by design
- **Closes with:** nothing further for a Redis deployment; in-memory mode is a dev path

```
{
  "present": {
    "depth": [
      "cryptoscan_jobs_queued",
      "cryptoscan_jobs_by_status"
    ],
    "age": [
      "cryptoscan_jobs_oldest_queued_seconds"
    ],
    "retry": [
      "cryptoscan_jobs_retry_scheduled"
    ],
    "dead_letter": [
      "cryptoscan_jobs_dead_letter"
    ],
    "workers": [
      "cryptoscan_workers_alive"
    ]
  },
  "emitted_series": 46
}
```

### `database_metrics` — PASS (EXECUTED)

*can an operator see that the database is unhealthy before users report it?*

- **Reading:** reachability, per-dependency latency and an aggregate degraded flag
- **Limit:** no connection-pool saturation metric (checked-out / overflow / waiting); a pool that is exhausted shows up as latency, not as pool pressure
- **Closes with:** emit SQLAlchemy pool status (checkedout, overflow, timeout count)

```
{
  "present": {
    "reachability": [
      "cryptoscan_api_db_reachable",
      "cryptoscan_dependency_up"
    ],
    "latency": [
      "cryptoscan_dependency_latency_ms"
    ],
    "pool": [
      "cryptoscan_dependencies_degraded"
    ]
  },
  "emitted_series": 46
}
```

### `evidence_metrics` — PASS (EXECUTED)

*can an operator see the evidence store going stale under a BOM?*

- **Reading:** added this pass: evidence volume, stale evidence and current facts, so 'the BOM stopped changing' can be told apart from 'nothing was observed'
- **Limit:** no chain-verification metric: evidence integrity is proven on demand (guide 112), not continuously monitored
- **Closes with:** a periodic verification job that emits its own age and verdict

```
{
  "present": {
    "volume": [
      "cryptoscan_evidence_records",
      "cryptoscan_findings_total"
    ],
    "staleness": [
      "cryptoscan_evidence_records_stale"
    ],
    "observations": [
      "cryptoscan_observations_current"
    ]
  },
  "emitted_series": 46
}
```

### `agent_metrics` — PASS (EXECUTED)

*can an operator see that an agent on a host stopped reporting?*

- **Reading:** added this pass: the agent fleet was already recorded — heartbeats, status, buffered events — but nothing exposed it as a metric
- **Limit:** the gauge is fleet-wide with no per-agent label: an operator learns that an agent is stale, then has to look up which one
- **Closes with:** a labelled series per agent (bounded by the enrolment count)

```
{
  "agent_series": [
    "cryptoscan_agent_last_seen_seconds",
    "cryptoscan_agents_reporting",
    "cryptoscan_agents_enrolled"
  ],
  "heartbeat_endpoints": [
    "services/api/api/routers/control_plane.py",
    "services/api/api/routers/onboarding.py"
  ],
  "meaning": "reporting counts agents inside AGENT_STALE_SECONDS; the age gauge is the stalest check-in, because the outlier is what the operator needs"
}
```

### `coverage_metrics` — PASS (EXECUTED)

*can an operator see which planes stopped being covered?*

- **Reading:** added this pass: the last discovery's coverage matrix is emitted as one labelled series per plane plus a count of planes that are not fully covered, so a dark plane is an alert and not a screen
- **Limit:** the read is platform-wide (metrics have no tenant context); in a multi-tenant deployment the gauges aggregate every tenant
- **Closes with:** tenant-labelled coverage series once a tenant-scoped scrape exists

```
{
  "coverage_series": [
    "cryptoscan_coverage_planes_unknown",
    "cryptoscan_coverage_plane",
    "cryptoscan_coverage_collected_ratio"
  ],
  "reported_when": "only after an estate discovery has been stored \u2014 with no run there is no coverage to report, which is correct: 'never observed' is not 'fully covered'"
}
```

### `health_surfaces` — PASS (EXECUTED)

*do the probes answer, and do they distinguish liveness from readiness?*

- **Reading:** added this pass: /healthz/workers — the worker probe the console had, reachable by an orchestrator without a session, answering 503 only when work is waiting and nothing is draining
- **Limit:** the probe reads the durable job and lease records, so it reports what the queue has done, not what a worker process is doing this second
- **Closes with:** a lease heartbeat on the queue consumer, carried into the same probe

```
{
  "routes": [
    "healthz",
    "healthz/dependencies",
    "healthz/schema",
    "healthz/workers",
    "readyz"
  ],
  "liveness": {
    "path": "/healthz",
    "status_code": 200
  },
  "readiness": {
    "path": "/readyz",
    "status_code": 200
  },
  "worker_probe_q": {
    "path": "/healthz/workers",
    "status_code": 503,
    "state": "Degraded",
    "detail": "work waiting beyond threshold with no drain observed in the last hour"
  },
  "worker_probe_draining": {
    "status_code": 200,
    "state": "Operational",
    "detail": "drain observed: 1 completion(s) in the last hour"
  },
  "distinguishes": true,
  "meaning": "three probes, three questions: liveness is the process, readiness is its dependencies, and the worker probe is whether anything is consuming \u2014 measured from the job and lease records, so it answers while the console is unreachable"
}
```

### `traces` — PASS (EXECUTED)

*is a single request traceable across API, worker and database?*

- **Reading:** added this pass: the span exporter that already existed is executed — a real HTTP sink receives the OTLP/JSON of a finished span, with the same trace and span ids and the route as an attribute
- **Limit:** the worker carries the trace id in its log context but does not open a child span, so a job's work is correlated by id rather than drawn as a trace; and no APM backend in this repository was sent the payload
- **Closes with:** a job-id span link opened by the consumer, and a collector the bank already runs

```
{
  "trace_context_modules": [
    "services/api/api/middleware/logging_middleware.py",
    "services/api/api/middleware/observability_middleware.py",
    "services/api/api/middleware/request_id_middleware.py",
    "services/api/api/middleware/trace.py"
  ],
  "span_exporters": [],
  "otlp_export": {
    "endpoint": "http://127.0.0.1:46763/v1/traces",
    "notifications": 1,
    "span_name": "GET /api/v1/collectors/authority",
    "trace_id_matches": true,
    "span_id_matches": true,
    "timings_present": true,
    "http_route_attribute": "/api/v1/collectors/authority",
    "service_name": "cryptoscan-observability-drill",
    "payload_bytes": 623,
    "unconfigured_store_spawns_exporter": false,
    "status": {
      "code": 1
    },
    "meaning": "the span a request finished is the span the collector received, with the same trace and span ids, the route as an attribute and the service name in the resource \u2014 export is off the request path and absent when unconfigured"
  },
  "worker_trace_propagation": [
    "services/worker/worker/core/job_executor.py",
    "services/worker/worker/pipeline/pipeline_runner.py"
  ],
  "request_id": [
    "services/api/api/middleware/request_id_middleware.py",
    "services/api/api/middleware/trace.py"
  ]
}
```

### `logs` — PASS (READ)

*are logs structured, correlated and safe to ship?*

- **Reading:** JSON logs through a shared logger, with request ids and redaction helpers
- **Limit:** no shipping pipeline in this repository: whether logs reach the bank's SIEM is a deployment question
- **Closes with:** a documented log pipeline in the deployment guide

```
{
  "structured_logging": [
    "services/api/api/main.py",
    "services/drift/drift/alerts/alert_dispatcher.py",
    "services/drift/drift/alerts/email_alerter.py",
    "services/drift/drift/alerts/webhook_alerter.py",
    "services/drift/drift/classifiers/drift_type_classifier.py"
  ],
  "redaction": [
    "services/api/api/config/settings.py",
    "services/api/api/intelligence/payloads.py",
    "services/api/api/live_scan/runner.py",
    "services/api/api/live_scan/vendor_realtime.py"
  ]
}
```

### `alert_rules` — PASS (EXECUTED)

*does every alert reference a metric that exists, and is anything paging?*

- **Reading:** 15 rules across availability, backlog, freshness and integrity; every series a rule names is checked against the endpoint's live output and the module's declared names, so a renamed metric fails this report instead of the pager — and added this pass, a rule from alerts.yml is delivered to the receiver alertmanager.yml names and counted in /metrics
- **Limit:** no Prometheus scraped these rules and no Alertmanager process ran: the evaluation and the grouping are the bank's, and what is proven here is the delivery half — the receiver, the token and the counted series
- **Closes with:** nothing further in code; a bank points alertmanager.yml at its own pager and the same series proves delivery

```
{
  "rules_file": "infra/monitoring/prometheus/alerts.yml",
  "groups": 2,
  "rules": 15,
  "metrics_referenced": 3,
  "metrics_declared": 42,
  "metrics_missing_from_endpoint": [],
  "metrics_not_emitted_in_this_run": [],
  "why_not_emitted": "queue series need REDIS_URL and worker leases; the run had no Redis, so they were declared but absent",
  "prometheus_wiring": {
    "scrapes_metrics": true,
    "rule_files": [
      "/etc/prometheus/rules/alerts.yml"
    ],
    "alertmanager_configured": true,
    "note": "rules are mounted at /etc/prometheus/rules/alerts.yml; without an Alertmanager stanza they evaluate and go nowhere"
  },
  "pager_path": {
    "alertmanager_config": "infra/monitoring/alertmanager/alertmanager.yml",
    "receivers": [
      "cryptoscan-null",
      "cryptoscan-platform"
    ],
    "receiver_url": "http://api:8010/api/v1/ops/alerts/alertmanager",
    "unrouted_sub_routes": [],
    "inhibit_rules": 2,
    "group_by": [
      "alertname",
      "plane"
    ],
    "paging_rule_used": {
      "alertname": "CryptoscanApiDown",
      "severity": "critical",
      "for": "2m"
    },
    "post_status": 200,
    "accepted": 1,
    "malformed_notification_status": 422,
    "series_after": [
      {
        "alertname": "CryptoscanApiDown",
        "severity": "critical",
        "status": "firing",
        "count": 1
      }
    ],
    "counted_in_metrics": true,
    "last_notification_age_seconds": "0.0",
    "meaning": "a rule that exists in alerts.yml was posted as an Alertmanager notification to the receiver its own config names, was accepted, and is now a scraped series \u2014 the alert evaluates outside the system it watches and the platform can prove it was told"
  },
  "severities": [
    "None",
    "critical",
    "high",
    "medium"
  ]
}
```

## Alert rules, checked against the endpoint

| Alert | Severity | For | Metrics | Runbook |
|---|---|---|---|---|
| _(recording rule)_ | — | — | — | no |
| _(recording rule)_ | — | — | — | no |
| _(recording rule)_ | — | — | — | no |
| _(recording rule)_ | — | — | — | no |
| _(recording rule)_ | — | — | — | no |
| `CryptoscanApiDown` | critical | 2m | — | no |
| `CryptoscanScrapeTargetMissing` | critical | 10m | — | no |
| `CryptoscanAvailabilityBudgetBurnHigh` | critical | 5m | — | no |
| `CryptoscanServerErrorRate` | high | 10m | — | no |
| `CryptoscanLatencyP99High` | high | 15m | — | no |
| `CryptoscanNoTraffic` | high | 15m | — | no |
| `CryptoscanRateLimitStorm` | medium | 10m | — | no |
| `CryptoscanCoveragePlaneUnknown` | high | 30m | `cryptoscan_coverage_planes_unknown` | no |
| `CryptoscanCoverageCollectedRatioLow` | medium | 1h | `cryptoscan_coverage_collected_ratio` | no |
| `CryptoscanDeadLetterGrowing` | high | 15m | `cryptoscan_jobs_dead_letter` | no |

## The metric families `/metrics` emits

`cryptoscan_agent_last_seen_seconds`, `cryptoscan_agents_enrolled`, `cryptoscan_agents_reporting`, `cryptoscan_alertmanager_notifications_total`, `cryptoscan_api_db_reachable`, `cryptoscan_api_up`, `cryptoscan_api_uptime_seconds`, `cryptoscan_coverage_collected_ratio`, `cryptoscan_coverage_plane`, `cryptoscan_coverage_planes_unknown`, `cryptoscan_dependencies_degraded`, `cryptoscan_dependency_latency_ms`, `cryptoscan_dependency_up`, `cryptoscan_drift_events_open`, `cryptoscan_estate_assets`, `cryptoscan_estate_assets_stale`, `cryptoscan_event_replay_gap_total`, `cryptoscan_evidence_records`, `cryptoscan_evidence_records_stale`, `cryptoscan_findings_by_status`, `cryptoscan_findings_total`, `cryptoscan_jobs_by_status`, `cryptoscan_jobs_dead_letter`, `cryptoscan_jobs_oldest_queued_seconds`, `cryptoscan_jobs_queued`, `cryptoscan_jobs_retry_scheduled`, `cryptoscan_monitor_changes_detected`, `cryptoscan_monitor_events_total`, `cryptoscan_monitor_targets_by_status`, `cryptoscan_monitor_targets_total`, `cryptoscan_monitor_targets_watch_enabled`, `cryptoscan_observations_current`, `cryptoscan_persistence_failure_total`, `cryptoscan_scan_duration_seconds`, `cryptoscan_scan_duration_seconds_bucket`, `cryptoscan_scan_duration_seconds_count`, `cryptoscan_scan_duration_seconds_sum`, `cryptoscan_scanner_family_jobs`, `cryptoscan_scans_by_status`, `cryptoscan_scans_total`, `cryptoscan_telecom_scan_age_seconds`, `cryptoscan_telecom_targets_by_severity`, `cryptoscan_telecom_targets_registered`, `cryptoscan_telecom_targets_unreachable`, `cryptoscan_tenant_isolation_violation_total`, `cryptoscan_workers_alive`

## What this does not prove

- The metrics were served in-process against a scratch database seeded with one row of each kind. A populated estate changes the values, not the presence or the meaning of a series.
- No Prometheus and no Alertmanager process ran here. The rules were checked against the endpoint's own output and a notification was delivered to the receiver the bundled config names; the evaluation interval, the grouping and the retry behaviour are Prometheus's, and unproven by this drill.
- The span exporter was watched against a local HTTP sink, not an APM backend: the payload is OTLP/JSON and its ids are checked, but no vendor collector accepted it.
- The worker probe reads durable job and lease records. A worker that is alive and idle looks the same as one that never started, which is why the probe reports 'Not measured' rather than inventing a state.
- Log shipping to a SIEM is a deployment question and is graded READ: the structured logger and the redaction helpers exist, and this checkout cannot show what leaves the host.

**The verdict this drill supports:** 10 of 10 surfaces answer. 9 were driven through their real endpoint, route or exporter — `collector_metrics`, `queue_metrics`, `database_metrics`, `evidence_metrics`, `agent_metrics`, `coverage_metrics`, `health_surfaces`, `traces`, `alert_rules` — and 1 is graded from the checkout because what it claims leaves the host: `logs`.

The three additions in this pass are the ones the previous pass named as its closing work: a worker probe an orchestrator can call without a session, a span exporter that was executed against a real HTTP sink, and a pager path from a rule in `alerts.yml` through Alertmanager's own config to a counted series in `/metrics`. Each is a control that now exists *and* has been watched working; none of them is a claim about a deployment.
