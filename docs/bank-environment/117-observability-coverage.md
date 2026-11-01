# Observability coverage — what an operator can see

`cryptoscan.observability-coverage/1` · generated 2026-11-01T02:41:07.605094+00:00 · **7 pass · 3 partial · 0 fail** · 45 series from `/metrics`

Each row is graded against something in this repository: the metrics rows are **executed** (the endpoint is served in-process and its output parsed), the alert row is checked rule by rule against that same output, and a surface that does not exist is reported as **FAIL**, not as future work.

| Surface | Verdict | Evidence | What was found |
|---|---|---|---|
| **can an operator see whether collectors are running and what they return?** | **PASS** | EXECUTED | complete |
| **can an operator see a queue that is not draining, or work that was given up on?** | **PASS** | EXECUTED | complete |
| **can an operator see that the database is unhealthy before users report it?** | **PASS** | EXECUTED | complete |
| **can an operator see the evidence store going stale under a BOM?** | **PASS** | EXECUTED | complete |
| **can an operator see that an agent on a host stopped reporting?** | **PASS** | EXECUTED | complete |
| **can an operator see which planes stopped being covered?** | **PASS** | EXECUTED | complete |
| **do the probes answer, and do they distinguish liveness from readiness?** | **PARTIAL** | READ | complete |
| **is a single request traceable across API, worker and database?** | **PARTIAL** | READ | span export to an APM backend |
| **are logs structured, correlated and safe to ship?** | **PASS** | READ | complete |
| **does every alert reference a metric that exists, and is anything paging?** | **PARTIAL** | EXECUTED | complete |

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
  "emitted_series": 45
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
  "emitted_series": 45
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
  "emitted_series": 45
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
  "emitted_series": 45
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
    "cryptoscan_agents_enrolled",
    "cryptoscan_agent_last_seen_seconds",
    "cryptoscan_agents_reporting"
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
    "cryptoscan_coverage_collected_ratio",
    "cryptoscan_coverage_planes_unknown",
    "cryptoscan_coverage_plane"
  ],
  "reported_when": "only after an estate discovery has been stored \u2014 with no run there is no coverage to report, which is correct: 'never observed' is not 'fully covered'"
}
```

### `health_surfaces` — PARTIAL (READ)

*do the probes answer, and do they distinguish liveness from readiness?*

- **Reading:** liveness, readiness and a dependency report are served by the API
- **Limit:** no worker liveness probe: a dead worker is visible only through the queue age metric added this pass
- **Closes with:** a worker /healthz the orchestrator can probe

```
{
  "routes": []
}
```

### `traces` — PARTIAL (READ)

*is a single request traceable across API, worker and database?*

- **Reading:** a W3C-shaped trace id and span id are minted per request and carried into structured logs, and the module says in its own docstring that it is not an exporter
- **Missing:** `span export to an APM backend`
- **Limit:** without an exporter there is no way to follow one request across services; the trace id only correlates log lines the bank has to join itself
- **Closes with:** an OpenTelemetry SDK exporter and a job-id span link carried across the queue

```
{
  "trace_context_modules": [
    "services/api/api/middleware/logging_middleware.py",
    "services/api/api/middleware/observability_middleware.py",
    "services/api/api/middleware/request_id_middleware.py",
    "services/api/api/middleware/trace.py"
  ],
  "span_exporters": [],
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

### `alert_rules` — PARTIAL (EXECUTED)

*does every alert reference a metric that exists, and is anything paging?*

- **Reading:** 15 rules across availability, backlog, freshness and integrity; every series a rule names is checked against the endpoint's live output and the module's declared names, so a renamed metric fails this report instead of the pager
- **Limit:** Alertmanager is not configured in the bundled Prometheus config, so the rules evaluate and go nowhere until a receiver is wired
- **Closes with:** an Alertmanager stanza and a receiver in the bank's own config

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
    "alertmanager_configured": false,
    "note": "rules are mounted at /etc/prometheus/rules/alerts.yml; without an Alertmanager stanza they evaluate and go nowhere"
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
| `None` | None | None | — | no |
| `None` | None | None | — | no |
| `None` | None | None | — | no |
| `None` | None | None | — | no |
| `None` | None | None | — | no |
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

`cryptoscan_agent_last_seen_seconds`, `cryptoscan_agents_enrolled`, `cryptoscan_agents_reporting`, `cryptoscan_api_db_reachable`, `cryptoscan_api_up`, `cryptoscan_api_uptime_seconds`, `cryptoscan_coverage_collected_ratio`, `cryptoscan_coverage_plane`, `cryptoscan_coverage_planes_unknown`, `cryptoscan_dependencies_degraded`, `cryptoscan_dependency_latency_ms`, `cryptoscan_dependency_up`, `cryptoscan_drift_events_open`, `cryptoscan_estate_assets`, `cryptoscan_estate_assets_stale`, `cryptoscan_event_replay_gap_total`, `cryptoscan_evidence_records`, `cryptoscan_evidence_records_stale`, `cryptoscan_findings_by_status`, `cryptoscan_findings_total`, `cryptoscan_jobs_by_status`, `cryptoscan_jobs_dead_letter`, `cryptoscan_jobs_oldest_queued_seconds`, `cryptoscan_jobs_queued`, `cryptoscan_jobs_retry_scheduled`, `cryptoscan_monitor_changes_detected`, `cryptoscan_monitor_events_total`, `cryptoscan_monitor_targets_by_status`, `cryptoscan_monitor_targets_total`, `cryptoscan_monitor_targets_watch_enabled`, `cryptoscan_observations_current`, `cryptoscan_persistence_failure_total`, `cryptoscan_scan_duration_seconds`, `cryptoscan_scan_duration_seconds_bucket`, `cryptoscan_scan_duration_seconds_count`, `cryptoscan_scan_duration_seconds_sum`, `cryptoscan_scanner_family_jobs`, `cryptoscan_scans_by_status`, `cryptoscan_scans_total`, `cryptoscan_telecom_scan_age_seconds`, `cryptoscan_telecom_targets_by_severity`, `cryptoscan_telecom_targets_registered`, `cryptoscan_telecom_targets_unreachable`, `cryptoscan_tenant_isolation_violation_total`, `cryptoscan_workers_alive`

## What this does not prove

- The metrics were served in-process with an empty database. A populated estate changes the values, not the presence of a series.
- Nothing here was scraped by a running Prometheus, and no alert was fired: the rules are checked against the endpoint's output, not against a pager.
- There is no tracing, and no agent heartbeat; both are reported as FAIL rather than described as future work.

**The verdict this drill supports:** collectors, the queue, the database and the evidence store can now be seen, and fifteen alert rules name metrics that exist. Two surfaces the review asked for do not exist — **agent health** and **traces** — and coverage is still a screen rather than a metric. Those three are named as FAIL above rather than softened.
