# Service objectives and enforced limits

One table for the numbers the platform promises and the numbers it enforces, so
that an SLO review, a capacity plan and an alert threshold cannot drift apart.
The source of truth is code; this page is checked against it by
`scripts/tests/test_monitoring_rules.py` and `scripts/tests/test_slo_limits_doc.py`.
When an alert fires, the procedure is
[on-call triage](../runbooks/oncall-triage.md); who gets called is
[the roster](on-call-and-comms.md).

## Service level objectives

Defined in `services/observability/observability/metrics.py` (`DEFAULT_SLOS`),
evaluated live at `/ops/slo`, and paged on by the Prometheus rules in
`infra/monitoring/prometheus/alerts.yml`.

| Objective | Target | Window | Paged when |
|---|---|---|---|
| Availability | 99.9 % | 1 h rolling | 5xx ratio above 1.44 % for 5 min (14.4× budget burn) |
| Latency p99 | 500 ms | 1 h rolling | p99 above 500 ms for 15 min |
| Error rate | 1 % | 1 h rolling | 5xx ratio above 1 % for 10 min |

The 1 h window is a rolling view, not a contract. A monthly objective of 99.9 %
allows about 43 minutes of full unavailability; do not spend it on unexamined
retries.

## Enforced request limits

Defined in `services/api/api/middleware/rate_limit.py` (`DEFAULT_RULES`). Limits
are per identity: API key, then session user, then the resolved client IP (see
`api/security/client_ip.py` — behind a proxy, the resolved IP depends on
`TRUSTED_PROXY_COUNT` and `TRUSTED_PROXY_CIDRS` being right).

| Endpoint class | Limit | Window | Scope |
|---|---|---|---|
| login | 5 | 60 s | per IP |
| register | 10 | 3600 s | per IP |
| scan_submit | 100 | 60 s | per identity |
| host_write | 10 | 60 s | per identity |
| host_read | 60 | 60 s | per identity |
| api | 600 | 60 s | per identity |

Exceeding a limit answers 429 with `Retry-After`. The limiter is in-process:
with more than one API replica each replica enforces its own window, so the
effective limit is per replica. Front the API with a shared limiter at the
ingress when the bank's policy requires an aggregate limit, and treat these as
the inner defence.

## Capacity rules of thumb

| Component | Sizing | Evidence |
|---|---|---|
| API | 2 replicas minimum (`maxUnavailable: 0`), 250 m CPU / 256 Mi request per replica | `scripts/load_test.py` against the real deployment |
| Worker | one replica per `MAX_CONCURRENT_JOBS` concurrent scans, 500 m / 512 Mi request | `scripts/benchmark_scan.py`, `scripts/worker_pool_soak.py` |
| PostgreSQL | the restore target, not the dashboard, decides the box | `scripts/pitr_drill.py` RTO measurement on the real cluster |
| Redis | realtime only; losing it loses events, not evidence | `docs/bank-environment/45-redis-tls-sentinel-qualification.md` |

A capacity claim is only a claim until it is measured on the bank's hardware
with the bank's data. `scripts/load_test.py` exits non-zero when the error or
throttle rate exceeds the thresholds you pass, and prints the JSON report; keep
that report with the release.

## What is deliberately not promised

- No fixed "minutes" RTO: it is measured per restore (`--evidence` output of
  `scripts/pitr_drill.py`), and includes dependency recovery and verification.
- No availability target for the worker tier: scans are queued, so worker
  downtime delays results rather than losing them.
- No multi-replica rate-limit guarantee, as described above.
