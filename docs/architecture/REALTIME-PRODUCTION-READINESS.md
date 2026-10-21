# Realtime architecture and production-readiness boundary

**Reviewed 2026-10-21 against implementation `e9bfbef7`.** Realtime delivery is
implemented, but neither an event bus nor a local TLS/Sentinel lab certifies a
production topology. The [root evidence gate](../../PRODUCTION-READINESS.md)
remains authoritative for release acceptance; it was not rerun for this refresh.

## Current shared-state contract

| Boundary | Implemented behavior | What is not established |
|---|---|---|
| Unified SSE/WS/polling | Exact-estate retained pages, opaque cursors, fresh credentials/estate checks and pre-queue filtering | Indefinite archives, automatic DB backfill or product-wide estate certification |
| Memory history | Independent bounded estate journals for development | Persistence across API process restart |
| Configured Redis history | Owner-partitioned streams, sequence/epoch/continuation validation; Pub/Sub only wakes readers | Lossless asynchronous replication or exactly-once delivery |
| Production Redis transport | Named non-default rediss credentials, CA/hostname verification, actual journal-command startup probe | Server patch approval, CA rotation or all service ACLs being correct |
| Optional Sentinel | Verified discovery/data TLS with separate discovery credentials; realtime/current-run client routing | Every queue/rate-limit/health client migrated or independent zones established |
| Primary changes | Role/process identity bound to snapshot validation; explicit old-cursor reset | Transparent continuation of a frozen old-primary snapshot |
| Subscription recovery | Interruptible bounded backoff, command revalidation and quiet-channel polling | Pub/Sub reconstruction of missed notifications or a production recovery SLO |
| Job execution | Persisted descriptor reconciliation before scope, current pinned initiating authority and QUEUED-only CAS | Automatic replay of RUNNING external side effects or atomic mid-collector revocation |
| SSH | RUNNING receipt before probes; host-key/optional-KEX phases and durable owned result | Device trust, full network discovery or six-BOM completeness |

Production does not silently fall back to local replay when its required Redis
journal is unusable. Configuration checks and PING alone are insufficient.
Health reporting still includes consumers with direct Redis construction;
inspect those separately rather than assuming the new factory covers everything.

## Replay and client recovery

`GET /api/v1/events/recent` returns retained-estate pages with `next_cursor`,
`has_more`, `complete`, `retention_gap`, `epoch` and snapshot bounds. Nonzero
numeric `since_id` is refused. SSE uses opaque Last-Event-ID or last_event_id
query tokens, estate-local IDs and checkpoint events. Initial reset/invalid
cursors return 409; backend errors return 503. Midstream failures use explicit
control events and close the stream.

A primary/process change requires explicit resynchronization, even if the
fixture's data all replicated. A complete new retained snapshot does not prove
all earlier acknowledgements survived. Preserve business receipts and historical
ownership; reconcile application state rather than retrying a rejected cursor
forever. See the [client guide](../user-guide/realtime.md).

## Local engineering evidence (not production certification)

The implementation ledger records **1315 passed / 4 skipped** in the broad
worker/API run; **205 passed** in the final focused run after the provenance
increment; **28 passed** in the fresh real TLS/Sentinel plus unit suite, including
planned promotion and primary SHUTDOWN NOSAVE. These overlapping runs must not be
added as unique coverage. The promotion fixture used an operator WAIT 2 barrier;
normal application writes are not thereby quorum commits. No bank deployment,
kill -9/power-loss, cross-zone partition/load or real CA-rotation qualification is
claimed. This documentation refresh does not rerun those suites.

- [Exact-estate streams/GraphQL/exports](../bank-environment/42-estate-streams-graphql-and-exports.md)
- [Persisted execution authority and SSH](../bank-environment/44-queued-authority-and-durable-ssh.md)
- [TLS/ACL/Sentinel harness and production checklist](../bank-environment/45-redis-tls-sentinel-qualification.md)
- [Upgrade/recovery procedure](../runbooks/execution-and-replay-upgrade.md)

## 1. Verified as realtime (live run, 2026-09-09)

The original local boot observations are retained below as historical evidence
for that date/environment, not a current production or scale qualification.
Later code changes supersede the old numeric per-node resume, memory-only
history and graceful production outage fallback descriptions.

| Signal | Evidence |
|---|---|
| Server boots + schema reconciling | `database_schema_ready` **205 indexes ensured**; `bootstrap_admin_created` |
| Live process foregrounds started | `event_tailer_started (2.0s)`, `automation_bridge_started`, `telemetry_heartbeat_started` |
| Health/LB probes | `/api/v1/healthz` → `200`; `/api/v1/readyz` → `{"status":"ready","database":"ok"}` |
| **Real** SSE stream | `GET /api/v1/events/stream` pushed live events: `cbom.versioned`, `auth.login`, `api.security.post` (my own identity-resolve call, with `request_id`), `telemetry.snapshot` (`events_per_sec`) |
| Scanners are real subprocesses | `api/live_scan/runner.py` invokes `network_scanner.main`, `container_scanner.main`, `ot_scanner.main`, `cloud_scanner.main`, hardware + runtime, capturing their JSON stdout |
| Honest empty state | `/api/v1/live-scan/inventory` → real zero counts (nothing scanned yet), never fabricated numbers |
| Intelligence engines compute | `/api/v1/security/intelligence/identity/resolve` merged network+agent+hardware observations into ONE canonical asset |
| Correlated observability | every `http_request` log carries `request_id` + `trace_id` + `span_id` |
