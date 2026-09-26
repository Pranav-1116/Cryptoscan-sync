# ZELNX Realtime Production-Readiness Assessment

**Question being answered:** *Is the product a realtime system, or a demo?*

**Short answer:** It is a **genuine realtime system** — verified by booting the
real API and observing the live loop — but its **horizontal-scaling layer** is
not yet production-complete: the rate limiter and in-process event bus are
single-instance. That is the one real "demo → production" boundary.

---

## 1. Verified as realtime (live run, 2026-09-09)

I booted `api.main:app` against a fresh local store and exercised the live loop.
All of the following came from the actual running system, not fixtures:

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

**What "realtime" means here (and is true):** backend scanners → evidence →
normalization → identity resolution → graph/CBOM/risk → persisted store →
**DB tailer federation** → SSE stream → frontend event store (`useRealtime`,
`useRealtimeRefresh`) with Last-Event-ID resume, auto-reconnect + backoff, a
stale-connection watchdog, and **no simulated/sample data** anywhere.

---

## 2. What is still single-instance (the real boundary)

The frontend and the *decision* layer are production-shaped and already realtime.
The remaining gaps are all in the **shared-state / horizontal scale** plane:

| Component | Today | Multi-instance gap | Fix |
|---|---|---|---|
| **Rate limiter** (`privacy/ratelimit.py`) | in-memory token bucket (`self._buckets` dict) | limits are per-node; two API replicas each allow a full budget | back it with Redis (shared bucket), fall back to in-memory when `REDIS_URL` unset |
| **Event bus** (`api/events/bus`) | in-process pub/sub | events only reach SSE clients on the same node | Redis pub/sub (or PG LISTEN/NOTIFY) for cross-instance fan-out; DB tailer already covers the 2s durable path |
| **Orchestrator / Runner current state** | singleton in-memory + DB persistence for durable bits | live "current scan" is per-node | store current-run summary in Redis so any replica can serve it (already persists history) |
| **DB** | SQLite default (dev) | SQLite is dev-only; prod fails closed | must run PostgreSQL in production (`DATABASE_URL` validation already enforces this) |

### Everything below is already production-shaped (verified in code)
- **AuthN/AuthZ** — HMAC-signed session tokens + **DB-backed revocation** with a
  *strict production* mode that denies tokens never issued through login
  (`_session_store_allows`). Roles come from the users table, never token claims.
- **Unified fail-closed gate** — WHO→TENANT→AUTHORIZATION→SCOPE→PRIVACY→SCAN_POLICY→
  RATE_LIMIT→TARGET_SAFETY→CREDENTIAL→START, deterministic, before any scanner runs.
- **Privacy/redaction/data-minimization** + **no demo/sample/seed data** in the
  console (`data/initial.ts` is all-empty/zero).
- **Observability** — structured logs with trace/span correlation, `X-Request-ID` /
  `X-Trace-Id` / `X-Request-Duration-ms` headers exposed via CORS.
- **Health/readiness**, **RBAC (8 roles)**, **audit trail**, **webhooks**, **SLA**,
  **risk acceptance**, **inventory**, **identity resolution**, **finding dedup**.

---

## 3. Shared-state layer — now implemented (opt-in behind `REDIS_URL`)

All three gaps are closed with Redis-backed stores that **fall back to the
existing in-memory behaviour when `REDIS_URL` is unset** (no Redis required to
run; set `REDIS_URL` to get cross-replica sharing):

1. **Rate limiter** — `privacy/ratelimit.py` now has a `BucketStore` abstraction:
   `MemoryBucketStore` (default, identical to before) and `RedisBucketStore`
   (atomic refill+spend via a single Lua script; background Redis shares one
   budget across N replicas). Also fixed a latent bug: `user_api` was always
   charging the *heavy* (10/min) bucket because `if heavy:` tested a non-empty
   string — normal API calls now use the normal (100/min) bucket.
2. **Event bus** — `api/events/redis_sync.py` publishes each event to a Redis
   channel and subscribes on every node, re-injecting events from *other* nodes
   into the local bus (own-echo ignored; per-node monotonic ids preserve
   Last-Event-ID resume). The durable DB tailer remains as the offline fallback.
   Wired in the app lifespan when `REDIS_URL` is set.
3. **Orchestrator current-run** — `api/live_scan/current_run.py` mirrors the live
   scan status snapshot to Redis; `ScanOrchestrator.status()` serves the shared
   snapshot when a node has no local run, so any replica can answer
   `/api/v1/live/orchestrator/status`.

**Verification caveat:** this environment has no Redis server and no `fakeredis`,
so the Redis paths are unit-tested against a **stubbed client** (wiring,
fallback, own-echo handling) but were **not** integration-tested against live
Redis. The default (no `REDIS_URL`) path is unchanged and verified — running the
API with no Redis boots and serves the live/SSE endpoints exactly as before.
Before a production rollout, run `pytest` against a real Redis/Valkey instance.

---

## 4. Other production (non-realtime) items already tracked

- **mTLS between services** (#17) and **customer-managed encryption keys** (#18)
  are infrastructure/deployment concerns — no code path without a PKI/KMS
  provider.
- **Data residency** (#19) — org-level setting exists in the control plane; the
  persistence routing decision is a deployment concern.
- Secrets management (`.env`/`SECRET_KEY`/vault) is a deployment responsibility;
  code already reads from env and refuses weak production defaults.
