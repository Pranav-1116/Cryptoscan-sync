# Scalability, observability, DR and compliance evidence — this round

Status: **built and test-verified** unless marked otherwise. Every number in
the drill/burn docs comes from a real run against real code in this repo.

## 1. Horizontal scale: multi-region log shipping (gap: event bus single-writer)

The bus stays single-writer **per log dir** — by design (HMAC-chained logs).
Horizontal scale comes from *replication between regions*, which is now real:

* `services/eventstream/eventstream/replication.py` — `Replicator.ship_once`:
  per-line HMAC verification, strict seq continuity (`target_last+1+i`),
  torn-tail withholding, **source-shrink abort** (log shrank ⇒ `ReplicationGapError`
  "history rewritten"), **converging-replica alignment** (failback: verified
  overlap lines are skipped, offset converges, then the remainder ships with
  seq continuity), **atomic batches** (a bad head line ships nothing).
* Role marker `write_role.json` (absent = primary); `bus.publish` raises on a
  replica — a promoted region flips by removing/moving the marker.
* `Replicator.promote()` / state `.replication.json` (`<source_id>:<topic>`).
* Verified: `scripts/region_drills.py` → **region failover drill PASS**
  (200 writes → replicate → promote B → failover writes seq 201 → failback
  ships 51 → 251 events, all HMAC-verified). `docs/region-failover.md`.
* Pin for operators: the in-process rate limiter is per-replica; a
  multi-replica deployment needs a shared backend (Redis) for global limits —
  `REDIS_URL` is already wired for the shared backend hook.

## 2. PITR (gap: verified backups beyond last nightly)

* `pitr_backup(snapshot_dir)` — sqlite `backup()` + full bus log copy +
  `manifest.json` (snapshot epoch).
* `pitr_restore(..., upto_epoch=...)` — restores the snapshot then **replays
  the live log window** `(snapshot_epoch, upto_epoch]`, HMAC-verifying every
  replayed line (tampered ⇒ ValueError), and the recovered bus continues seq.
* Verified: PITR drill PASS — recover to mark T2 = 32 events, next write
  continues at seq 33, post-recovery DB state correct.
  `docs/pitr-drill.md`.

## 3. Observability on the platform itself (gap: "who watches the watcher")

* `services/observability/observability/metrics.py` — Prometheus counters +
  latency histograms (deterministic rendering), W3C `traceparent` parse/propagate,
  span store (JSONL sink), SLO math (availability / p99 / error-rate with
  budget), deterministic self-alert rules, capacity forecast from the real
  metering trail.
* `services/api/api/middleware/observability_middleware.py` — one pass per
  request: trace context in/out (`traceparent` response header), metrics.
* New endpoints (admin): `/api/v1/ops/metrics`, `/ops/traces`, `/ops/slo`,
  `/ops/alerts` (self-alerts also publish to the bus `alerts` topic),
  `/ops/capacity/forecast`. OTLP export activates when
  `OTEL_EXPORTER_OTLP_ENDPOINT` is set (no vendor SDK lock-in).
* Honest limits: single-process registry per replica; aggregate outside if
  you run N replicas (scrape each or add OTLP).

## 4. Live-infra verification (gap: registry webhooks)

* `scripts/registry_webhook_burn.py` → **9/9 PASS** over live HTTP
  (`docs/registry-webhook-burn.md`): signed push event triggers a REAL
  container scan (3 real packages discovered, real vuln lookup), tampered
  signature 401, `X-Hub-Signature-256` interop, missing root 404,
  `/ops` surface live during burn.
* AWS credentials and Neo4j/JVM remain **blocked in this sandbox** — flagged,
  never faked.

## 5. Compliance evidence automation (gap: attestation + WORM + auditor)

* `services/compliance/compliance/engine.py`:
  * `collect_evidence` — six live controls (session config, production-gate,
    signed audit-chain integrity verified per raw log line, deployed-schema
    drift, rate-limit policy, WORM policy), pack SHA-256 self-hash;
  * `create_attestation`/`verify_attestation` — **real JWS (HS256)** over the
    pack snapshot, tamper-rejecting;
  * `can_delete` — deterministic 7-year WORM gate for append-only stores.
* Endpoints: `GET /compliance/evidence`, `POST /compliance/attestations`,
  `POST /compliance/attestations/verify`, `GET /compliance/retention`, and the
  read-only **auditor API** `/compliance/audit/{evidence,retention}`
  (`X-Auditor-Key` = `AUDITOR_API_KEY`, fail-closed 401 in production).
* Verified: `scripts/compliance_burn.py` → **11/11 PASS** over live HTTP
  (`docs/compliance-burn.md`).
