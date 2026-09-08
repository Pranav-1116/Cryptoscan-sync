# REST API

Base path: `/api/v1` (also accepted by some clients as `/api` when a reverse
proxy strips the prefix). Interactive docs: `/api/docs`.

## Auth

`POST /auth/login` `{username, password}` → cookie `cryptoscan_session` and
`token`. Send `Authorization: Bearer <token>` or rely on the cookie.

Default login: `admin` / `cryptoscan`.

`GET /discovery/plugins` lists registered source scanners (`static-java-scanner`, `static-python-scanner`, `static-js-scanner`, `static-csharp-scanner`, `static-go-scanner`, `static-php-scanner`, `static-ruby-scanner`, `static-rust-scanner`, `static-kotlin-scanner`, `static-config-scanner`). Operator CLI: `scripts/zelnx plugins`.

## Scans and jobs

- `POST /scans/trigger` `{repo_url, branch?}` → 202 `{job_id}`
- `GET /jobs` / `GET /jobs/{job_id}` / `GET /jobs/{job_id}/logs`
- `GET /scans` / `GET /scans/{scan_id}`
- `GET /scans/{scan_id}/findings`
- `GET /scans/{scan_id}/export` / `export.csv` / `verify` / `verification-script`
- `GET /scans/{scan_id}/cbom`
- `GET /scans/{scan_id}/evidence-pack` / `audit-pack` / `agility` / `work-orders` / `gate` / `gate.sarif` / `materials`
- `POST /evidence-pack/verify` `{pack, secret?}`
- `POST /ci/gate` `{scan_id, require_baseline?}`

## Findings, assets, systems

- `GET /findings` / `GET /findings/{evidence_id}`
- `GET /assets` / `GET /assets/{asset_id}`
- `GET /systems` / `POST /systems` / `GET /systems/{id}` / `PATCH /systems/{id}`
- `POST /systems/import` `{csv|systems}` CMDB bulk register
- `POST /systems/{id}/scan` queue a CBOM scan for that system
- `POST /systems/{id}/assets` / `POST /systems/{id}/dependencies`

## Policy, drift, container, CBOM

- `GET /policy/rules`
- `GET /drift` / `POST /drift/{id}/acknowledge`
- `POST /baselines/approve`
- `GET /stats/summary`
- `GET /container/scans` / `POST /container/scan`
- `GET /vulns`
- `GET /cbom` estate catalog (paginated; includes coverage)
- `GET /cbom/coverage` unknown vs scanned systems
- `POST /cbom/scan-uncovered` `{limit?}` queue scans for systems without a current CBOM
- `GET /cbom/search?q=` find an algorithm or path across systems
- `GET /cbom/portfolio` org-wide CycloneDX 1.5 CBOM
- `GET /cbom/scan/{scan_id}` / `GET /cbom/system/{system_id}`
- `POST /cbom/custom` `{asset_ids, include_vulnerabilities?}`
- `POST /cbom/validate` `{bom}` / `POST /cbom/ingest` `{bom, system_name?}`
- `POST /cbom/diff` `{left:{system_id|scan_id|bom}, right:{…}}`
- `POST /webhooks/github`

## Agility, exceptions, OT, analytics, vendors

- `GET /agility` / `GET /systems/{id}/agility` / `POST /systems/{id}/agility/recalculate`
- `GET /readiness`
- `GET /exceptions` / `POST /exceptions` / `POST /exceptions/{id}/approve|reject|revoke|review`
- `POST /exceptions/expire-due`
- `POST /ot/scan` / `GET /ot/devices` / `GET /ot/findings`
- `GET /analytics` / `trends` / `heatmap` / `forecast` / `recommendations` / `executive`
- `GET /vendors/{id}/questionnaire` / `POST /vendors/{id}/questionnaire|cbom|docs`
- `GET /vendors/{id}/risk` / `GET /vendor-risks`
- `GET /network/due` / `POST /network/run-due` / `GET /certificates/{id}/usages`

`repo_url` may be a git URL, `local://demo/polyglot-app`, or a `cloud://aws/<account>` target.

## Cloud estate

Live AWS/Azure/GCP APIs never run unless `live=true` or `CRYPTOSCAN_CLOUD_LIVE` is set. Registering an account is not a scan.

- `POST /cloud/scan` `{path, live?}` IaC preview (no persist)
- `POST /cloud/inventory` `{path?, live?, persist?, account_id?}` persist IaC as systems; `live=true` queues **one CLOUD job per account**
- `POST /cloud/accounts/{id}/inventory` `{live?}` same, for a registered account
- `GET /cloud/accounts` / `POST /cloud/accounts`
- `POST /estate/campaigns` `{limit? 25..100, dry_run?, include_cloud?, include_git?}` coverage campaign
- `GET /estate/campaigns` preview the same plan

Campaigns never enqueue a job per KMS key. Cloud systems share one `CLOUD` job per provider account. Worker skips git clone for `job_type=CLOUD`.

## Live hardware monitoring (24/7 engine)

The live hardware engine ingests agent telemetry, management-API and passive
observations, maintains per-asset live state (§3), a chained evidence journal,
versioned HBOMs (§15), drift/risk/incident verdicts (§14/§19/§20) and edge-agent
sync (§21). The database is the current truth: every ingest persists state plus
the journal row, so `/timeline/state-at` replays the journal to reconstruct
state at any timestamp (§16).

RBAC: `hardware.read` = all roles; `hardware.manage` = superadmin, ciso,
security_analyst; `hardware.ingest` = superadmin, ciso, scanner.

- `POST /hardware/events` `{event_type, asset_id, manufacturer?, model?, serial_reference?, device_type?, component?, version?, agent_id?, source?, payload?}` — ingest one hardware event → `{envelope, state_verdict, evidence_id, chain_hash, hbom_version, drift, risk, incident, pqc_assessment, targeted_plan, network_relationships?}`
- `POST /hardware/events/batch` `{events: [...]}` — bulk ingest, `{accepted, events}`
- `POST /hardware/heartbeats` `{agent_id, last_successful_discovery?, last_crypto_check?, last_firmware_check?, event_queue_depth?, event_lag_seconds?, agent_health?, hardware_count?, version?}` — agent heartbeat (§4) → `{agent_id, agent_status, health}`; missing heartbeats mark the agent `AGENT_UNAVAILABLE` (hardware stays in live state)
- `POST /hardware/reaction-plan` `?event_type=&asset_id=` — §6 dry-run targeted reaction plan (no execution)
- `POST /hardware/edge/sync` `{agent_id, events: [...]}` — central sync target for edge agents; the agent drains its local durable queue only after the 200 ACK (§21)
- `GET /hardware/state` / `GET /hardware/state/{asset_id}` — live state (§3)
- `GET /hardware/timeline` — chained evidence journal
- `GET /hardware/timeline/state-at?asset_id=&at=<ISO-8601>` — point-in-time state reconstruction (§16)
- `GET /hardware/agents` — agent heartbeats/health/queue depth (§4)
- `GET /hardware/hbom/versions` — versioned HBOM history (§15)
- `GET /hardware/incidents` — correlated incidents (§20)
- `GET /hardware/risk` — per-asset risk scores/levels (§19)

Edge agent CLI (deployable, stdlib-only):

```
python -m universal_vendor.hardware.live.edge_cli --agent-id edge-a \
    --queue-dir /var/lib/zelinx-edge ingest event.json
python -m universal_vendor.hardware.live.edge_cli --agent-id edge-a \
    --queue-dir /var/lib/zelinx-edge sync \
    --url http://central:8010/api/v1/hardware/edge/sync
python -m universal_vendor.hardware.live.edge_cli --agent-id edge-a \
    --queue-dir /var/lib/zelinx-edge status
```

## Universal crypto scanner (live engine)

The universal cryptography scanner exposes a deterministic, no-AI live
engine: events in → state → targeted analysis → versioned CycloneDX CBOM →
PQC risk recalculation. Key material is never accepted — payloads carry
metadata and algorithm identifiers only.

| Endpoint | Method | Permission | Description |
| --- | --- | --- | --- |
| `/api/v1/crypto/live/events` | POST | `crypto.ingest` | Ingest a live crypto event (`CERT_NEW`, `CERT_RENEWED`, `CERT_EXPIRING`, `CERT_REVOKED`, `ALGORITHM_DETECTED`, `ALGORITHM_REMOVED`, `LIBRARY_UPGRADED`, `TLS_POLICY_CHANGED`, `KEY_ROTATED`, `KEY_EXPIRED`, `PQC_CAPABILITY_CHANGED`, `PROTOCOL_CHANGED`, `UNKNOWN_CRYPTO_OPERATION`, …) |
| `/api/v1/crypto/live/state` | GET | `crypto.read` | All live crypto states (algorithms, quantum status, readiness, agility, risk) |
| `/api/v1/crypto/live/state/{asset_id}` | GET | `crypto.read` | One asset's live crypto state |
| `/api/v1/crypto/live/risk-summary` | GET | `crypto.read` | Per-asset risk score/level + readiness + CBOM version |
| `/api/v1/crypto/live/timeline` | GET | `crypto.read` | Immutable event journal (filters: `asset_id`, `event_type`, pagination) |
| `/api/v1/crypto/live/{asset_id}/cbom` | GET | `crypto.read` | Versioned CycloneDX 1.6 CBOM (cryptography registry OIDs) |
| `/api/v1/crypto/accuracy` | GET | `crypto.read` | Ground-truth accuracy platform: precision/recall/F1/FPR/FNR per dataset (7 datasets incl. weak_crypto + pqc_classification) |
| `/api/v1/crypto/scan` | POST | `crypto.manage` | One-shot §36 pipeline: full scan bundle → observations/findings/quantum/readiness/agility/graph/unknown-crypto report |
| `/api/v1/crypto/simulate` | POST | `crypto.manage` | What-if migration: current → candidate → readiness/quantum/agility/risk impact |

Ingest example (certificate renewed → PQC risk recalculated):

```json
POST /api/v1/crypto/live/events
{
  "event_type": "CERT_RENEWED",
  "asset_id": "payments",
  "payload": {
    "certificate_id": "cert-1",
    "previous_signature_algorithm": "RSA-PSS",
    "signature_algorithm": "ML-DSA-65",
    "public_key_algorithm": "ML-DSA-65"
  }
}
```

CLI: `python -m universal_crypto.cli scan <path|--request file.json> [--policy NIST]`,
`python -m universal_crypto.cli accuracy [--dataset <name>]` and
`python -m universal_crypto.cli simulate --current RSA --target ML-KEM-768
--protocol TLS --library OpenSSL --hardware HSM`.

## Live environment & integrated scan orchestrator

The unified scan flow turns Network, Hardware, Vendor and Cryptography into ONE
product instead of four scanners. Every integrated run gets ONE global scan id
(`SCAN-YYYY-NNNN`, unique across restarts via the persisted `scan_seq` counter)
and a deterministic phase machine: `scope_validated → discovery → correlation →
risk_calculation → live_monitoring`.

```
POST /api/v1/live/orchestrator/start?scanners=…   202  start one integrated scan for the tenant's authorized scope
GET  /api/v1/live/orchestrator/status              current scan: scan id, phase, per-domain progress, runner
GET  /api/v1/live/orchestrator/history?limit=25    finished runs, rebuilt from the durable platform event log
GET  /api/v1/live/environment                      ONE view of the whole estate: domain counts + graph + scan + events
```

`/live/environment` aggregates the same authoritative inventory and the same
correlation graph the whole platform reads, so the customer sees one estate —
no per-scanner datasets. Scope is fail-closed: an empty authorized scope denies
the scan (`scope_validated: false`, `SCAN_FAILED`) rather than probing anything.

Roles: `orchestrator/start` = admin, superadmin, ciso, security_analyst, scanner;
`status`, `history`, `environment` = any authenticated user. Scans emit
`platform.scan_phase` / `platform.scan_completed` (persisted as
`SCAN_STARTED`/`SCAN_PHASE`/`SCAN_COMPLETED`/`SCAN_FAILED` platform events).

## Realtime event stream

The control plane exposes a realtime SSE stream (spec §42 — Backend → SSE → frontend event store; no polling):

```
GET /api/v1/events/stream?last_event_id=N     text/event-stream, auth required
GET /api/v1/events/recent?since_id=N&limit=M  JSON fallback / polling
GET /api/v1/events/stats                      bus health (subscribers, buffer, published_total)
```

Every control-plane operation emits a deterministic event (persisted to `monitor_events` AND published
to the bus with zero tailer latency; cross-process rows federate within `EVENT_TAILER_SECONDS`):

- `platform.platform_discovery_completed` — after POST /platform/discover
- `platform.platform_drift_evaluated` — after POST /platform/drift
- `platform.platform_risk_scored` — after POST /platform/risk
- `platform.platform_blast_queried` — after POST /platform/blast
- `platform.platform_whatif_analyzed` — after POST /platform/whatif
- `platform.platform_cbom_served` — after GET /platform/bom
- `platform.platform_security_enforced` — after POST /platform/security
- `platform.platform_evidence_verified` — after GET /platform/evidence

Plus a `telemetry.snapshot` heartbeat every 15s (events/sec, subscribers, buffer depth) and `monitor.*`
events federated from the DB event log. The stream supports Last-Event-ID resume; after an API restart
the backlog is seeded from the durable `monitor_events` table (index `ix_monitor_events_created_at`,
migration 0038).
