# ZELNX CryptoScan — End-to-End Architecture

> A precise, implementation-accurate description of the whole platform's
> architecture, from the scanners that gather facts to the dashboard a human
> reads. It is grounded in the code as it exists in this repository (not a wish
> list): the service map, the microservice boundaries, the two databases, the
> **Technology BOM** model, the real-time event pipeline, and the security /
> integrity backbone.

---

## Table of contents

1. [Architecture in one diagram](#1-architecture-in-one-diagram)
2. [Guiding principle](#2-guiding-principle)
3. [The estate: repos, services, libraries, infra](#3-the-estate-repos-services-libraries-infra)
4. [Layer 1 — Collection (scanners)](#4-layer-1--collection-scanners)
5. [Layer 2 — Integrity (evidence chain)](#5-layer-2--integrity-evidence-chain)
6. [Layer 3 — Data (the unified asset model)](#6-layer-3--data-the-unified-asset-model)
7. [Layer 4 — Normalization & policy](#7-layer-4--normalization--policy)
8. [Layer 5 — Analysis (risk, drift, graph, agility, quantum)](#8-layer-5--analysis)
9. [Layer 6 — The Technology BOM (shared views and binary BOM family)](#9-layer-6--the-technology-bom)
10. [Layer 7 — Export Service & Evidence Package](#10-layer-7--export-service--evidence-package)
11. [Layer 8 — Real-time delivery (event bus, SSE, Redis)](#11-layer-8--real-time-delivery)
12. [Layer 9 — API gateway & dashboard](#12-layer-9--api-gateway--dashboard)
13. [Security & integrity backbone](#13-security--integrity-backbone)
14. [Deployment topologies](#14-deployment-topologies)

---

## 1. Architecture in one diagram

```
  ┌──────────────────────────── COLLECTION ─────────────────────────────┐
  │  source    network   cloud    container  hardware   runtime   OT    │
  │  scanner   scanner   scanner  scanner    scanner    scanner  scan   │
  │  (AST/    (TLS/     (AWS/    (image/    (HSM/TPM/  (host     (ICS/  │
  │   regex)   cipher)   GCP)     k8s)       firmware)  agents)   PLC)   │
  └───────────────────────────────┬────────────────────────────────────┘
                                  │ facts (JSON findings)
                                  ▼
  ┌──────────────────────────── INTEGRITY ───────────────────────────────┐
  │  evidence  service:  content_hash → chain_hash → manifest_hash       │
  │  (SHA-256, tamper-evident hash chain, audit packs, transfer)         │
  └───────────────────────────────┬──────────────────────────────────────┘
                                  │ hashed evidence records
                                  ▼
  ┌──────────────────────── DATA / UNIFIED ASSET MODEL ─────────────────┐
  │  Postgres (prod) / SQLite (dev) · Alembic migrations · inventory    │
  │  System · CryptoAsset · HardwareAsset · Vendor · Certificate ·      │
  │  SystemDependency · SystemVendor · TechnologyBom[Snapshot|Export]   │
  └───────────────────────────────┬──────────────────────────────────────┘
                                  │ unified inventory rows
                                  ▼
  ┌────────────────────── NORMALIZE + POLICY ───────────────────────────┐
  │  normalization (IANA/NIST/CBOM) → YAML policy (BASELINE/PCI-DSS/    │
  │  NIST 131A/CNSA 2.0/FIPS/HIPAA) → deterministic rule evaluation     │
  └───────────────────────────────┬──────────────────────────────────────┘
                                  │ normalized, policy-tagged assets
                                  ▼
  ┌────────────────────────── ANALYSIS ─────────────────────────────────┐
  │  drift · graph engine · risk · agility · quantum (PQC) · assurance  │
  └───────────────────────────────┬──────────────────────────────────────┘
                                  │
                                  ▼
  ┌──────────── TECHNOLOGY BOM (shared views + binary BOM family) ──────┐
  │  materialize_technology_bom() → SBOM · CBOM · HBOM · VBOM            │
  │  binary_boms → static NBOM · vulnerability BOM · technology sidecar │
  │  fingerprint → immutable snapshot_id (TECHBOM-YYYYMMDD-HHMMSS)       │
  └───────────────────────────────┬──────────────────────────────────────┘
                                  │ state
                                  ▼
  ┌────────────────── EXPORT SERVICE + EVIDENCE PACKAGE ────────────────┐
  │  validate → filter → generate → HMAC-signed → audit                 │
  │  JSON · CSV · CycloneDX · XML · SPDX · PDF                          │
  └───────────────────────────────┬──────────────────────────────────────┘
                                  │
                                  ▼
  ┌────────────────────────── REAL-TIME (SSE) ──────────────────────────┐
  │  EventBus (in-process, thread-safe) → DB tailer → Redis federation  │
  │  /api/v1/events/stream  (text/event-stream, Last-Event-ID resume)   │
  └───────────────────────────────┬──────────────────────────────────────┘
                                  ▼
  ┌──────────────────────── API (FastAPI /api/v1) ──────────────────────┐
  │  auth (PBKDF2, MFA, OIDC SSO, RBAC, API keys) · rate limits ·      │
  │  258+ routes · /metrics · /health · /readyz · gzip · security hdrs  │
  └───────────────────────────────┬──────────────────────────────────────┘
                                  ▼
  ┌──────────────────────────── DASHBOARD ──────────────────────────────┐
  │  Vite/React SPA (Live Asset Intelligence, CBOM, HBOM, graph, ...)   │
  │  live SSE feed · no full-page refresh · 6 sidebar sections          │
  │  31 menu slots / 30 unique primary routes + deep-linked pages       │
  └─────────────────────────────────────────────────────────────────────┘
```

---

## 2. Guiding principle

> **"Deterministic Truth First, AI Assists Second."**

The platform collects **facts** (scanners) → hashes them into an **evidence
chain** (integrity) → **normalizes** to canonical names → evaluates **YAML
policy** (binary, no AI) → produces **drift / gates / graph / agility /
quantum** → serves via **API + dashboard**.

Three non-negotiable rules, enforced by tests:

1. **Policy is never decided by AI.** All rule evaluation is deterministic.
2. **Key material is never touched.** The platform reads **metadata only** —
   never secret values (evidence packs use strict field whitelists).
3. **No fabricated data.** Every panel renders zero/empty/offline until a real
   operation produces evidence.

---

## 3. The estate: repos, services, libraries, infra

| Area | Contents |
|---|---|
| **Services** (`services/`) | ~35 Python microservices (see list below) |
| **Shared libraries** (`shared/`) | `shared_models` (enums, `algorithm_registry`, `quantum_classify`, `platform_scope`), `shared_config`, `shared_logging` |
| **Frontend** (`frontend/`) | Vite + React SPA, `src/lib/api.ts` client, `src/pages/` views |
| **Infra** | `docker-compose*.yml`, `k8s/`, `infra/monitoring/` (Prometheus+Grafana) |
| **Data** | Alembic migrations, demo SQLite DBs, seed scripts |
| **Docs** | architecture ADRs, runbooks, security guides |
| **Config** | env-driven settings (`shared_config`) with strict settings base |

Key services by role:

- **Collection** — `scanner`, `network_scanner`, `cloud_scanner`, `container_scanner`, `ot_scanner`, `runtime`, `not_scanner`, `universal_crypto`, `universal_vendor`, `vendor_intel`
- **Integrity** — `evidence`, `deduplication`
- **Data** — `database`
- **Normalize/policy** — `normalization`, `policy`, `ruleset`
- **Platform** — `cbom`, `graph_engine`, `drift`, `agility`, `quantum`, `api`, `worker`, `control_plane`
- **Ops/governance** — `automation`, `governance`, `sla`, `anomaly`, `remediation`, `reporting`, `onboarding`
- **Identity/security** — `identity`, `policy`, `privacy`, `sector_profiles`, `apikeys`, `vaultlease`, `keyassure`, `payment_crypto`, `ot_safety`
- **Connectors** — `connector_sdk`, `business_context`, `marketplace`, `datalake`, `dashboard`, `runtime`, `universal_platform`

---

## 4. Layer 1 — Collection (scanners)

Scanners are the **only** source of facts. They are deterministic: each one
runs a real detector (or a real subprocess) and emits structured JSON findings.
There is **no synthetic scan data**.

| Scanner | What it reads | Output |
|---|---|---|
| **Source** (`scanner`) | Java AST + JAR strings, Python `ast`, JS/TS, C#, Go, Rust, Kotlin, PHP, Ruby; config-tree (TLS/IaC); PEM/cert material | `algorithm`, `mode`, `key_size`, `padding`, `purpose`, `confidence`, `file/line/method`, git context |
| **Network** (`network_scanner`) | TLS/cipher probes on targets | negotiated ciphers, TLS versions, OCSP/renegotiation |
| **Cloud** (`cloud_scanner`) | read-only cloud accounts/tenants (AWS/Azure/GCP) | cloud estate tree |
| **Container** (`container_scanner`) | images, IaC, K8s | container/scan posture |
| **Hardware** (`hardware`/`not_scanner`) | HSM/TPM/firmware/network devices (30+ hardware plugins) | hardware root-of-trust |
| **Runtime** (`runtime`) | live hosts via agents | host findings |
| **OT** (`ot_scanner`) | passive ICS/OT capture, zero packets | OT device inventory + findings |
| **Universal** (`universal_crypto`/`universal_vendor`) | 68 vendor plugins / 16 categories | vendor BOM + crypto capability |

The **live scan runner** (`api.live_scan.runner`) invokes these on demand and/or
on a background interval, captures real JSON stdout, and publishes results onto
the EventBus. Scans run **one at a time on a single daemon worker thread** —
they never overlap.

---

## 5. Layer 2 — Integrity (evidence chain)

Every finding is hashed into a **tamper-evident chain** before storage:

```
content_hash[i] = SHA-256(canonical JSON of finding i)
chain_hash[0]   = SHA-256(content_hash[0] + scan_session_id)
chain_hash[n]   = SHA-256(content_hash[n] + chain_hash[n-1])
manifest_hash   = SHA-256(sorted evidence IDs)
```

- The **canonical serializer** guarantees the same finding produces the same
  hash regardless of key order.
- **Evidence service** produces **audit packs** (`audit_zip`, examiner export)
  and **scan transfer** (digest-verified cross-instance import/export).
- `GET /api/v1/scans/{id}/verify` returns `chain_intact: true` for a valid scan.
- The **Evidence Package** (see §10) reuses this: content hash + HMAC signature
  bound to a real snapshot.

---

## 6. Layer 3 — Data (the unified asset model)

There is **one** asset model, not four databases. The inventory tables are the
single source of truth:

| Model | Table | Role |
|---|---|---|
| `System` | systems | applications / SBOM source |
| `CryptoAsset` | crypto_assets | crypto usage / CBOM source |
| `HardwareAsset` | hardware_live | hardware / HBOM source |
| `Vendor` | vendors | vendor inventory / VBOM source |
| `Certificate` | certificates | CBOM evidence (fingerprint, subject, expiry) |
| `SystemDependency` | system_dependency | relationship edges (app → app) |
| `SystemVendor` | system_vendor | vendor → system linkage (VBOM) |
| `TechnologyBomSnapshot` | technology_bom_snapshots | immutable versioned BOM states |
| `TechnologyBomExportSchedule` | technology_bom_export_schedules | scheduled exports |
| `TechnologyBomExportRun` | technology_bom_export_runs | recorded export executions |

- **Production** uses **Postgres**; **dev/demo** uses **SQLite**.
- Schema is managed by **Alembic** migrations (the demo DB is migrated to head
  `0056`).
- The migration chain (`0001` → `0056`) also creates `users`, `user_sessions`,
  `audit_log`, `monitor_events`, `baselines`, `drift_events`, `graph_snapshots`,
  `report_snapshots`, payment HSM tables, etc.

---

## 7. Layer 4 — Normalization & policy

**Normalization** (`services/normalization`) maps raw scanner output to **IANA
/ NIST / CBOM** canonical names and coerces key sizes (e.g. a raw
`"rsa-2048 + aes-256-gcm"` becomes `RSA-2048` + `AES-256-GCM`).

**Policy** (`services/policy`) is **versioned YAML** in `rule_definitions/`:
**29 rules across 6 scopes** — BASELINE, PCI-DSS, NIST SP 800-131A, CNSA 2.0,
FIPS 140, HIPAA. Condition types: algorithm-in-list, key-size minimum, mode
whitelist, boolean flags, complex scoped conditions, timelines. Evaluation is
**fully deterministic**; `scope_resolver` maps system scopes.

This is the boundary that keeps "policy is never decided by AI" true.

---

## 8. Layer 5 — Analysis

Several services consume the normalized, policy-tagged asset set:

- **Drift** (`services/drift`) — `new/removed/changed/degraded` crypto vs. an
  approved baseline → severity. Also the **CI/CD gate** (`POST /api/v1/ci/gate`):
  purpose-aware blocking, weak-algorithm list, standard/strict/lenient profiles,
  SARIF output, fail-open recording.
- **Graph engine** (`services/graph_engine`) — the asset/relationship graph
  behind the BOM: connected components, blast radius, dependents/upstream,
  vendor chains, graph snapshots with timeline + compare.
- **Risk** — `services/risk` + `apiStatsSummary` → unified risk score/level.
- **Agility** (`services/agility`) — `/api/v1/agility` per-system migration
  readiness metrics.
- **Quantum/PQC** (`services/quantum`) — `/api/v1/quantum/plan` → deterministic
  post-quantum migration plan (waves, replacement algorithm mapping).
- **Assurance** (`keyassure`, `payment_crypto`, `ot_safety`) — active TLS
  enumeration, CT monitoring, HSM checks, payment-key ceremonies, OT safety.

---

## 9. Layer 6 — The Technology BOM

The centerpiece the customer asked for. **One change updates multiple
inventories** because the BOM is a **materialised view**, not a separate store.

`cbom.technology_bom.materialize_technology_bom(inventory, environment,
state_version)` takes **one** inventory dict and projects the shared inventory
views via `_LAYER_BUILDERS`:

| View | Collection | Builder | bom-ref prefix |
|---|---|---|---|
| **SBOM** | applications | `_app_component` | `app:` |
| **CBOM** | crypto | `_crypto_component` | `crypto:` |
| **HBOM** | hardware | `_hardware_component` | `hw:` |
| **VBOM** | vendors | `_vendor_component` | `vendor:` |

Certificates are attached to the CBOM as evidence; dependencies are retained as
relationship edges. A bounded binary or firmware scan additionally materializes
a correlated bundle with static-only **NBOM** capability candidates,
**Vulnerability BOM** findings and a deterministic **Technology-BOM snapshot**
sidecar. The full family is therefore SBOM, CBOM, HBOM, NBOM, VBOM,
Vulnerability BOM and the unified Technology-BOM snapshot. Binary NBOM records
carry `observed: false` until an authorized network scan corroborates them;
VBOM remains vendor/product/supply-chain evidence and is not vulnerability data.

Key properties:

- `fingerprint = SHA-256` over the canonical materialised component set (same
  state → same fingerprint).
- `snapshot_id = f"TECHBOM-{YYYYMMDD-HHMMSS}"` — **immutable**, content-stamped.
- `environment`, `state_version`, `generated_at`, `as_of`, `total_components`,
  `components_by_layer`, `certificate_count`, `dependency_count`, `layers`,
  `scan` metadata are all carried.
- `diff_technology_bom(prev, cur)` produces per-layer **added/removed**
  components keyed by `bom-ref`, with honest counts.
- `empty_inventory()` returns an **honest empty** state — an un-scanned estate
  renders zeroes, never fake components.

**Versioning** (`POST /technology-bom/snapshot`): a snapshot is only stored when
the fingerprint actually changed (no duplicate versions). `GET
/technology-bom/history` and `/compare` read these immutable versions. This is
the **materialise → version → investigate → export** loop.

---

## 10. Layer 7 — Export Service & Evidence Package

`cbom.export_service.ExportService` is the **pure** operational pipeline (no DB,
no I/O, no FastAPI). It takes a materialised state and returns a verifiable
export manifest.

```
validate → filter → generate → sign/hash → audit
```

1. **validate** — reject unsupported format/layer up front
   (`ExportValidationError`).
2. **filter** — project onto a subset: `layer`, `search`, `risk_level`,
   `key_size_min`, `type`, `include_certificates`.
3. **generate** — render **JSON / CSV / CycloneDX / CycloneDX-XML / SPDX / PDF**
   (plus `xml` as an alias for CycloneDX XML).
4. **sign/hash** — bind an **HMAC-SHA256** signature + content hash to the
   artifact (bytes-safe; canonical JSON body).
5. **audit** — the router supplies an `on_audit` callback that emits a
   `technology_bom.export` platform event.

Supported formats: `json`, `csv`, `cyclonedx`, `cyclonedx-xml`, `spdx`, `pdf`,
`xml`. Supported layers: `all`, `sbom`, `cbom`, `hbom`, `vendor`, `certificates`.

**Router behavior** (`/technology-bom/export`):
- For `csv`/`xml`/`pdf` → returns a `Response` with headers `X-ZELNX-Snapshot-Id`,
  `X-ZELNX-Integrity-Sha256`, `X-ZELNX-Signature-Hmac`.
- For `json`/`cyclonedx`/`spdx` → returns the manifest JSON object.
- Adds `scan_in_progress` / `live_scan_note` when a scan is running (see §10.2).

### 10.1 Scheduled exports
`/technology-bom/export-schedules`:
- Frequencies: `daily`, `weekly`, `monthly`, `after_scan`, `after_major_change`.
- Stores `name` (unique), `frequency`, `fmt`, `layer`, `filters` (JSON),
  `environment`, `recipients` (JSON), `active`, `last_run_at`, `next_run_at`,
  `last_snapshot_id`, `created_by`.
- `POST .../run` runs one schedule; `POST .../run-due` runs all due schedules
  idempotently. `_compute_next_run` handles time-based frequencies; event-driven
  frequencies return `None` (not time-scheduled).
- Every run is recorded in `/technology-bom/export-runs`.

### 10.2 Export-while-scanning
If a scan is `RUNNING`/`QUEUED` (`_scan_in_progress`), exports and the live view
are still allowed but **honest**: they carry a `live_scan_note`
("LIVE SCAN IN PROGRESS — BOM is partially updated") and the export adds
`X-ZELNX-Scan-In-Progress: true`.

### 10.3 Evidence Package
`/technology-bom/evidence-package` aggregates: BOM (total components,
components-by-layer, certificate & dependency counts, fingerprint) + certificate
compliance (total / expired / expiring / self_signed / revoked) + `content_sha256`
+ `signature_hmac`. Supports `json` and `pdf`.

---

## 11. Layer 8 — Real-time delivery

The scanner → event bus → live state → SSE → frontend pipeline, **no full-page
refresh**.

### 11.1 In-process bus and estate journals

The local bus fans out to bounded subscriber queues. Unified SSE/WS history is
an independent per-estate retained journal, not a filtered global ring buffer.
Development memory journals are non-durable; configured Redis streams are the
replay authority. Public IDs/sequences are estate-local and continuation tokens
are opaque and owner-bound.

### 11.2 Platform event persistence

`emit_platform_event` and the database tailer remain source publishers. Source
DB persistence is distinct from acceptance into the retained replay journal;
a best-effort source emitter is not a DB/Redis distributed transaction. Required
Redis append failures must not be represented as durable local success.

### 11.3 DB tailer

`tail_monitor_events` polls eligible owned source rows (default about two seconds)
and republishes them. Unified replay does not synthesize a historical DB backlog
when the retained estate journal is empty. Tailer clocks and source observation
clocks are not interchangeable.

### 11.4 Redis federation and primary-bound replay

Federation journals owner-partitioned streams and uses `zelinx:events` Pub/Sub
as a wakeup path. Production requires verified TLS, named ACL credentials and an
actual scratch append/replay command probe. Optional Sentinel provides verified
realtime/current-run discovery; not all queue/rate-limit/health clients use it.
Listener reconnect uses bounded backoff and command revalidation. A production
primary/process change changes public epochs and explicitly refuses old cursors;
a new complete snapshot cannot certify lossless asynchronous replication.

### 11.5 SSE stream

`GET /api/v1/events/stream` rechecks live authority and selected estate before
replay and live/idle checkpoints. It subscribes before reading the estate journal;
queues only wake readers, so overflow or missed notification is recovered through
retained pages. Resume with opaque Last-Event-ID/last_event_id tokens, not numeric
IDs. Initial invalid/reset cursors return 409; backend failures return 503.
Midstream gap/unavailable/refused events direct recovery. There is no guaranteed
indefinite history, exactly-once delivery or production HA certification.
See [client semantics](user-guide/realtime.md) and
[TLS/Sentinel qualification](bank-environment/45-redis-tls-sentinel-qualification.md).

### 11.6 Technology BOM events
Every BOM operation emits a typed event on `target_name="technology-bom"`:

| Event | When |
|---|---|
| `technology_bom.snapshot` | snapshot captured (v, snapshot_id, counts, diff) |
| `technology_bom.export` | export generated (version, snapshot_id, format, layer, filter, integrity, signature) |
| `technology_bom.evidence_package` | evidence package generated (content_sha256, signature_hmac) |
| `technology_bom.schedule` | export schedule created |

---

## 12. Layer 9 — API gateway & dashboard

### 12.1 API (FastAPI `/api/v1`)
- **Auth**: PBKDF2 password hashing, persistent lockout, MFA TOTP, OIDC SSO,
  RBAC (admin / auditor / viewer), machine API keys, server-side token
  revocation.
- **Security**: rate limiting (login 5/min/IP, scans 100/min/user), tamper-evident
  audit hash chain with verify + WORM-ready export, security headers, gzip.
- **Ops**: `/metrics` (Prometheus), `/health`, `/readyz` (drain).
- **Routing**: `techbom.router` is mounted at `prefix="/technology-bom"` under
  the `/api/v1` prefix → `/api/v1/technology-bom/*`. Router dependencies:
  `get_current_user`, `get_db_session`.
- 258+ live paths total.

### 12.2 Dashboard (Vite + React SPA)
- `frontend/src/lib/api.ts` — a typed API client (all BOM/export/schedule/
  evidence/vendor functions), with `getToken()` auth headers and raw-fetch for
  CSV/XML/PDF downloads.
- `frontend/src/components/Live.tsx` / `useLive.tsx` — `useLive<T>(path, fallback)`
  polls a live endpoint and `useLiveTicker` for the SSE tick.
- `frontend/src/pages/LiveAssetIntelligence.tsx` — the unified BOM page with
  **6 tabs**: Overview, Components, Compare, Export, Schedules, Evidence & Vendor.
- Six primary sidebar sections — Overview / Discovery / Intelligence /
  Governance / Output / Administration — with 31 menu slots, 30 unique
  primary route paths and additional deep-linked pages. See
  `docs/NAVIGATION-FEATURE-REFERENCE.md` for the exact current map.

---

## 13. Security & integrity backbone

| Concern | Mechanism |
|---|---|
| **Evidence tamper-evidence** | SHA-256 content + chain + manifest hash (`/verify`) |
| **Export integrity** | `integrity_sha256` (content) + `signature_hmac` (HMAC-SHA256) |
| **Signing secret** | `export_service.signing_secret()` from env/SEK, fallback `"zelnx-export-secret-change-me"` (dev only; prod fails closed) |
| **Auth** | PBKDF2 + MFA TOTP + OIDC SSO + RBAC + API keys |
| **Audit** | tamper-evident audit hash chain + `monitor_events` durable log |
| **Isolation** | fail-closed ABAC scope/tenant isolation (`tenant_isolation`) |
| **No key material** | metadata-only collection, evidence whitelists |
| **Policy is deterministic** | YAML rules evaluated with no AI |
| **Rate limiting** | login/scans/API-key throttles (Redis-backed when present) |

Production fails closed on demo secrets, plaintext admin passwords, SQLite, and
wildcard CORS.

---

## 14. Deployment topologies

- **Dev** (`docker compose up --build`): seeds SQLite on first boot; admin
  `admin`/`cryptoscan`.
- **Prod** (`docker-compose.yml` + `docker-compose.prod.yml`): set secrets, uses
  Postgres, fails closed on demo config.
- **Kubernetes** (`k8s/app/`): API + worker manifests with probes, resource
  limits, non-root, secrets.
- **Monitoring**: Prometheus `/metrics` + Grafana dashboards.
- **HA/DR**: leader lease for the 24/7 monitor daemon, replication-friendly
  SQLAlchemy session handling, backup/restore with SHA-256 manifests + chain
  re-verification.
- **Local stack** (`scripts/run_stack.sh`): one-command bring-up that seeds
  inventory on first boot.

---

## End-to-end flow (the summary)

```
scan source/network/cloud/container/hardware/runtime/OT
  → evidence chain (SHA-256)
  → unified asset model (Postgres/SQLite + Alembic)
  → normalize (IANA/NIST/CBOM) → YAML policy (deterministic)
  → drift / graph / risk / agility / quantum
  → materialize shared Technology BOM (SBOM/CBOM/HBOM/VBOM)
  → for binary scans: static NBOM + vulnerability BOM + correlated sidecars
  → immutable snapshot + version/compare
  → Export Service (validate/filter/generate/sign/audit)
  → EventBus → SSE (+ Redis federation) → dashboard (no full-page refresh)
```

---

## Related docs

- **[DATAFLOW.md](./DATAFLOW.md)** — the *paths* data takes through the components
  described here. Use it to follow a single fact from scanner → evidence →
  inventory → BOM → snapshot → export → SSE, plus the scheduled-export flow.
- **[NAVIGATION-FEATURE-REFERENCE.md](./NAVIGATION-FEATURE-REFERENCE.md)** — the
  current six-section sidebar, 31 menu slots, deep-linked routes, role guards
  and the pipeline each primary page consumes.
