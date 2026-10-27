# ZELNX CryptoScan — Dataflow

> A step-by-step description of **how data moves** through the platform: where a
> fact is born (scanner), how it is hashed, stored, normalised, analysed, turned
> into a **Technology BOM**, versioned, exported, and delivered live to the
> browser. Unlike the architecture document (which describes *components*),
> this one describes *paths*: the exact endpoints, events and payloads data
> travels through.

## Dataflow at a glance

```
┌────────────────────────── FLOW A — INGEST ───────────────────────────┐
│  scanner ──(facts)──► evidence (SHA-256 chain) ──► unified inventory  │
└───────────────────────────────────┬──────────────────────────────────┘
                                    │
                                    ▼
┌──────────────── FLOW B — MATERIALIZE + VERSION ──────────────────────┐
│  gather inventory ──► materialize(sbom/cbom/hbom/vendor)             │
│                        │ fingerprint unchanged? → no-op (no vN)      │
│                        ▼                                             │
│  snapshot vN ──► diff(added/removed per layer) ──► immutable state   │
└───────────────────────────────────┬──────────────────────────────────┘
                                    │ state (or snapshot vN)
                                    ▼
┌──────────────── FLOW C — EXPORT + AUDIT ─────────────────────────────┐
│  validate ─► filter ─► generate ─► sign/hash (HMAC) ─► audit event   │
│  json · csv · cyclonedx · xml · spdx · pdf                           │
└───────────────────────────────────┬──────────────────────────────────┘
                                    │
                                    ▼
┌──────────────── FLOW D — LIVE DELIVERY ──────────────────────────────┐
│  every op ──► emit_platform_event                                     │
│                 ├─ persist (monitor_events, durable)                  │
│                 └─ publish (in-proc EventBus) ─► SSE ─► browser       │
│         DB tailer (cross-process) ──► Redis federation (multi-node)   │
└───────────────────────────────────┬──────────────────────────────────┘
                                    ▼
┌──────────── FLOW E — SCHEDULED EXPORTS ─────────────────────────────┐
│  schedule ──► run-due (next_run_at, idempotent) ──► export_bom ─► run│
└──────────────────────────────────────────────────────────────────────┘
```

> **Read it as a pipeline:** facts are gathered (A), turned into the one BOM (B),
> exported/audited (C), streamed live (D), and reproduced on a schedule (E).
> Flows **A–D** run continuously; **E** is the only timer/event-triggered path.

---

## Table of contents

1. [The five data flows](#1-the-five-data-flows)
2. [Flow A — Scan → Evidence → Inventory](#2-flow-a--scan--evidence--inventory)
3. [Flow B — Inventory → Technology BOM → Snapshot](#3-flow-b--inventory--technology-bom--snapshot)
4. [Flow C — BOM → Export → Audit](#4-flow-c--bom--export--audit)
5. [Flow D — Live events → SSE → Frontend](#5-flow-d--live-events--sse--frontend)
6. [Flow E — Scheduled / after-event exports](#6-flow-e--scheduled--after-event-exports)
7. [Data model reference](#7-data-model-reference)
8. [Event types reference](#8-event-types-reference)
9. [End-to-end timeline (annotated)](#9-end-to-end-timeline-annotated)

---

## 1. The five data flows

| # | Flow | One-line description |
|---|---|---|
| **A** | Scan → Evidence → Inventory | Facts are collected, hashed, and persist to the unified asset model |
| **B** | Inventory → Technology BOM → Snapshot | The asset model is materialised into 4 BOM layers and versioned |
| **C** | BOM → Export → Audit | A BOM state is validated, filtered, generated, signed and audited |
| **D** | Live events → SSE → Frontend | Operations emit events that stream live to the browser |
| **E** | Scheduled / after-event exports | Schedules run exports on a timer or after a scan/change |

Every flow enforces two invariants:
- **No fabricated data** — a flow renders zero/empty until a real operation
  produces evidence.
- **Integrity travels with the data** — once data crosses a boundary it carries a
  content hash and (for exports) an HMAC signature.

---

## 2. Flow A — Scan → Evidence → Inventory

```
┌──────────┐    facts     ┌─────────────┐   hashed   ┌──────────────┐
│ scanner  │ ───────────► │  evidence   │ ─────────► │  inventory   │
│ (source, │  JSON finding│  service    │  record    │  DB          │
│  network,│              │  SHA-256    │            │  (unified    │
│  cloud,  │              │  chain      │            │   model)     │
│  hw, ...)│              └─────────────┘            └──────────────┘
└──────────┘
```

1. **Collection.** A scanner runs a deterministic detector (or subprocess) and
   emits a structured finding, e.g.:
   ```json
   {
     "algorithm": "RSA-2048",
     "mode": null,
     "key_size": 2048,
     "purpose": "encryption",
     "confidence": "HIGH",
     "file": "/src/payment/keyservice.py",
     "line": 247
   }
   ```
2. **Canonical serialization.** The finding is serialised to a canonical form
   (stable key order) so the same finding always hashes identically.
3. **Evidence chain.** `content_hash = SHA-256(canonical finding)`;
   `chain_hash[n] = SHA-256(content_hash[n] + chain_hash[n-1])`. The row is bound
   to its scan session.
4. **Persistence.** The evidence record + the derived inventory row are written
   to the database (Postgres prod / SQLite dev) via Alembic-managed tables:
   `evidence_record`, `scan`, `scan_job`, `crypto_asset`, `system`,
   `hardware_live`, `certificate`, `system_dependency`, `system_vendor`, etc.
5. **Best-effort guard.** If the DB is briefly unavailable, evidence collection
   still completes downstream via the event bus; the durable persist is retried
   via the tailer / next scan.

**Where it lands:** the **unified asset model** (Flow B's input). A single asset
can appear in multiple layers.

---

## 3. Flow B — Inventory → Technology BOM → Snapshot

```
 inventory rows         inventory dict          materialize()             state
┌──────────────┐  gather ┌──────────────┐   ┌───────────────────┐   ┌──────────────┐
│ System       │ ───────►│ applications  │──►│ _app_component    │──►│ SBOM layer    │
│ CryptoAsset  │ ───────►│ crypto        │──►│ _crypto_component │──►│ CBOM layer    │
│ HardwareAsset│ ───────►│ hardware      │──►│ _hardware_component│─►│ HBOM layer    │
│ Vendor       │ ───────►│ vendors       │──►│ _vendor_component │──►│ VBOM layer    │
│ Certificate  │ ───────►│ certificates  │   └───────────────────┘   │ (fingerprint, │
│ SystemDepend │ ───────►│ dependencies  │                            │  snapshot_id) │
└──────────────┘         └──────────────┘                            └──────────────┘
```

### 3.1 Gather
`GET /api/v1/technology-bom` calls `_gather_inventory(db, limit)` which reads the
unified tables and produces one dict:
```
{
  "applications": [...], "crypto": [...], "hardware": [...],
  "vendors": [...], "certificates": [...], "dependencies": [[parent, child], ...],
  "scan": {"collected_at": "<iso>"}
}
```

### 3.2 Materialize
`materialize_technology_bom(inventory, environment, state_version)` loops over
`_LAYER_BUILDERS` (sbom/cbom/hbom/vendor), normalising **each row into one
`bom-ref`-keyed component**. Certificates attach to the CBOM as evidence. The
resulting **state** carries:

```
environment · state_version · generated_at · as_of
total_components · components_by_layer · certificate_count · dependency_count
layers {sbom|cbom|hbom|vendor} {components[], count} · certificates · scan
fingerprint (SHA-256 of canonical component set)
snapshot_id = "TECHBOM-YYYYMMDD-HHMMSS"
```

This is the **"one change updates multiple inventories"** guarantee: a change to a
`CryptoAsset` row is reflected in the CBOM layer, and if it sits on a system it
is also reflected in the SBOM dependents.

### 3.3 Version / snapshot
`POST /api/v1/technology-bom/snapshot`:
1. Compute `version = max(existing.version) + 1`.
2. Materialise the current inventory.
3. **No-op guard:** if `fingerprint == latest.fingerprint`, return
   `{recorded: false}` (no duplicate version).
4. Otherwise compute `diff_technology_bom(prev, cur)` (per-layer added/removed by
   `bom-ref`) and persist a `TechnologyBomSnapshot` row (immutable).
5. Emit `technology_bom.snapshot` to the event bus (§5).
6. Return `{recorded: true, snapshot, diff}`.

### 3.4 Read flows
- `GET /technology-bom/history` — newest-first snapshot list.
- `GET /technology-bom/history/versions` — lightweight version list (filterable by
  `environment`).
- `GET /technology-bom/compare?from_version=N&to_version=M` — truthful diff
  recomputed from the two stored full states.

---

## 4. Flow C — BOM → Export → Audit

```
   state (current or snapshot v)
        │
        ▼
 validate ─► filter ─► generate ─► sign/hash ─► audit ─► response
 (format/    (layer/    (json/csv/    (content     (emit
  layer)      search/    cyclonedx/    hash +       technology_bom.export)
  ✓)         risk/...    spdx/pdf)     HMAC)
```

`GET /api/v1/technology-bom/export?version=&fmt=&layer=&search=&risk_level=&
key_size_min=&type=&include_certificates=`:

1. **Select state** — either a stored snapshot (`version`) or the current live
   materialised state.
2. **Validate** — `export_service.validate_export_request` rejects an unsupported
   format/layer with `ExportValidationError` → HTTP 400.
3. **Filter** — `filter_technology_bom` projects onto `layer`/`search`/
   `risk_level`/`key_size_min`/`type`/`include_certificates`.
4. **Generate** — `export_technology_bom` renders:
   - `json` → dict
   - `csv` → `(str, mime text/csv)`
   - `cyclonedx` → `(dict, application/vnd.cyclonedx+json)`
   - `cyclonedx-xml` / `xml` → `(str, application/xml)`
   - `spdx` → `(dict, application/spdx+json)`
   - `pdf` → `(bytes, application/pdf)`
5. **Sign/hash** — content hash over the canonical body + HMAC-SHA256 over
   `{snapshot_id, body}` using `signing_secret()`.
6. **Audit** — the router's `_audit(manifest)` callback calls
   `emit_platform_event("technology_bom.export", ...)` and returns the event
   `row_id`.

**Response shaping:**
- `csv`/`xml`/`pdf` → raw `Response` (+ `X-ZELNX-*` headers).
- `json`/`cyclonedx`/`spdx` → the manifest JSON object.
- If `_scan_in_progress()` is true, add `scan_in_progress` / `live_scan_note`
  (and `X-ZELNX-Scan-In-Progress` for raw formats).

### 4.1 Evidence Package
`GET /api/v1/technology-bom/evidence-package?version=&fmt=json|pdf`:
1. Select state (snapshot or live).
2. Aggregate BOM + certificate compliance summary + `generated_at`/`generated_by`.
3. `canonical = json_dumps(package)` → `content_sha256 = SHA-256(canonical)` →
   `signature_hmac = HMAC(canonical, signing_secret())`.
4. Emit `technology_bom.evidence_package`.
5. Return JSON, or render a signed PDF header (`_build_pdf`) for `fmt=pdf`.

### 4.2 Vendor inventory (VBOM)
`GET /api/v1/technology-bom/vendor` reads `Vendor` + `SystemVendor` + `System`,
returning `{vendors: [{id,name,vendor_type,criticality,contract_end_date,
last_assessment_date,integration_type,systems,system_count}], linkage:[...],
vendor_count}`. This is the vendor-facing view of the same unified model.

---

## 5. Flow D — Live events → SSE → Frontend

```
  operation            persist            publish (in-proc)      DB tailer        Redis
 (scanner, ...) ──► monitor_events ──► EventBus.publish ──► (republish rows) ──► zelixin:events
                     (durable)             │                         │               │
                                          ▼                         ▼               ▼
                                    SSE clients  ◄── local bus  ◄── (local bus) ◄── re-inject
                                    (this node)          │                        (other nodes)
                                                         ▼
                                                /api/v1/events/stream
                                                (text/event-stream)
```

Every operation emits a **deterministic platform event**. The pipeline is:

1. **Persist** — `emit_platform_event` writes the row to `monitor_events`
   (durable). Best-effort: DB failure → warning, bus still delivers. A platform
   row has **no** `monitor_targets` row behind it (`target_id` NULL, written
   through a target shim whose id is None), so its owner is the row's own
   `tenant_id` — NULL means the platform estate. Readers must scope on those
   columns: `GET /monitor/events` scoped only through the target join and so
   answered `{"events": []}` against a full journal until round 81.
2. **Publish** — the same event is immediately published to the **in-process
   EventBus** (zero tailer latency for same-process subscribers).
3. **Dedup** — a shared `published_event_ids` registry on `app.state` means the
   DB tailer won't re-deliver an already-published row.
4. **Tailer** — `api.routers.events.tail_monitor_events` (default ~2s) picks up
   rows from **other** processes and republishes them locally.
5. **Redis federation** — when `REDIS_URL` is set, `RedisEventSync` publishes
   local events to `zelinx:events` and re-injects remote events into the local
   bus (ignoring its own, no echo loop).

**Delivery to the browser** (`GET /api/v1/events/stream`):
- Fresh credentials and selected-estate authority are checked before replay and
  live/idle delivery. Foreign events are filtered before subscription queueing.
- Ordered retained estate pages are authoritative; source DB tailing is separate,
  not a synthetic historical backlog. Queues/Pub/Sub are wakeups only.
- Resume with opaque Last-Event-ID tokens or `/events/recent?cursor=...` pages.
  Numeric global IDs cannot resume estate history; nonzero since_id returns 409.
- Retention gaps, invalid/changed epochs and backend unavailability are explicit,
  not successful emptiness. Production primary/process changes require a fresh
  snapshot; they do not promise lossless replication.
- Development memory is non-durable; production factory Redis requires verified
  TLS/ACLs and command readiness. Sentinel covers realtime/current-run clients,
  not every Redis consumer. See [current replay guide](user-guide/realtime.md).

### Technology BOM events (target_name = `technology-bom`)
| Event type | payload |
|---|---|
| `technology_bom.snapshot` | `{version, snapshot_id, total_components, components_by_layer, diff}` |
| `technology_bom.export` | `{version, snapshot_id, format, layer, filter, scan_in_progress, integrity_sha256, signature_hmac}` |
| `technology_bom.evidence_package` | `{snapshot_id, state_version, content_sha256, signature_hmac}` |
| `technology_bom.schedule` | `{schedule_id, name, frequency, fmt, layer}` |

---

## 6. Flow E — Scheduled / after-event exports

```
 create schedule         interval (daily/weekly/monthly)
┌────────────────┐      ┌────────────────────────────────┐
│ POST /export- │ ────► │ run-due picks due next_run_at  │
│ schedules      │      └───────────────┬────────────────┘
└────────────────┘                      ▼
                                        │ run schedule
                                        ▼
                               materialize state ─► export_bom ─► persist run
                                                          │            │
                                                          ▼            ▼
                                                 technology_bom.export  export-runs
```

1. **Create** — `POST /api/v1/technology-bom/export-schedules` with
   `{name, frequency, fmt, layer, filters, recipients}`. Validates
   format/layer/frequency, enforces a unique `name`, persists a
   `TechnologyBomExportSchedule` row, assigns `next_run_at` via
   `_compute_next_run`, and emits `technology_bom.schedule`.
2. **Time-based frequencies** (`daily`/`weekly`/`monthly`) produce a `next_run_at`.
   Event-driven frequencies (`after_scan`/`after_major_change`) return `None`
   (triggered by an event, not a timer).
3. **Run due** — `POST /export-schedules/run-due` selects rows where
   `next_run_at <= now()` (UTC-aware via `_as_aware`), runs each once, and is
   **idempotent** (re-running with nothing due does nothing). Each run:
   - materialises the current state (or a snapshot if targeted),
   - calls `export_bom(...)` (full validate→filter→generate→sign→audit),
   - persists a `TechnologyBomExportRun` row + `artifact_b64`,
   - updates `last_run_at`/`next_run_at`/`last_snapshot_id`,
   - emits `technology_bom.export`.
4. **Run one** — `POST /export-schedules/{id}/run` forces a single schedule.
5. **History** — `GET /export-runs` lists all recorded runs.

---

## 7. Data model reference

The BOM-specific tables and the unified tables they read from:

| Table | Key fields | Purpose |
|---|---|---|
| `systems` | `id`, `name`, `owner`, `environment`, `criticality` | SBOM source |
| `crypto_assets` | `id`, `algorithm`, `key_size`, `purpose`, `mode`, `file_path`, `confidence`, `libraries` | CBOM source |
| `hardware_live` | `id`, `asset_id`, `manufacturer`, `model`, `device_type`, `firmware`, `hsm`, `tpm`, `risk_level` | HBOM source |
| `vendors` | `id`, `name`, `product`, `model`, `lifecycle`, `risk_level`, `vendor_type`, `criticality` | VBOM source |
| `certificates` | `fingerprint_sha256`, `subject`, `expiry_status`, `is_self_signed`, `revocation_status` | CBOM evidence |
| `system_dependency` | `parent_id`, `child_id` | relationship edges |
| `system_vendor` | `vendor_id`, `system_id`, `dependency_type` | vendor↔system linkage |
| `technology_bom_snapshots` | `version`, `fingerprint`, `parent_fingerprint`, `snapshot_id`, `environment`, `total_components`, `components_by_layer`, `state`, `diff`, `created_by` | immutable versions |
| `technology_bom_export_schedules` | `name`(unique), `frequency`, `fmt`, `layer`, `filters`, `environment`, `recipients`, `active`, `last_run_at`, `next_run_at`, `last_snapshot_id`, `created_by` | scheduled exports |
| `technology_bom_export_runs` | `schedule_id`, `version`, `snapshot_id`, `environment`, `fmt`, `layer`, `filters`, `total_components`, `content_sha256`, `signature_hmac`, `artifact_b64`, `mime_type`, `audit_event_id`, `trigger` | export executions |

---

## 8. Event types reference

Other notable platform events (beyond the technology-bom set above) that feed the
same live stream:

| Event | When | Where |
|---|---|---|
| `events.subscribe` | a new SSE client connects | `/events/stream` |
| `scan.*` | a scan starts/stops/progresses | live scan runner |
| `live_scan.*` | on-demand scanner runs | `/live-scan/*` |
| `drift.*` | drift detected vs baseline | drift detector |
| `alerts.*` | alert raised | alert pipeline |
| `events.dropped` | a subscriber overflowed (advice to reconnect) | SSE stream |

---

## 9. End-to-end timeline (annotated)

```
t0  Scanner collects a fact (RSA-2048 @ line 247).
t1  Evidence service hashes it into the chain (content_hash → chain_hash).
t2  Inventory rows write to the unified asset model (crypto_asset, system, ...).
t3  Normalization maps it to IANA/NIST/CBOM canonical; policy tags it.
t4  Analysis notices drift / risk / agility / quantum verdict.
t5  GET /technology-bom → _gather_inventory → materialize → 4-layer state.
t6  POST /technology-bom/snapshot → fingerprint changed? → store vN + diff.
t7  GET /technology-bom/export → validate → filter → generate → sign → audit.
t8  emit_platform_event("technology_bom.export", ...).
t9  EventBus.publish → SSE stream → browser renders (no refresh).
t10 Optional schedule: run-due → another export + export-runs row.
```

The key property is that **t5–t9 never fabricate**: the dashboard only shows what
the inventory, the materialised state, and the event stream actually contain.

---

## Related docs

- **[END-TO-END-ARCHITECTURE.md](./END-TO-END-ARCHITECTURE.md)** — the *components*
  this dataflow runs on. Read it for the service map, the unified asset model, the
  Technology BOM layering, and the real-time delivery infrastructure. *This* file
  is the complement: it traces the **paths** data takes through those components.
- **[NAVIGATION-FEATURE-REFERENCE.md](./NAVIGATION-FEATURE-REFERENCE.md)** — what
  each page/surface exposes, for the consumer side of these flows (which endpoint a
  button hits, which live feeds a view renders).
