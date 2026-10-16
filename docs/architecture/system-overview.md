# System overview

CryptoScan / ZELNX is a deterministic cryptographic inventory platform. The
doctrine is **Deterministic Truth First, AI Assists Second**: a scan never asks
a model to decide whether an algorithm is allowed. Policy is versioned YAML,
hashes are SHA-256, every observation is chained to evidence, and an unproven
thing is reported `UNKNOWN` / `BLOCKED` / `PARTIAL` — never `PASS`, never zero.

**Measured 2026-10-16** (round 80): 51 services, 834 API paths / 920
operations, 95 migrations, 75 ORM models, 75 console pages / 80 routes, 64
policy rules in 13 packs.

## One scan, end to end

```
authorized target (tenant → target → mode, admission-checked)
        │
        ▼
 ┌──────────────┐  clone / local:// / binary:// / cloud:// …
 │   Scanner    │  20+ parsers: Java (+AST), Python, JS/TS, C#, Go, Kotlin,
 └──────┬───────┘  Rust, Swift, Ruby, PHP, C, SQL, Shell, XML, config/crypto
        │ RawFinding   configs, key inventories, runtime logs — and mainframe:
        ▼              COBOL, PL-I, Natural, HLASM/DEFs, legacy 4GL, IBM i RPG/CL
 ┌──────────────┐  canonicalize → SHA-256 content hash → chain hash → manifest
 │   Evidence   │  key *metadata* only; strict field whitelists on every pack
 └──────┬───────┘
        ▼
 ┌──────────────┐  SQLite locally (WAL, busy_timeout 5 s) / PostgreSQL in compose
 │   Database   │  ORM-level tenancy: a query added later cannot forget the filter
 └──────┬───────┘
        │
        ├── Normalization   aliases → NIST / IANA / CBOM fields
        ├── Policy engine   baseline + scoped packs (PCI-DSS, NIST SP 800-131A,
        │                   CNSA 2.0, FIPS, HIPAA, ISO, sector profiles)
        ├── Dedup           → crypto_assets (the asset identity spine)
        ├── Drift           vs the approved baseline → owned remediation tasks
        ├── Quantum         harvest-now-decrypt-later, Mosca deadlines, PQC wave
        ├── CBOM / graph    CycloneDX pin + dependency edges (Neo4j or memory)
        └── Alert           notifications, SIEM/CEF sinks, webhooks
        │
        ▼
 API (`/api/v1`) + React console (`frontend/`) + signed reports
```

## The worker pipeline

`PipelineRunner.run()` (`services/worker`) is the only orchestrator. It walks
twelve named stages, advancing job telemetry between them:

| # | Stage | Writes |
|---|---|---|
| 1 | `clone` | workspace (ephemeral by design) |
| 2 | `language_detect` | `scan_meta.languages` |
| 3 | `scan` | `RawFinding`s; resolves the owning system before hashing |
| 4 | `evidence` | `evidence_records` — content hash, chain hash, manifest |
| 5 | `load` | the `Scan` row and its findings |
| 6 | `normalize` | `cryptographic_facts` (the fact identity spine) |
| 7 | `policy` | verdicts, rule evaluations, risk |
| 8 | `drift` | drift events; then condition-level verification of previously RESOLVED conditions (fail-soft) |
| 9 | `quantum` | PQC priority per asset |
| 10 | `gate` | drift-gate decision (`drift.core.gate.evaluate_gate`) + agility score + work-order counts into `Scan.statistics`; GitHub commit status `cryptoscan/drift-gate`, `failure` when the decision is FAIL |
| 11 | `cbom` | CycloneDX rendering + the durable `cbom_snapshots` pin; then coverage stamped `CURRENT` |
| 12 | `alert` | notifications and outward dispatch |

**Transaction contract.** The run opens one session, writes every stage, and
commits once at the end — the evidence load is deliberately atomic. Anything
that writes a *derived* row (the CBOM pin, the `graph.updated` platform event,
job telemetry) must ride that session or wait for it: on SQLite, which
serializes writers, a second connection waits out `busy_timeout` and loses the
write. Round 80 closed the three sites that did exactly that, which is why
scans used to report COMPLETED with `cbom_snapshots=0` and `monitor_events=0`.
The failure path releases the lock (rollback) *before* stamping coverage
`FAILED`, because that stamp has to survive the rollback.

The same shape appeared one layer up in round 81, in the API: `POST
/remediation/tasks` created its row on the request session and then emitted
`remediation.task_created` on a *second* connection inside the still-open request
transaction, so on SQLite the audit event was lost (`database is locked`, ~5 s per
request) while the route answered 200. `create_task` and
`drift._create_drift_remediation_tasks` now pass `session=db`. The rule
generalizes: **an emit that follows a write on the request's own session must ride
that session**, or the platform's journal silently disagrees with its tables.

**Evidence coordinates are the target's, never the worker's.** A finding's identity
is `(file_path, line_number, algorithm)`, and every consumer — drift comparison,
condition-level verification, the CBOM spine — assumes `file_path` names the file in
the *scanned target's* coordinates. The container collector derives paths from its
own staging directory (`data/workspaces/job-<uuid>/repo`), which is fresh per job, so
a dependency-derived record that kept that path changed identity on every rescan:
drift reported REMOVED/ADDED for crypto that never moved, and verification's
target-wide regression sweep always found a "new" non-compliant row and downgraded an
honest VERIFIED to REGRESSION. Round 81 rebases those paths in the container stage
(`_rebase_findings`, disclosed as `scan_meta["container"]["evidence_paths_rebased"]`;
paths genuinely foreign to the target — an image-internal `/etc/apk/world` — are left
untouched), and `PipelineRunner._container` delegates to the stage instead of
carrying a second inline copy of it. `ContainerScan.target` still records the staging
path on purpose: that is provenance about the run, not identity of the evidence.

**Fail-soft is disclosed, not silent.** Optional collectors and derived stages
(OT, container, cloud, network, certificate inventory, CBOM pin, stakeholder
alert) may fail without failing the scan — but every one of them records an
`optional_stage_failures` entry in the Scan statistics, which the console
renders as an amber "observation incomplete" marker. A COMPLETED scan never
implies complete observation (§4.8, round 39; the source guard
`test_optional_stage_disclosure.py` counts the sites).

**Authorization is checked twice.** Admission at request time
(`scan_admission.py`) and again at execution time by the round-46 gate
(`worker/core/execution_gate.py`), which fails **closed**: if it cannot read
the control plane, the job is refused with a reason rather than run. A refusal
stamps the job FAILED with that reason and never raises (round 80).

## Processes

| Process | Entrypoint | Notes |
|---|---|---|
| API | `make api` → `uvicorn api.main:app` (:8010) | 103 router modules; also answers `/` with the console build or the legacy air-gap shell |
| Worker | `make worker` → `python -m worker.main` | Redis queue consumer + execution gate + pool; monitor sweeps (evidence chain, reintroduction, SLA) |
| Monitor | `scripts/run_monitor.py` (compose `monitor`) | leader-leased periodic sweeps, telecom realtime, report runs |
| Console | `cd frontend && npm run dev` (:3003) | React + Vite + TypeScript; nginx (:8088) fronts it in compose and proxies `/api` + `/health` SSE-safe |

A scan request becomes work in one of two ways: `api/routers/trigger.py`
publishes the job to Redis (`enqueue_job` → the worker's list, with a
dead-letter key), or — when no queue is configured — runs the pipeline
in-process as a background task, re-entering the tenant scope first so results
cannot land unscoped. `scripts/trigger_scan.py --inline` is the operator-facing
version of that second path.

## What this overview replaced

The previous version of this page (2026-08-26) ended with "Still out of scope:
network/runtime/cloud, full graphs, AI, OT/ICS, GitHub workflow fills,
tree-sitter/Roslyn as hard dependencies", and described a four-language
scanner and an eight-stage pipeline. Current truth:

| Old claim | Now |
|---|---|
| network out of scope | `network_scanner` (26k LOC): active TLS probes, certificate estate, deep probes, NBOM |
| runtime out of scope | `runtime`: TLS forward-proxy tap → session records |
| cloud out of scope | `cloud_scanner` (21k LOC) + `inventory` (AWS KMS, Azure Key Vault), credential-scoped and read-only |
| full graphs out of scope | `graph_engine`: Neo4j when configured, in-process memory otherwise; estate dependency edges in system CBOMs |
| OT/ICS out of scope | `ot_scanner` (passive, verified zero-packet) + `ot_safety` maintenance-window guard |
| AI out of scope | AI *assists* — correlation, anomaly and remediation services are deterministic by construction ("every judgment is a formula or a table"); policy is never decided by a model (tested invariant) |
| Java / Python / JS / C# only | 20+ parsers including the mainframe estate (COBOL, PL-I, Natural, HLASM/DEFs, legacy 4GL, IBM i RPG/CL) |
| tree-sitter/Roslyn as hard deps | still true — optional accelerators, never required |

Boundaries that are *real* product decisions (not gaps) live in
[platform-boundaries.md](platform-boundaries.md), mirrored from
`shared_models/platform_scope.py` and served at `GET /api/v1/platform/scope`.

## What is still not proven

Stated here so this page cannot be read as a readiness claim
([`PRODUCTION-READINESS.md`](../../PRODUCTION-READINESS.md) and
[`docs/readiness-evidence/`](../readiness-evidence/) are the authority):

- The engineering-gate verdict is **FAIL**, solely on credential-blocked
  checks: immutable image digests, branch-protection verification, and customer
  COBOL / PL-I / RPG samples ("corpus evidence is not customer validation").
- No SMTP transport is wired: email notification routing is count-only, and
  outward dispatch is operator-triggered, not scheduled.
- Hostile-input sandbox isolation and sensitive historical-evidence disposition
  are open P0 items; an independent pen test and a multi-day target-scale soak
  have not run; HSM live-mode qualification needs provider credentials this
  environment does not hold.
- The full local gate is green (round 80: backend 7,629 passed / 34 skipped /
  0 failed, frontend Vitest 334 + clean `tsc --noEmit`, ruff clean, tenant
  isolation audit PASS) — but those are local SQLite-lane gates, not
  target-environment qualification.
