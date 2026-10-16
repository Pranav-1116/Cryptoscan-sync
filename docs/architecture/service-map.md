# Service map

**Measured 2026-10-16** at round 80: `services/` holds **51 service
directories** (383,466 lines of Python between them), `shared/` holds 3 shared
packages, and the operator console is the React/Vite app in `frontend/`.

The previous version of this page listed 16 services, described the API as the
"dashboard host" and `services/dashboard` as *the* single-page UI. Both were
true in August 2026 and are not true now: the console is a 75-page React SPA
with its own 334-test Vitest suite, and `services/dashboard` is the legacy
air-gap fallback shell the API serves only when no console build is present.
Roles below are each service's own package docstring, trimmed; LOC and test
counts are measured (`*.py` under the service directory, `test_*.py` under its
`tests/`).

## The deterministic spine

The scan path, in the order `PipelineRunner.run()` walks it: `scanner` →
`evidence` → `database` → `normalization` → `policy` → `deduplication` →
`drift` → `quantum` → `cbom` → `graph_engine`, orchestrated by `worker` and
served by `api`. Every stage writes tenant-scoped rows and commits once, at the
end of the run (round 80: derived writes ride that same transaction rather than
opening a competing one).

## Services (51, alphabetical)

| Service | Path | Role | LOC | Tests |
|---|---|---|---:|---:|
| agility | `services/agility` | 6-factor agility score + migration readiness; DB-free CLI over a JSON inventory | 2,832 | 4 |
| anomaly | `services/anomaly` | Deterministic anomaly detection + forecasting (no AI/ML) | 819 | 2 |
| api | `services/api` | FastAPI application — routers, middleware, security; the `/api/v1` surface (834 paths / 920 operations) | 102,133 | 248 |
| apikeys | `services/apikeys` | Machine API-key platform policy — scopes, methods, quota | 374 | 1 |
| automation | `services/automation` | Discovery-driven scanner auto-selection and risk-based scheduling | 3,154 | 6 |
| billing | `services/billing` | Billing integrations (real PSP gateways over the tenant plan model) | 334 | 1 |
| business_context | `services/business_context` | Business impact enrichment and prioritization | 787 | 3 |
| cbom | `services/cbom` | CycloneDX CBOM → auditable crypto-posture report (score, grade, per-algorithm), snapshots and diffs | 14,422 | 29 |
| cloud_scanner | `services/cloud_scanner` | Cloud and IaC cryptographic configuration scanner (AWS / Azure / GCP, Terraform, K8s) | 21,790 | 25 |
| compliance | `services/compliance` | Compliance assurance: attestations, SOC-2-style evidence, WORM retention | 754 | 2 |
| connector_sdk | `services/connector_sdk` | Standard framework for every platform connector (AWS, Azure, GCP, VMware, K8s, HSM, PKI) | 553 | 1 |
| container_scanner | `services/container_scanner` | Image-root inventory — package manifests, embedded JARs and shared libraries | 6,399 | 16 |
| control_plane | `services/control_plane` | Deterministic core logic: authorization, admission, leases, the event queue | 3,815 | 5 |
| correlation | `services/correlation` | Deterministic correlation engine — every judgment is a formula or a table | 453 | 2 |
| dashboard | `services/dashboard` | **Legacy** self-contained vanilla-JS shell (`index.html`, no build step). The API's `/` fallback when no console build exists; not the operator console | 0 py | 0 |
| database | `services/database` | SQLAlchemy models, 49 repositories, 95 alembic migrations, ORM-level tenancy, cryptographic fact identity | 24,930 | 29 |
| datalake | `services/datalake` | Append-only, hash-chained data-lake export | 314 | 1 |
| deduplication | `services/deduplication` | Cross-scanner asset deduplication into `crypto_assets` | 871 | 4 |
| devsecops | `services/devsecops` | Encryption at rest for stored scan artifacts, keyed per tenant; CI gates and artifact sidecars | 27,474 | 24 |
| drift | `services/drift` | Drift detection against the approved baseline + alerting | 5,606 | 16 |
| eventstream | `services/eventstream` | Signed envelopes, replayable topics, stream processor (normalize → dedup → enrich) | 2,284 | 6 |
| evidence | `services/evidence` | Evidence integrity: canonicalization, SHA-256 content hash, chain hash, manifest | 3,363 | 17 |
| governance | `services/governance` | Rule-based approvals + migration gating | 2,543 | 4 |
| graph_engine | `services/graph_engine` | Dependency graph — Neo4j when configured, in-process memory otherwise | 5,204 | 14 |
| identity | `services/identity` | API-key network guard and rotation reminders (pure functions, no DB/IO) | 1,740 | 1 |
| inventory | `services/inventory` | Cloud KMS inventory connectors (AWS KMS, Azure Key Vault) → crypto assets, read-only metadata | 1,054 | 3 |
| keyassure | `services/keyassure` | Deterministic TLS protocol-version and cipher-suite classification | 3,007 | 3 |
| marketplace | `services/marketplace` | Plugin marketplace core — deterministic, hash-pinned, signed plugins | 565 | 1 |
| network_scanner | `services/network_scanner` | Network TLS scanner — active probe, certificate inventory, deep probes | 26,146 | 37 |
| normalization | `services/normalization` | Algorithm aliases → NIST / IANA / CBOM fields | 4,836 | 17 |
| observability | `services/observability` | Metrics, tracing, SLOs, self-alerting, forecasting | 517 | 1 |
| ot_safety | `services/ot_safety` | OT/ICS maintenance-window safety guard | 478 | 1 |
| ot_scanner | `services/ot_scanner` | Passive OT/ICS crypto inventory — never sends packets | 1,560 | 3 |
| payment_crypto | `services/payment_crypto` | Payment cryptography visibility: HSM key inventory, TR-31, audit-log telemetry, PAY policy | 2,903 | 4 |
| policy | `services/policy` | YAML policy packs (64 rules / 13 packs) + the rule engine over normalized findings | 4,286 | 24 |
| privacy | `services/privacy` | Privacy engine + the unified scanner gate | 3,193 | 8 |
| quantum | `services/quantum` | Quantum / harvest-now-decrypt-later risk analysis (Shor, Grover, Mosca) | 942 | 3 |
| remediation | `services/remediation` | Deterministic remediation suggestions — never a compliance determination | 1,644 | 4 |
| reporting | `services/reporting` | Compliance report renderer (PDF/Markdown, signed exports) | 2,218 | 8 |
| ruleset | `services/ruleset` | Deterministic ruleset engine for marketplace plugins | 374 | 1 |
| runtime | `services/runtime` | Runtime crypto discovery — TLS forward-proxy tap → session records | 2,897 | 6 |
| scanner | `services/scanner` | Multi-language static crypto detection: 20+ parsers incl. Java (+AST), Python, JS/TS, C#, Go, Kotlin, Rust, Swift, Ruby, PHP, C, SQL, Shell, XML, COBOL, PL-I, Natural, HLASM/mainframe DEFs, legacy 4GL, IBM i RPG/CL | 33,116 | 58 |
| sector_profiles | `services/sector_profiles` | Sector layer — one universal engine, sectors differ in context and defaults | 1,077 | 2 |
| sla | `services/sla` | Remediation-SLA tracker | 347 | 1 |
| telecom_scanner | `services/telecom_scanner` | 5G air-interface ciphering and integrity algorithms (3GPP TS 33.501 §5) | 4,272 | 6 |
| universal_crypto | `services/universal_crypto` | Universal cryptography scanner (cross-domain detection core) | 10,348 | 15 |
| universal_platform | `services/universal_platform` | Universal asset model — canonical identity across the five scanner domains | 2,880 | 6 |
| universal_vendor | `services/universal_vendor` | Vendor plugin SDK template: copy the directory, implement the contract (includes its own `sdk_template/tests`) | 22,863 | 33 |
| vaultlease | `services/vaultlease` | Short-lived vault-lease policy — no AI, no secret storage | 418 | 1 |
| vendor_intel | `services/vendor_intel` | Vendor documentation algorithm extraction, questionnaires, CBOM import, 0–100 vendor risk | 2,188 | 5 |
| worker | `services/worker` | Worker process: queue consumer, round-46 execution gate, pool, `PipelineRunner`, monitor sweeps | 16,389 | 52 |

## Shared packages

| Package | Path | Role |
|---|---|---|
| shared_models | `shared/shared_models` | Cross-service contracts: `platform_scope.py` (the boundaries manifest served at `GET /platform/scope`), `capability_maturity.py` (75 surfaces: 33 GA / 32 beta / 10 preview), findings, events |
| shared_config | `shared/shared_config` | Configuration contracts shared by API, worker and monitor |
| shared_logging | `shared/shared_logging` | Structured logging setup — one format across services |

## Operator console and how it is served

The console is `frontend/` — TypeScript + React + Vite, **75 page components /
80 lazy-loaded routes**, 334 Vitest tests, clean `tsc --noEmit`
(`make test-frontend`). Serving chain:

```
browser ──▶ nginx (:8088 in compose) ──▶ frontend (:3003, built by .docker/frontend/Dockerfile)
                    │
                    └──▶ /api, /health ──▶ api (:8010)   [SSE-safe: buffering off, long read timeout]
```

`api/main.py` also answers `/` itself: it serves `services/dashboard/dist/`
when a console build has been copied there, and otherwise falls back to the
legacy `services/dashboard/index.html` — the air-gap shell (no build step, no
CDN dependencies). In local development the console runs from `frontend` with
Vite proxying `/api` to `:8010`; `make api` prints exactly that.

## Entrypoints

- `make api` — API on `:8010` (`uvicorn api.main:app`), plus `cd frontend && npm run dev` on `:3003`
- `make worker` — worker process (`python -m worker.main`; needs `REDIS_URL` for the queue)
- `make test` — whole backend tree in one hermetic parallel pytest run (xdist, `--import-mode=importlib`, `-m "not live"`)
- `make test-serial` — one suite at a time, for bisecting (this is the lane that surfaces order-dependent tests; see round 80)
- `make test-frontend` — `tsc --noEmit` + Vitest
- `docker compose up` — postgres, redis, api, worker, monitor, frontend, nginx

See [dev/TESTING.md](../dev/TESTING.md) for the test doctrine and
[platform-boundaries.md](platform-boundaries.md) for what the platform
deliberately does not do.
