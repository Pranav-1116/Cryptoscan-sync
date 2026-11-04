# CryptoScan

> **Current source review (2026-10-23, tenth increment from `8c1b2bcf`):**
> [implementation / CI / migration / six-BOM boundaries](docs/CURRENT-IMPLEMENTATION-STATUS.md),
> [CI and product-build plan](docs/CI-WORKFLOW-AND-PRODUCT-BUILD-PLAN.md),
> [operator installation and recovery](docs/runbooks/operator-install-upgrade-recover.md).
> [workflow / real PostgreSQL / built-browser qualification](docs/readiness-evidence/quality-workflow-qualification-2026-10-23.md), migration **0106**.
> [shared private-read hardening](docs/readiness-evidence/quality-shared-private-reads-2026-10-23.md): 516 frontend checks and 11 built-browser checks; synthetic HTTP, not site acceptance.
> Older dated tables/diagrams are historical; configured CI does not mean a signed
> release or site approval. The user reports one remaining workflow failure.

CryptoScan discovers cryptographic assets across approved and supported collection surfaces within the bank's defined scope.

Every finding retains provenance and evidence status, with unsupported or unobserved facts represented explicitly as unknown rather than inferred as secure.

**New host-first increment (2026-10-24):** [approved offline non-Git collection](docs/bank-environment/59-approved-offline-host-collection.md) and [ten-point acceptance ledger](docs/bank-environment/60-host-first-product-acceptance.md). Linux synthetic collection and authenticated evidence/CBOM intake are implemented. [Reviewed host-to-six-BOM metadata associations](docs/bank-environment/61-host-to-six-bom-associations.md) now add per-edge provenance, independent human review, stale/retraction handling and graph export; they do not establish runtime dependencies. Windows execution, production host isolation, whole-bank coverage and the joined six-BOM host estate are **not qualified**.

**Phase-wise foundation:** [Universal collection Phase 1](docs/bank-environment/62-universal-collection-foundation.md) now adds stable scoped targets, authorization, offline jobs and one evidence envelope feeding multiple BOM reference views. [Phase 2 Linux](docs/bank-environment/63-linux-collection-phase-two.md) now adds explicit PID/shared-object mappings, namespace TCP listeners, named systemd service probes, CPU/DMI/TPM metadata interfaces and Alpine packages. [Phase 3 Windows](docs/bank-environment/64-windows-collection-phase-three.md) begins with an explicit offline candidate and named SCM status query. Native systemd/DMI/TPM/Windows qualification, signed identity and production execution remain open; metadata is not cryptographic use.

**Collector hardening:** [Guide 65](docs/bank-environment/65-signed-collector-isolation-and-native-gates.md) adds approval-pinned Ed25519 handoffs, real Linux Landlock/seccomp file-stage isolation, bounded RPM exports, an executable native-fixture gate and the next Windows OS declaration candidate. Signing-key identity is not host attestation; production admission remains blocked.

**Current Stats (2026-10-16, measured):** 51 services (~389k lines of Python), 103 API router modules, **834 API paths / 920 operations** (regenerated reference: `docs/api-reference/rest-api.md`), 95 alembic migrations with schema-parity tests, 75 frontend page components with lazy-loaded routes, 783 backend test files (full local suite: 7,629 passed / 34 skipped) plus a 334-test Vitest frontend suite with clean `tsc --noEmit`. Deterministic policy — no AI in the decision path. Per-round build ledger: `audit_reports/00_ROUND_STATUS.md` (complete through round 80).

**Real-Time System:** Read-only binary-job WebSocket progress (`/api/v1/ws/binary/jobs/{id}`), event WebSocket (`/api/v1/ws/events`), SSE (`/api/v1/events/stream`) and paginated polling (`/api/v1/events/recent`). Unified event replay is owner-partitioned, retained and epoch/cursor-bound: local memory in development or Redis Streams when configured. Fresh stream authority and explicit gaps/reset/backend errors do not imply indefinite history, exactly-once delivery or production HA qualification. See [the estate replay contract](docs/bank-environment/42-estate-streams-graphql-and-exports.md).

**Cryptographic Digital Twin (CDT):** A read-only replica of the cryptographic estate built from live scanner state (`crypto_live_states`, versioned CBOMs), an append-only event journal (`crypto_live_events`) for per-asset time-travel, stored network scan probes (the same wire derivation the NBOM uses, so the two can never disagree), dependency edges from the relational table or the latest graph snapshot, and the hardware fleet from the live hardware engine (HSM inventory with declared PQC capability). The `/digital-twin` surface reports what the twin holds and where each section came from, measures fidelity (staleness, coverage, journal depth, network observation) with honest unknowns where the estate is unscanned, diffs the twin's algorithm inventory against its own evidence store (`/digital-twin/reconciliation`), and runs ten deterministic scenario types (algorithm migration, certificate expiry, key rotation, HSM outage, vendor compromise, protocol deprecation, compliance change, attack path, PQC migration, agility drift) over the replica. Scenarios are heuristic projections, not vendor simulations, and never touch production — the same engine powers the what-if preview. Beta capability (see [docs/CAPABILITY-MATURITY.md](docs/CAPABILITY-MATURITY.md)).


Deterministic scanners, hashed evidence, YAML policy, drift, and a dashboard.
Policy is never decided by AI.

**Local:** `bash scripts/run_stack.sh` (boots empty — no demo data; inventory appears when real scans run).  
**Development login:** `admin` / `cryptoscan` (refused in production). **Docs:** [docs/README.md](docs/README.md) (all guides) · [RUN.md](RUN.md) · [REST API reference](docs/api-reference/rest-api.md).  
**Docker (dev):** `docker compose up --build`.  
**Docker (prod):** set secrets, then `docker compose -f docker-compose.yml -f docker-compose.prod.yml up --build`.

The working loop is: scan source → evidence chain → SQLite/Postgres → normalize → policy → drift → API → dashboard.

## How it operates inside a bank

[Bank environment and six-BOM walkthrough](docs/bank-environment/README.md)
explains approved deployment/access, actual scanning paths, SBOM/NBOM/CBOM/TechBOM/
HBOM/VBOM generation, practical payments examples, console/API exports and
acceptance criteria. It distinguishes code-backed behavior from prerequisites,
known route differences and unqualified bank/provider runtime claims.

[Live, change-driven estate intelligence](docs/bank-environment/100-live-change-driven-estate.md)
is the current operating model: collectors observe continuously, the platform establishes an
evidence-backed baseline once, stores only the changes, keeps the Digital Twin current and
projects the six BOMs on download — `GET /api/v1/estate/evidence/boms/CBOM/export?fmt=cyclonedx`.
A scheduled or manual discovery of an unchanged estate writes no run and no BOM revision
(`storage.state = NO_CHANGE`); the bank-side agent (`services/agent`, `python -m agent.runner`)
posts an observation only when its state hash moves, signs it with Ed25519 when a key is
configured, and reports a failed collector as a `FAILED` plane instead of a smaller estate.
Attack patterns state which collectors corroborate them without raising their level, and live
history is trimmed only on request (`POST /api/v1/ingestion/live/compact`, a dry run by default).

The [dependency and cascade guides](docs/bank-environment/12-dependency-discovery-and-evidence.md)
explain discovery, directional blast radius, bank examples, APIs, current limits
and recommended acceptance checks. They distinguish modeled exposure from
confirmed operational failure.

[Coverage and truncation qualifications](docs/bank-environment/25-coverage-truncation-and-missing-link-qualifications.md)
are shown before cascade impact: source read omissions, bounded horizons,
missing links and explanation limits stay separate. Incomplete runs cannot
silently become watch removals or comparable impact deltas. Unknown completeness
is not zero exposure or proof of safety.

[Bank-negative and backend qualification tests](docs/bank-environment/26-bank-negative-tests-and-backend-qualification.md)
cover exact-estate derived history/replay, writer-only watches and backend
semantic/isolation negatives. All ten local implementation steps are delivered;
real-bank and live backend certification remain separate obligations.

[International, multi-vendor bank assessment program](docs/bank-environment/27-international-bank-scan-program.md)
adds eight detailed planning guides (27–34): vendor evidence/access, safe
system-by-system collection, six-BOM identity/coverage, regional deployment,
30 failure scenarios, prioritized improvements and a worked multinational example.
These are proposed requirements and rollout designs, not newly shipped controls. The subsequent
[A01 API-network implementation](docs/bank-environment/35-network-admission-and-durable-collection.md)
adds shared admission and mandatory linked job/probe records for four API paths;
the [scheduled TLS worker delivery](docs/bank-environment/36-worker-scheduled-tls-admission.md)
extends that contract to the leader-worker target rotation. The subsequent
[NETWORK monitor lifecycle isolation](docs/bank-environment/37-network-monitor-lifecycle-isolation.md)
adds owner/rollback/freshness guards. The
[bounded monitor phase delivery](docs/bank-environment/38-monitor-network-phase-admission.md)
adds admission and linked jobs for TLS/IPsec/explicit-resolver DNSSEC. The
[bounded TCP discovery increment](docs/bank-environment/39-bounded-tcp-monitor-discovery.md)
adds explicit IPv4 CIDR/port monitor sweeps without automatic TLS/plugin follow-up.
Unqualified scope/plugins remain refused. The
[exact-estate HTTP history increment](docs/bank-environment/40-exact-estate-http-history.md)
restricts job/run details, logs, retries, metrics and drift to the selected estate.
[WebSocket history checkpoints](docs/bank-environment/41-exact-estate-websocket-history.md)
add the boundary to binary progress and event sockets, including fresh authority
and pre-queue filtering. The subsequent
[estate streams/GraphQL/export delivery](docs/bank-environment/42-estate-streams-graphql-and-exports.md)
adds retained per-estate pagination and closes the reviewed cross-surface history
reads. [Broader qualification](docs/bank-environment/43-a01-a02-qualification-and-open-blockers.md)
records the historical standalone Redis evidence and original queued-authority
blockers. [Persisted queue authority and durable SSH](docs/bank-environment/44-queued-authority-and-durable-ssh.md)
now close those two controls locally and add stored SSH results/status.
[Verified Redis TLS/ACL/Sentinel qualification](docs/bank-environment/45-redis-tls-sentinel-qualification.md)
adds command readiness, subscriber recovery, primary-bound replay resets and a
destructive disposable lab, not production deployment certification.
**A01 and A02 remain partial; production safety is not certified.**
For current compatibility and recovery steps, use the
[execution/replay upgrade runbook](docs/runbooks/execution-and-replay-upgrade.md).
The regenerated [API reference](docs/api-reference/rest-api.md) has a dedicated
[contract companion](docs/api-reference/execution-and-replay.md); the
[documentation status map](docs/DOCUMENTATION-STATUS.md) distinguishes current
instructions from historical measurements.


## Scope & honest boundaries

CryptoScan is an **end-to-end crypto & security-configuration platform** —
not a universal "scan everything" tool.

- ✅ **It does:** crypto inventory + security-configuration posture across
  source trees, network/TLS, containers/IaC, cloud accounts/tenants you
  have access to (AWS/Azure/GCP), OT/ICS (passive, zero packets), payment
  HSM/PCI metadata and audit-trail ingestion, vendor/supply-chain, plus shared
  evidence-chain / CBOM / graph / PQC / remediation / compliance layers.
- ❌ **It does not:** application source-code hacking (general SAST), malware
  analysis, SIEM behavior analytics, core-banking transaction validation,
  or universal employee endpoint scanning.
- 🌐 **Cloud:** only the accounts/tenants your credentials can see — external
  surface only via public internet scanning of configured targets.
- 🔒 **Always:** read-only collection, evidence-chained observations, and
  **key *metadata* only — never key material or secret values** (enforced by
  tests; evidence packs use strict field whitelists).
- ⚠️ **Not operational:** Windows collection, complete hardware discovery, HSM
  cryptographic operations, runtime algorithm invocation and the generic
  simulation engine are modelled or partially implemented. The five statements,
  with what is real behind each, are in
  [the capability boundaries](docs/CAPABILITY-MATURITY.md#capability-boundaries--five-things-this-build-does-not-do).

Mainframe/legacy **crypto-oriented static parsers and metadata ingestion** do
exist, including COBOL/PL/I/RPG and selected configuration/key-inventory inputs.
That is not complete live mainframe discovery, a general core-banking audit or
production qualification; see [the bounded collection playbook](docs/bank-environment/29-system-by-system-collection-playbooks.md).

Every shipped console surface is **supported** — the sidebar carries no maturity
badges, because a product's navigation is not the place to negotiate what is
proven. What used to be a `beta` or `preview` label is now a **stated limit per
surface**, listed in [docs/CAPABILITY-MATURITY.md](docs/CAPABILITY-MATURITY.md)
(`GET /api/v1/platform/capabilities`, source `shared_models/capability_maturity.py`).
A support statement and a completeness statement are different claims, and only
the first one is uniform across the product.

The boundaries are a single source of truth
(`shared_models/platform_scope.py`), served at `GET /api/v1/platform/scope`,
enforced by tests, and documented in
[docs/architecture/platform-boundaries.md](docs/architecture/platform-boundaries.md).
For an honest feature-by-feature benchmark against real-world tools
(Venafi/Keyfactor, SandboxAQ Cryptosense, Prowler, Trivy, testssl.sh,
Nozomi, SAST), see
[docs/architecture/real-world-comparison.md](docs/architecture/real-world-comparison.md).

## Operations (production hardening, 2026-08-26)

| Capability | Where |
|---|---|
| **CI** — discovered backend/shared + offline scanner matrices; PostgreSQL 15/16 migration/parity; frontend typecheck, Vitest, coverage smoke, build/toolchain; six-image **build-only** lane; fail-closed `ci-required`. Manual unsigned release preflight is separate. Actual run status and release/site approval are not implied. | [Current CI contract](docs/dev/release-automation.md), [product-build plan](docs/CI-WORKFLOW-AND-PRODUCT-BUILD-PLAN.md) |
| **Multi-user auth** — `users` / `user_sessions` / `audit_log` tables, roles (`admin`/`auditor`/`viewer`), persistent lockout, server-side token revocation, admin user management (`GET/POST/PATCH /api/v1/auth/users`), audit trail (`GET /api/v1/auth/audit`) | `services/api/api/security/`, `services/database/db/models/user.py`, migration `0019` |
| **RBAC** — scan trigger + baseline approve + drift ack/resolve require auditor/admin; reads need any role | `api/dependencies.py` (`require_roles`) |
| **Concurrent worker** — `MAX_CONCURRENT_JOBS` thread pool with backpressure and graceful drain | `services/worker/worker/core/pool.py` |
| **Burn-in harness** — proves external integrations: signed GitHub webhook round-trip, live TLS probe, SMTP delivery, Neo4j, cloud, container | `python scripts/burn_in.py --target all` |
| **Backup/restore** — SHA-256 manifests, online SQLite snapshot, Postgres dump, chain re-verification on the backup | `scripts/backup_evidence.py`, `scripts/restore_evidence.py`, [runbook](docs/admin-guide/backup-restore.md) |
| **Deployment (k8s)** — digest-pinned images only, rolling update with `maxUnavailable: 0`, pod disruption budget, topology spread, default-deny network policy, read-only root filesystem, and the proxy hop the client IP depends on | `k8s/app/`, [k8s/README.md](k8s/README.md) |
| **Metrics** — Prometheus `/metrics` (scans, findings by status, open drift, queued jobs) + Grafana dashboard | `api/routers/metrics.py`, `infra/monitoring/` |
| **Kubernetes** — API + worker manifests (probes, resources, non-root, secrets) | `k8s/app/`, [k8s/README.md](k8s/README.md) |
| **CI/CD policy gates** — standard/strict/lenient profiles, GitHub/Jenkins/GitLab/ArgoCD snippets, `ci_gate.py` CLI (exit 1 blocks) | `services/drift/drift/core/gate.py`, `POST /api/v1/ci/gate`, `scripts/ci_gate.py` |
| **Remediation & migration** — 15 rules × 4 languages of before/after fixes + 3 guides; scan → project → tasks → progress/velocity forecast; GitHub issue export/sync | `GET /api/v1/remediation/*`, `POST /api/v1/migrations/from-scan` |
| **Compliance reporting** — 6 templates, requirement-by-requirement from policy evidence, attestation + canonical SHA-256 hash (PKI honestly absent) | `GET /api/v1/scans/{id}/report[.html]`, `GET /api/v1/report-templates` |
| **Rate limiting + tamper-evident audit** — login 5/min/IP, scans 100/min/user; audit hash chain with verify + WORM-ready export | `api/middleware/rate_limit.py`, `GET /api/v1/auth/audit/{verify,export}` |
| **Platform status matrix** — every planned capability (W37–60) vs. what ships, gaps named honestly | [docs/PLATFORM-STATUS.md](docs/PLATFORM-STATUS.md) |
| **Live monitoring (24/7)** — watch-list daemon re-scans network/cloud/repo/container targets on intervals; backoff, alert-once, BLOCKED-honesty; live status API + dashboard view | `scripts/run_monitor.py`, `GET /api/v1/monitor/status`, [guide](docs/user-guide/live-monitoring.md) |
| **Payment crypto (HSM/PCI/TR-39)** — payment-key inventory with ceremony provenance, HSM audit-trail ingestion (JSONL/syslog/CSV), TR-31 parsing, PAY-001..010 policy, PAYMENT monitor target, dashboard view | `POST /api/v1/payment-crypto/hsm-events`, [guide](docs/user-guide/payment-crypto.md) |
| **Full-estate one-command scan** — source + containers/IaC + TLS/certs + OT (passive) through the real worker pipeline, exporting evidence pack, tamper-evident transfer, CycloneDX CBOM and compliance report (JSON/HTML/PDF) | `scripts/scan_estate.py`, `GET /api/v1/scans/{id}/report.pdf` |

First boot bootstraps the `admin` user from `ADMIN_USERNAME`/`ADMIN_PASSWORD[_HASH]`; afterwards manage accounts through the API. Production startup fails closed on demo secrets, plaintext admin passwords, SQLite, and wildcard CORS.

---

## How a fact gets into the product

The pipeline is deterministic and each stage leaves the thing it produced:

1. **Collection** — a collector reads one surface (a host, a TLS endpoint, a
   container, a cloud account, a source tree, a vendor declaration, a payment
   HSM audit trail) and writes evidence records. A collector that cannot read a
   surface says so; it does not return an empty result that looks like a clean
   estate.
2. **Normalisation** — records become crypto artifacts, components and
   relationships in the BOM projection engine, with the evidence id behind every
   field.
3. **Policy evaluation** — versioned rules (NIST, FIPS, NSA CNSA, PCI-DSS,
   ISO 27001, internal) produce findings. This is code, not a model, and it is
   reproducible from the stored evidence.
4. **The estate twin** — assets, relationships, crypto graph, evidence graph and
   history over one stored discovery run. Impact is computed by walking the
   stored graph; a radius is reported with what it could not read.
5. **Simulation** — scenarios edit evidence facts on a copy (or cascade a
   failure along established edges) and report what they could and could not
   reach.

There is no stage where an invented fact becomes an observation. Where the
product cannot establish something, the honest answer is the output.

## What this build does not do

Five capabilities are modelled or partially implemented, and are not presented
as operational. Each statement is machine-read from
`shared_models/capability_boundaries.py`, published by
`GET /api/v1/estate/evidence/discovery/maturity`, and rendered in the console
under **Collector depth → Maturity**:

| Capability | The limit |
|---|---|
| Windows collector | A candidate implementation: no universal Windows admission, no complete collector. |
| Hardware discovery | Synthetic and metadata paths only. Not complete hardware discovery. |
| HSM | A metadata model — vendor, model, firmware, algorithm capability, key metadata, certificate relationships. Not proof of HSM cryptographic operations. |
| Runtime crypto | Process, binary, library and service metadata. Not evidence that a process invoked AES-256-GCM. |
| Simulation | A real PQC-migration foundation and ten scenario-specific models, nine of them partial. Not a generic enterprise simulation engine: the custom expression has no arithmetic, joins or timelines, and the trust walk cannot see trust stores, cross-signing or revocation. |

The full list, with what *is* real behind each row and the route that lets you
check it, is in [docs/CAPABILITY-MATURITY.md](docs/CAPABILITY-MATURITY.md#capability-boundaries--five-things-this-build-does-not-do).
`GET /api/v1/estate/evidence/twin/simulation-scenarios` states, per scenario,
whether this build computes it and what it cannot see.

## Where the rest of it is

| Question | Answer |
|---|---|
| What does each console surface do, and where does it stop? | [docs/CAPABILITY-MATURITY.md](docs/CAPABILITY-MATURITY.md) |
| What did we decide not to do, and why? | `shared_models/platform_scope.py`, [docs/architecture/platform-boundaries.md](docs/architecture/platform-boundaries.md) |
| How is this operated — deploy, back up, restore, monitor? | [docs/admin-guide/](docs/admin-guide/), [k8s/README.md](k8s/README.md) |
| What is proven, and what is still open? | [docs/PLATFORM-STATUS.md](docs/PLATFORM-STATUS.md), [docs/readiness-evidence/](docs/readiness-evidence/) |
| How does it compare with the tools a bank already runs? | [docs/architecture/real-world-comparison.md](docs/architecture/real-world-comparison.md) |
