# CryptoScan

Production cryptographic inventory and compliance platform — **Full End-to-End Product**.

**Current Stats (2026-10-16, measured):** 51 services (~389k lines of Python), 103 API router modules, **834 API paths / 920 operations** (regenerated reference: `docs/api-reference/rest-api.md`), 95 alembic migrations with schema-parity tests, 75 frontend page components with lazy-loaded routes, 783 backend test files (full local suite: 7,629 passed / 34 skipped) plus a 334-test Vitest frontend suite with clean `tsc --noEmit`. Deterministic policy — no AI in the decision path. Per-round build ledger: `audit_reports/00_ROUND_STATUS.md` (complete through round 80).

**Real-Time System:** WebSocket hub per topic /ws/{topic} plus global /ws/global; SSE /events/{topic} and /events/global; in-process event bus (publish/subscribe/recent) with a DB tailer that federates cross-process monitor events; live dashboard at /live/dashboard with history replay and auto-reconnect. Deterministic and auditable.

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
adds owner/rollback/freshness guards, not monitor protocol admission parity.
A01 remains partial; these changes do not certify production safety.


## Scope & honest boundaries

CryptoScan is an **end-to-end crypto & security-configuration platform** —
not a universal "scan everything" tool.

- ✅ **It does:** crypto inventory + security-configuration posture across
  source trees, network/TLS, containers/IaC, cloud accounts/tenants you
  have access to (AWS/Azure/GCP), OT/ICS (passive, zero packets), payment
  HSM/PCI, vendor/supply-chain, plus shared evidence-chain / CBOM / graph /
  PQC / remediation / compliance layers.
- ❌ **It does not:** application source-code hacking (general SAST), malware
  analysis, SIEM behavior analytics, core-banking transaction validation,
  or universal employee endpoint scanning.
- 🌐 **Cloud:** only the accounts/tenants your credentials can see — external
  surface only via public internet scanning of configured targets.
- 🔒 **Always:** read-only collection, evidence-chained observations, and
  **key *metadata* only — never key material or secret values** (enforced by
  tests; evidence packs use strict field whitelists).

Mainframe/legacy **crypto-oriented static parsers and metadata ingestion** do
exist, including COBOL/PL/I/RPG and selected configuration/key-inventory inputs.
That is not complete live mainframe discovery, a general core-banking audit or
production qualification; see [the bounded collection playbook](docs/bank-environment/29-system-by-system-collection-playbooks.md).

Not every surface is equally proven: **33 GA · 32 beta · 10 preview** console
surfaces (75 in total — the same 75 the page-component count above reports), labelled on every page and listed in
[docs/CAPABILITY-MATURITY.md](docs/CAPABILITY-MATURITY.md)
(`GET /api/v1/platform/capabilities`, source `shared_models/capability_maturity.py`).

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
| **CI** — active `ci.yml`: ruff + backend unit tests (core services), frontend typecheck + build (Vitest runs locally per change, not yet in CI), production config guard, PostgreSQL parity. Named scanner/migration/docker workflows are staged in `.github/workflows-pending/` (three zero-byte placeholders remain active-side) | `.github/workflows/`, `.github/workflows-pending/` |
| **Multi-user auth** — `users` / `user_sessions` / `audit_log` tables, roles (`admin`/`auditor`/`viewer`), persistent lockout, server-side token revocation, admin user management (`GET/POST/PATCH /api/v1/auth/users`), audit trail (`GET /api/v1/auth/audit`) | `services/api/api/security/`, `services/database/db/models/user.py`, migration `0019` |
| **RBAC** — scan trigger + baseline approve + drift ack/resolve require auditor/admin; reads need any role | `api/dependencies.py` (`require_roles`) |
| **Concurrent worker** — `MAX_CONCURRENT_JOBS` thread pool with backpressure and graceful drain | `services/worker/worker/core/pool.py` |
| **Burn-in harness** — proves external integrations: signed GitHub webhook round-trip, live TLS probe, SMTP delivery, Neo4j, cloud, container | `python scripts/burn_in.py --target all` |
| **Backup/restore** — SHA-256 manifests, online SQLite snapshot, Postgres dump, chain re-verification on the backup | `scripts/backup_evidence.py`, `scripts/restore_evidence.py`, [runbook](docs/admin-guide/backup-restore.md) |
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

# ⚙️ FOUNDATIONAL ARCHITECTURE PRINCIPLE
## "Deterministic Truth First, AI Assists Second"

```
╔══════════════════════════════════════════════════════════════════════════╗
║              CORE ARCHITECTURAL TRUTH PIPELINE                          ║
╠══════════════════════════════════════════════════════════════════════════╣
║                                                                          ║
║   STEP 1: DETERMINISTIC EVIDENCE COLLECTION                             ║
║   ┌──────────────────────────────────────────────────────────────────┐  ║
║   │  Raw Facts Only - No Interpretation                              │  ║
║   │  → Static code analysis finds: "RSA-2048 at line 247, file X"   │  ║
║   │  → Network scan finds: "TLS 1.1 on port 443, server Y"          │  ║
║   │  → Binary scan finds: "libssl 1.0.2 in container Z"             │  ║
║   │  → Certificate scan: "SHA-1 cert expires 2025-03-01"            │  ║
║   │  CONFIDENCE STAMP: 99.9% (machine-verified, not interpreted)     │  ║
║   └──────────────────────────────────────────────────────────────────┘  ║
║                           │                                              ║
║                           ▼                                              ║
║   STEP 2: NORMALIZATION ENGINE                                          ║
║   ┌──────────────────────────────────────────────────────────────────┐  ║
║   │  Convert all evidence to standard CBOM schema                    │  ║
║   │  → IETF RFC 9166 format                                          │  ║
║   │  → CycloneDX CBOM v1.5 format                                    │  ║
║   │  → SPDX 3.0 compatible                                           │  ║
║   │  → Common algorithm naming (IANA registry)                       │  ║
║   └──────────────────────────────────────────────────────────────────┘  ║
║                           │                                              ║
║                           ▼                                              ║
║   STEP 3: RULES / POLICY ENGINE (Deterministic)                        ║
║   ┌──────────────────────────────────────────────────────────────────┐  ║
║   │  Hard rules. Binary. No AI involvement.                          │  ║
║   │  → IF algorithm = MD5 AND use = integrity THEN status = FAIL     │  ║
║   │  → IF TLS_version < 1.2 THEN status = FAIL                       │  ║
║   │  → IF key_length(RSA) < 2048 THEN status = FAIL                  │  ║
║   │  → IF cert_expiry < 30_days THEN status = WARN                   │  ║
║   │  Rules sourced from: NIST/FIPS/NSA/PCI-DSS/HIPAA/ISO (versioned) │  ║
║   └──────────────────────────────────────────────────────────────────┘  ║
║                           │                                              ║
║                           ▼                                              ║
║   STEP 4: VERIFICATION LAYER                                            ║
║   ┌──────────────────────────────────────────────────────────────────┐  ║
║   │  Cross-validate evidence against policy output                   │  ║
║   │  → Evidence hash locked to finding                               │  ║
║   │  → Timestamp & source recorded immutably                         │  ║
║   │  → Human reviewer sign-off for HIGH/CRITICAL findings            │  ║
║   │  → Audit trail: who verified, when, what evidence used           │  ║
║   └──────────────────────────────────────────────────────────────────┘  ║
║                           │                                              ║
║                           ▼                                              ║
║   STEP 5: AI ASSISTANCE LAYER (Never Source of Truth)                  ║
║   ┌──────────────────────────────────────────────────────────────────┐  ║
║   │  AI ONLY does:                                                   │  ║
║   │  ✅ Correlate findings across systems                            │  ║
║   │  ✅ Explain findings in plain language                           │  ║
║   │  ✅ Prioritize remediation order                                 │  ║
║   │  ✅ Predict migration cost & timeline                            │  ║
║   │  ✅ Generate migration plans                                     │  ║
║   │  ✅ Recommend algorithm choices                                  │  ║
║   │                                                                  │  ║
║   │  AI NEVER does:                                                  │  ║
║   │  ❌ Declare compliance status                                    │  ║
║   │  ❌ Override deterministic policy findings                       │  ║
║   │  ❌ Approve or reject vendor crypto independently               │  ║
║   │  ❌ Generate evidence (only interprets it)                       │  ║
║   │                                                                  │  ║
║   │  Every AI output labeled: "AI RECOMMENDATION - NOT COMPLIANCE    │  ║
║   │  DETERMINATION. Verify with Policy Engine output."               │  ║
║   └──────────────────────────────────────────────────────────────────┘  ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
```

---
---

# 💡 IDEA #1: "CryptoScan Intelligence Platform"
## Universal Cryptographic Discovery, Inventory & Dependency Engine

---

### 🔴 PROBLEM

```
┌──────────────────────────────────────────────────────────────────────┐
│                      THE HIDDEN CRISIS                               │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  PROBLEM 1: Nobody knows where their crypto lives                   │
│  → 10,000+ apps, 500,000+ certs, millions of crypto calls/day       │
│  → No inventory = No migration path = No compliance proof           │
│                                                                      │
│  PROBLEM 2: Nobody knows what DEPENDS on what crypto                │
│  → RSA-2048 is deprecated. Great. Which of 10,000 apps use it?     │
│  → If you rotate that key - what breaks? Nobody knows.              │
│                                                                      │
│  PROBLEM 3: Crypto drifts silently in production                    │
│  → Developer deploys update → accidentally downgrades TLS to 1.1    │
│  → Nobody notices for 8 months → compliance violation               │
│                                                                      │
│  PROBLEM 4: No business context to cryptographic assets             │
│  → Security finds: "RSA-2048 weak in system XYZ-447"               │
│  → Business owner asks: "What is XYZ-447?"                          │
│  → Nobody can answer. Fix gets deprioritized. Risk remains.          │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

### ✅ SOLUTION

```
┌──────────────────────────────────────────────────────────────────────┐
│                  CryptoScan Intelligence Platform                    │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  MODULE 1A: MULTI-LAYER DISCOVERY ENGINE                            │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │                                                                │ │
│  │  SOURCE CODE SCANNING:                                        │ │
│  │  → AST-based parser (not regex) for 30+ languages             │ │
│  │  → Detects: algorithm, key size, mode, padding, IV handling   │ │
│  │  → Confidence: HIGH (deterministic static analysis)           │ │
│  │                                                                │ │
│  │  BINARY & CONTAINER SCANNING:                                 │ │
│  │  → Disassembly + crypto library fingerprinting               │ │
│  │  → Docker/OCI image layer scanning                            │ │
│  │  → SBOM + CBOM correlation (knows OpenSSL version in image)  │ │
│  │  → Confidence: HIGH                                           │ │
│  │                                                                │ │
│  │  RUNTIME NETWORK SCANNING:                                    │ │
│  │  → TLS handshake interception & analysis                      │ │
│  │  → Certificate chain validation & extraction                  │ │
│  │  → Protocol version & cipher suite enumeration               │ │
│  │  → Confidence: VERIFIED (live evidence)                       │ │
│  │                                                                │ │
│  │  API & PROTOCOL SCANNING:                                     │ │
│  │  → REST/GraphQL/gRPC/SOAP endpoint analysis                   │ │
│  │  → JWT algorithm validation (HS256 vs RS256 vs PS256)         │ │
│  │  → OAuth/OIDC crypto configuration                            │ │
│  │  → Confidence: HIGH                                           │ │
│  │                                                                │ │
│  │  CLOUD CONFIGURATION SCANNING:                                │ │
│  │  → AWS KMS / Azure Key Vault / GCP Cloud KMS                 │ │
│  │  → S3/Blob/GCS encryption settings                           │ │
│  │  → Database encryption at rest (RDS, CosmosDB, BigQuery)     │ │
│  │  → Confidence: HIGH (API-verified)                            │ │
│  │                                                                │ │
│  │  OT/ICS/IoT SCANNING:                                        │ │
│  │  → Passive network monitoring (no impact to OT systems)      │ │
│  │  → Protocol support: Modbus, DNP3, IEC 61850, PROFINET       │ │
│  │  → Firmware crypto extraction                                 │ │
│  │  → Confidence: MEDIUM (passive, mark accordingly)            │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                                                                      │
│  MODULE 1B: CRYPTO DEPENDENCY GRAPH (FLAGSHIP FEATURE)             │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │                                                                │ │
│  │  CRYPTOGRAPHIC REACHABILITY ANALYSIS ENGINE:                  │ │
│  │                                                                │ │
│  │  Traces every cryptographic asset through the entire system:  │ │
│  │  → Which services CALL this algorithm?                        │ │
│  │  → Which services DEPEND on the output of this crypto?       │ │
│  │  → Which USERS/CUSTOMERS are affected?                        │ │
│  │  → Which BUSINESS PROCESSES rely on this crypto?              │ │
│  │  → Which VENDORS touch this crypto chain?                     │ │
│  │                                                                │ │
│  │  EXAMPLE - CLICK "RSA-2048" → FULL IMPACT MAP:               │ │
│  │                                                                │ │
│  │           RSA-2048 [QUANTUM VULNERABLE]                       │ │
│  │           Key ID: KMS-2891-PROD                               │ │
│  │           Owner: Payments Team (Sarah Chen)                   │ │
│  │           Business Process: Customer Payments                  │ │
│  │                │                                               │ │
│  │    ┌───────────┼────────────┐                                 │ │
│  │    │           │            │                                 │ │
│  │    ▼           ▼            ▼                                 │ │
│  │ Payment API  Customer   Vendor API                            │ │
│  │ [CRITICAL]   Portal     [HIGH]                               │ │
│  │ Revenue:$2M  [HIGH]     Vendor: BankCo                       │ │
│  │ /day         Auth only  Revenue: $800K                       │ │
│  │    │           │            │                                 │ │
│  │    ▼           ▼            ▼                                 │ │
│  │ Payment    Customer    External                               │ │
│  │ Gateway    Auth Svc    Bank API                              │ │
│  │ [CRITICAL] [HIGH]      [CRITICAL]                            │ │
│  │    │                       │                                  │ │
│  │    ▼                       ▼                                  │ │
│  │ 3.2M Customers         Regulatory                            │ │
│  │ affected if broken     Reporting                             │ │
│  │                        Affected                              │ │
│  │                                                                │ │
│  │  IMPACT ANALYSIS PANEL (auto-generated):                      │ │
│  │  ┌──────────────────────────────────────────────────────────┐ │ │
│  │  │ If RSA-2048 (KMS-2891) is compromised or migrated:      │ │ │
│  │  │                                                          │ │ │
│  │  │ SYSTEMS DIRECTLY AFFECTED:        3 systems             │ │ │
│  │  │ SYSTEMS TRANSITIVELY AFFECTED:    14 systems            │ │ │
│  │  │ CUSTOMERS AT RISK:                3.2 million           │ │ │
│  │  │ REVENUE AT RISK/DAY:              $2.8 million          │ │ │
│  │  │ REGULATORY EXPOSURE:              PCI-DSS, DORA, SWIFT  │ │ │
│  │  │ VENDORS TO COORDINATE:            4 vendors             │ │ │
│  │  │ ESTIMATED MIGRATION EFFORT:       14 weeks              │ │ │
│  │  │ MIGRATION COMPLEXITY:             HIGH                  │ │ │
│  │  │ BUSINESS OWNER:                   Sarah Chen            │ │ │
│  │  │ EXECUTIVE SPONSOR:                CFO (payments risk)   │ │ │
│  │  └──────────────────────────────────────────────────────────┘ │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                                                                      │
│  MODULE 1C: BUSINESS OWNER MAPPING                                  │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │                                                                │ │
│  │  Every cryptographic asset tagged with:                       │ │
│  │                                                                │ │
│  │  CRYPTO ASSET:         RSA-2048 / KMS-2891-PROD               │ │
│  │  Technical Owner:      Platform Security Team                 │ │
│  │  Business Owner:       Sarah Chen (VP Payments)               │ │
│  │  Executive Sponsor:    CFO                                    │ │
│  │  Business Process:     Customer Payment Processing            │ │
│  │  Revenue Association:  $2M/day                                │ │
│  │  Criticality Tier:     TIER-1 (Mission Critical)              │ │
│  │  SLA:                  99.999% uptime required                │ │
│  │  Last Reviewed:        2024-01-15 (Sarah Chen, signed)        │ │
│  │                                                                │ │
│  │  BUSINESS OWNER PORTAL:                                       │ │
│  │  → Sarah receives monthly plain-English crypto health report  │ │
│  │  → Sarah approves/rejects migration plans for her systems     │ │
│  │  → Sarah's sign-off recorded as audit evidence                │ │
│  │  → Escalation path defined if Sarah unresponsive 30 days      │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                                                                      │
│  MODULE 1D: CRYPTO-DRIFT DETECTION (Production Assurance)          │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │                                                                │ │
│  │  CONTINUOUS MONITORING ENGINE:                                │ │
│  │                                                                │ │
│  │  BASELINE SNAPSHOT (Jan 1):                                   │ │
│  │  → Payment API: TLS 1.3, AES-256-GCM, ECDHE ✅               │ │
│  │                                                                │ │
│  │  DRIFT DETECTED (Jan 15, 03:22 AM):                          │ │
│  │  → Payment API: TLS 1.1, AES-128-CBC, RSA key exchange       │ │
│  │  → Triggered by: Deployment DEP-9921 by dev-user-john        │ │
│  │  → Delta: 3 crypto properties degraded                        │ │
│  │                                                                │ │
│  │  AUTOMATED RESPONSE:                                          │ │
│  │  🚨 Immediate alert: Security Team + Sarah Chen (Biz Owner)  │ │
│  │  🔒 Auto-block: Deployment flagged in CI/CD pipeline         │ │
│  │  📋 Evidence: Full before/after crypto snapshot captured      │ │
│  │  🎫 Ticket auto-created: JIRA-SEC-4421 assigned to john       │ │
│  │  ⏱️  SLA: 4 hours to remediate or escalate to CISO           │ │
│  │                                                                │ │
│  │  DRIFT TYPES MONITORED:                                       │ │
│  │  → Algorithm downgrade (TLS 1.3 → TLS 1.1)                   │ │
│  │  → Key length reduction (RSA-4096 → RSA-2048)                │ │
│  │  → Certificate near-expiry (< 30 days)                       │ │
│  │  → New unknown algorithm introduced                           │ │
│  │  → Crypto library version downgrade                           │ │
│  │  → Certificate authority change                               │ │
│  │  → New encryption-exempt endpoint appears                     │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                                                                      │
│  MODULE 1E: CRYPTO-AGILITY ASSESSMENT                               │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │                                                                │ │
│  │  CAN YOUR SYSTEM SWAP CRYPTO WITHOUT BREAKING?                │ │
│  │                                                                │ │
│  │  AGILITY SCORING per system:                                  │ │
│  │                                                                │ │
│  │  ┌──────────────────────────────────────────────────────────┐ │ │
│  │  │ SYSTEM: Payment API                                      │ │ │
│  │  │                                                          │ │ │
│  │  │ Algorithm Hardcoded?          YES ❌ (-30 pts)           │ │ │
│  │  │ Config-driven crypto?         NO  ❌ (-20 pts)           │ │ │
│  │  │ Crypto abstraction layer?     NO  ❌ (-20 pts)           │ │ │
│  │  │ Algorithm negotiation?        YES ✅ (+15 pts)           │ │ │
│  │  │ Key management centralized?   YES ✅ (+20 pts)           │ │ │
│  │  │ PQC library available?        NO  ❌ (-15 pts)           │ │ │
│  │  │                                                          │ │ │
│  │  │ AGILITY SCORE: 35/100 🔴 LOW                            │ │ │
│  │  │                                                          │ │ │
│  │  │ IMPLICATION: Migration requires code changes in 47      │ │ │
│  │  │ files before algorithm can be swapped. Estimated        │ │ │
│  │  │ pre-migration refactor: 8 weeks.                        │ │ │
│  │  └──────────────────────────────────────────────────────────┘ │ │
│  │                                                                │ │
│  │  AI RECOMMENDATION (labeled, not compliance determination):   │ │
│  │  "Based on agility score of 35/100, recommend prioritizing   │ │
│  │  Payment API for crypto abstraction layer implementation      │ │
│  │  before PQC migration. This will reduce future migration     │ │
│  │  cost by estimated 60%."                                      │ │
│  │  [AI RECOMMENDATION - NOT COMPLIANCE DETERMINATION]          │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

### 📊 CBOM Output Standard

```
┌──────────────────────────────────────────────────────────────────────┐
│                    CBOM ENTRY STRUCTURE                              │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  {                                                                   │
│    "cbom_version": "1.5",                                           │
│    "asset_id": "CBOM-RSA-2891-PROD",                               │
│    "algorithm": "RSA",                                              │
│    "key_size": 2048,                                                │
│    "mode": null,                                                    │
│    "purpose": "key-exchange",                                       │
│    "location": {                                                    │
│      "system": "payment-api-prod",                                 │
│      "file": "src/crypto/KeyManager.java:247",                     │
│      "library": "OpenJDK-11 / SunRSA provider"                    │
│    },                                                               │
│    "evidence": {                                                    │
│      "source": "static-analysis",                                  │
│      "tool": "CryptoScan-v2.1",                                    │
│      "timestamp": "2024-01-15T08:22:31Z",                         │
│      "evidence_hash": "sha256:a1b2c3...",                          │
│      "confidence": "HIGH",                                         │
│      "verified_by": "runtime-confirmation"                         │
│    },                                                               │
│    "ownership": {                                                   │
│      "technical_team": "Platform Security",                        │
│      "business_owner": "Sarah Chen",                               │
│      "executive_sponsor": "CFO",                                   │
│      "business_process": "Customer Payment Processing"             │
│    },                                                               │
│    "policy_evaluation": {                                           │
│      "status": "NON_COMPLIANT",                                    │
│      "rules_failed": ["NIST-PQC-2024", "NSA-CNSA2-2025"],        │
│      "determined_by": "policy-engine-v3.2",                       │
│      "NOT_determined_by": "AI"                                     │
│    },                                                               │
│    "quantum_vulnerability": {                                       │
│      "vulnerable": true,                                           │
│      "estimated_break_year": "2030",                               │
│      "harvest_now_decrypt_later_risk": "HIGH"                      │
│    },                                                               │
│    "dependency_graph_id": "DEP-GRAPH-2891",                       │
│    "agility_score": 35                                              │
│  }                                                                   │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

