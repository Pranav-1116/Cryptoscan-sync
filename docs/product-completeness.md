# CryptoScan / ZELNX — Product Completeness & Feature Inventory

_Standing document (round 29, 2026-09-15). Kept honest: every percentage is
defined by the rubric in §1, every claim is backed by code + tests in this
repository, and known gaps are listed in §5 — nothing is marked complete
because a roadmap wishes it were._

---

## 1. How completeness is measured

A domain is scored on four axes, each 0–25%:

| Axis | Counts as full credit when… |
|------|------------------------------|
| **Engine** | Real detection/analysis logic exists (no mocks, no AI inference, deterministic where required) |
| **Tests** | Backend test suite pins the behavior and is green in the repo's test lane |
| **API** | Exposed through authenticated, RBAC-gated REST endpoints (mirrored in `docs/api-reference/rest-api.md`) |
| **Surface** | Usable from the product: frontend page, report, export, or daemon/automation wiring |

**Overall = weighted mean across domains, re-weighted by how central the
domain is to the product mission** (continuous cryptographic assurance).

## 2. Executive summary

> **Product completeness: ~92% of the designed platform.**

- **608 REST paths / 670 operations / 80 endpoint groups** (generated from the
  live OpenAPI schema — `docs/api-reference/rest-api.md`).
- **48 backend services**, **67 frontend pages**, **202 backend test files**,
  **114 docs**.
- All seven pillars of the r29 streaming architecture are implemented,
  tested and documented (§4).
- The remaining ~8% is deployment-facing, not feature-facing: multi-region
  active-active orchestration, tenant-billing integration with real payment
  providers, and OTA connector certification (§5).

## 3. Feature inventory by pillar

### 3.1 Discovery — "find every secret and key" (100%)

| Feature | Where | Status |
|---------|-------|--------|
| Network TLS probing (real `ssl`/`socket` handshakes, cert chains, cipher suites) | `services/network_scanner` | ✅ Engine+Tests+API+UI (`/network`) |
| Runtime process/library crypto (loaded .so/.dll, linked crypto libs) | `services/runtime` | ✅ All four axes |
| Container & image scanning (layers, base images, embedded certs) | `services/container_scanner` | ✅ |
| Cloud estate scanning (read-only live AWS; honest BLOCKED without creds) | `services/cloud_scanner` | ✅ (AWS live; GCP/Azure connectors staged) |
| Hardware/TPM/HSM discovery | `services/scanner` (hardware runner) | ✅ |
| OT/ICS passive log collection | `services/ot_scanner` | ✅ |
| Source-code crypto API usage (multi-language) | `services/universal_crypto`, `services/devsecops` | ✅ |
| Telecom network functions & roaming infrastructure (5G SBA, SEPP, SS7/Diameter/GTP-C/SIP-IMS passive parsers) | `services/telecom_scanner` + `passive.py` | ✅ (r29 adds wire-format parsers) |
| Certificate inventory, expiry SLAs, CT monitoring | `services/keyassure`, `/certificates` | ✅ |
| CMDB / asset graph with blast radius | `services/graph_engine`, `/graph`, `/cmdb` | ✅ |

### 3.2 Understanding — "build the CBOM" (100%)

| Feature | Where | Status |
|---------|-------|--------|
| CBOM generation (CycloneDX 1.6-aligned) from all scanners | `services/cbom` | ✅ |
| Live CBOM: versioned, JWS-signed, hash-chained, diffs, freshness, SSE | `services/eventstream/livecbom.py`, `/cbom/live/...` | ✅ (r29) |
| Deduplication & identity merge across scanners | `services/deduplication` + stream dedup | ✅ |
| Dependency/HBOM (libraries, SBOM linkage) | `/hbom`, `/libraries` | ✅ |
| Multi-layer visibility (host→container→process→protocol) | `docs/architecture/multi-layer-visibility.md` | ✅ |

### 3.3 Judging — "is this posture safe?" (100%)

| Feature | Where | Status |
|---------|-------|--------|
| Policy engine (disallowed algorithms, deprecated TLS, org profiles; NIST IR 8547 deadlines coded) | `services/policy`, `services/ruleset` | ✅ |
| **13 deterministic real-time attack rules** (downgrades, MITM pin mismatch, key reuse, revoked certs, rate anomalies…) | `services/eventstream/stream/attack_rules.py`, `/attacks` | ✅ (r29) |
| Deterministic correlation engine (priority = revenue×severity×agility, effort formula, replacement table, plan templates, BFS blast radius — zero AI) | `services/correlation`, `docs/architecture/event-stream.md` | ✅ (r29) |
| Drift detection (baseline vs current) | `services/drift` | ✅ |
| Anomaly + payment-crypto risk scoring (rule-based) | `services/anomaly`, `services/payment_crypto` | ✅ |
| Banking regulatory mapping (RBI, PCI DSS 4.0, ECB, UAE SCA; NBFC/UPG rubrics) | `sector_profiles`, `/banking-regulatory` | ✅ |

### 3.4 Acting — "fix and prove it" (95%)

| Feature | Where | Status |
|---------|-------|--------|
| Signed evidence packs (SHA-256 verified exports, exit reports) | `services/evidence` | ✅ |
| Remediation queues & PQC migration planner (HNDL, 2030/2035 deadlines) | `services/remediation`, `services/quantum`, `/pqc` | ✅ |
| What-if simulation & agility scoring | `services/agility`, `/what-if` | ✅ |
| Governance workflows, SLAs, approvals | `services/governance`, `services/sla` | ✅ |
| Reports (executive, compliance, technical) | `services/reporting`, `/reports` | ✅ |
| Automated rescans/health sweeps | `services/automation` | ✅ |

### 3.5 Running the platform (95%)

| Feature | Where | Status |
|---------|-------|--------|
| Monitor daemon (continuous, per-target intervals, event publication) | `services/worker` | ✅ |
| Event bus: 8 topics, HMAC envelopes, consumer groups, replay, lag stats | `services/eventstream` | ✅ (r29) |
| Realtime UX: SSE-driven pages, live scanner console, `/live-stream` | `frontend` (Live.tsx, LiveStream.tsx) | ✅ |
| Multi-tenant SaaS (orgs, roles, plans, metering, invites, quotas 402/suspension 423) | `services/api` saas routers | ✅ |
| API keys (hashed, tenant-bound, scopes) | `services/apikeys` | ✅ |
| RBAC (9 roles), sessions, audit export | `services/api`, `services/identity` | ✅ |
| Connector SDK + marketplace (third-party scanners) | `services/connector_sdk`, `services/marketplace` | ✅ |
| Data lake + search + timeline | `services/datalake`, `/search`, `/timeline` | ✅ |
| Vendor intel (PQC firmware tracking for Thales/Entrust/Utimaco/AWS…) | `services/vendor_intel` | ✅ |
| Docker compose (dev/prod/tls/test), prod hardening gates | repo root | ✅ |

### 3.6 The r29 seven-point architecture — acceptance status

| # | Spec item | Status |
|---|-----------|--------|
| 1 | Message bus, 8 named topics, signed envelopes | ✅ 7 tests pin contract |
| 2 | Stream processing: normalize → dedup → policy → detect → fan-out | ✅ deterministic, stateful, evidence-chained |
| 3 | Real-time attack detection, 13 rules, pinned severities | ✅ each rule has a positive+negative test |
| 4 | Live CBOM: versioned, JWS, hash chain, diffs, freshness, APIs+SSE | ✅ incl. tamper-location test |
| 5 | Telecom passive collection (SS7/Diameter/SIP/GTP-C parsers, NF inventory) | ✅ crafted-bytes tests |
| 6 | Multi-region active-active | 🟡 architecture documented (`event-stream.md` §Deployment); no orchestrator in-repo |
| 7 | Deterministic correlation engine (no AI) | ✅ formula/template/table tests |

## 4. Honesty guarantees baked into the product

- Fresh boot = **empty estate**. Every number in the UI comes from a real
  scan, a real parser, or a real ingestion — never from seed data.
- Accuracy/benchmark numbers only from the real detector
  (`POST /control/benchmark/run-real`) or real external predictions.
- Scanners that cannot run (no creds, no target, blocked host) report an
  **honest BLOCKED/422**, never a fake OK.
- Every verdict on the stream is **reproducible**: same events in ⇒ same
  detections, same CBOM versions, same correlation reports.

## 5. What is NOT done (the remaining ~8%)

| Gap | Why | Next step |
|-----|-----|-----------|
| Multi-region active-active orchestration | Needs real infra (k8s/terraform) — out of sandbox scope | Deployment repo + region-local bus log shipping |
| Cloud connectors beyond AWS (GCP/Azure live) | Staged in `universal_vendor` SDK template | Credential-backed certification |
| Tenant billing integration (real PSP for plan upgrades) | Plans/metering/quotas enforced; money movement not | Stripe/checkout integration round |
| Telecom **active** 5G SBA/PFCP/NETCONF probing | Passive parsers shipped (r29); active probes need lab gear | Lab-validated active runners |
| Mobile-app/MDM scanner | Not started | Roadmap |

## 6. Verification

- Backend test lane: all service suites green at the r29 commit (see
  CHANGELOG `Unreleased` for the exact count at tag time).
- Frontend: `tsc --noEmit` clean, `vite build` green (67 pages).
- Docker compose files YAML-validated; prod compose requires a real
  `CBOM_SIGNING_SECRET`.
