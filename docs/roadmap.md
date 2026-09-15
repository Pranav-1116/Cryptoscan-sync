# CryptoScan Roadmap — status against the master update list

_Tracked against the r30 "what more to update" list. Kept honest: every item
is either ✅ shipped (with pointer), 🔨 improved this round, ⛔ **blocked on
real infrastructure** (not codeable in this repo alone), or 📋 planned. When
an item was believed missing but already exists, the pointer says so._

Legend: ✅ exists · 🔨 improved r30 · ⛔ infra-blocked · 📋 planned · 🟨 partial

## A. Known gaps

| # | Gap | Status |
|---|-----|--------|
| 1 | Container scan E2E unverified | 🟨 Scanner + registry handlers + tests shipped; live-image E2E ⛔ needs a Docker daemon (CI job) |
| 2 | JWS vs HMAC signing | 🔨 r30: export manifests now carry RFC 7515 compact JWS (`signature_jws`) over the same canonical bytes as the content hash; legacy HMAC hex retained for old verifiers. CBOM docs already had RS256/ES256/HS256 (`cbom.signing.jws_signer`); Live CBOM JWS since r29 |
| 3 | Neo4j not live-burned | 🟨 graph_engine complete with fallback store; live Neo4j burn ⛔ needs a Neo4j instance (compose has the service; CI/ops task) |
| 4 | Cloud scanners never run live | ⛔ needs real AWS/Azure/GCP credentials (AWS live scanner shipped, honest BLOCKED without creds) |
| 5 | TLS live probing gated off | ✅ `CRYPTOSCAN_TLS_LIVE` flag implemented (`network_scanner.core.scanner`), real handshake tests in the suite |
| 6 | Graph visualization missing | ✅ interactive dependency graph (`frontend/src/pages/DependencyGraph.tsx`, 870 lines: click-select, expand, zoom, overlays) |
| 7 | Business context not seeded | 🟨 models + repos + `business.py`/`business_context.py` routers shipped; seeding is **user data via API** — the product never auto-seeds fake context (honesty rule) |
| 8 | Prioritization dashboard thin | 🔨 r30: `GET /api/v1/priority` + `/priorities` page — deterministic rank (revenue×severity×agility), effort bars, replacement table, BFS blast radius, honest coverage footer |
| 9 | Stakeholder alerting absent | 🟨 notifications router routes per-tenant event classes to inApp/email/webhook/siem; template emails + exec-sponsor digests 📋 |
| 10 | Config drift not first-class | ✅ `drift.core.config_detector` (CONFIG_ADDED/REMOVED/CHANGED, weakness-ranked severity) |
| 11 | Tree-sitter/Roslyn depth | 🟨 tree-sitter parsers present (`scanner/parsers`, java_ast); Roslyn/C# 📋 |
| 12 | Registry webhook live | 🟨 ACR/DockerHub/ECR/Harbor handlers shipped; live registry round-trip ⛔ needs a registry |
| 13 | Real GitHub round-trip | 🟨 webhook handler shipped + secret-verified; end-to-end needs a repo webhook config (ops task) |
| 14 | Email delivery proof | ⛔ needs an SMTP relay; channel plumbing + preference routing shipped |
| 15 | Perf benchmark 10K files | 📋 run + publish numbers (scanner benchmark harness exists under `services/control_plane`) |

## B. Missing features (by family)

| Family | Status |
|--------|--------|
| B1 Key lifecycle | 🟨 certificate/key inventory + expiry SLAs shipped; rotation-policy monitoring, escrow inventory, destruction verification, ceremony audit 📋 |
| B2 HSM integration | 🟨 hardware scanner (TPM/HSM discovery), vendor firmware intel (Thales/Entrust/Utimaco/payShield, PQC firmware status), KMS/HSM policy-change attack rule (r29); partition mapping + cloud-HSM connectors 📋 |
| B3 CA management | 🟨 certificate inventory, CT monitoring (`crypto-assurance/ct-monitor`), unexpected-CA attack rule (r29); internal-CA hierarchy mapping 📋 |
| B4 Code & artifact signing | 🟨 JWS-signed exports/CBOMs (platform's own artifacts); binary/container/firmware signature verification of scanned estates 📋 |
| B5 RNG monitoring | 🟨 shannon-entropy weak_entropy rule (r29), TPM presence checks; entropy-source inventory 📋 |
| B6 Protocol state machines | 🟨 TLS suite + SSH analysis + Diameter/GTP-C/SIP parsers (r29); Kerberos/DNSSEC/IPsec-IKE/Kerberos/RADIUS deep probes 📋 |
| B7 Data classification | 🟨 business-process data_classifications + regulatory mapping (banking pack); data-at-rest/in-transit classification 📋 |
| B8 Blockchain/DLT | 📋 not started |
| B9 Embedded/IoT/firmware | 🟨 OT scanner (passive ICS), firmware vendor intel; firmware image static analysis 📋 |
| B10 Zero trust | 🟨 service-mesh/container TLS visibility; mTLS posture rollups 📋 |
| B11 Threat modeling | 🟨 13-rule detection + evidence chain; STRIDE/ATT&CK mapping 📋 |
| B12 Incident response | 🟨 attack-detections + alerts topics, signed evidence packs; playbooks/72h-notification automation 📋 |
| B13 Resilience testing | 📋 chaos/probe harness (key-loss simulation, boundary validation) |

## C. Operational maturity

| Item | Status |
|------|--------|
| Multi-tenancy | ✅ orgs, isolation (DB + header + API-key binding), per-tenant RBAC/keys/CBOM/policies, metering+quotas (r26–r28); PSP billing ⛔/📋 |
| Observability | 🟨 structured logging, SSE stats, bus lag metrics; OTel tracing + SLO/error-budget tracking 📋 |
| Backup & DR | 🟨 compose volumes + snapshot dirs; verified PITR + cross-region drills ⛔/📋 |
| Capacity planning | 🟨 load-test script (`scripts/load_test.py`); forecasting/autoscaling 📋 |
| Platform self-security | 🟨 JWS-signed artifacts, secret-required prod compose, SSRF/validation guards, security docs; SBOM-for-self, pen-test, VDP 📋 |

## D. Compliance depth

- Shipped: banking pack (RBI/PCI DSS 4.0/ECB/UAE), NIST IR 8547 deadlines,
  FIPS 140-3 status tracking (vendor intel), audit hash chain (r29),
  WORM-ish append-only metering.
- 📋 GDPR Art.32/CCPA/PIPL packs, 3GPP TS 33.501/33.210 profile packs,
  FedRAMP/CMMC/IRAP/BSI crosswalks, regulatory change feed, attestation
  workflow, 7-year retention, external-auditor API.

## E. Integrations

- Shipped: webhook channel (SIEM-ready), GitHub webhook ingest, registry
  handlers (ACR/DockerHub/ECR/Harbor), OpenAPI spec + regenerated reference,
  connector SDK + marketplace, CLI scanner.
- 📋 SIEM connectors (Splunk/Sentinel/QRadar/Chronicle), GRC (ServiceNow/
  Archer/Vanta/Drata), ticketing (JIRA/ITSM), CI/CD adapters, cloud KMS/HSM
  connectors, CA integrations (ACME/Venafi), SDKs (Python/Go/JS), Terraform
  provider, K8s operator/Helm.

## F/G/H/I/J. DX, testing, docs, business, geo

- DX: quickstart + CLI + i18n (en/ar, RTL) shipped; IDE extensions, bots,
  mobile 📋.
- Testing: 202+ backend test files, deterministic suites, probe tests,
  contract-pinned engines; property-based/fuzz/mutation 📋.
- Docs: architecture docs + API reference + runbooks shipped; C4 diagrams,
  video walkthroughs, glossary 📋.
- Business: plans/quotas/metering shipped (FREE/PRO/ENTERPRISE); Stripe,
  marketplace listings, partner program 📋/⛔.
- Geo: ar/en with RTL shipped; data residency + sovereign deploys = the
  multi-region item (⛔ infra), regional compliance packs 📋.

## r30 delta (this round)

- `GET /api/v1/priority` + `/priorities` page (A8) — deterministic ranked
  remediation queue with revenue/agility/graph context and honest coverage.
- RFC 7515 JWS on export manifests (A2) — canonical signature, legacy HMAC
  retained.
- This roadmap + refreshed completeness tracker.
