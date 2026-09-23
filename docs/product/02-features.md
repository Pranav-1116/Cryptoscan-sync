# 2. Features, end to end

_Every capability, grouped by the stage of the loop it belongs to. Each row
names the console page, the API group and the service that implements it,
and its maturity tier (**GA** · **beta** · **preview**) from
`shared_models/capability_maturity.py`. Nothing is listed that a reader
cannot exercise on the current build._

![The loop](img/01-product-overview.png)

---

## Stage 1 — Onboard and scope

_"What am I responsible for?" Everything downstream is filtered by this._

| Feature | What it does | Page · API · service | Tier |
|---|---|---|---|
| First-run onboarding | create organisation, environments, scope, connectors; test credentials; launch first discovery scan | `/onboarding` · `onboarding` · `api` | beta |
| Platform scope self-description | the product states what it does and what it refuses to do, from one source of truth | `/scope` · `platform/scope` · `shared_models/platform_scope.py` | GA |
| Sector profiles | banking / telecom / energy / government baselines select the rule packs used later | `/sectors` · `sectors` · `sector_profiles` | beta |
| Organisation and business context | business processes, owners, revenue and criticality per system — feeds impact scoring | `/organization` · `business` · `business_context` | beta |
| Repository configuration | which repos, branches, schedules; GitHub App / webhook wiring | Integrations · `repos`, `webhooks` · `api` | GA |
| Network scan targets and scan policy | who may scan which CIDRs / hosts; active vs passive | Network · `network_scans` · `network_scanner` | GA |
| Multi-tenancy core | tenant model, invitations, tenant-scoped queries (single-tenant deployment is the default) | `/tenancy` · `tenants` · `api/security/tenancy.py` | beta |

## Stage 2 — Collect

_Eleven kinds of input into one inventory. Every collector is read-only and
deterministic; an unreachable target is reported as unreachable._

| Collector | What it finds | Page · API · service | Tier |
|---|---|---|---|
| **Source code** | hard-coded keys and PEM material, weak primitives (MD5, SHA-1, DES, RC4, ECB), key sizes, IV/nonce reuse, insecure random, TLS settings, secrets misuse. Python, Java, C#, JS/TS, Go, Rust first-class (AST); Kotlin, PHP, Ruby, config/IaC | `/scanners` · `scans`, `jobs`, `trigger` · `scanner`, `worker` | GA |
| **SBOM / dependencies** | manifests + 10 lockfile formats → resolved and transitive components, licences, crypto libraries; NTIA completeness score | `/dev-sec-ops` · `devsecops/sbom/*` · `devsecops` | GA |
| **Binaries / firmware** | real parsing: ELF (deps, RPATH, build-id, symbols, Go build-info + module graph, hardening flags, crypto constant tables), PE (imports, resources, Authenticode presence, CLR), Mach-O, `ar`/`.deb`/RPM/zip/WASM/Java class; firmware container chains with offsets and entropy; containers followed inside a stated budget | `/dev-sec-ops` → Binaries · `devsecops/binary/*` · `devsecops/binary_scan.py` | GA |
| **Network / TLS** | live handshakes: protocol and cipher posture, certificate chains, STARTTLS, weak parameters, expiry | `/network`, `/protocols` · `network_scans` · `network_scanner` | GA |
| **Certificates** | inventory and expiry from network and source scans; full lifecycle (CSR → issue → renew → revoke) | `/certificates` · `certificates` · `api` | GA |
| **Cloud** | AWS KMS / ACM (live), Azure Key Vault and GCP Cloud KMS key metadata; read-only roles | `/cloud` · `cloud`, `inventory/cloud` · `cloud_scanner` | GA (needs credentials to show data) |
| **Containers / IaC** | image and filesystem package inventory, crypto binaries, Dockerfile/IaC rules; registry push webhooks (ACR/ECR/GCR/Harbor/Docker Hub) | `/scanners` · `container_scans`, `webhooks` · `container_scanner` | GA |
| **OT / ICS** | passive — zero packets sent; PLC/RTU/SCADA crypto posture; safety-aware maintenance windows | `/scanners` · `ot` · `ot_scanner`, `ot_safety` | GA (passive core) |
| **Telecom** | 5GC / EPC / IMS / roaming verdicts, SEPP PQC readiness, per-carrier packs, closed-network ingest | `/telecom` · `telecom` · `telecom_scanner` | beta |
| **Hardware** | HSM / TPM / firmware registry, quantum-resistant flags with firmware-cited provenance; 68 vendor plugins across 16 categories | `/hardware`, `/catalog` · `hardware` · `universal_crypto`, `universal_vendor` | beta |
| **Payment** | HSM key inventory, TR-39-style ceremony provenance, dual custody, PCI attributes, ISO 20022 | Banking · `payment-crypto` · `payment_crypto` | GA |
| **Runtime hosts** | agent-reported findings from live hosts (eBPF / LD_PRELOAD adapters) | `/runtime`, `/live-environment` · `runtime` · `runtime` | beta |
| **Vendors** | vendor questionnaires, vendor CBOMs and documents → 0–100 vendor crypto risk | `/vendor` · `vendors` · `vendor_intel` | GA |
| **CMDB import** | ServiceNow-style CMDB resolution into systems | `/cmdb` · `cmdb` · `inventory` | beta |

## Stage 3 — Evidence

_Every finding becomes a record whose integrity can be checked later by
someone who does not trust the server._

| Feature | What it does | Page · API · service | Tier |
|---|---|---|---|
| Evidence chain | `content_hash → chain_hash → manifest_hash` (SHA-256) per scan; chain includes the previous record | `/evidence` · `scans/{id}/verify` · `evidence` | GA |
| Verification on demand | recomputes every hash; returns `chain_intact`, `PASS/FAIL`, first broken index; logged to `verification_log` | `/evidence` · `scans/{id}/verify` | GA |
| Hash-chained audit log | every auth/admin action chained; incremental verify; examiner-ready export ZIP | Audit Log · `audit-export/pack` · `api` | GA |
| Artifact provenance | stored bytes + sha256 + HMAC manifest for every SBOM/binary artifact; `/verify` detects byte flips and manifest edits | DevSecOps · `devsecops/sbom/{id}/verify` | GA |
| WORM retention gate | append-only stores refuse truncation or deletion | — · `compliance` | GA |

## Stage 4 — Inventory and BOMs

_One asset model; a key seen by two collectors is one asset with two evidence sources._

| Feature | What it does | Page · API · service | Tier |
|---|---|---|---|
| Unified asset inventory | System · CryptoAsset · Certificate · HardwareAsset · Vendor · dependencies; activity feed; unified risk | `/assets`, `/cmdb` · `assets`, `systems` · `database`, `inventory` | GA |
| Crypto inventory by primitive | algorithms, key sizes, libraries, protocols — where each is used | `/crypto-assets`, `/libraries`, `/protocols` · `crypto`, `algorithms` | GA / beta |
| Normalisation | IANA / NIST / CBOM vocabulary for names and sizes; 114 normalisation tests | — · `normalization` | GA |
| Deduplication and correlation | one asset, N occurrences; cross-scanner identity resolution | — · `deduplication`, `correlation` | GA / preview |
| **CBOM** | CycloneDX 1.5 cryptographic BOM; versioned, fingerprinted, signed | `/cbom` · `cbom/*` · `cbom` | GA |
| **HBOM / VBOM** | hardware and vendor views over the same Technology BOM | `/hbom`, `/vendor` · `technology-bom` | beta / GA |
| **SBOM** | per-artifact software BOM with licence, VEX and gate | `/dev-sec-ops` · `devsecops/sbom/*` | GA |
| Technology BOM materialisation | `materialize_technology_bom()` → one state, four views; unchanged fingerprint → no new version; per-layer diff | `/live-asset-intelligence` · `technology-bom/*` · `cbom/technology_bom.py` | GA |
| Dependency graph and blast radius | component/system relationships; interactive graph; Neo4j when configured, in-database otherwise | `/graph`, `/dependency-graph` · `graph` · `graph_engine` | beta |
| Library fingerprint database | fingerprints for crypto libraries and versions (ADR-007) | `/libraries` · `fingerprints` · `database` | GA |

## Stage 5 — Assess

_Inventory becomes posture. Every verdict is a rule or a formula._

| Feature | What it does | Page · API · service | Tier |
|---|---|---|---|
| **Policy engine** | YAML rule packs — baseline, PCI-DSS, NIST SP 800-131A, CNSA 2.0, FIPS, HIPAA, UAE; scopes; deterministic; the only source of pass/fail | `/security-policy`, `/findings` · `policies`, `findings` · `policy`, `ruleset` | GA |
| Findings | policy-evaluated findings with evidence links, severity, rule, location, remediation hint; CSV export | `/findings` · `findings` | GA |
| **Drift** | approved baseline vs observed; added / removed / changed, including config drift with weakness-ranked severity; CI drift gate | `/drift`, `/crypto-changes` · `drift`, `baselines` · `drift` | GA / beta |
| **PQC readiness** | NIST IR 8547-aligned migration buckets; harvest-now-decrypt-later exposure; per-asset quantum classification (176 tests) | `/pqc`, `/pqc-map` · `quantum` · `quantum`, `shared_models` | GA / preview |
| **Crypto agility** | 6-factor agility score, migration readiness, what-if simulation of an algorithm swap | `/agility`, `/what-if` · `agility` · `agility` | beta / preview |
| Risk and prioritisation | deterministic rank (revenue × severity × agility), effort bars, replacement table, BFS blast radius | `/priorities`, `/risk` · `priority`, `risk` · `universal_platform` | beta |
| Migration tracking | scan → project → tasks → velocity | `/migration` · `migration` · `database` | beta |
| Crypto assurance | JWS-signed attestations over a snapshot (KeyAssure checks) | `/crypto-assurance` · `crypto-assurance` · `compliance`, `keyassure` | beta |
| Exceptions and waivers | time-boxed, approved, audited; never a silent suppression | `/governance` · `exceptions` · `governance` | beta |
| Security intelligence | cross-scanner correlation into incidents | `/security-intelligence` · `security` | preview |

## Stage 6 — Gate and act

_Stop bad change at the pipeline; act only with the required human authorisation._

| Feature | What it does | Page · API · service | Tier |
|---|---|---|---|
| **CI gate** | profiles, SARIF 2.1.0 for GitHub code scanning, PR-comment markdown, blocked-deployment stats; exit codes | Integrations · `ci`, `gate` · `scripts/ci_gate.py`, `api` | GA |
| **SBOM gate** | critical/high allowances, denied licences, unpinned limits, signature requirement; CLI `python -m devsecops.sbom_gate` exits 0/1/2/3 | DevSecOps · `devsecops/sbom/gate` · `devsecops/sbom_gate.py` | GA |
| Offline advisory matching and VEX | feed you supply; `exploitable` with fix, `not_affected` requires a justified operator statement (else 422) | DevSecOps · `devsecops/sbom/advisories`, `vex` | GA |
| Licence policy | SPDX family-aware matching, undeclared reported as undeclared, copyleft review trigger | DevSecOps · `devsecops/sbom/license` | GA |
| **Monitor daemon** | watch-list of repos, hosts, endpoints; scheduled scans; alert-once with cooldown | Alerts, Live Stream · `monitor/*` · `scripts/run_monitor.py`, `api/live_scan` | GA |
| Alerts and notifications | in-app, email, webhook, SIEM channels; per-tenant routing by event class | `/alerts`, `/notifications` · `alerts`, `notifications` | GA / beta |
| **Automation engine** | deterministic WHEN/IF/THEN plans, safety tiers, fail-closed approval gates; playbooks (certificate rotation, NF-down, crypto-team notify) | `/automation` · `automation/*` · `automation`, `control_plane` | beta |
| Remediation | deterministic suggestions and work orders — never a compliance determination | Findings · `remediation` · `remediation` | GA |
| SLA tracking | remediation deadlines by severity | — · `sla` | preview |
| Delivery integrations | ServiceNow incidents (idempotent `correlation_id`), Splunk HEC, Jira REST v3, Microsoft Sentinel; preview-the-payload endpoints | `/integrations` · `connectors` · `automation/connectors.py` | GA / beta |

## Stage 7 — Prove

_A regulator needs an artefact, not a dashboard._

| Feature | What it does | Page · API · service | Tier |
|---|---|---|---|
| **Signed exports** | json · csv · cyclonedx · cyclonedx-xml · spdx · xml · pdf; each with content hash, HMAC and RFC 7515 JWS; audit event per export | CBOM, Evidence · `technology-bom/export` · `cbom/export_service.py` | GA |
| Scheduled exports | cron-like schedules, idempotent run-due, run records | `/reports` · `technology-bom/schedules` | GA |
| **Compliance reports** | eight templates: PCI-DSS 4.0, DORA, NIST SP 800-131A r2, FIPS 140-3, SOC 2, ISO/IEC 27001:2022, NIST SP 800-53 r5, UAE PDPL; frameworks without a native pack say they are mapped | `/compliance` · `compliance` · `reporting`, `compliance` | GA |
| Evidence pack | hash-manifested export of scan evidence | `/evidence` · `evidence/pack` · `evidence` | GA |
| Audit pack · exit report · engagement archive | the three hash-sealed engagement deliverables; SC-1…4 scorecard | `/reports` · `audit-export`, `reports` · `reporting/exit_report.py` | GA |
| Regulatory packs | banking action plan (ECB/FCA-framed), SWIFT CSP evidence, NRA per-carrier packs, supervisor pack | `/banking-regulatory`, `/supervision` · `banking`, `telecom` | beta / preview |
| Executive and role dashboards | posture, risk, migration roadmap, cost of inaction; CISO / analyst / OT engineer workspaces | `/executive`, `/role-dashboard`, `/command-center` · `stats` | beta / GA |
| Localisation | English + Arabic RTL for regulatory submissions | all pages · `frontend/src/i18n` | GA |
| Own SBOM | the platform's own SBOM (`make sbom`) | — · `scripts/generate_own_sbom.py` | GA |

---

## Cross-cutting: operating the platform

| Feature | What it does | Where | Tier |
|---|---|---|---|
| Identity | local + TOTP MFA; OIDC token relay, authorization code, PKCE; SAML 2.0 SP with enveloped-signature verification; LDAP/AD group→role; SCIM 2.0 | `/identity` · `auth`, `sso`, `scim` | GA |
| RBAC | 9 roles (superadmin, ciso, security_analyst, developer, auditor, business_owner, scanner, readonly, supervisor); fail-closed `require_permission`; ABAC middleware | `/identity` · `api/security/rbac.py` | GA |
| API keys | scoped machine keys, rotation, IP allow-list | `/integrations` · `api-keys` | GA |
| Rate limiting and security headers | per-identity budget (600/min in production), CSP/HSTS/etc, request-id on every response | — · `api/middleware` | GA |
| Production guard | `ENVIRONMENT=production` refuses SQLite, demo secrets, weak webhook secret, `CORS=*`, plaintext admin password — tested both ways | — · `api/config/settings.py`, `scripts/check_prod_guard.py` | GA |
| Real-time | SSE `/api/v1/events/stream` with `Last-Event-ID` resume; WebSocket; Redis federation across nodes | `/live-stream` · `events`, `stream`, `ws` · `eventstream` | GA |
| Observability | Prometheus `/metrics`, `/health`, `/readyz` with drain semantics, structured logs, trace middleware, Grafana dashboard | `/system-health` · `observability` | GA |
| GraphQL | typed read API over the same repositories | — · `graphql` | beta |
| Backup, restore, PITR, DR | `db_backup.sh` with sha256 manifest and retention, restore and PITR drills with recorded results, region failover drills | `/resilience` · `scripts/db_*.sh`, `docs/runbooks/dr-recovery.md` | GA (scripts) / beta (page) |
| Air-gap mode | JWKS from file, feed import, no phone-home; air-gap install guide | admin guide | GA |
| Security posture of the platform itself | headers, rate limits, audit chain verification, pen-test findings tracker | `/security-center`, `/security` · `security`, `pentest` | GA / beta |
| Staging without Docker | embedded PostgreSQL + Redis + api/worker/monitor with production guards | `deploy/staging/staging-up.sh` | GA |
| Soak, burn-in, load | `scripts/soak.py` (7-day pipeline soak), `scripts/burn_in.py` (integrations), `scripts/load_test.py` | `docs/soak-evidence/` | GA (harness) |

## Not built, and said so

| Item | Status |
|---|---|
| Database TDE / mainframe (RACF, ICSF) collectors | not built — needs customer-environment adapters; mainframe *extract ingest* exists |
| Qualys / ServiceNow VR / Jira Server connectors | not built — same connector pattern, on demand |
| Multi-active HA control plane | partial — readiness drains and read-only mirrors designed; multi-active untested without real infrastructure |
| Managed multi-tenant SaaS operations | not claimed — tenant model ships; running it as a service is a product decision |
| ISO 27001 / SOC 2 attestation of this product | external — controls implemented and auditable; the audit is a company action |
| Independent penetration test, multi-site DR, 24/7 on-call | external |

Next: [3. Architecture](03-architecture.md)
