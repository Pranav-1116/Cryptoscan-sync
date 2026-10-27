# 01_REPOSITORY_MAP.md
## ZELNX CryptoScan — Complete Repository Inventory

**Generated:** 2026-09-20  
**Scope:** Full repository discovery — no modifications, no assumptions  
**Method:** Direct source code inspection, directory traversal, configuration analysis

---

## 1. TOP-LEVEL DIRECTORY STRUCTURE

```
/home/array/Desktop/CryptoScan/
├── .docker/                    # Dockerfile definitions per service
├── .github/                    # GitHub workflows, PR template
├── .local-stack/               # LocalStack state
├── .ruff_cache/                # Ruff lint cache
├── .venv/                      # Python virtual environment
├── __pycache__/                # Python bytecode cache
├── _tmp/                       # Temporary files
├── config/                     # Configuration files (telecom_registry.json, etc.)
├── data/                       # Runtime data directory
├── deploy/                     # Deployment configurations (CI, marketplace, nginx, staging, systemd)
├── docs/                       # Documentation (admin-guide, api-reference, architecture, accuracy)
├── frontend/                   # React + TypeScript + Vite frontend
├── infra/                      # Infrastructure (monitoring, neo4j, nginx, postgres, redis)
├── integrations/               # External integrations (ArgoCD, GitHub, GitLab, Jenkins)
├── k8s/                        # Kubernetes manifests
├── scripts/                    # Operational scripts (backup, restore, scan_estate, burn_in, etc.)
├── services/                   # Backend microservices (51 services)
├── shared/                     # Shared libraries (config, logging, models)
├── tmp/                        # Temporary files
├── .dockerignore
├── .editorconfig
├── .env.example
├── .env.production.example
├── .env.test
├── .gitignore
├── .pre-commit-config.yaml
├── ANALYSIS-2026-08-26.md
├── ANALYSIS.md
├── AUDIT_REPORT.md
├── BACKEND-DATABASE-GAPS.md
├── CHANGELOG.md
├   FULL-REPO-STUDY.md
├── Makefile
├── PRODUCTION-READINESS.md
├── README.md
├── ROADMAP-TO-ENTERPRISE.md
├── RUN.md
├── VERSION
├── conftest.py
├── docker-compose.prod.yml
├── docker-compose.test.yml
├── docker-compose.tls.yml
├── docker-compose.yml
├── logic-1.md through logic-5.md
├── pytest.ini
├── requirements.lock.txt
├── requirements.txt
├── ruff.toml
└── run_backend.py
```

---

## 2. BACKEND SERVICES INVENTORY (51 services)

### Core Discovery & Scanning Services
| Service | Path | Purpose |
|---------|------|---------|
| **scanner** | `services/scanner/` | Multi-language static analysis (30+ languages), AST-based, cascade analysis |
| **network_scanner** | `services/network_scanner/` | Active TLS probing, certificate inventory |
| **container_scanner** | `services/container_scanner/` | Container image scanning, SBOM generation |
| **cloud_scanner** | `services/cloud_scanner/` | Cloud crypto configuration (AWS/Azure/GCP) |
| **ot_scanner** | `services/ot_scanner/` | OT/ICS passive network monitoring |

### Evidence & Integrity
| Service | Path | Purpose |
|---------|------|---------|
| **evidence** | `services/evidence/` | Tamper-evident evidence pipeline, chain hashing, canonical serialization |
| **verification** | (part of evidence) | Integrity verification log |

### CBOM/HBOM/Graph
| Service | Path | Purpose |
|---------|------|---------|
| **cbom** | `services/cbom/` | CycloneDX 1.5 CBOM generator, assessment, ingestion, diff, signing |
| **graph_engine** | `services/graph_engine/` | Dependency graph (Neo4j + in-memory), blast radius, vendor chains |
| **normalization** | `services/normalization/` | Algorithm normalization, rule-based matching, enrichers (NIST, IANA, CBOM) |

### Policy, Drift, Compliance
| Service | Path | Purpose |
|---------|------|---------|
| **policy** | `services/policy/` | YAML-driven policy engine, condition evaluator, rule validation |
| **drift** | `services/drift/` | Drift detection, daily digest, acknowledgment workflow |
| **compliance** | `services/compliance/` | Compliance reporting, requirement-by-requirement evidence |

### Crypto Intelligence
| Service | Path | Purpose |
|---------|------|---------|
| **universal_crypto** | `services/universal_crypto/` | §36 Deterministic crypto engine: AST, binary, runtime, protocol, cert, PQC, agility |
| **quantum** | `services/quantum/` | Quantum risk analysis (Shor/Grover), HNDL risk, migration deadlines |
| **agility** | `services/agility/` | Migration readiness, roadmap, simulation, system scoring |
| **remediation** | `services/remediation/` | Deterministic remediation rules (15 rules), backlog generation |

### Platform & Operations
| Service | Path | Purpose |
|---------|------|---------|
| **api** | `services/api/` | FastAPI application, 325 router modules (85 registered) |
| **database** | `services/database/` | SQLAlchemy 2.0, Alembic migrations (71), tenant isolation |
| **worker** | `services/worker/` | Job queue, concurrent scan execution, backpressure |
| **inventory** | `services/inventory/` | Asset inventory management |
| **control_plane** | `services/control_plane/` | Agent management, live scan orchestration |
| **eventstream** | `services/eventstream/` | Real-time event bus, SSE/WebSocket, DB tailer |
| **observability** | `services/observability/` | Prometheus metrics, W3C trace context, span storage |

### Specialized Domains
| Service | Path | Purpose |
|---------|------|---------|
| **banking** | `services/banking/` | Banking regulatory compliance |
| **payment_crypto** | `services/payment_crypto/` | HSM/PCI/TR-39 payment cryptography |
| **telecom** | `services/telecom/` | Telecom crypto, network registry |
| **sector_profiles** | `services/sector_profiles/` | Sector-specific risk profiles |
| **hardware** | `services/hardware/` | HSM/TPM/Hardware crypto inventory |
| **vendor_intel** | `services/vendor_intel/` | Vendor due diligence, supply chain |
| **identity** | `services/identity/` | User/role management, SCIM, SSO |
| **governance** | `services/governance/` | Access reviews, policy exceptions |
| **automation** | `services/automation/` | Workflow automation, connectors |
| **marketplace** | `services/marketplace/` | Extension marketplace |
| **datalake** | `services/datalake/` | Data lake integration |
| **anomaly** | `services/anomaly/` | Anomaly detection |
| **sla** | `services/sla/` | SLA tracking |
| **vaultlease** | `services/vaultlease/` | Credential leasing |
| **connector_sdk** | `services/connector_sdk/` | Custom connector framework |
| **universal_platform** | `services/universal_platform/` | Platform abstraction layer |
| **universal_vendor** | `services/universal_vendor/` | Vendor abstraction |
| **keyassure** | `services/keyassure/` | Key assurance/certification |
| **privacy** | `services/privacy/` | Privacy compliance |
| **ot_safety** | `services/ot_safety/` | OT safety systems |
| **runtime** | `services/runtime/` | Runtime crypto observation |
| **correlation** | `services/correlation/` | Cross-source correlation |
| **deduplication** | `services/deduplication/` | Finding deduplication |
| **ruleset** | `services/ruleset/` | Rule set management |
| **business_context** | `services/business_context/` | Business context enrichment |
| **apikeys** | `services/apikeys/` | API key management |
| **billing** | `services/billing/` | Billing/subscription |
| **devsecops** | `services/devsecops/` | DevSecOps pipeline gates |
| **reporting** | `services/reporting/` | Report generation (PDF/HTML/JSON) |
| **resilience** | `services/resilience/` | Resilience testing |
| **readiness** | `services/readiness/` | Migration readiness |
| **sla** | `services/sla/` | Service level agreements |

---

## 3. FRONTEND

**Location:** `frontend/`

**Technology Stack:**
- React 18.3.1 + TypeScript 5.6.3
- Vite 5.4.11 build system
- React Router 7.18.4 (lazy-loaded routes)
- Framer Motion 14.0.0 (animations)
- Phosphor Icons 2.1.10
- @formkit/auto-animate 0.10.0

**Pages (71 lazy-loaded routes):**
- CommandCenter (dashboard), Assets, CryptoAssets, Crypto, CryptoAssurance, CryptoChanges
- CBOM, HBOM, NBOM, Graph, DependencyGraph, DigitalTwin
- Network, Cloud, Container, Certificates, Hardware
- Findings, Evidence, Drift, Compliance, Risk, Security, SecurityCenter, SecurityIntelligence
- PQC, PQCMap, Agility, Migration, WhatIf
- Scanners, LiveScanners, LiveStream, LiveAssetIntelligence, LiveEnvironment
- DevSecOps, Automation, AutomationOps, ControlPlane, Governance
- BankingRegulatory, Telecom, PaymentCrypto, OT, OTSafety
- Vendor, VendorDueDiligence, Sectors, Catalog, Libraries
- Executive, Reports, Reports, Schedules, Alerts, Notifications
- Identity, Organization, Tenancy, Settings, Admin
- Onboarding, InviteAccept, Login, Register, ResetPassword
- Accuracy, Priorities, Scope, Enterprise, PlatformP2, Marketplace
- Resilience, Readiness, Supervision, SystemHealth, RoleDashboard
- SecurityPolicy, Nbom, Timeline, Trust

**Components:** Layout, UI primitives (Panel, Badge, Table, Kpi, Feed, Code, Tabs), icons, Live components, Enterprise modals

**Testing:** Vitest 2.1.9 + jsdom + @testing-library/react, offline-first test environment

---

## 4. DATABASE

**Location:** `services/database/`

**ORM:** SQLAlchemy 2.0.52 (declarative models)
**Migrations:** Alembic 1.19.1 (71 migration versions)
**Database:** PostgreSQL 15 (production), SQLite (test)
**Connection Pool:** SQLAlchemy engine with NullPool for migrations

**Models (52 tables):**
- Core: `Scan`, `EvidenceRecord`, `VerificationLog`, `ScanJob`, `RepoConfiguration`
- Crypto: `CryptoAsset`, `CryptoAssetEvidence`, `CryptoLibraryFingerprint`, `CryptoLive`
- Drift: `DriftEvent`, `Baseline`
- Graph: `GraphSnapshot`, `CascadeRun`, `CascadeExtensions`
- Systems: `System`, `SystemAsset`, `SystemDependency`, `SystemAgilityScore`, `SystemBusinessProcess`
- Certificates: `Certificate`, `CertificateUsage`
- Network: `NetworkInventory`, `NetworkScanRun`, `NetworkScanTarget`
- Cloud: `CloudAccount`
- Containers: `ContainerScan`, `Vulnerability`, `BinaryScan`
- OT: `OTDevice`, `OTMaintenance`
- Identity: `User`, `Tenant`, `APIKey`, `AccessReview`
- Enterprise: `Enterprise`, `ControlPlane`, `Automation`, `ReportSchedule`
- Payment: `PaymentCrypto`, `CredentialLease`
- Vendor: `Vendor`, `VendorProfile`, `VendorCrypto`, `VendorDueDiligence`
- Monitoring: `Monitor`, `HardwareLive`, `CertificateRenewal`, `TransactionVolume`, `CeremonyStatus`
- Technology BOM: `TechnologyBomSnapshot`, `TechnologyBomExport`
- Pentest: `PentestFinding`
- Migration: `MigrationProject`
- Audit: `DeliveryLog`, `AuditExport`
- App Settings: `AppSetting`

**Tenancy:** Row-level tenant isolation via `TenantScoped` mixin + `filtered_get()` helper

---

## 5. API

**Location:** `services/api/api/`

**Framework:** FastAPI 0.141.1 + Uvicorn 0.52.4
**Authentication:** Session-based + API keys, RBAC (admin/auditor/viewer)
**Rate Limiting:** Redis-backed (fail-closed in production)
**Middleware Stack:** 11 middlewares (CORS, Auth, TenantScope, RateLimit, Logging, RequestID, SecurityHeaders, Observability, ABAC, ControlEvent)

**Registered Routers (85):**
- Core: `auth`, `scans`, `findings`, `evidence`, `cbom`, `graph`, `drift`, `policy`
- Inventory: `assets`, `inventory`, `inventory_cloud`, `certificates`, `crypto`, `crypto_assurance`
- Network/Cloud: `network`, `network_scans`, `cloud`, `cloud_scans`, `container`, `container_scans`
- Systems: `systems`, `estate`, `business`, `business_context`, `scope`, `control_plane`
- Compliance: `compliance`, `governance`, `audit_export`, `risk`, `security`
- PQC/Agility: `quantum`, `agility`, `pqc`, `pqc_map`, `migration`, `remediation`, `readiness`
- Operations: `jobs`, `stats`, `monitor`, `live`, `live_scan`, `events`, `stream`, `ws`
- DevSecOps: `devsecops`, `automation`, `automation_ops`, `trigger`, `webhooks`, `repo_configs`
- Banking/Payment: `banking`, `payment_crypto`, `telecom`, `ot`, `ot_safety`
- Vendor: `vendor`, `vendor_due_diligence`, `marketplace`, `datalake`, `anomaly`, `connector`
- Identity: `identity`, `api_keys`, `sso`, `scim`, `onboarding`, `organization`, `tenancy`
- Reporting: `reports`, `report_schedules`, `export`, `export` (duplicate?)
- Hardware: `hardware`, `hsm_pkcs11`, `kmip`
- Platform: `platform`, `enterprise`, `sectors`, `sla`, `resilience`, `readiness`
- Billing: `billing`, `saas`, `priority`, `analytics`, `metrics`
- Specialized: `algorithms`, `baselines`, `exceptions`, `notifications`, `vulnerability`, `vulns`, `pentest`, `reachability`, `digital_twin`, `techbom`, `workload`, `ops`, `crypto_assurance`

---

## 6. WORKERS

**Location:** `services/worker/worker/`

**Core:** Thread pool with `MAX_CONCURRENT_JOBS` (default 4), graceful drain, backpressure
**Job Types:** Git scan, cloud scan, container scan, network scan, binary scan
**Queue:** Redis list (`cryptoscan:jobs:queue`) with Redis 8.1.0
**Persistence:** Job state in `scan_jobs` table with status transitions

---

## 7. SCANNER/DISCOVERY ENGINES

### Static Source Scanner (`services/scanner/scanner/`)
- **Core:** `Scanner` class orchestrating file discovery → language detection → per-file parsing
- **Parsers (25+):** Python, Java, C/C++, Go, Rust, JavaScript/TypeScript, C#, Ruby, PHP, Kotlin, Swift, SQL, Shell, XML, COBOL, RPG, PL/I, Natural, 4GL, Mainframe defs
- **Detectors:** Cipher, HMAC, MessageDigest, Signature, KeyGenerator, HardcodedKey
- **Extractors:** Algorithm, CipherSuite, Confidence, Context, Entropy, Snippet
- **Analysis:** Cascade (dependency import graph), DependencyInventory
- **Output:** JSON writer with evidence chain integration
- **Parallelism:** Multiprocessing (fork/spawn) via `CRYPTOSCAN_SCAN_PROCESSES`

### Network TLS Scanner (`services/network_scanner/`)
- Active probe with certificate chain extraction
- TLS version, cipher suite, certificate validation
- Output feeds NBOM (Network BOM)

### Container Scanner (`services/container_scanner/`)
- Docker/OCI image layer analysis
- SBOM generation (CycloneDX/SPDX)
- CVE matching against advisory feeds
- Dockerfile policy rules

### Cloud Scanner (`services/cloud_scanner/`)
- AWS KMS, Azure Key Vault, GCP Cloud KMS inventory
- S3/Blob/GCS encryption settings
- Database encryption at rest
- IAM policy analysis

---

## 8. CERTIFICATE/TLS DISCOVERY

**Implementation:** 
- `services/scanner/scanner/detectors/materials/pem_scanner.py` — PEM/key material detection
- `services/network_scanner/` — Live TLS probing
- `services/universal_crypto/universal_crypto/certificate_intel.py` — Certificate analysis (public key alg, key size, curve, signature alg, expiry, trust store)
- `services/api/api/routers/certificates.py` — Certificate inventory API

---

## 9. CRYPTOGRAPHIC ALGORITHM DISCOVERY

**Registry:** `shared/shared_models/shared_models/algorithm_registry.py` (64K lines)
- 300+ algorithm entries with IANA OIDs, NIST designations, quantum status
- Classification: `QUANTUM_VULNERABLE`, `QUANTUM_SAFE`, `GROVER_MARGINAL`, `CLASSICALLY_BROKEN`, `UNKNOWN`
- Primitive mapping: asymmetric, symmetric, hash, KEM, signature

**Detection:**
- Static: AST visitors per language → algorithm identifiers
- Binary: Disassembly + string extraction + library fingerprinting
- Runtime: API call interception, loaded library enumeration
- Network: TLS cipher suite → algorithm mapping
- Certificates: Public key algorithm + signature algorithm

---

## 10. DEPENDENCY DISCOVERY

**Source Code:** Import analysis per language (Python imports, Java imports, Go modules, etc.)
**Binary:** Shared library dependencies, dynamic linking
**Package Managers:** Lockfile parsing (pip, npm, Maven, Gradle, Cargo, NuGet)
**Containers:** Base image + layer dependencies
**Graph:** `SystemDependency` table + scanner cascade (`depends_on_systems`)

---

## 11. EVIDENCE CHAIN IMPLEMENTATION

**Location:** `services/evidence/evidence/`

**Pipeline (`core/pipeline.py`):**
1. Raw findings → canonical JSON (sorted keys, no whitespace, excluded fields)
2. Content hash: SHA-256 of canonical bytes
3. Deduplication by content hash (collapses byte-identical findings)
4. Chain hash: `chain_hash[0] = SHA256(content_hash[0] + scan_session_id)`, `chain_hash[N] = SHA256(content_hash[N] + chain_hash[N-1])`
5. Manifest: Merkle-style root over evidence IDs

**Storage:** `EvidenceRecord` model with `content_hash`, `chain_hash`, `chain_position`, `previous_hash`
**Verification:** `VerificationLog` table with periodic chain verification

---

## 12. CBOM IMPLEMENTATION

**Location:** `services/cbom/cbom/`

**Generator:** `CbomGenerator` class
- Input: Normalized records (from evidence or direct ingestion)
- Output: CycloneDX 1.5 JSON/XML with `cryptoProperties` (assetType, oid, nistDesignation, quantumVulnerable, primitive)
- Signing: JWS (RS256/ES256/HS256) over canonical BOM, `cryptoscan:jws` metadata property
- Verification: Full check-by-check report (`verify_report`)

**Endpoints:** 
- `GET /cbom/scan/{id}`, `GET /cbom/system/{id}`, `GET /cbom/portfolio`
- `POST /cbom/ingest`, `POST /cbom/validate`, `POST /cbom/diff`, `POST /cbom/verify`
- `POST /cbom/custom` (asset selection), `POST /cbom/nbom` (network BOM)

---

## 13. HBOM IMPLEMENTATION

**Status:** Minimal — `Hbom.tsx` frontend page exists (1.9K lines), backend router references HBOM in `techbom.py` but no dedicated HBOM service found. `services/cbom/cbom/nbom.py` exists for Network BOM.

---

## 14. GRAPH IMPLEMENTATION

**Location:** `services/graph_engine/graph_engine/`

**Backends:**
- **Neo4j** (production): `Neo4jGraphStore` with constraints/indexes
- **In-memory** (default): `GraphEngine` class with adjacency lists

**Node Types:** System, CryptoAsset, BusinessProcess, BusinessOwner, Vendor, Certificate, CloudResource, NetworkResource, ComplianceScope
**Edge Types:** USES, CALLS, SUPPORTS, OWNED_BY, DEPENDS_ON_VENDOR, SECURED_BY, DEPLOYED_ON, CONNECTS_TO, MUST_COMPLY_WITH, IMPORTS

**Queries:** Blast radius, business impact, vendor path/chain, dependents, shortest path, hotspots, cycles, certificate exposure, migration waves, drift detection

**Persistence:** `GraphSnapshot` model (content-addressed versions with fingerprint)

---

## 15. POLICY/COMPLIANCE ENGINE

**Location:** `services/policy/policy/`

**Architecture:**
- Rules loaded from YAML (`RuleLoader`)
- Validated (`RuleValidator`)
- Evaluated (`PolicyEvaluator`) against normalized evidence
- Pack hash for versioning (`pack_hash()`)

**Rule Model:** `PolicyRule` with condition (exact/pattern/family), severity, standard_reference, enabled flag

**Integration:** `NormalizationEngine` → normalized crypto → `PolicyEngine.evaluate()` → `PolicyEvaluation`

---

## 16. DRIFT DETECTION

**Location:** `services/drift/drift/`

**Components:**
- `DriftEvent` model (drift_type, severity, resolution_status)
- `Baseline` model (approved scan snapshots)
- Daily digest (`drift/alerts/daily_digest.py`)
- Acknowledgment/resolution/false-positive workflow with audit trail
- API: `GET /drift`, `GET /drift/digest`, `POST /drift/{id}/acknowledge|resolve|false-positive`

---

## 17. PQC READINESS

**Location:** `services/quantum/quantum/risk.py` + `services/agility/agility/readiness.py`

**Classification (deterministic):**
- `SHOR_VULNERABLE`: RSA, ECDH, ECDSA, Ed25519, X25519, DH, DSA
- `GROVER_MARGINAL`: AES-128, SHA-256
- `CLASSICALLY_BROKEN`: DES, 3DES, RC4, MD5, SHA-1, SSLv3, TLS 1.0/1.1
- `PQC_RESISTANT`: ML-KEM, ML-DSA, SLH-DSA, KYBER, DILITHIUM, SPHINCS+

**Scoring:** `score_asset()` with sensitivity × HNDL multiplier × timeline × criticality
**Readiness:** 5-factor (agility, dependencies, testing, team capacity, change freeze)

---

## 18. CRYPTO-AGILITY

**Location:** `services/agility/agility/`

**Scoring (`system_score.py`):** 6 factors (abstraction, config-driven, negotiation, key mgmt, PQC lib, testing)
**Readiness (`readiness.py`):** 5 factors (agility, dependency count, crypto tests, team capacity, freeze)
**Roadmap (`roadmap.py`):** Wave assignment (1-3) constrained by dependency cycles
**Simulation (`simulation.py` & `twin_scenarios.py`):** 10 scenario types (algorithm migration, cert expiry, key rotation, HSM outage, vendor compromise, protocol deprecation, compliance change, attack path, PQC migration, agility drift)

---

## 19. REMEDIATION

**Location:** `services/remediation/remediation/engine.py`

**Rules (15 deterministic):**
- P0: DES, 3DES, RC4, MD5, SSLv3, hardcoded keys
- P1: SHA-1, TLS 1.0/1.1, ECB mode
- P2: RSA, DSA, ECC (ECDH/ECDSA/Ed25519/X25519), DH → ML-KEM/ML-DSA
- P3: AES-128 → AES-256

**Output:** Prioritized suggestions with effort estimation, backlog generation
**Disclaimer:** "DETERMINISTIC SUGGESTION - NOT COMPLIANCE DETERMINATION"

---

## 20. AUTHENTICATION/AUTHORIZATION

**Auth (`services/api/api/security/auth.py`):**
- Session cookies (HttpOnly, Secure, SameSite=Lax)
- Password: bcrypt (configurable rounds)
- API keys: Prefix + hash (SHA-256), rotation, allowlist
- MFA: TOTP (optional)
- Admin bootstrap from env vars

**RBAC (`services/api/api/security/rbac.py`):**
- Roles: `admin`, `auditor`, `viewer`
- Permissions: `scans.trigger`, `baselines.approve`, `drift.acknowledge`, `drift.resolve`, `crypto.ingest`, `crypto.read`, `crypto.manage`
- `require_permission()`, `require_roles()` dependencies

**ABAC:** `AbacMiddleware` for Region→BU→Environment→Asset isolation (fail-closed when `ABAC_ENFORCED`)

---

## 21. AUDIT LOGGING

**Models:** `AuditLog` (user, action, target_type, target_id, detail, timestamp)
**Endpoints:** `GET /api/v1/auth/audit`, `GET /api/v1/auth/audit/verify`, `GET /api/v1/auth/audit/export`
**Chain:** Hash chain over audit entries with verification endpoint
**Control Events:** `ControlEventMiddleware` emits `api.<segment>.<verb>` on mutating calls

---

## 22. MONITORING

**Monitor Daemon:** `scripts/run_monitor.py` (separate container)
- Watch-list re-scans (network, cloud, repo, container)
- Configurable tick, lease TTL, jitter, concurrency
- Alerts: CEF (syslog), webhook, email (SMTP)
- Live status API: `GET /api/v1/monitor/status`

**Metrics:** Prometheus `/metrics` (scans, findings by status, open drift, queued jobs)
**Tracing:** W3C trace-context on every request, OTLP export optional
**Spans:** JSONL file sink (`traces/spans.jsonl`)

---

## 23. REPORTING/EXPORT

**Templates (6):** `services/api/api/routers/report_templates.py`
**Formats:** JSON, HTML, PDF (fpdf2)
**Endpoints:** `GET /api/v1/scans/{id}/report[.html|.pdf]`, `GET /api/v1/report-templates`
**Compliance:** Requirement-by-requirement from policy evidence

---

## 24. TESTS

**Backend:** pytest 9.1.1 + pytest-asyncio + pytest-xdist
- Unit: per-module (detectors, extractors, parsers, normalization, policy)
- Integration: full scan pipeline, git clone, polyglot fixtures
- Accuracy: Bank validation, external validation, GCC validation, cascade analysis
- Security: SSRF, path traversal, command injection, rate limiting

**Frontend:** Vitest 2.1.9 + jsdom + @testing-library/react
- Offline-first (fetch stub rejects all calls)
- Component rendering tests, page smoke tests

**Database:** pgserver (embedded PostgreSQL 16) for migration parity tests
**Redis:** fakeredis for job path hardening tests

---

## 25. CI/CD

**Workflows:** `.github/workflows/` (lint, test suites, E2E seed, polyglot matrix, Postgres migration up/down, Docker builds)
**Gates:** `scripts/ci_gate.py` — standard/strict/lenient profiles
**CI Gate API:** `POST /api/v1/ci/gate`

---

## 26. DOCKER

**Files:**
- `docker-compose.yml` (development)
- `docker-compose.prod.yml` (production overrides)
- `docker-compose.tls.yml` (TLS termination)
- `docker-compose.test.yml` (test)
- `.docker/api/Dockerfile`, `.docker/worker/Dockerfile`, `.docker/frontend/Dockerfile`, `.docker/nginx/Dockerfile`

**Security:** Non-root user, `no-new-privileges:true`, `cap_drop: ALL`, minimal `cap_add`

---

## 27. KUBERNETES

**Location:** `k8s/app/`
- API deployment, worker deployment, monitor deployment
- Probes (liveness/readiness/startup), resources, non-root, secrets
- Ingress, ServiceMonitor for Prometheus

---

## 28. INFRASTRUCTURE

**PostgreSQL 15:** Primary database
**Redis 7:** Job queue, rate limiting, event federation
**Neo4j 5.26:** Graph backend (constraints/indexes via `neo4j-init` service)
**Nginx:** TLS termination, reverse proxy

---

## 29. CONFIGURATION

**Settings:** `services/api/api/config/settings.py` (pydantic-settings)
**Environment:** `.env.example`, `.env.production.example`, `.env.test`
**Key Variables:** `DATABASE_URL`, `REDIS_URL`, `NEO4J_URI`, `SECRET_KEY`, `CBOM_SIGNING_SECRET`, `STREAM_SECRET`, `WORKSPACE_BASE_PATH`, `CRYPTOSCAN_SOURCE_ROOTS`

---

## 30. DOCUMENTATION

**Location:** `docs/`
- `admin-guide/` (25 guides: installation, hardening, neo4j, cloud setup, etc.)
- `api-reference/rest-api.md`
- `architecture/` (real-world-comparison, platform-boundaries, capability-maturity)
- `accuracy/` (validation reports: bank, UAE, GCC, SNB, cascade)
- `CAPABILITY-MATURITY.md` (33 GA / 30 beta / 8 preview)

---

## SUMMARY STATISTICS

| Metric | Count |
|--------|-------|
| Backend Services | 51 |
| API Router Modules | 325 (85 registered) |
| Frontend Pages | 71 |
| Database Migrations | 71 |
| Database Models | 52 |
| Test Files | 498 |
| Python Lines (est.) | ~276,000 |
| Frontend Lines (est.) | ~50,000 |
| Documentation Files | 100+ |

---

## ARCHITECTURAL PATTERNS OBSERVED

1. **Service-per-domain** — Each cryptographic domain is a separate service
2. **Shared models** — `shared_models` package provides canonical types
3. **Deterministic pipeline** — No AI in evidence collection, normalization, policy evaluation
4. **Evidence-first** — Every finding traces to source + hash chain
5. **Tenant isolation** — Row-level security via `TenantScoped` mixin
6. **Graceful degradation** — Neo4j optional, Redis optional, in-memory fallbacks
7. **Explicit versioning** — CBOM versions, graph snapshots, policy pack hashes
8. **Fail-closed defaults** — Production rejects weak secrets, unsigned webhooks, demo creds
## UPDATE — round 20 re-verification (2026-10-10)

Snapshot re-confirmed: counts remain stale in the report's favor (799
routes then, 744 paths / 824 operations now after round 20's
`/graph/export`; migration chain 0074 then, 0077 now; ~4.3k backend
tests). Structural inventory unchanged — no services added or removed.
The graph_builder/graph_engine entries gained bounded-walk collection
and prune-on-sync behavior this round (see audit 03/09 addenda).
