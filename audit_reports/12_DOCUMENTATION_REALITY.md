# 12_DOCUMENTATION_REALITY.md
## ZELNX CryptoScan — Documentation vs. Reality Audit

**Generated:** 2026-09-20  
**Method:** Cross-reference documentation claims against actual source code implementation  
**Scope:** All `.md` files in `docs/`, `README.md`, `CHANGELOG.md` vs. actual code

---

## 1. EXECUTIVE SUMMARY

| Documentation Set | Accuracy | Major Discrepancies |
|-------------------|----------|---------------------|
| **README.md** | ⚠️ 85% | Overstates HBOM, vendor crypto, some detection claims |
| **docs/admin-guide/** | ✅ 95% | Accurate operational docs |
| **docs/api-reference/rest-api.md** | ⚠️ 70% | Missing many endpoints, outdated schemas |
| **docs/architecture/** | ✅ 90% | Honest about boundaries, maturity |
| **docs/accuracy/** | ✅ 90% | Validation reports exist but not automated |
| **CHANGELOG.md** | ✅ 95% | Detailed, matches commits |

**Overall: Documentation is unusually honest for a security product** — admits "UNKNOWN" states, labels beta/preview, documents gaps. Primary issue: **API reference incomplete**, **README overclaims** on some features.

---

## 2. README.md vs. REALITY

### 2.1 Claims vs. Implementation

| README Claim | Reality | Status |
|--------------|---------|--------|
| "51 services (~276k lines)" | 51 dirs in `services/`, ~276K Python lines | ✅ Accurate |
| "325 API router modules (85 registered)" | 325 files in `api/routers/`, 85 imported in `main.py` | ✅ Accurate |
| "57 alembic migrations" | 71 migrations in `database/migrations/versions/` | ❌ Outdated (71 not 57) |
| "71 frontend pages" | 71 lazy-loaded routes in `App.tsx` | ✅ Accurate |
| "498 test files" | ~500 test files across services | ✅ Accurate |
| "33 GA · 30 beta · 8 preview" | `shared_models/capability_maturity.py` defines these | ✅ Accurate |
| "Deterministic policy — no AI in decision path" | Policy engine is pure YAML rules; AI only in simulator | ✅ Accurate |
| "Real-Time System: WebSocket hub + SSE + DB tailer" | Implemented in `api/events/`, `api/middleware/` | ✅ Accurate |
| "Cryptographic Digital Twin (CDT)" | `DigitalTwin.tsx` + `/digital-twin` router + simulator | ✅ Implemented (beta) |
| "HBOM" | Frontend page exists; **no backend implementation** | ❌ **OVERCLAIM** |
| "Vendor/supply-chain" | `vendor_intel`, `vendor_due_diligence` services exist | ⚠️ Partial — no automated detection |
| "OT/ICS (passive, zero packets)" | `ot_scanner` exists; passive network monitoring | ✅ Implemented |
| "Payment HSM/PCI" | `payment_crypto` service + HSM event ingestion | ✅ Implemented |
| "Mainframe COBOL" | `cobol_parser.py`, `rpg_parser.py`, `pli_parser.py` | ✅ Implemented |

### 2.2 Scope Boundaries — Honest
| Boundary | Documented | Implemented |
|----------|------------|-------------|
| ❌ General SAST | "Not a universal scan everything tool" | No general SAST |
| ❌ Malware analysis | Explicitly excluded | Not implemented |
| ❌ SIEM behavior analytics | Explicitly excluded | Not implemented |
| ❌ Employee endpoint scanning | Explicitly excluded | Not implemented |
| ✅ Cloud: only your accounts | "Only accounts your credentials can see" | Cloud scanner uses provided creds |

---

## 3. API REFERENCE (docs/api-reference/rest-api.md) vs. REALITY

### 3.1 Coverage Gap
| Router Category | Documented Endpoints | Actual Endpoints | Coverage |
|-----------------|---------------------|------------------|----------|
| **Core (scans, findings, evidence)** | ~15 | ~25 | 60% |
| **CBOM** | ~10 | 22 | 45% |
| **Graph** | ~5 | 28 | 18% |
| **Crypto Live** | ~3 | 8 | 38% |
| **Drift** | ~3 | 4 | 75% |
| **DevSecOps** | ~5 | 20+ | 25% |
| **Network/Cloud/Container** | ~8 | 15+ | 50% |
| **Compliance/Risk** | ~5 | 10+ | 40% |
| **Admin/Identity** | ~5 | 15+ | 33% |

**Result:** API reference covers ~40% of actual endpoints. Many critical endpoints (graph queries, CBOM portfolio/ingest, migration plan, vendor chains) undocumented.

### 3.2 Schema Accuracy
- **Request/response models:** Often outdated (Pydantic v1 style vs v2 actual)
- **Authentication:** Documents session only; API keys, OIDC, SCIM missing
- **Error responses:** Not documented
- **Rate limits:** Not documented

---

## 4. ARCHITECTURE DOCS vs. REALITY

### 4.1 Platform Boundaries (`docs/architecture/platform-boundaries.md`)
| Claim | Reality | Match |
|-------|---------|-------|
| "Single source of truth: `shared_models/platform_scope.py`" | `GET /api/v1/platform/scope` serves this | ✅ |
| "33 GA / 30 beta / 8 preview" | `capability_maturity.py` defines exactly this | ✅ |
| "Enforced by tests" | `test_capability_maturity.py` not found | ⚠️ No test found |

### 4.2 Real-World Comparison (`docs/architecture/real-world-comparison.md`)
| Comparison | Documented | Reality Check |
|------------|------------|---------------|
| vs. Venafi/Keyfactor | Certificate management focus | CryptoScan broader (code+binary+network+cloud) |
| vs. SandboxAQ Cryptosense | Code scanning + CBOM | CryptoScan has network/container/cloud too |
| vs. Prowler | Cloud config | CryptoScan has cloud but less rules |
| vs. Trivy | Container/SBOM | CryptoScan has SBOM + crypto focus |
| vs. testssl.sh | TLS testing | CryptoScan has network scanner |
| vs. Nozomi | OT passive | CryptoScan has OT scanner |
| vs. SAST | Code scanning | CryptoScan crypto-specific, not general SAST |

**Assessment:** Honest positioning — doesn't claim to replace specialized tools.

### 4.3 Capability Maturity (`docs/CAPABILITY-MATURITY.md`)
| Maturity Level | Count | Examples |
|----------------|-------|----------|
| **GA (General Availability)** | 33 | Scans, Findings, CBOM, Graph, Drift, Network, Cloud, Container, Certificates, etc. |
| **Beta** | 30 | Digital Twin, What-If, Migration, Remediation, Agility, PQC Map, etc. |
| **Preview** | 8 | HBOM, NBOM, TechBOM, Payment Crypto, OT Safety, Vendor Due Diligence, etc. |

**Reality Check:** HBOM listed as Preview but **not implemented** — should be "Planned" not "Preview".

---

## 5. ACCURACY DOCS vs. REALITY

### 5.1 Validation Reports (`docs/accuracy/`)
| Report | Claim | Reality |
|--------|-------|---------|
| `EXTERNAL-VALIDATION.md` | Independent validation methodology | Describes methodology; no automated CI gate |
| `BANK-READINESS.md` | Banking sector readiness | Documents features; no formal certification |
| `DUBAI-BANKS-E2E.md` | UAE banking E2E test | Describes test scenario; not automated |
| `UAE-VALIDATION.md` | UAE regulatory validation | Maps features to regulations |
| `SNB-VALIDATION.md` | Swiss National Bank validation | Describes validation approach |
| `SNB-1K-E2E.md` | 1000-repo E2E | Describes scale test; not in CI |
| `GCC-VALIDATION.md` | GCC region validation | Regional compliance mapping |
| `KEY-INVENTORY.md` | Key inventory accuracy | Describes approach |
| `CASCADE-ANALYSIS.md` | Cascade analysis validation | Documents cascade accuracy |
| `REPORT.md` | Consolidated accuracy report | Summary of above |

**Gap:** Validation is **documented but not automated** — no CI gate that fails on accuracy regression.

---

## 6. ADMIN GUIDES vs. REALITY

### 6.1 Installation (`docs/admin-guide/installation.md`)
| Step | Documented | Reality |
|------|------------|---------|
| Docker Compose | `docker compose up --build` | Works (dev) |
| Production | `docker compose -f docker-compose.yml -f docker-compose.prod.yml up --build` | Works with secrets |
| Kubernetes | `k8s/app/` manifests | Exist but not tested in CI |
| Air-gap | `docs/admin-guide/air-gap-install.md` | Describes offline image load |

### 6.2 Configuration Guides
| Guide | Accuracy |
|-------|----------|
| `system-configuration.md` | ✅ Matches `api/config/settings.py` |
| `scanner-configuration.md` | ✅ Matches `scanner/config/scanner_config.py` |
| `network-scan-targets-config.md` | ✅ Matches `network_scanner` config |
| `container-registry-integration.md` | ✅ Matches container scanner |
| `github-integration.md` | ✅ Webhook + app setup |
| `oidc-sso.md` | ✅ OIDC client config |
| `neo4j-setup.md` | ✅ Neo4j constraints + init |
| `backup-restore.md` | ✅ Scripts exist and documented |

---

## 7. CHANGELOG vs. REALITY

**CHANGELOG.md** — 53K lines, detailed entries per version
- Matches git history (spot-checked v1.0.0 through v1.5.0)
- Documents breaking changes, migrations, new features
- **Accurate** — no fabrications found

---

## 8. DISCREPANCY LIST — PRIORITIZED

| # | Documentation | Claim | Reality | Severity |
|---|---------------|-------|---------|----------|
| 1 | README.md | "57 alembic migrations" | 71 migrations | P2 |
| 2 | README.md | "HBOM" as capability | Frontend only; no backend | P1 |
| 3 | README.md | "Vendor crypto detection" | Scaffolded service, no detection | P1 |
| 4 | API Reference | Complete REST API | ~40% coverage | P1 |
| 5 | CAPABILITY-MATURITY.md | HBOM = Preview | HBOM = Not Implemented | P1 |
| 6 | Platform Boundaries | "Enforced by tests" | No capability maturity test found | P2 |
| 7 | Architecture Docs | "Real-time CBOM" | Two separate CBOM systems (static + live) | P2 |
| 8 | README | "Deterministic scanners" | Binary parser has heuristic fallback | P3 |
| 9 | Admin Guides | "Production hardening" | Some hardening optional (mTLS, DB encryption) | P2 |

---

## 9. UNDOCUMENTED FEATURES (Code exists, no docs)

| Feature | Location | Why It Matters |
|---------|----------|----------------|
| **Graph snapshot versioning** | `GraphSnapshot` + `/graph/snapshot`, `/graph/timeline`, `/graph/compare` | Powerful audit capability |
| **Evidence chain verification** | `VerificationLog` + `ChainHasher.verify_chain()` | Core integrity feature |
| **CBOM JWS signing (RS256/ES256)** | `CbomGenerator.sign_jws()` + `verify_report()` | Production-grade signing |
| **Migration plan from graph** | `/graph/migration-plan` creates real MigrationProject | Unique capability |
| **Vendor chain analysis** | `/graph/vendor-chain`, `/graph/vendor-chains` | Supply chain visibility |
| **Live crypto engine (§36)** | `universal_crypto/engine.py` — full pipeline | Separate from static scanner |
| **Drift daily digest** | `/drift/digest` + `drift/alerts/daily_digest.py` | Operational necessity |
| **Remediation backlog** | `remediation/backlog.py` — effort estimation | Actionable output |
| **Quantum risk with HNDL** | `quantum/risk.py` — harvest-now-decrypt-later | Regulatory relevance |
| **TechBOM (separate from CBOM)** | `techbom.py` 58K lines + snapshot/export | Duplicate BOM system |

---

## 10. RECOMMENDATIONS

### P1 — High
1. **Update README migration count** — 71 not 57
2. **Remove HBOM from capabilities** — or implement it
3. **Complete API reference** — Auto-generate from FastAPI OpenAPI spec
4. **Fix CAPABILITY-MATURITY.md** — HBOM = Planned, not Preview

### P2 — Medium
5. **Document undocumented features** — Graph snapshots, CBOM JWS, migration plan, vendor chains
6. **Add capability maturity tests** — Enforce GA/Beta/Preview boundaries
7. **Document dual CBOM systems** — Static (evidence) vs Live (crypto engine)
8. **Clarify vendor crypto status** — "Planned" not "Implemented"

### P3 — Enhancement
9. **API reference automation** — CI job to verify docs match routes
10. **Architecture decision records (ADRs)** — For major choices (Neo4j, dual CBOM, etc.)
## UPDATE — round 20 (2026-10-10)

`docs/api-reference/rest-api.md` regenerated after round 20 (744 paths /
824 operations / 91 groups; `GET /graph/export` added). The automation
gap the report names (docs-vs-routes verification in CI) remains covered
on the code side by the OpenAPI contract tests; CI wiring stays blocked
by the standing no-workflows constraint. ADRs (P3#10) remain open.
