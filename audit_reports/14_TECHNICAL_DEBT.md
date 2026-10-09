# 14_TECHNICAL_DEBT.md
## ZELNX CryptoScan — Technical Debt Audit

**Generated:** 2026-09-20  
**Method:** Source code inspection for code smells, duplication, architectural violations, and maintainability issues  
**Scope:** All 51 services, frontend, database, infrastructure

---

## 1. TECHNICAL DEBT CATALOG — BY SEVERITY

### 1.1 CRITICAL (P0) — Architectural Debt

| # | Debt Item | Location | Impact | Effort |
|---|-----------|----------|--------|--------|
| **TD-001** | **API Monolith** — 325 router files, 85 registered in single FastAPI app | `services/api/api/main.py` + `services/api/api/routers/` | Deployment coupling, memory pressure, circular imports, scaling limits | High (split into 5-6 services) |
| **TD-002** | **Neo4j No Tenant Isolation** — All tenants share single graph database | `services/graph_engine/graph_engine/connection/neo4j_driver.py` | Cross-tenant data leakage in multi-tenant deployments | High (arch redesign) |
| **TD-003** | **Dual CBOM Systems** — Static (evidence) + Live (crypto engine) — separate pipelines, schemas, state | `services/cbom/` vs `services/api/api/routers/crypto.py` | Data inconsistency, duplicate work, no reconciliation | High (unify) |
| **TD-004** | **TechBOM Duplicate** — 58K lines duplicating CBOM logic with separate models, versioning, export | `services/api/api/routers/techbom.py` + `TechnologyBomSnapshot/Export` models | Maintenance burden, confusion, schema drift | Medium (merge) |
| **TD-005** | **Two Algorithm Registries** — `shared_models/algorithm_registry.py` (64K) + `universal_crypto/registry.py` (12K) | Both used for classification | Inconsistent quantum status, duplicate maintenance | Medium (merge) |

### 1.2 HIGH (P1) — Service & Code Debt

| # | Debt Item | Location | Impact | Effort |
|---|-----------|----------|--------|--------|
| **TD-006** | **Service Proliferation** — 10+ services < 5 files (`billing`, `sla`, `vaultlease`, `connector_sdk`, `keyassure`, `privacy`, `ot_safety`, `ruleset`, `universal_platform`, `universal_vendor`) | `services/*/` | Operational overhead, deployment complexity, cognitive load | Low (consolidate to libraries) |
| **TD-007** | **CBOM Portfolio In-Memory** — `_located_assets()` loads ALL assets for estate CBOM | `services/api/api/routers/cbom.py:178` | OOM at scale, blocks event loop | Medium (streaming) |
| **TD-008** | **Graph Sync Full Rebuild** — `sync_graph()` deletes all Neo4j nodes + reloads | `services/api/api/graph_builder.py` | Downtime during sync, O(N) scaling | Medium (incremental) |
| **TD-009** | **No Read Replicas** — All queries hit primary PostgreSQL | `docker-compose.yml`, `database/connection/engine.py` | Analytics block writes, no HA | Medium (config + routing) |
| **TD-010** | **Evidence Chain No Auto-Verification** — `VerificationLog` only manual | `services/evidence/evidence/core/pipeline.py` | Corruption undetected | Low (cron job) |
| **TD-011** | **Link Tables No Tenant_ID** — `SystemAsset`, `SystemDependency`, `CertificateUsage`, `CryptoAssetEvidence` | `services/database/db/models/` | Tenant isolation bypass via joins | Medium (migration) |
| **TD-012** | **Live Crypto Bypasses Evidence** — `crypto_live` table separate pipeline | `services/api/api/routers/crypto.py` | No integrity chain for live observations | High (refactor) |
| **TD-013** | **Hardcoded Secrets in docker-compose** — `SECRET_KEY`, passwords, keys in env | `docker-compose.yml`, `docker-compose.prod.yml` | Secret leakage, no rotation | Low (Vault integration) |
| **TD-014** | **No DB Encryption at Rest** — PostgreSQL, Redis, Neo4j unencrypted | `docker-compose.yml` | Data at rest exposure | Medium (config) |
| **TD-015** | **No mTLS Between Services** — Internal Docker network unencrypted | `docker-compose.yml` | Lateral movement risk | Medium (service mesh) |

### 1.3 MEDIUM (P2) — Code Quality Debt

| # | Debt Item | Location | Impact | Effort |
|---|-----------|----------|--------|--------|
| **TD-016** | **DevSecOps Page 93K Lines** — Single component doing too much | `frontend/src/pages/DevSecOps.tsx` | Unmaintainable, slow compiles | Medium (split) |
| **TD-017** | **CommandCenter 800+ Lines** — Too much logic in component | `frontend/src/pages/CommandCenter.tsx` | Hard to test, modify | Low (extract hooks) |
| **TD-018** | **Graph Router 1272 Lines** — All graph endpoints in one file | `services/api/api/routers/graph.py` | Hard to navigate, test | Low (split) |
| **TD-019** | **CBOM Router 31K Lines** — All CBOM endpoints in one file | `services/api/api/routers/cbom.py` | Hard to navigate, test | Low (split) |
| **TD-020** | **TechBOM Router 58K Lines** — Monolithic | `services/api/api/routers/techbom.py` | Unmaintainable | Medium (split + merge) |
| **TD-021** | **Universal Crypto Engine 34K Lines** — God class orchestrating everything | `services/universal_crypto/universal_crypto/engine.py` | Hard to test, extend | Medium (decompose) |
| **TD-022** | **Scanner Core 400+ Lines** — `Scanner.scan()` does everything | `services/scanner/scanner/core/scanner.py` | Hard to test individual stages | Low (extract stages) |
| **TD-023** | **Policy Engine + Normalization Coupling** — Both use YAML rules but different loaders | `services/policy/`, `services/normalization/` | Rule drift, duplicate logic | Medium (unify) |
| **TD-024** | **Frontend Types Drift** — No shared types package; `frontend/src/types.ts` vs backend schemas | `frontend/src/types.ts` | Runtime errors from schema changes | Low (shared package) |
| **TD-025** | **Realtime Event Array Unbounded** — `rt.events` grows forever | `frontend/src/lib/realtime.js` | Memory leak in long sessions | Low (circular buffer) |

### 1.4 LOW (P3) — Maintenance Debt

| # | Debt Item | Location | Impact | Effort |
|---|-----------|----------|--------|--------|
| **TD-026** | **Inline Styles in Frontend** — `style={{...}}` throughout components | `frontend/src/components/`, `pages/` | CSP violation, inconsistent theming | Low (CSS modules) |
| **TD-027** | **No Virtualized Lists** — `Table`, `Feed` render all rows | `frontend/src/components/ui.jsx` | Performance at 1000+ rows | Low (react-window) |
| **TD-028** | **No Column Sorting/Filtering in Table** | `frontend/src/components/ui.jsx:Table` | Large datasets unusable | Low (feature) |
| **TD-029** | **Color-Only Badge Meaning** | `frontend/src/components/ui.jsx:Badge` | Accessibility fail | Low (add text/icons) |
| **TD-030** | **Missing ARIA on Custom Components** | `Tabs`, `Table`, `Feed` | Screen reader fail | Low (ARIA) |
| **TD-031** | **No Shared Test Utilities** — Fixtures duplicated per service | `services/*/tests/conftest.py` | Maintenance burden | Low (shared fixtures) |
| **TD-032** | **No Coverage Reporting** | `pytest.ini`, `vitest.config.ts` | Cannot enforce quality gates | Low (config) |
| **TD-033** | **No E2E Tests** | — | Critical flows untested | Medium (Playwright) |
| **TD-034** | **Migration 0060 Risk** — UUID → VARCHAR(36) without data validation | `services/database/migrations/versions/0060_uuid_columns_to_varchar36.py` | Data corruption risk | Low (validate) |
| **TD-035** | **No Secret Rotation Automation** | — | Manual rotation, downtime | Medium (Vault) |

---

## 2. CODE DUPLICATION ANALYSIS

### 2.1 Major Duplication Clusters

| Cluster | Files | Lines Duplicated | Root Cause |
|---------|-------|------------------|------------|
| **CBOM Generation** | `cbom/generator.py` + `techbom.py` + `crypto.py` (live CBOM) | ~5,000 | Three implementations |
| **Algorithm Registry** | `shared_models/algorithm_registry.py` + `universal_crypto/registry.py` | ~2,000 | Two registries |
| **Quantum Classification** | `quantum/risk.py` + `graph.py:_quantum_vulnerable_algorithm()` + `shared_models/quantum_classify.py` | ~500 | Three implementations |
| **Graph Build** | `graph_engine/core/engine.py` + `api/graph_builder.py` + `api/routers/graph.py` | ~1,000 | Multiple entry points |
| **Evidence Hashing** | `evidence/hashing/` + `shared_models/canonical.py` | ~300 | Two canonical JSON impls |
| **Scanner Cascade** | `scanner/analysis/cascade.py` + `api/routers/graph.py` (code_only systems) | ~500 | Duplicate logic |

### 2.2 Boilerplate Duplication
| Pattern | Count | Example |
|---------|-------|---------|
| **Router CRUD boilerplate** | 20+ | `list`, `get`, `create`, `update`, `delete` for each entity |
| **Repository pattern** | 15+ | `list_*`, `get_by_id`, `create` repeated |
| **Pydantic schemas** | 50+ | Similar `BaseModel` with `ConfigDict` |
| **Middleware order comments** | 11 | Explaining Starlette middleware ordering |

---

## 3. ARCHITECTURAL VIOLATIONS

| Violation | Location | Principle Violated |
|-----------|----------|-------------------|
| **API imports from 30+ services** | `services/api/api/main.py` | Dependency inversion — API should not depend on implementation details |
| **Circular import risk** | `api/routers/*` → `services/*` → `shared_models` → `api` | Acyclic dependencies |
| **Database models in API routers** | `api/routers/*.py` import `db.models.*` | Layer violation — API should use repositories |
| **Business logic in routers** | `cbom.py:ingest_document()`, `graph.py:_snapshot_graph()` | Fat controllers |
| **Neo4j direct in API** | `graph.py` uses `Neo4jGraphStore` directly | Should be behind graph service |
| **Worker imports API models** | `worker/worker/core/` imports `db.models.scan` | Worker should be independent |

---

## 4. DEBT BY SERVICE

| Service | Critical | High | Medium | Low | Total Debt Score |
|---------|----------|------|--------|-----|------------------|
| **api** | 3 | 4 | 5 | 3 | **HIGH** |
| **scanner** | 0 | 1 | 2 | 1 | Medium |
| **graph_engine** | 1 | 1 | 1 | 1 | Medium |
| **cbom** | 1 | 1 | 1 | 0 | Medium |
| **universal_crypto** | 1 | 1 | 1 | 0 | Medium |
| **evidence** | 0 | 1 | 0 | 0 | Low |
| **database** | 0 | 2 | 1 | 1 | Medium |
| **worker** | 0 | 0 | 1 | 1 | Low |
| **frontend** | 0 | 0 | 3 | 5 | Medium |
| **normalization** | 0 | 1 | 0 | 0 | Low |
| **policy** | 0 | 1 | 0 | 0 | Low |
| **drift** | 0 | 0 | 0 | 0 | Low |
| **quantum** | 0 | 0 | 0 | 0 | Low |
| **agility** | 0 | 0 | 0 | 0 | Low |
| **remediation** | 0 | 0 | 0 | 0 | Low |
| **Other 37 services** | 0 | 10 | 0 | 0 | **HIGH** (proliferation) |

---

## 5. DEBT VELOCITY — TRENDING

| Indicator | Current | Trend | Concern |
|-----------|---------|-------|---------|
| **Service count** | 51 | ↗️ Increasing | Proliferation accelerating |
| **Router count** | 325 | ↗️ Increasing | API monolith growing |
| **Migration count** | 71 | ↗️ Steady | Schema complexity growing |
| **Frontend page count** | 71 | ↗️ Increasing | UI complexity growing |
| **Test file count** | 498 | ↗️ Increasing | Good but coverage unknown |
| **Lines of code (Python)** | ~276K | ↗️ Increasing | Maintenance burden growing |
| **Technical debt items** | 35 identified | ↗️ Increasing | Not being paid down |

---

## 6. REFACTORING PRIORITIES — ROI ORDER

| Priority | Debt Item | ROI Rationale | Approach |
|----------|-----------|---------------|----------|
| **1** | TD-001 API Monolith | Enables independent scaling, deployment, team ownership | Strangler fig: extract domain services |
| **2** | TD-002 Neo4j Tenant Isolation | Blocks multi-tenant; security critical | Separate DB per tenant or namespace |
| **3** | TD-003 Dual CBOM | Data integrity; single source of truth | Merge live + static into unified pipeline |
| **4** | TD-006 Service Proliferation | Reduces ops burden 80% | Merge <5-file services into libraries |
| **5** | TD-007 CBOM Portfolio Streaming | Prevents OOM; enables scale | Cursor-based streaming response |
| **6** | TD-008 Incremental Graph Sync | Reduces sync from minutes to seconds | CDC from relational → Neo4j |
| **7** | TD-009 Read Replicas | Immediate performance win for analytics | Proxy read queries |
| **8** | TD-011 Link Table Tenant_ID | Completes tenant isolation | 4 migrations + backfill |
| **9** | TD-012 Live Crypto Evidence | Closes integrity gap | Route live events through evidence pipeline |
| **10** | TD-016 DevSecOps Page Split | Developer velocity; 93K lines unmaintainable | Extract sub-pages + shared components |

---

## 7. DEBT PAYDOWN STRATEGY

### 7.1 Immediate (Sprint 1-2)
- Add tenant_id to 4 link tables (TD-011)
- Implement evidence chain verification cron (TD-010)
- Add circular buffer to realtime events (TD-025)
- Enable DB encryption at rest (TD-014)

### 7.2 Short-term (Month 1-2)
- Merge 10 micro-services into libraries (TD-006)
- Split DevSecOps page (TD-016)
- Implement read replica routing (TD-009)
- Merge algorithm registries (TD-005)

### 7.3 Medium-term (Month 3-4)
- API monolith decomposition (TD-001) — start with scans, inventory, graph
- Neo4j tenant isolation (TD-002) — architecture decision + implementation
- Unify CBOM pipelines (TD-003) — single evidence → CBOM path
- Incremental graph sync (TD-008)

### 7.4 Long-term (Quarter 2+)
- TechBOM merge (TD-004)
- Live crypto through evidence pipeline (TD-012)
- mTLS service mesh (TD-015)
- Secret rotation automation (TD-035)

---

## 8. DEBT PREVENTION — PROCESS CHANGES

| Practice | Current | Target |
|----------|---------|--------|
| **Architecture review** | Ad-hoc | Required for new services |
| **Debt budget** | None | 20% sprint capacity |
| **Code ownership** | Implicit | Explicit CODEOWNERS |
| **Deprecation policy** | None | 2-version deprecation |
| **Shared libraries** | `shared_models` only | `shared_utils`, `shared_api`, `shared_ui` |
| **Monolith extraction** | Reactive | Proactive quarterly review |
## UPDATE — 2026-10-09: debt register status after rounds 13–15

Fixed since this report: TD-002 (tenant gate), TD-008 (sync coordinator),
TD-011 (all four link tables TenantScoped), TD-012 (live evidence linkage),
TD-016 (DevSecOps split — now 1.7k lines), TD-025 (event cap), and this
round TD-010 (evidence-chain integrity sweep at `GET /ops/evidence/chain-status`,
same verifier the export uses, event on breakage).

Deliberate architecture, not being "paid down": TD-001 (single deployable
API), TD-003/004 (Technology BOM is the unified surface; layered exports),
TD-005 (registries unified through shared_models normalization).

Open: TD-007 (portfolio streaming), TD-009 (read replicas), TD-013/014/015
(deployment-scope secrets/encryption/mTLS), TD-035 (rotation automation).
