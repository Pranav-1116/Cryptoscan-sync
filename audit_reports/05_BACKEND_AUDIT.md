# 05_BACKEND_AUDIT.md
## ZELNX CryptoScan — Backend Deep Audit

**Generated:** 2026-09-20  
**Method:** Source code inspection of all 51 services, API routers (85 registered), and worker  
**Scope:** Actual implementation — endpoints, controllers, services, data access, security

---

## 1. API SERVICE ARCHITECTURE

### 1.1 Main Application (`services/api/api/main.py`)
- **Framework:** FastAPI 0.141.1 + Uvicorn 0.52.4
- **Lifespan:** DB init, Neo4j schema apply, admin bootstrap, event tailer, telemetry heartbeat, Redis federation, live scan snapshot restore
- **Middleware Stack (11, order matters):**
  1. CORSMiddleware
  2. TrustedHostMiddleware
  3. LoggingMiddleware
  4. GZipMiddleware
  5. RequestIDMiddleware
  6. TenantScopeMiddleware (auth required)
  7. AuthMiddleware
  8. RateLimitMiddleware (Redis, fail-closed in prod)
  9. ObservabilityMiddleware (metrics + traces)
  10. AbacMiddleware (fail-closed when ABAC_ENFORCED)
  11. SecurityHeadersMiddleware
  12. ControlEventMiddleware (innermost — emits events on mutating calls)

### 1.2 Router Registration (85 routers)
All under `/api/v1` prefix. **Critical ordering:** `runtime.router` before `scans.router` (catch-all path conflict).

---

## 2. ENDPOINT AUDIT — BY DOMAIN

### 2.1 Scans & Findings (Core)
| Endpoint | Router | Method | Auth | Validation | Issues |
|----------|--------|--------|------|------------|--------|
| `/scans` | `scans.py` | GET | viewer | Pagination | — |
| `/scans` | `scans.py` | POST | admin/auditor | ScanCreate schema | — |
| `/scans/{id}` | `scans.py` | GET | viewer | UUID | Catch-all shadows `/scans/runtime-findings` |
| `/scans/{id}/report` | `scans.py` | GET | viewer | Format param | PDF/HTML/JSON |
| `/scans/{id}/evidence` | `scans.py` | GET | viewer | — | — |
| `/findings` | `findings.py` | GET | viewer | Filters | — |
| `/evidence` | (in scans) | GET | viewer | — | — |

### 2.2 CBOM (Comprehensive)
| Endpoint | Router | Method | Auth | Validation | Issues |
|----------|--------|--------|------|------------|--------|
| `/cbom` | `cbom.py` | GET | viewer | Pagination, coverage, q | — |
| `/cbom/coverage` | `cbom.py` | GET | viewer | — | — |
| `/cbom/scan-uncovered` | `cbom.py` | POST | admin/auditor | Limit | Triggers scan jobs |
| `/cbom/portfolio` | `cbom.py` | GET | viewer | fmt, signed | Loads ALL assets in memory |
| `/cbom/search` | `cbom.py` | GET | viewer | q, limit | — |
| `/cbom/validate` | `cbom.py` | POST | viewer | IngestCbomRequest | — |
| `/cbom/verify` | `cbom.py` | POST | viewer | IngestCbomRequest | Full check-by-check report |
| `/cbom/assess` | `cbom.py` | POST | viewer | CbomRef | Lazy DB session |
| `/cbom/ingest` | `cbom.py` | POST | viewer | IngestCbomRequest | Signature gate + validation |
| `/cbom/diff` | `cbom.py` | POST | viewer | DiffCbomRequest | — |
| `/cbom/scan/{id}` | `cbom.py` | GET | viewer | fmt, signed | Cascade deps included |
| `/cbom/system/{id}` | `cbom.py` | GET | viewer | fmt, signed | Estate linkage deps |
| `/cbom/custom` | `cbom.py` | POST | viewer | CustomCbomRequest | Asset selection |
| `/cbom/nbom` | `cbom.py` | POST | viewer | NbomRequest | Network BOM |
| `/cbom/nbom/cascade` | `cbom.py` | POST | viewer | NbomRequest + ref | Blast radius |

### 2.3 Graph (Rich Query Surface)
| Endpoint | Router | Method | Auth | Purpose |
|----------|--------|--------|------|---------|
| `/graph/health` | `graph.py` | GET | viewer | Backend status |
| `/graph/sync` | `graph.py` | POST | admin | Full Neo4j reload |
| `/graph` | `graph.py` | GET | viewer | Full vis export |
| `/graph/blast-radius` | `graph.py` | GET | viewer | Downstream from system/asset |
| `/graph/impact` | `graph.py` | GET | viewer | Business impact (revenue, customers) |
| `/graph/compliance` | `graph.py` | GET | viewer | Compliance inheritance |
| `/graph/vendor-path` | `graph.py` | GET | viewer | Upstream to vendor |
| `/graph/vendor-chain` | `graph.py` | GET | viewer | Vendor → systems → assets |
| `/graph/vendor-chains` | `graph.py` | GET | viewer | All vendor chains |
| `/graph/dependents` | `graph.py` | GET | viewer | Upstream blast radius |
| `/graph/path` | `graph.py` | GET | viewer | Shortest CALLS path |
| `/graph/hotspots` | `graph.py` | GET | viewer | QV concentration ranking |
| `/graph/cycles` | `graph.py` | GET | viewer | SCC detection |
| `/graph/certificates/exposure` | `graph.py` | GET | viewer | Expiring certs + revenue risk |
| `/graph/stats` | `graph.py` | GET | viewer | Graph composition |
| `/graph/drift` | `graph.py` | GET | viewer | Live vs Neo4j diff |
| `/graph/migration-waves` | `graph.py` | GET | viewer | Readiness waves + cycles |
| `/graph/crypto` | `graph.py` | GET | viewer | Assets for system |
| `/graph/simulate` | `graph.py` | POST | admin | What-if change impact |
| `/graph/explain` | `graph.py` | GET | viewer | Evidence-backed risk chain |
| `/graph/migration-plan` | `graph.py` | POST | admin | Creates MigrationProject + tasks |
| `/graph/snapshot` | `graph.py` | POST | admin | Content-addressed version |
| `/graph/timeline` | `graph.py` | GET | viewer | Version history |
| `/graph/compare` | `graph.py` | GET | viewer | Version diff |
| `/graph/edges` | `graph.py` | GET | viewer | List dependency edges |
| `/graph/edges` | `graph.py` | POST | admin | Register edge |
| `/graph/edges/{p}/{c}` | `graph.py` | DELETE | admin | Remove edge |
| `/graph/edges/discovered` | `graph.py` | GET | viewer | Scanner/graph proposals |
| `/graph/edges/adopt` | `graph.py` | POST | admin | Adopt discovered edges |

### 2.4 Crypto Live Engine (Separate Pipeline)
| Endpoint | Router | Method | Auth | Purpose |
|----------|--------|--------|------|---------|
| `/crypto/live/events` | `crypto.py` | POST | crypto.ingest | Ingest live event |
| `/crypto/live/state` | `crypto.py` | GET | crypto.read | All asset states |
| `/crypto/live/state/{id}` | `crypto.py` | GET | crypto.read | Single asset state |
| `/crypto/live/risk-summary` | `crypto.py` | GET | crypto.read | Risk scores |
| `/crypto/live/timeline` | `crypto.py` | GET | crypto.read | Event journal |
| `/crypto/live/{id}/cbom` | `crypto.py` | GET | crypto.read | Versioned CBOM |
| `/crypto/scan` | `crypto.py` | POST | crypto.manage | §36 full pipeline |
| `/crypto/simulate` | `crypto.py` | POST | crypto.manage | What-if migration |

### 2.5 Drift (Operational)
| Endpoint | Router | Method | Auth | Purpose |
|----------|--------|--------|------|---------|
| `/drift` | `drift.py` | GET | viewer | List with filters |
| `/drift/digest` | `drift.py` | GET | viewer | Daily digest |
| `/drift/{id}/acknowledge` | `drift.py` | POST | auditor | Ack with notes |
| `/drift/{id}/resolve` | `drift.py` | POST | auditor | Resolve with notes |
| `/drift/{id}/false-positive` | `drift.py` | POST | auditor | Mark FP with notes |

### 2.6 DevSecOps (Pipeline Gates)
| Endpoint | Router | Method | Purpose |
|----------|--------|--------|---------|
| `/container/scan` | `container_scans.py` | POST | Dockerfile + packages + feed → CVE |
| `/k8s/scan` | `container_scans.py` | POST | K8s manifest misconfig rules |
| `/cloud/posture` | `cloud_scans.py` | POST | CIS-style cloud config |
| `/sbom/scan` | `devsecops.py` | POST | Source/container → SBOM + crypto |
| `/sbom/artifacts` | `devsecops.py` | GET | Persisted SBOM artifacts |
| `/sbom/diff` | `devsecops.py` | POST | SBOM diff |
| `/sbom/validate` | `devsecops.py` | POST | NTIA minimum elements |
| `/sbom/import` | `devsecops.py` | POST | CycloneDX/SPDX import |
| `/sbom/license` | `devsecops.py` | POST | License compliance |
| `/binary/scan` | `devsecops.py` | POST | Binary/firmware scan |
| `/binary/batch` | `devsecops.py` | POST | Fleet intake (spool dir) |
| `/knowledge` | `devsecops.py` | GET | Installed detection packs |

---

## 3. CONTROLLER → SERVICE → REPOSITORY PATTERN

### 3.1 Typical Flow (CBOM Example)
```
Router (cbom.py:cbom_for_system)
  → SystemRepository.get_by_id(system_id)
  → SystemRepository.assets_for(system_id)
  → AssetRepository.replace_for_scan() (on ingest)
  → CbomGenerator.from_records()
  → _render() → JSONResponse/XMLResponse
```

### 3.2 Repository Pattern
**Location:** `services/database/db/repositories/`

| Repository | Key Methods |
|------------|-------------|
| `ScanRepository` | `list_scans`, `get_by_id`, `create` |
| `EvidenceRepository` | `get_all_for_scan`, `create_batch` |
| `AssetRepository` | `list_assets`, `get_by_id`, `replace_for_scan`, `search_located` |
| `SystemRepository` | `list_systems`, `get_by_id`, `get_or_create`, `assets_for`, `dependencies_for`, `catalog_row`, `coverage_summary` |
| `DriftRepository` | `list_events`, `list_since`, `acknowledge`, `resolve`, `mark_false_positive` |
| `CryptoRepository` | `list_states`, `get_state`, `upsert_state`, `update_risk`, `append_event`, `list_events` |

**Issue:** Repositories are instantiated per-request via `Depends(get_db_session)` — no connection pooling per repository.

---

## 4. INCOMPLETE / DEAD ENDPOINTS

### 4.1 Stubs / Minimal Implementation
| Endpoint | Router | Status | Missing |
|----------|--------|--------|---------|
| `/hbom/*` | `hbom.py` | **STUB** | Only frontend page; no backend router found |
| `/nbom` (GET) | `cbom.py` | **PARTIAL** | Only from network scans; no live probe |
| `/graph/hardware-links` | `graph.py` | **PARTIAL** | CRUD only; no cascade integration |
| `/graph/vendor-edges` | `graph.py` | **PARTIAL** | CRUD only; no supply chain analysis |
| `/quantum/*` | `quantum.py` | **MINIMAL** | Only risk analysis; no migration execution |
| `/agility/*` | `agility.py` | **PARTIAL** | Score/readiness; no roadmap execution |
| `/remediation/*` | `remediation.py` | **PARTIAL** | Suggestions only; no tracking |
| `/policy/*` | `policy.py` | **MINIMAL** | Evaluation only; no rule management UI |

### 4.2 Duplicate/Conflicting Endpoints
| Conflict | Routers | Resolution |
|----------|---------|------------|
| `/export` | `export.py` + `audit_export.py` | Different purposes but same prefix |
| `/cbom` + `/techbom` | `cbom.py` + `techbom.py` | Overlapping BOM generation |
| `/crypto/live/*` + `/cbom/live/*` | `crypto.py` + `cbom.py` | Two live CBOM systems |

---

## 5. VALIDATION & AUTHORIZATION GAPS

### 5.1 Input Validation
- ✅ Pydantic schemas on all request bodies (`api/schemas/*.py`)
- ✅ Query parameter validation (Query with constraints)
- ⚠️ **Path traversal:** `WORKSPACE_BASE_PATH` + `CRYPTOSCAN_SOURCE_ROOTS` guard in `api/dependencies.py:validate_workspace_path()` — but only used in scan trigger
- ⚠️ **SSRF:** Target validation in `trigger.py:enqueue_scan_job()` — validates URL scheme/host but not comprehensive

### 5.2 Authorization
| Endpoint Category | Required Role | Implementation |
|-------------------|---------------|----------------|
| Read (scans, findings, cbom, graph) | `viewer` | `get_current_user` (any authenticated) |
| Scan trigger, baseline approve | `auditor`/`admin` | `require_roles("auditor", "admin")` |
| Drift ack/resolve/FP | `auditor` | `require_auditor` dependency |
| Crypto ingest/manage | `crypto.ingest`/`crypto.manage` | `require_permission()` |
| Admin (users, tenants, settings) | `admin` | `require_roles("admin")` |

**Gap:** No resource-level authorization (e.g., user can only see scans in their tenant — relies on `TenantScopeMiddleware` filtering)

---

## 6. ERROR HANDLING

### 6.1 Exception Hierarchy
```python
# api/security/exceptions.py
class CryptoScanError(Exception): pass
class AuthenticationError(CryptoScanError): pass
class ValidationError(CryptoScanError): pass
class AuthorizationError(CryptoScanError): pass
class NotFoundError(CryptoScanError): pass
class ConflictError(CryptoScanError): pass
```

### 6.2 Global Handlers (main.py)
- `AuthenticationError` → 401
- `ValidationError` → 400 with errors list
- Unhandled → 500 (logged)

### 6.3 Issues
| Issue | Location | Impact |
|-------|----------|--------|
| **Inconsistent error shapes** | Some routers return `{"detail": "..."}`, others `{"error": "..."}` | Client handling complexity |
| **No structured error codes** | All routers | Hard to automate retry/fallback |
| **Database errors leak** | `filtered_get()` raises `HTTPException(404)` but SQLAlchemy errors bubble as 500 | Information disclosure risk |
| **Validation errors not logged** | `ValidationError` handler | Debugging difficult |

---

## 7. TRANSACTION & CONCURRENCY

### 7.1 Transaction Boundaries
- **Per-request:** Single DB session per request (FastAPI dependency)
- **Explicit commits:** In routers after multi-step operations (ingest, graph sync, migration plan)
- **Rollback:** On exception in audit logging (`_audit()` helper in drift.py)

### 7.2 Concurrency Issues
| Scenario | Risk | Current Mitigation |
|----------|------|-------------------|
| **Concurrent scan ingest** | Duplicate assets, chain break | Pipeline dedup by content_hash; but DB insert not atomic |
| **Graph snapshot race** | Duplicate versions | Fingerprint check + insert not atomic |
| **Drift ack/resolve** | Lost updates | UPDATE without version check |
| **API key rotation** | Allowlist inconsistency | Rotation not atomic with validation |
| **Worker job dequeue** | Duplicate processing | Redis `LPOP` + DB status update — gap between |

### 7.3 Worker Job Isolation
**File:** `services/worker/worker/core/pool.py`
- Thread pool with `MAX_CONCURRENT_JOBS` (default 4)
- Job status: QUEUED → RUNNING → COMPLETED/FAILED
- **Graceful drain:** `shutdown()` waits for running jobs
- **Backpressure:** Queue depth monitored; `MAX_QUEUE_DEPTH` not enforced

**Gap:** No job-level resource limits (CPU/memory/time); no sandboxing for untrusted repo scans.

---

## 8. RATE LIMITING

**Implementation:** `services/api/api/middleware/rate_limit.py:RateLimitMiddleware`
- **Backend:** Redis (fail-closed in production)
- **Keys:** `ratelimit:{user_id}:{endpoint}` or `ratelimit:ip:{ip}:{endpoint}`
- **Limits:** Configurable per-endpoint (default 100/min user, 5/min IP for login)
- **Response:** 429 with `Retry-After` header

**Gap:** No distributed rate limiting for WebSocket/SSE connections.

---

## 9. SECRETS HANDLING

### 9.1 Environment Variables (docker-compose.yml)
| Secret | Used By | Rotation |
|--------|---------|----------|
| `SECRET_KEY` | Auth sessions, CBOM signing (fallback) | Not supported |
| `CBOM_SIGNING_SECRET` | CBOM JWS signing | Retired secrets via `CRYPTOSCAN_CBOM_RETIRED_SECRETS` |
| `CBOM_PRIVATE_KEY` | Asymmetric JWS (RS256/ES256) | File path or PEM literal |
| `REGISTRY_WEBHOOK_SECRET` | Registry webhook verification | Fail-closed in prod |
| `STREAM_SECRET` | Event stream HMAC | Not rotated |
| `AUDITOR_API_KEY` | Auditor read-only access | Required in prod |
| `GITHUB_WEBHOOK_SECRET` | GitHub webhook verification | — |
| `NEO4J_PASSWORD` | Graph DB | — |
| `POSTGRES_PASSWORD` | Primary DB | — |

### 9.2 Issues
- **No secret rotation automation** — manual env var change + restart
- **Secrets in env vars** — not using Docker secrets or HashiCorp Vault
- **CBOM signing key fallback to SECRET_KEY** — weak if SECRET_KEY compromised

---

## 10. INJECTION & EXECUTION RISKS

### 10.1 Command Execution
| Location | Command | Input Source | Validation |
|----------|---------|--------------|------------|
| `scanner/git/git_client.py` | `git clone`, `git log` | Repo URL, branch | `GitClient.temp_clone()` uses temp dir; URL not validated for command injection |
| `container_scanner` | `docker save`, `trivy` | Image reference | Not inspected — assumed trusted |
| `scripts/scan_estate.py` | Multiple subprocess calls | Config file | Internal use only |

### 10.2 Path Traversal
- **Guard:** `validate_workspace_path()` in `api/dependencies.py` — resolves path, checks under `WORKSPACE_BASE_PATH` or `CRYPTOSCAN_SOURCE_ROOTS`
- **Used in:** Scan trigger (`trigger.py`), SBOM scan (`devsecops.py`)
- **Gap:** Not applied to all file operations (e.g., SBOM artifact download, report export)

### 10.3 SQL Injection
- **ORM:** SQLAlchemy 2.0 — parameterized queries by default
- **Raw SQL:** Minimal; `graph_snapshot.py` uses `select()` with parameters
- **Risk:** Low

### 10.4 Deserialization
- **YAML:** `yaml.safe_load()` used in policy rule loader, config loading
- **JSON:** `json.loads()` — standard
- **Pickle:** Not used

---

## 11. TENANT ISOLATION IN BACKEND

### 11.1 Middleware
`TenantScopeMiddleware` → sets `request.state.tenant_id` from authenticated user
`filtered_get()` helper enforces tenant filter on queries

### 11.2 Bypass Vectors
| Vector | Location | Risk |
|--------|----------|------|
| **Graph snapshots** | `graph_snapshot.py` | Explicit tenant filter but `graph_from_db()` doesn't filter |
| **Neo4j** | `graph_engine/connection/neo4j_driver.py` | No tenant context; all tenants share graph |
| **Event stream** | `api/events/bus.py` | In-process bus not tenant-scoped |
| **Live crypto** | `crypto_live` table | Has tenant_id but `CryptoRepository` filters |
| **Monitor** | `monitor_events_realtime` | Has tenant_id but monitor daemon may cross-tenant |

---

## 12. AUDIT LOGGING

### 12.1 Coverage
| Action | Audited | Detail Captured |
|--------|---------|-----------------|
| Login/logout | ✅ | IP, user agent, MFA |
| Scan trigger | ✅ | User, repo, branch, job_id |
| Baseline approve | ✅ | User, scan_id |
| Drift ack/resolve/FP | ✅ | User, drift_id, notes |
| CBOM ingest/verify | ✅ | User, system_name, signature verification |
| Graph sync/snapshot | ✅ | User, version, fingerprint |
| User management | ✅ | Actor, target user, role changes |
| API key create/rotate | ✅ | Actor, key_id |

### 12.2 Audit Chain
**File:** `services/api/api/security/auth.py:AuthService.audit()`
- Hash chain: `chain_hash = SHA256(prev_hash + payload)`
- Verification endpoint: `GET /api/v1/auth/audit/verify`
- Export: `GET /api/v1/auth/audit/export` (WORM-ready)

---

## 13. MONITORING & HEALTH

### 13.1 Health Endpoints
| Endpoint | Checks | Production Behavior |
|----------|--------|---------------------|
| `/health` | Liveness only | Always 200 if process alive |
| `/ready` | DB health + migration status | 503 if DB down or migrations pending |
| `/healthz` | Alias of `/api/v1/healthz` | LB probe |
| `/readyz` | Alias of `/api/v1/readyz` | K8s probe with drain semantics |

### 13.2 Metrics (`/metrics`)
- `cryptoscan_scans_total` (by status)
- `cryptoscan_findings_total` (by severity)
- `cryptoscan_drift_open_total` (by severity)
- `cryptoscan_jobs_queued_total`
- `cryptoscan_http_requests_total` (by method, path, status)
- `cryptoscan_http_request_duration_seconds` (histogram)

### 13.3 Missing
- No SLO/SLI definitions
- No alerting rules (only monitor daemon alerts)
- No distributed tracing propagation to worker/monitor/Neo4j

---

## 14. BACKEND SECURITY SUMMARY

| Category | Status | Critical Gaps |
|----------|--------|---------------|
| Authentication | ✅ Strong | Session + API key, MFA, lockout |
| Authorization | ⚠️ Partial | Resource-level missing; tenant via middleware only |
| Input Validation | ✅ Good | Pydantic everywhere; path/SSRF guards partial |
| Rate Limiting | ✅ Good | Redis, fail-closed prod |
| Secrets | ⚠️ Weak | Env vars only; no rotation; fallback risks |
| Audit | ✅ Strong | Hash chain, verification, export |
| Encryption | ⚠️ Partial | TLS at nginx; no mTLS; DB encryption not configured |
| Injection | ✅ Low risk | ORM, safe YAML, no pickle |
| Concurrency | ⚠️ Gaps | Race conditions in ingest, snapshot, drift |

---

## 15. RECOMMENDATIONS

### P0 — Critical
1. **Implement resource-level authorization** — check tenant ownership on every mutating operation
2. **Neo4j tenant isolation** — separate databases or document limitation
3. **Fix race conditions** — atomic upserts for scan ingest, graph snapshot, drift ack

### P1 — High
4. **Secret rotation automation** — integrate HashiCorp Vault or AWS Secrets Manager
5. **mTLS between services** — at minimum API ↔ Worker ↔ Monitor
6. **Structured error codes** — RFC 9457 Problem Details format
7. **Job sandboxing** — container isolation for untrusted repo scans

### P2 — Medium
8. **Consolidate duplicate BOM endpoints** — single `/bom` router with type parameter
9. **Complete HBOM backend** — implement hardware BOM generation
10. **API versioning** — formal `/api/v1/`, `/api/v2/` with deprecation headers
11. **Distributed tracing** — propagate trace context through Redis, DB, Neo4j

### P3 — Enhancement
12. **OpenAPI spec generation** — separate files per domain for client SDK generation
13. **Request/response logging** — structured logs for all mutating endpoints
14. **Performance budgets** — p95 latency targets per endpoint category