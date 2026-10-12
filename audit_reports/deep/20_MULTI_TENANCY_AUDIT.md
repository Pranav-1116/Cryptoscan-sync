# 20_MULTI_TENANCY_AUDIT.md
## ZELNX CryptoScan — Multi-Tenancy & Data Isolation Audit

**Generated:** 2026-09-20  
**Method:** Deep inspection of tenant isolation across database, API, cache, graph, and background jobs  
**Scope:** All isolation layers — database, API, cache, Neo4j, event stream, file storage, background workers

---

## EXECUTIVE SUMMARY

| Isolation Layer | Status | Score |
|-----------------|--------|-------|
| Database (Row-Level) | Partial | 6/10 |
| API (Middleware) | Good | 7/10 |
| Neo4j Graph | **Failed** | 0/10 |
| Redis/Cache | **Failed** | 2/10 |
| Event Stream | Partial | 4/10 |
| Background Workers | Partial | 4/10 |
| File/Artifact Storage | **Failed** | 1/10 |
| Audit/Export | Partial | 5/10 |

**Overall: 3.5/10 — NOT READY for multi-tenant SaaS**

**Critical Blockers:** Neo4j shared database, link tables without tenant_id, shared Redis, shared file volumes.

---

## 1. DATABASE ISOLATION

### 1.1 Row-Level Security Implementation

**Mechanism:** `TenantScoped` mixin + `filtered_get()` helper

```python
# db/tenancy.py
class TenantScoped:
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)

def filtered_get(db, model, id):
    return db.query(model).filter(model.id == id, model.tenant_id == current_tenant()).first()
```

**Coverage:** 32/52 models (62%)

### 1.2 Models WITH Tenant Isolation

| Model | Table | `TenantScoped` | `filtered_get` |
|-------|-------|----------------|----------------|
| `Scan` | `scans` | ✅ | ✅ |
| `EvidenceRecord` | `evidence_records` | ✅ | ✅ |
| `CryptoAsset` | `crypto_assets` | ✅ | ✅ |
| `System` | `systems` | ✅ | ✅ |
| `DriftEvent` | `drift_events` | ✅ | ✅ |
| `Baseline` | `baselines` | ✅ | ✅ |
| `ScanJob` | `scan_jobs` | ✅ | ✅ |
| `RepoConfiguration` | `repo_configurations` | ✅ | ✅ |
| `User` | `users` | ✅ | ✅ |
| `Tenant` | `tenants` | ✅ | ✅ |
| `APIKey` | `api_keys` | ✅ | ✅ |

### 1.3 Models WITHOUT Tenant Isolation (CRITICAL)

| Model | Table | Risk |
|-------|-------|------|
| `SystemAsset` | `system_assets` | Link table — join bypass |
| `SystemDependency` | `system_dependencies` | Link table — join bypass |
| `CertificateUsage` | `certificate_usage` | Link table — join bypass |
| `CryptoAssetEvidence` | `crypto_asset_evidence` | Link table — join bypass |
| `SystemBusinessProcess` | `system_business_process` | Link table — join bypass |
| `SystemBusinessProcessMap` | `system_business_process_map` | Link table — join bypass |
| `GraphSnapshot` | `graph_snapshots` | Manual filter only (mig 0071) |

**Impact:** A query joining `systems` → `system_assets` → `crypto_assets` bypasses tenant filter if not explicitly scoped.

---

### 1.4 Tenant Context Resolution

**File:** `services/api/api/dependencies.py:_resolve_tenant_context()`

```python
# Priority:
# 1. API key tenant binding (hard-bound)
# 2. X-Tenant-ID header (for superadmin)
# 3. User memberships (auto-resolve single, require header for multiple)
```

**Gap:** Middleware (`TenantScopeMiddleware`) runs AFTER auth but some routers don't use `get_tenant_context` dependency.

---

### 1.5 Tenant Scope Middleware

**File:** `services/api/api/middleware/tenant_scope.py`

```python
# Runs AFTER AuthMiddleware
# Calls resolve_tenant_for_request() for every request
# Sets db session tenant filter via tenant_scope()
```

**Gap:** Runs on ALL requests including those that shouldn't be scoped (health, metrics, webhooks).

---

## 2. NEO4J GRAPH ISOLATION — CRITICAL FAILURE

### 2.1 Current State

```python
# services/graph_engine/graph_engine/connection/neo4j_driver.py
def get_driver() -> Driver:
    # Single driver for ALL tenants
    return GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
```

### 2.2 No Tenant Separation

| Aspect | Implementation |
|--------|----------------|
| Database | Single `neo4j` database |
| Nodes | No `tenant_id` property |
| Relationships | No `tenant_id` property |
| Queries | No tenant filter |
| Snapshots | Tenant-scoped in PostgreSQL only |

### 2.3 Cross-Tenant Leakage Vectors

| Vector | Example |
|--------|---------|
| `GET /graph` | Returns ALL tenants' nodes/edges |
| `GET /graph/blast-radius` | Traverses cross-tenant edges |
| `GET /graph/vendor-chains` | Shows all vendors |
| `POST /graph/sync` | Syncs ALL tenants' data to same Neo4j |
| `GraphEngine.vendor_chain()` | Returns cross-tenant vendor paths |

### 2.4 Mitigation Options

| Option | Effort | Isolation |
|--------|--------|-----------|
| Separate Neo4j DB per tenant | High | Complete |
| Neo4j Fabric (multi-db) | High | Complete |
| Namespace isolation (tenant_id property) | Medium | Application-level |
| Document single-tenant only | Zero | None |

**Recommendation:** Document single-tenant limitation OR implement separate DBs per tenant.

---

## 3. REDIS/CACHE ISOLATION

### 3.1 Shared Redis Usage

| Usage | Key Pattern | Isolation |
|-------|-------------|-----------|
| Job queue | `cryptoscan:jobs:queue` | **None** — all tenants share |
| Rate limiting | `ratelimit:{user_id}:{endpoint}` | Per-user, not per-tenant |
| Event federation | `zelinx:events:*` | **None** — shared pub/sub |
| Current run store | `zelinx:current_run:{tenant}` | Tenant-prefixed ✅ |
| Session store | `session:{token}` | Token-based, not tenant |

### 3.3 Rate Limiting Bypass

```python
# rate_limit.py
key = f"ratelimit:{user_id}:{endpoint}"  # No tenant prefix
```

**Impact:** Tenant A's requests count against Tenant B's limits if same user_id (unlikely but possible with shared users).

---

### 3.4 Event Federation Cross-Tenant Leakage

```python
# events/redis_sync.py
# Publishes ALL events to Redis channel
# All API replicas receive ALL tenants' events
```

**Impact:** Tenant A's scan events visible to Tenant B's dashboard if they share Redis.

---

## 4. EVENT STREAM ISOLATION

### 4.1 In-Process Event Bus

**File:** `services/api/api/events/bus.py`

```python
class EventBus:
    def __init__(self):
        self._subscribers: dict[str, list[Callable]] = defaultdict(list)
```

**Scope:** Process-local. In multi-replica deployment, each replica has own bus.

---

### 4.2 Redis Federation

```python
# events/redis_sync.py:start_redis_federation()
# Publishes local events to Redis, subscribes to remote events
# NO tenant filtering
```

**Impact:** All tenants' events replicated to all replicas.

---

### 4.3 DB Tailer

```python
# events/tailer.py:tail_events()
# Tails platform_events table (tenant-scoped)
# But publishes to in-process bus without tenant filter
```

---

## 5. BACKGROUND WORKER ISOLATION

### 5.1 Worker Architecture

**File:** `services/worker/worker/core/pool.py`

```python
class WorkerPool:
    def __init__(self):
        self._executor = ThreadPoolExecutor(max_workers=MAX_CONCURRENT_JOBS)
```

### 5.2 Job Isolation Gaps

| Gap | Impact |
|-----|--------|
| **Shared job queue** | `cryptoscan:jobs:queue` — all tenants' jobs in same Redis list |
| **No tenant context in worker** | Worker doesn't set tenant scope for DB session |
| **Shared workspace** | `/tmp/cryptoscan-workspaces` — all tenants' clones in same directory |
| **No resource quotas per tenant** | One tenant's large scan blocks others |

### 5.3 Worker Tenant Context

```python
# worker/core/pool.py — NO tenant context set
# Jobs execute with platform-level DB session
```

**Required:** Worker must extract tenant_id from job payload and set `tenant_scope()` for DB session.

---

## 5. FILE/ARTIFACT STORAGE ISOLATION

### 5.1 Shared Volumes

| Volume | Path | Contents | Isolation |
|--------|------|----------|-----------|
| `telecom_data` | `/var/lib/cryptoscan/telecom` | Event stream, live CBOM, traces | **None** |
| `traces_data` | `/var/lib/cryptoscan/telecom/traces` | W3C traces | **None** |
| Workspace | `/tmp/cryptoscan-workspaces` | Git clones, extracted sources | **None** |

### 5.2 Artifact Storage

```python
# CBOM artifacts stored in DB (crypto_assets, evidence_records)
# But SBOM artifacts, binary scan artifacts, reports stored on filesystem
```

**Gap:** No tenant prefix in artifact paths.

---

## 6. API ISOLATION

### 6.1 Middleware Stack

```python
# main.py middleware order (outer to inner):
1. CORSMiddleware
2. TrustedHostMiddleware
3. LoggingMiddleware
4. GZipMiddleware
5. RequestIDMiddleware
6. TenantScopeMiddleware  # ← Sets tenant scope
7. AuthMiddleware         # ← Validates auth
8. RateLimitMiddleware    # ← Per-user, not per-tenant
9. ObservabilityMiddleware
10. AbacMiddleware        # ← ABAC (opt-in)
11. SecurityHeadersMiddleware
12. ControlEventMiddleware
```

### 6.2 Isolation Verification

| Check | Implementation |
|-------|----------------|
| **Request scoped** | `tenant_scope()` context manager on DB session |
| **Query filtering** | `filtered_get()` + `tenant_scope()` on all repos |
| **Header validation** | `X-Tenant-ID` validated against memberships |
| **API key binding** | Key hard-bound to tenant at creation |

### 6.3 API Isolation Gaps

| Gap | Location |
|-----|----------|
| **GraphQL endpoint** | `/graphql` — no tenant context in resolvers |
| **WebSocket endpoints** | `/ws/*` — no tenant scope in connection |
| **SSE endpoints** | `/events/*` — event bus not tenant-scoped |
| **Metrics endpoint** | `/metrics` — exposes all tenants' metrics |
| **Health/ready** | `/health`, `/ready` — no tenant context needed |

---

## 7. EXPORT/ARTIFACT ISOLATION

### 7.1 CBOM Export

```python
# cbom.py:cbom_portfolio()
# Loads ALL assets across ALL tenants (if platform admin)
# Tenant-scoped only if X-Tenant-ID header or membership
```

### 7.2 Report Export

```python
# scans.py:generate_report()
# Uses get_tenant_context() — properly scoped
```

### 7.3 Evidence Export

```python
# audit_export.py:export_evidence()
# Uses filtered_get() — properly scoped
```

### 7.4 Audit Log Export

```python
# auth.py:audit_export()
# Platform admin sees all; tenant admin sees own tenant
```

---

## 8. CROSS-TENANT LEAKAGE TEST SCENARIOS

### 8.1 Scenario 1: Graph Query

**Setup:** Tenant A and Tenant B both have systems with crypto assets.

**Attack:** Tenant A calls `GET /graph/blast-radius?system_id=B's_system`

**Result:** **SUCCESS** — Returns Tenant B's downstream systems because Neo4j shared.

---

### 8.2 Scenario 2: Rate Limit Bypass

**Setup:** Tenant A and Tenant B share a user (unlikely but possible).

**Attack:** Tenant A makes 1000 requests, exhausts rate limit for shared user_id.

**Result:** **PARTIAL** — Rate limit keyed by user_id, not tenant_id.

---

### 8.3 Scenario 3: Event Stream Snooping

**Setup:** Tenant A's dashboard connects to SSE `/events/global`.

**Attack:** Tenant A receives Tenant B's `SCAN_COMPLETED` events via Redis federation.

**Result:** **SUCCESS** — Events not tenant-filtered in federation.

---

### 8.4 Scenario 4: Workspace Collision

**Setup:** Tenant A scans repo `https://github.com/org/repo`, Tenant B scans same repo.

**Attack:** Both clone to `/tmp/cryptoscan-workspaces/org/repo` — second scan corrupts first.

**Result:** **SUCCESS** — Shared workspace directory.

---

### 8.5 Scenario 5: CBOM Portfolio

**Setup:** Platform admin (superadmin) without `X-Tenant-ID` header.

**Attack:** Calls `GET /cbom/portfolio` — returns ALL tenants' crypto assets.

**Result:** **SUCCESS** — Platform admin sees all tenants by default.

---

## 9. COMPLIANCE REQUIREMENTS

### 9.1 Data Residency

| Requirement | Status |
|-------------|--------|
| EU data in EU | Not enforced — single DB region |
| Data not leaving tenant | **Failed** — Neo4j, Redis, event stream |
| Tenant data deletion | Partial — CASCADE deletes but no verification |

---

### 9.2 Audit Requirements

| Requirement | Status |
|-------------|--------|
| Tenant-scoped audit log | ✅ Implemented |
| Cross-tenant access logging | ❌ Missing |
| Tenant admin audit trail | ✅ Implemented |

---

## 10. SAAS DEPLOYMENT READINESS

| Requirement | Status | Blocker |
|-------------|--------|---------|
| Tenant onboarding | ✅ | — |
| Tenant isolation (DB) | ⚠️ Partial | Link tables |
| Tenant isolation (Graph) | ❌ Failed | Neo4j shared |
| Tenant isolation (Cache) | ❌ Failed | Redis shared |
| Tenant isolation (Events) | ❌ Failed | Federation unscoped |
| Tenant isolation (Workers) | ❌ Failed | No tenant context |
| Tenant isolation (Files) | ❌ Failed | Shared volumes |
| Tenant billing | ❌ Stub | `billing` service not implemented |
| Tenant customization | ❌ Missing | No per-tenant config |
| Tenant data export | ✅ | Scoped exports work |
| Tenant data deletion | ⚠️ Partial | CASCADE but no verification |

---

## 11. CLASSIFICATION MATRIX

| Component | Classification | Evidence |
|-----------|----------------|----------|
| Database (core tables) | **SAFE** | `TenantScoped` + `filtered_get()` |
| Database (link tables) | **UNSAFE** | No `tenant_id`, join bypass |
| API Middleware | **SAFE** | `TenantScopeMiddleware` + `filtered_get()` |
| Neo4j Graph | **UNSAFE** | Single DB, no tenant property |
| Redis (Queue) | **UNSAFE** | Shared queue, no tenant prefix |
| Redis (Rate Limit) | **UNSAFE** | No tenant in key |
| Redis (Event Federation) | **UNSAFE** | Cross-tenant pub/sub |
| Event Stream (In-Process) | **PARTIAL** | Process-local but replicas share via Redis |
| Background Workers | **UNSAFE** | No tenant context, shared queue |
| File Storage | **UNSAFE** | Shared workspace, shared telecom volume |
| Audit/Export | **SAFE** | Properly scoped via `get_tenant_context()` |
| WebSocket/SSE | **UNSAFE** | No tenant scope in connection |
| Metrics | **UNSAFE** | `/metrics` exposes all tenants |

---

## 12. REMEDIATION ROADMAP

### Phase 1: Critical (P0) — Before SaaS Launch

| Task | Effort | Dependency |
|-----|--------|------------|
| Add `tenant_id` to 4 link tables + migration | 2 days | Schema change |
| Implement Neo4j tenant isolation (separate DBs) | 2 weeks | Infra change |
| Add tenant prefix to Redis keys | 1 week | Key migration |
| Add tenant context to worker pool | 1 week | Worker refactor |
| Tenant-scoped workspace directories | 3 days | Path template |
| Event federation tenant filtering | 1 week | Redis channels per tenant |

### Phase 2: High (P1)

| Task | Effort |
|-----|--------|
| Tenant-scoped file storage | 1 week |
| WebSocket/SSE tenant scope | 1 week |
| Metrics tenant filtering | 3 days |
| Cross-tenant access audit logging | 1 week |
| Tenant data deletion verification | 1 week |

### Phase 3: Medium (P2)

| Task | Effort |
|-----|--------|
| Tenant billing implementation | 2 weeks |
| Per-tenant resource quotas | 1 week |
| Tenant customization (settings) | 2 weeks |
| Data residency controls | 2 weeks |

---

## 13. VERIFICATION CHECKLIST

### 13.1 Automated Tests Needed

| Test | Description |
|------|-------------|
| `test_tenant_isolation_db` | Tenant A cannot read Tenant B's scans via ORM |
| `test_tenant_isolation_graph` | Tenant A cannot traverse Tenant B's nodes |
| `test_tenant_isolation_redis` | Tenant A's rate limit doesn't affect Tenant B |
| `test_tenant_isolation_worker` | Worker sets correct tenant scope |
| `test_tenant_isolation_files` | Tenant A's artifacts not accessible to Tenant B |
| `test_tenant_isolation_events` | Tenant A doesn't receive Tenant B's events |
| `test_cross_tenant_scenarios` | All 5 leakage scenarios blocked |

---

## 14. CONCLUSION

**CryptoScan is NOT multi-tenant ready.** The database row-level security is well-implemented for core tables but fails at link tables. The Neo4j graph database has zero tenant isolation. Redis cache, event stream, background workers, and file storage all share resources across tenants.

**For single-tenant enterprise deployment:** Ready with current architecture.

**For multi-tenant SaaS:** Requires 6-8 weeks of focused engineering on isolation layers before any pilot.

---

## 15. EVIDENCE INDEX

All findings traceable to source files:

| Finding | File |
|---------|------|
| `TenantScoped` mixin | `services/database/db/tenancy.py` |
| `filtered_get()` | `services/database/db/tenancy.py` |
| Link tables missing tenant_id | `services/database/db/models/system_asset.py`, etc. |
| Neo4j driver | `services/graph_engine/graph_engine/connection/neo4j_driver.py` |
| TenantScopeMiddleware | `services/api/api/middleware/tenant_scope.py` |
| Redis rate limiting | `services/api/api/middleware/rate_limit.py` |
| Event federation | `services/api/api/events/redis_sync.py` |
| Worker pool | `services/worker/worker/core/pool.py` |
| Docker volumes | `docker-compose.yml` |
| Workspace path | `services/api/api/config/settings.py:WORKSPACE_BASE_PATH` |
---

## Round 26 update (2026-10-10) — isolation claims re-verified

* **§1.3 link tables without tenant_id — STALE.** `system_assets`,
  `system_dependencies`, `crypto_asset_evidence`, `certificate_usage`
  (and the business-process maps) all carry `TenantScoped` today.
* **§5.2 worker tenant context — STALE.** `worker/core/job_consumer.py`
  carries `tenant_id` across the queue and re-enters the caller's scope;
  bulk inserts stamp the scan owner's tenant explicitly (an unscoped
  write would land as platform estate — the code says so in comments).
* **§3.4/§8.3 event federation cross-tenant — STALE.** Federation frames
  carry `tenant_id`; the SSE surface uses per-tenant buses
  (`get_bus_for_tenant`).
* **§3.3 rate-limit keying — ADDRESSED.** Windows key on the API key
  digest or session user (else client IP); the shared-user scenario is
  mitigated by per-key buckets.
* **§8.4 workspace collision — STALE.** Clones live under
  `<workspace>/<job-id>/repo`.
* **§6.3 /metrics — MITIGATED.** Token-gated operational counters, no
  per-tenant dimensions.
* **REMAIN OPEN, deployment/product-scoped:** Neo4j per-tenant isolation
  (same item as deep/27 P0#1 — separate DBs or property-scoped Cypher
  is an infrastructure decision; the in-memory fallback stays scoped),
  per-tenant resource quotas, billing, data-residency enforcement.

## Round 35 addendum (2026-10-12) — Neo4j per-tenant isolation, WRITE side BUILT

The §6.3-adjacent infrastructure decision now has its write-side half
in code: every node MERGE keys on `(tenant_id, business id)` and stamps
`tenant_id` explicitly (upgrade-safe); every edge endpoint MATCH is
tenant-scoped; `PRUNE_KIND` deletes only within the syncing tenant —
plus un-stamped legacy nodes, and only on a platform-scope sync
(self-migrating cleanup that cannot eat another tenant's nodes).
One stamping point in `Neo4jGraphStore.sync()`; payload builders
re-attach the stamp (a real bug found by the fake-driver tests: fresh
builder dicts dropped it, which would have fed every node to the
platform prune). Read queries are deliberately still un-filtered: under
a tenant scope the facade serves the memory engine (the existing
zero-Bolt isolation contract, unchanged and pinned by
`test_tenant_isolation.py`); property-scoped read Cypher or per-tenant
databases remain the deployment decision this report recorded. Tests:
`services/graph_engine/tests/test_tenant_node_identity.py`.
