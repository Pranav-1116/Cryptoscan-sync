# 02_ARCHITECTURE_AUDIT.md
## ZELNX CryptoScan — Architecture Audit

**Generated:** 2026-09-20  
**Scope:** Architectural assessment of the actual implementation vs. stated principles

---

## EXECUTIVE SUMMARY

The repository implements a **genuinely deterministic, evidence-first cryptographic intelligence platform** with 51 backend services, 71 frontend pages, and a comprehensive pipeline from source discovery through CBOM/HBOM to drift detection and PQC readiness. The architecture follows the stated principle "Deterministic Truth First, AI Assists Second" — no AI/ML is used in evidence collection, normalization, or policy evaluation.

**Overall Architecture Grade: A-** (Strong foundation, some integration gaps, operational complexity)

---

## 1. ARCHITECTURAL PRINCIPLES — COMPLIANCE AUDIT

| Principle | Stated | Implemented | Evidence |
|-----------|--------|-------------|----------|
| Deterministic evidence collection | ✅ | ✅ | Static AST parsers, binary disassembly, live TLS probes — no heuristics |
| No AI in decision path | ✅ | ✅ | Policy engine is pure YAML rule evaluation; AI only in `simulator` labeled "AI RECOMMENDATION" |
| Evidence chain integrity | ✅ | ✅ | SHA-256 content hash + blockchain-style chain hash + manifest |
| CBOM as standard output | ✅ | ✅ | CycloneDX 1.5 with cryptoProperties, JWS signing, verification |
| Crypto-agility as first-class | ✅ | ✅ | 6-factor agility score, 5-factor readiness, migration waves, 10 scenario simulator |
| Tenant isolation | ✅ | ⚠️ Partial | Row-level `TenantScoped` mixin + `filtered_get()`, but some queries bypass (graph snapshots) |
| Fail-closed production defaults | ✅ | ✅ | Startup rejects demo secrets, plaintext admin, SQLite, wildcard CORS |
| Honest unknowns | ✅ | ✅ | Dashboard shows "UNKNOWN — no live evidence" not zeros; NBOM excludes unreachable endpoints |

---

## 2. SERVICE ARCHITECTURE ANALYSIS

### 2.1 Service Boundaries — STRENGTHS
- **Clear domain separation:** Each cryptographic domain (scanner, network, container, cloud, OT) is isolated
- **Shared kernel:** `shared_models` provides canonical types (algorithm registry, quantum classification, canonical serialization)
- **Explicit contracts:** Services communicate via database models + API, not direct calls

### 2.2 Service Boundaries — WEAKNESSES

| Issue | Location | Impact |
|-------|----------|--------|
| **Service proliferation** | 51 services | Operational complexity; many services < 5 files (`billing`, `sla`, `vaultlease`, `connector_sdk`, `keyassure`, `privacy`, `ot_safety`, `ruleset`, `universal_platform`, `universal_vendor`) |
| **Duplicate concepts** | `cbom` + `techbom` + `nbom` routers | Three BOM types with overlapping generators; `techbom.py` 58K lines duplicates CBOM logic |
| **God service** | `api` (325 router files, 85 registered) | API service is a monolith; routers import from 30+ other services creating circular dependency risk |
| **Orphan services** | `marketplace`, `datalake`, `anomaly`, `governance` | Registered routers but minimal implementation; appear to be scaffolded for future |

### 2.3 Critical Architectural Flows

```
SOURCE CODE
    │
    ▼
┌─────────────────────────────────────┐
│  scanner (static)                   │
│  ├── FileDiscovery                  │
│  ├── LanguageDetector (30+ langs)   │
│  ├── Per-language Parsers (25)      │
│  ├── Detectors (6)                  │
│  ├── Extractors (6)                 │
│  ├── Cascade Analysis               │
│  └── Output: RawFinding[] + evidence│
└─────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────┐
│  evidence pipeline                  │
│  ├── Canonical JSON serialization   │
│  ├── Content hash (SHA-256)         │
│  ├── Deduplication by content hash  │
│  ├── Chain hash (blockchain-style)  │
│  └── Manifest (Merkle root)         │
└─────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────┐
│  normalization                      │
│  ├── RuleRegistry (YAML rules)      │
│  ├── Exact/Pattern/Fallback match   │
│  ├── Enrichers: NIST, IANA, CBOM    │
│  └── Output: NormalizedCrypto       │
└─────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────┐
│  policy engine                      │
│  ├── RuleLoader (YAML)              │
│  ├── RuleValidator                  │
│  ├── PolicyEvaluator (deterministic)│
│  └── Output: PolicyEvaluation       │
└─────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────┐
│  graph engine                       │
│  ├── Neo4j / In-memory backend      │
│  ├── Nodes: System, Asset, Process  │
│  ├── Edges: USES, CALLS, DEPENDS_ON │
│  ├── Queries: blast radius, impact  │
│  └── Snapshots: content-addressed   │
└─────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────┐
│  CBOM generator                     │
│  ├── CycloneDX 1.5 + cryptoProperties│
│  ├── JWS signing (RS256/ES256/HS256)│
│  ├── Verification report            │
│  ├── Diff, ingest, custom, portfolio│
└─────────────────────────────────────┘
```

---

## 3. DATA MODEL COHERENCE

### 3.1 Strengths
- **Single source of truth for algorithms:** `shared_models/algorithm_registry.py` (64K lines) — 300+ entries with OID, NIST designation, quantum status
- **Canonical serialization:** `shared_models/canonical.py` used by evidence, CBOM signing, fingerprinting
- **Quantum classification:** Single function `is_shor_vulnerable()` used by quantum risk, graph hotspots, remediation

### 3.2 Inconsistencies

| Inconsistency | Location | Risk |
|---------------|----------|------|
| **Multiple CryptoAsset models** | `db/models/crypto_asset.py` vs `shared_models/crypto_asset.py` | Divergent fields; API uses DB model, universal_crypto uses shared |
| **Evidence in 3 places** | `EvidenceRecord` (DB), `Evidence` (universal_crypto), `EvidenceRecordDTO` (shared) | Different schemas, different purposes |
| **Scan vs ScanJob** | `Scan` (completed) vs `ScanJob` (queued/running) | Status overlap; worker updates both |
| **System vs SystemAsset** | `System` has `assets` relationship, `SystemAsset` is separate link table | Redundant; `SystemAsset` adds `source` field but not used consistently |
| **CBOM in 3 services** | `cbom` service, `techbom` router, `crypto` live CBOM | Different generators, different schemas |

---

## 4. INTEGRATION PATTERNS

### 4.1 Database-Centric Integration (Primary)
```
Service A → writes to DB → Service B reads from DB
```
- Used by: scanner → evidence → normalization → policy → CBOM → graph
- **Problem:** Tight coupling to schema; schema changes cascade to all services

### 4.2 API-Centric Integration (Secondary)
```
Service A → HTTP → API Router → Service B
```
- Used by: frontend → API, webhook receivers, external integrations
- **Problem:** API service imports from 30+ services (circular import risk)

### 4.3 Event-Driven Integration (Emerging)
```
Service A → EventBus → Service B (async)
```
- Used by: `ControlEventMiddleware` → event stream → monitor, dashboard SSE
- **Problem:** In-process bus only; Redis federation added but not fully integrated

---

## 5. SCALABILITY ARCHITECTURE

### 5.1 Horizontal Scaling
| Component | Scaling Strategy | Status |
|-----------|-----------------|--------|
| API | Multiple replicas + Redis rate limit + Redis event federation | ✅ Implemented |
| Worker | `MAX_CONCURRENT_JOBS` thread pool per replica | ✅ Implemented |
| Monitor | Single leader (lease-based) | ✅ Implemented |
| Scanner | Multiprocess per scan (`CRYPTOSCAN_SCAN_PROCESSES`) | ✅ Implemented |
| Database | Read replicas not configured | ❌ Missing |
| Neo4j | Single instance; no clustering | ❌ Missing |
| Redis | Single instance; sentinel/cluster not configured | ❌ Missing |

### 5.2 Bottlenecks Identified
1. **API monolith** — All 85 routers in one process; memory/CPU pressure under load
2. **Database connection pool** — Single pool for all routers; no per-service pooling
3. **Graph sync** — `POST /graph/sync` loads entire inventory into Neo4j; O(N) on each sync
4. **CBOM portfolio** — `_located_assets()` loads ALL assets into memory for estate CBOM

---

## 6. SECURITY ARCHITECTURE

### 6.1 Defense in Depth — IMPLEMENTED
- ✅ Non-root containers, `no-new-privileges`, `cap_drop: ALL`
- ✅ TLS termination at nginx, mTLS not configured
- ✅ Rate limiting (Redis-backed, fail-closed in prod)
- ✅ Input validation (Pydantic schemas on all endpoints)
- ✅ Path traversal protection (`WORKSPACE_BASE_PATH` + `CRYPTOSCAN_SOURCE_ROOTS`)
- ✅ SSRF protection (target validation guard)
- ✅ Audit hash chain with verification endpoint

### 6.2 Security Gaps
| Gap | Location | Severity |
|-----|----------|----------|
| **No mTLS between services** | Docker network | P1 |
| **Secrets in env vars** | docker-compose.yml | P1 |
| **No API request signing** | Inter-service calls | P2 |
| **Graph snapshot tenant isolation bypass** | `graph_snapshot.py` uses explicit tenant filter | P2 |
| **CBOM signing key rotation** | Single `CRYPTOSCAN_CBOM_SECRET` + retired secrets | P2 |

---

## 7. TENANT ISOLATION AUDIT

### 7.1 Implementation
```python
# db/tenancy.py — TenantScoped mixin
class TenantScoped:
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)

# filtered_get() helper enforces tenant filter
def filtered_get(db, model, id):
    return db.query(model).filter(model.id == id, model.tenant_id == current_tenant()).first()
```

### 7.2 Coverage
| Model | TenantScoped | filtered_get used | Gap |
|-------|--------------|-------------------|-----|
| Scan | ✅ | ✅ | — |
| EvidenceRecord | ✅ | ✅ | — |
| CryptoAsset | ✅ | ✅ | — |
| System | ✅ | ✅ | — |
| GraphSnapshot | ✅ | ⚠️ | Explicit filter in query |
| VerificationLog | ✅ | ❌ | Not exposed via API |
| Baseline | ✅ | ✅ | — |
| DriftEvent | ✅ | ✅ | — |

### 7.3 Cross-Tenant Leakage Vectors
1. **Graph snapshots** — `graph_snapshot.py` queries with explicit `tenant_id` but `graph_from_db()` doesn't filter
2. **Neo4j** — No tenant isolation in graph backend; all tenants share graph
3. **Event stream** — In-process bus not tenant-scoped; Redis federation publishes all events

---

## 8. OBSERVABILITY ARCHITECTURE

### 8.1 Implemented
- **Metrics:** Prometheus `/metrics` (scan counts, findings by status, drift, queue depth)
- **Tracing:** W3C trace-context on every request, `TraceStore` with JSONL sink + OTLP export
- **Logging:** Structlog with JSON output in production, request ID correlation
- **Health:** `/health` (liveness), `/ready` (readiness + migration status)

### 8.2 Missing
- **Distributed tracing:** No span propagation to worker/monitor/Neo4j
- **Alerting:** Only monitor daemon alerts (CEF/webhook/email); no PrometheusAlertmanager
- **SLO/SLI:** Not defined
- **Log aggregation:** File-only; no Loki/Elasticsearch integration

---

## 9. DEPLOYMENT ARCHITECTURE

### 9.1 Docker Compose (Development)
- 7 services: postgres, redis, neo4j, neo4j-init, api, worker, monitor, frontend, nginx
- Shared volumes for telecom data, traces
- Health checks on all infrastructure

### 9.2 Production Overrides (`docker-compose.prod.yml`)
- Secrets from environment (not defaults)
- Resource limits
- Restart policies

### 9.3 Kubernetes (`k8s/app/`)
- Deployments with probes, resources, non-root
- ServiceMonitor for Prometheus
- **Missing:** HorizontalPodAutoscaler, PodDisruptionBudget, NetworkPolicy, mTLS (Istio/Linkerd)

---

## 10. ARCHITECTURAL DEBT — PRIORITIZED

| Priority | Issue | Affected Components | Remediation |
|----------|-------|---------------------|-------------|
| **P0** | API service is a monolith (325 routers) | All API routes | Split into domain-specific API services (scans, inventory, graph, crypto, compliance) |
| **P0** | No database read replicas | All read-heavy endpoints | Configure read replicas; route analytics/reporting to replicas |
| **P1** | Neo4j single point of failure | Graph engine, blast radius, vendor chains | Neo4j cluster or fallback to in-memory with sync |
| **P1** | Tenant isolation incomplete in graph/Neo4j | Multi-tenant deployments | Implement tenant-scoped subgraphs or separate Neo4j databases |
| **P1** | CBOM/TechBOM/NBOM duplication | `cbom` service, `techbom` router, `crypto` live | Unify under single BOM service with type parameter |
| **P2** | Service proliferation (51 services) | Operations, deployment | Consolidate <5-file services; use libraries not services |
| **P2** | No distributed tracing propagation | Worker, monitor, Neo4j | Add trace context to Redis queue, DB queries, Neo4j sessions |
| **P2** | Event bus not tenant-scoped | Real-time dashboard, monitor | Add tenant_id to all events; filter at consumer |
| **P3** | Configuration sprawl | 51 services × env vars | Centralized config service (Consul/etcd) or pydantic-settings with validation |
| **P3** | No API versioning strategy | All routers | Implement URL versioning (`/api/v1/`, `/api/v2/`) with deprecation policy |

---

## 11. ARCHITECTURAL DECISIONS — ASSESSMENT

| Decision | Assessment | Evidence |
|----------|------------|----------|
| **SQLAlchemy 2.0 + Alembic** | ✅ Sound | 71 migrations, schema-parity tests, async-ready |
| **FastAPI + Pydantic 2** | ✅ Sound | Type-safe, OpenAPI generation, dependency injection |
| **Neo4j for graph** | ⚠️ Risk | Single instance, no HA, operational burden |
| **Redis for queue + rate limit + events** | ✅ Sound | Multi-purpose but single instance |
| **CycloneDX 1.5 for CBOM** | ✅ Sound | Industry standard, cryptoProperties extension |
| **YAML policy rules** | ✅ Sound | Human-readable, version-controlled, hot-reloadable |
| **Multiprocess scanner** | ✅ Sound | CPU-bound parsing benefits from processes not threads |
| **Canonical JSON for hashing** | ✅ Sound | Interoperable with CBOM signing, fingerprinting |
| **In-memory graph fallback** | ✅ Sound | Works without Neo4j; same query API |
| **Lazy-loaded frontend routes** | ✅ Sound | 71 pages, code-split, fast initial load |

---

## 12. RECOMMENDATIONS — ARCHITECTURAL

### Immediate (P0)
1. **Split API monolith** into 5-6 domain services (scans, inventory, graph, crypto, compliance)
2. **Add database read replicas** for reporting/analytics endpoints
3. **Fix tenant isolation in graph** — either tenant-scoped Neo4j or remove Neo4j from multi-tenant path

### Short-term (P1)
4. **Unify BOM services** — single `bom` service handling CBOM/HBOM/NBOM/TechBOM
5. **Consolidate micro-services** — merge 10+ services with <5 files into libraries
6. **Add distributed tracing** — propagate trace context through Redis queue, DB, Neo4j

### Medium-term (P2)
7. **Neo4j HA** — cluster or document single-instance limitation
8. **Event bus tenant scoping** — add tenant_id to all platform events
9. **Configuration service** — replace env var sprawl with central config

### Long-term (P3)
10. **API versioning** — formal deprecation policy, versioned OpenAPI specs
11. **Service mesh** — mTLS, traffic splitting, observability (Istio/Linkerd)
12. **Multi-region** — active-passive or active-active for DR

---

## 13. VERDICT

**The architecture is fundamentally sound and implements the stated principles.** The deterministic pipeline (source → evidence → normalization → policy → graph → CBOM) is real and auditable. The primary architectural risks are **operational complexity from service proliferation** and **incomplete tenant isolation in the graph layer**. The API monolith is the single largest technical debt item and should be decomposed before significant scale.