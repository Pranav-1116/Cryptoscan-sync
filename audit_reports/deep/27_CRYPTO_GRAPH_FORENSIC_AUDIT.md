# 27_CRYPTO_GRAPH_FORENSIC_AUDIT.md
## ZELNX CryptoScan — Crypto Dependency Graph Forensic Audit

**Generated:** 2026-09-20  
**Method:** Deep inspection of graph engine, Neo4j backend, API endpoints, data flow from source to graph queries  
**Scope:** Graph build, persistence, queries, evidence linkage, migration waves, blast radius, vendor chains

---

## EXECUTIVE SUMMARY

| Aspect | Score | Status |
|--------|-------|--------|
| Graph Model | 8/10 | 11 node types, 10 edge types |
| In-Memory Engine | 8/10 | Full query suite |
| Neo4j Backend | 5/10 | No tenant isolation, full sync only |
| Evidence Linkage | 4/10 | Weak — asset.extra only |
| Query API | 9/10 | Comprehensive query surface |
| Migration Waves | 8/10 | Cycle-constrained, readiness-based |
| Blast Radius | 8/10 | Forward + reverse |
| Vendor Chains | 7/10 | Manual edges only |
| Graph Versioning | 8/10 | Content-addressed snapshots |
| Evidence Linkage | 4/10 | Asset.extra only, no EvidenceRecord FK |

**Overall: 6.8/10** — Strong query capabilities, weak evidence linkage and Neo4j multi-tenancy

---

## 1. GRAPH ARCHITECTURE

### 1.1 Dual Backend Design

```python
# graph_engine/core/facade.py
def resolve_graph() -> GraphEngine:
    # Returns Neo4jGraphStore if configured, else in-memory GraphEngine
```

**Backends:**
| Backend | Class | Use Case |
|---------|-------|----------|
| In-Memory | `GraphEngine` | Default, dev, testing, Neo4j unavailable |
| Neo4j | `Neo4jGraphStore` | Production, persistence, Cypher queries |

**Fallback:** Automatic — if Neo4j unavailable, uses in-memory.

---

### 1.2 Node Types (11)

| Node Kind | Source | Key Properties | Tenant Scoped |
|-----------|--------|----------------|---------------|
| `System` | `systems` table | id, name, environment, criticality, business_unit, compliance_scopes, code_cascade | ✅ |
| `CryptoAsset` | `crypto_assets` table | id, algorithm, purpose, confidence, file_path, key_size, quantum_vulnerable | ✅ |
| `BusinessProcess` | `system_business_process` | id, name, revenue_daily, customer_count | ✅ |
| `BusinessOwner` | `business_owner` table | id, name, email | ✅ |
| `Vendor` | `vendors` table | id, name, criticality | ✅ |
| `Certificate` | `certificates` table | id, subject, issuer, expiry_status, public_key_algorithm | ✅ |
| `CloudResource` | `cloud_accounts` | id, name, cloud_provider | ✅ |
| `NetworkResource` | `network_inventory` | id, name, endpoint, resource_type | ✅ |
| `ComplianceScope` | `systems.compliance_scopes` | id, name, standard_name | ✅ |
| `Hardware` | `hardware_live` | id, name, type, pqc_capable | ✅ |
| `CascadeProvider` | `cascade_run` | file, algorithms, wave, dependents | ❌ |

---

### 1.3 Edge Types (10)

| Relation | From → To | Source Table | Evidence Source |
|----------|-----------|--------------|-----------------|
| `USES` | System → CryptoAsset | `system_assets` | `CryptoAsset.extra.detection` |
| `CALLS` | System → System | `system_dependencies` (relation=CALLS) | `source` field |
| `IMPORTS` | System → System | `system_dependencies` (relation=IMPORTS) | `source` field |
| `SUPPORTS` | System → BusinessProcess | `system_business_process` | None |
| `OWNED_BY` | System → BusinessOwner | `systems.owner` | None |
| `DEPENDS_ON_VENDOR` | System → Vendor | `systems.vendor_id` | None |
| `SECURED_BY` | System → Certificate | `certificate_usage` | None |
| `DEPLOYED_ON` | System → CloudResource | `cloud_accounts.system_id` | None |
| `CONNECTS_TO` | System → NetworkResource | `network_inventory.system_id` | None |
| `MUST_COMPLY_WITH` | System → ComplianceScope | `systems.compliance_scopes` | None |

---

## 2. GRAPH BUILD PIPELINE

### 2.1 Build Flow

```python
# api/graph_builder.py:collect_graph_payload()
# 1. Query all tenant-scoped tables
# 2. Build payload: {systems, assets, edges, processes, owners, vendors, certificates, cloud, network}
# 3. GraphEngine.build(payload) → in-memory adjacency lists
# 4. If Neo4j: sync_graph() → Neo4jGraphStore
```

### 2.2 Data Sources

| Source | Query | Tenant Scoped |
|--------|-------|---------------|
| Systems | `SystemRepository.list_systems()` | ✅ |
| CryptoAssets | `AssetRepository.list_assets()` + `SystemRepository.assets_for()` | ✅ |
| System Dependencies | `SystemRepository.dependencies_for()` | ✅ |
| Business Processes | `SystemRepository.processes_for()` | ✅ |
| Business Owners | `SystemRepository.owners_for()` | ✅ |
| Vendors | `SystemRepository.vendors_for()` | ✅ |
| Certificates | `SystemRepository.certificates_for()` | ✅ |
| Cloud Resources | `CloudAccount` + system links | ✅ |
| Network Resources | `NetworkInventory` + system links | ✅ |

---

### 2.3 Graph Sync (Relational → Neo4j)

**File:** `services/api/api/graph_builder.py:sync_graph()`

```python
def sync_graph(db):
    # 1. collect_graph_payload(db) → payload
    # 2. Neo4jGraphStore.apply_schema() — constraints + indexes
    # 3. MATCH (n) DETACH DELETE n  # Full wipe!
    # 4. Batch create nodes (1000/tx)
    # 5. Batch create relationships (1000/tx)
```

**Critical Issues:**
| Issue | Impact |
|-------|--------|
| **Full delete + rebuild** | O(N) downtime, blocks reads |
| **No incremental sync** | Cannot sync only changed data |
| **No sync status API** | Cannot monitor progress |
| **Tenant isolation** | All tenants' data in same Neo4j DB |

---

## 3. GRAPH QUERY CAPABILITIES

### 3.1 Implemented Queries

| Query | Endpoint | Method | Description |
|-------|----------|--------|-------------|
| Blast Radius | `/graph/blast-radius` | GET | Downstream from system/asset |
| Business Impact | `/graph/impact` | GET | Revenue, customers, processes at risk |
| Compliance Inheritance | `/graph/compliance` | GET | Compliance scopes downstream |
| Vendor Path | `/graph/vendor-path` | GET | Upstream to vendor |
| Vendor Chain | `/graph/vendor-chain` | GET | Vendor → systems → assets |
| All Vendor Chains | `/graph/vendor-chains` | GET | All vendors with chains |
| Dependents (Reverse) | `/graph/dependents` | GET | Upstream systems |
| Shortest Path | `/graph/path` | GET | CALLS path between systems |
| Crypto Hotspots | `/graph/hotspots` | GET | QV concentration ranking |
| Cycles | `/graph/cycles` | GET | SCCs (Tarjan) |
| Certificate Exposure | `/graph/certificates/exposure` | GET | Expiring certs + revenue risk |
| Graph Stats | `/graph/stats` | GET | Composition + hygiene |
| Graph Drift | `/graph/drift` | GET | Live vs Neo4j diff |
| Migration Waves | `/graph/migration-waves` | GET | Readiness waves + cycles |
| Crypto Inventory | `/graph/crypto` | GET | Assets for system |
| What-If Simulate | `/graph/simulate` | POST | Change impact analysis |
| Explain Risk | `/graph/explain` | GET | Evidence-backed risk chain |
| Migration Plan | `/graph/migration-plan` | POST | Creates MigrationProject + tasks |
| Graph Snapshot | `/graph/snapshot` | POST | Content-addressed version |
| Graph Timeline | `/graph/timeline` | GET | Version history |
| Graph Compare | `/graph/compare` | GET | Version diff |

---

### 3.2 Blast Radius Algorithm

**File:** `services/graph_engine/graph_engine/core/engine.py:blast_radius()`

```python
def blast_radius(self, start_id, hops=5):
    # 1. Resolve start_id to node
    # 2. If CryptoAsset: find all Systems using it (incoming USES)
    # 3. BFS from each System, tracking minimum hops
    # 4. Return Systems with hops, criticality, name
```

**Asset Blast Radius:** Fans out over ALL systems using the asset (shared key/library breaks all users).

---

### 3.3 Business Impact

**File:** `services/graph_engine/graph_engine/core/engine.py:business_impact()`

```python
def business_impact(self, start_id, hops=5):
    # 1. Blast radius to get affected Systems
    # 2. For each System: sum BusinessProcess revenue_daily + customer_count
    # 3. Collect Owners (via OWNED_BY)
    # 4. Collect ComplianceScopes (via MUST_COMPLY_WITH)
```

**Output:** `total_revenue_at_risk`, `total_customers_at_risk`, `affected_processes`, `business_owners`, `compliance_scopes`

---

### 3.4 Migration Waves

**File:** `services/api/api/routers/graph.py:graph_migration_waves()`

```python
# 1. Get readiness from MaturityRepository (per system)
# 2. Base wave from readiness_category (READY_NOW=1, READY_WITH_PREP=2, NOT_READY=2, BLOCKED=3)
# 3. Cycle constraint: SCC members get max(wave) of group
# 4. Import constraint: IMPORTS edges order dependent after provider
# 5. Code-only systems: from cascade_run (cryptoscan-systems.yml)
```

**Wave Assignment:**
| Readiness Category | Base Wave |
|--------------------|-----------|
| READY_NOW | 1 |
| READY_WITH_PREP | 2 |
| NOT_READY | 2 |
| BLOCKED | 3 |

**Cycle Constraint:** All systems in SCC get max(wave) of group.

---

## 4. EVIDENCE LINKAGE — WEAK

### 4.1 Current Implementation

**File:** `services/api/api/routers/graph.py:_edge_evidence()`

```python
def _edge_evidence(graph, edge, asset_rows):
    # Finds CryptoAsset row for edge endpoint
    # Returns: type, confidence, source, evidence, first_seen, last_seen, verified
    
    asset_row = asset_rows.get(to_id) or asset_rows.get(from_id)
    confidence = node.get("confidence")
    evidence = node.get("extra", {}).get("detection", "")
    first_seen = asset_row.created_at
    last_seen = asset_row.updated_at
    verified = confidence == "HIGH"
```

### 4.2 Evidence Gaps

| Gap | Current | Required |
|-----|---------|----------|
| **Edge → EvidenceRecord** | No direct FK | Direct FK to EvidenceRecord |
| **Node → EvidenceRecord** | Via `CryptoAsset.extra.detection` | Direct FK to EvidenceRecord |
| **CALLS edge provenance** | `SystemDependency.source` (manual/discovered/imported) | Confidence score, last_verified |
| **IMPORTS edge (code)** | From cascade `depends_on_systems` | Scanner cascade evidence |
| **Runtime edges** | Not in graph | Live crypto observations |
| **Content hash on edges** | None | `content_hash` + `chain_hash` |

### 4.3 CryptoAssetEvidence Link Table — NOT POPULATED

**Model:** `services/database/db/models/crypto_asset_evidence.py`

```python
class CryptoAssetEvidence(BaseModel, TenantScoped):
    asset_id: Mapped[str] = mapped_column(ForeignKey("crypto_assets.id"))
    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidence_records.id"))
```

**Status:** Table exists (migration 0011), **pipeline never populates it**.

---

## 5. GRAPH VERSIONING — CONTENT-ADDRESSED SNAPSHOTS

### 5.1 Snapshot Model

**File:** `services/database/db/models/graph_snapshot.py`

```python
class GraphSnapshot(BaseModel, TenantScoped):
    version: int                          # Tenant-scoped, incremental
    fingerprint: str                      # SHA-256 of canonicalized nodes+edges
    parent_fingerprint: str               # Previous version fingerprint
    node_count, edge_count: int
    nodes_by_kind: dict
    edges_by_relation: dict
    nodes: list[dict]                     # Canonicalized
    edges: list[dict]                     # Canonicalized
    added_nodes, removed_nodes: list
    added_edges, removed_edges: list
    new_quantum_vulnerable: list          # New QV algorithms
    created_by: str
```

### 5.2 Snapshot Creation

**File:** `services/api/api/routers/graph.py:_snapshot_graph()`

```python
# 1. Build in-memory graph from DB
# 2. Canonicalize nodes/edges (sort by kind, name, algorithm)
# 3. Compute fingerprint (SHA-256 of canonical JSON)
# 4. Compare with latest tenant snapshot
# 5. If changed: diff nodes/edges/QV, create new version
# 6. Emit graph.updated platform event
```

### 5.3 Version Comparison

**Endpoint:** `GET /graph/compare?from_version=X&to_version=Y`

```python
# Uses STORED diff from snapshot creation (not recomputed)
# Returns: added/removed nodes/edges, new QV algorithms
```

**Honest:** Returns actual diff stored at snapshot time.

---

## 6. NEO4J BACKEND — CRITICAL GAPS

### 6.1 No Tenant Isolation

**File:** `services/graph_engine/graph_engine/connection/neo4j_driver.py`

```python
def get_driver() -> Driver:
    return GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
```

**Issues:**
| Issue | Impact |
|-------|--------|
| Single Neo4j database | All tenants share graph |
| No `tenant_id` on nodes | Cross-tenant queries possible |
| No `tenant_id` on relationships | Cross-tenant traversal possible |
| `GraphSnapshot` tenant-scoped in PG only | Neo4j has all tenants' data |

### 6.2 Schema Application

**File:** `services/graph_engine/graph_engine/core/store.py:Neo4jGraphStore.apply_schema()`

```python
# Creates constraints:
# CREATE CONSTRAINT FOR (n:System) REQUIRE n.id IS UNIQUE
# CREATE CONSTRAINT FOR (n:CryptoAsset) REQUIRE n.id IS UNIQUE
# CREATE INDEX FOR (n:System) ON (n.name)
# ...
```

**Gap:** No tenant isolation in constraints/indexes.

---

## 7. GRAPH API — COMPREHENSIVE

### 7.1 Query Endpoints (All Implemented)

| Endpoint | Parameters | Auth | Use Case |
|----------|------------|------|----------|
| `/graph/health` | — | viewer | Backend status |
| `/graph/sync` | — | admin | Full Neo4j reload |
| `/graph` | — | viewer | Full vis export |
| `/graph/blast-radius` | system_id/asset_id, hops | viewer | Downstream impact |
| `/graph/impact` | system_id/asset_id | viewer | Business impact |
| `/graph/compliance` | system_id, hops | viewer | Compliance inheritance |
| `/graph/vendor-path` | system_id | viewer | Upstream to vendor |
| `/graph/vendor-chain` | vendor_id | viewer | Vendor → assets |
| `/graph/vendor-chains` | limit | viewer | All vendor chains |
| `/graph/dependents` | system_id, hops | viewer | Upstream systems |
| `/graph/path` | system_id, target_id, direction | viewer | Shortest CALLS path |
| `/graph/hotspots` | — | viewer | QV concentration |
| `/graph/cycles` | — | viewer | SCCs |
| `/graph/certificates/exposure` | — | viewer | Cert expiry + revenue |
| `/graph/stats` | — | viewer | Graph composition |
| `/graph/drift` | — | viewer | Live vs Neo4j |
| `/graph/migration-waves` | — | viewer | Readiness waves |
| `/graph/crypto` | system_id | viewer | Assets for system |
| `/graph/simulate` | node_id, change | admin | What-if impact |
| `/graph/explain` | node_id | viewer | Evidence-backed risk chain |
| `/graph/migration-plan` | node_id, change, algorithm_to | admin | Creates MigrationProject |

### 7.2 Graph Management Endpoints

| Endpoint | Method | Auth | Purpose |
|----------|--------|------|---------|
| `/graph/snapshot` | POST | admin | Content-addressed version |
| `/graph/timeline` | GET | viewer | Version history |
| `/graph/compare` | GET | viewer | Version diff |
| `/graph/edges` | GET | viewer | List dependency edges |
| `/graph/edges` | POST | admin | Register edge |
| `/graph/edges/{p}/{c}` | DELETE | admin | Remove edge |
| `/graph/edges/discovered` | GET | viewer | Scanner/graph proposals |
| `/graph/edges/adopt` | POST | admin | Adopt discovered edges |
| `/graph/hardware-links` | GET | viewer | Crypto↔Hardware links |
| `/graph/hardware-links` | POST | admin | Declare hardware link |
| `/graph/vendor-edges` | GET | viewer | Vendor-of-vendor edges |
| `/graph/vendor-edges` | POST | admin | Declare vendor edge |

---

## 8. MIGRATION PLANNING INTEGRATION

### 8.1 Migration Plan Creation

**Endpoint:** `POST /graph/migration-plan`

```python
# 1. Blast radius from node
# 2. Collect affected QV CryptoAssets (via USES edges)
# 3. Create MigrationProject in IntelligenceRepository
# 4. Create MigrationTask per affected asset
# 5. Return project_id, tasks_created, affected assets
```

**Integration:** Graph → Intelligence Repository → Migration Tasks

---

### 8.2 Migration Waves with Cycles

**File:** `services/agility/agility/roadmap.py:wave_for()`

```python
# Readiness category → Wave mapping
READY_NOW → 1
READY_WITH_PREP → 2
NOT_READY → 2
BLOCKED → 3
```

**Cycle Handling:** `merge_cycle_constraints()` — SCC members get max wave.

**Import Constraints:** `apply_import_constraints()` — IMPORTS edges order dependent after provider.

---

## 9. GRAPH DRIFT DETECTION

### 9.1 Drift Endpoint

**Endpoint:** `GET /graph/drift`

```python
# Compares live relational graph vs Neo4j
# Uses collect_graph_payload() vs Neo4j query
# Returns: nodes/edges only in one backend
```

**Implementation:** `graph_engine/core/drift.py:graph_drift()`

---

## 10. MISSING GRAPH CAPABILITIES

| Capability | Status | Needed For |
|------------|--------|------------|
| **Incremental Neo4j sync** | ❌ | Production scale |
| **Neo4j tenant isolation** | ❌ | Multi-tenant SaaS |
| **Runtime edges** | ❌ | Live crypto in graph |
| **Network/Container/Cloud nodes** | ❌ | Complete graph |
| **Edge evidence hashes** | ❌ | Cryptographic verification |
| **CryptoAssetEvidence population** | ❌ | Evidence traceability |
| **Neo4j Cypher query API** | ❌ | Advanced analytics |
| **Graph partitioning** | ❌ | Large scale |
| **Historical graph queries** | ❌ | Time-travel analysis |
| **Graph export (GraphML/GEXF)** | ❌ | External analysis |

---

## 11. RECOMMENDATIONS

### P0 — Critical

1. **Neo4j tenant isolation** — Separate DB per tenant or document limitation
2. **Populate CryptoAssetEvidence link table** in evidence pipeline
3. **Add content_hash/chain_hash to graph edges** for verification

### P1 — High

4. **Implement incremental Neo4j sync** (CDC from PostgreSQL)
5. **Add runtime/network/container/cloud nodes to graph**
6. **Add edge evidence hashes** for cryptographic verification

### P2 — Medium

7. **Implement Neo4j Cypher query API** for advanced analytics
8. **Add historical graph queries** (time-travel via snapshots)
9. **Graph export** — GraphML, GEXF, Cypher dump
10. **CryptoAssetEvidence population** in pipeline

### P3 — Enhancement

11. **Graph analytics library** — PageRank, betweenness, community detection
12. **Graph partitioning** for large scale
13. **Graph visualization hints** — Layout coordinates in snapshots

---

## 12. VERIFICATION EVIDENCE

| Finding | File |
|---------|------|
| GraphEngine | `services/graph_engine/graph_engine/core/engine.py` |
| Neo4jGraphStore | `services/graph_engine/graph_engine/core/store.py` |
| Graph facade | `services/graph_engine/graph_engine/core/facade.py` |
| Graph builder | `services/api/api/graph_builder.py` |
| Graph router | `services/api/api/routers/graph.py` |
| GraphSnapshot model | `services/database/db/models/graph_snapshot.py` |
| Migration waves | `services/api/api/routers/graph.py:graph_migration_waves()` |
| Neo4j driver | `services/graph_engine/graph_engine/connection/neo4j_driver.py` |
| Graph drift | `services/graph_engine/graph_engine/core/drift.py` |
| CryptoAssetEvidence model | `services/database/db/models/crypto_asset_evidence.py` |
| Migration roadmap | `services/agility/agility/roadmap.py` |
---

## Round 25 update (2026-10-10) — every actionable P0/P1 verified or shipped

* **P0#2 (populate CryptoAssetEvidence) — STALE.** The pipeline's dedup
  stage feeds each merged asset's `evidence_ids` and
  `AssetRepository.replace_for_scan` bulk-inserts the links. Verified
  live this round (2/2 links for a staged scan). See deep/25's addendum.
* **P0#3 / P1#6 (edge evidence hashes) — SHIPPED this round.** `GET
  /graph` edges now carry `evidence_count` + `evidence_refs`
  (evidence_id, content_hash, chain_hash) from the link table, bounded
  with honest counts. An edge is now cryptographically verifiable, not
  just described.
* **P1#5 (network/container/cloud nodes) — STALE.** NetworkResource
  nodes (config-driven TLS probe targets, with Neo4j sync) and
  ContainerImage nodes (honest RUNS linkage) have been in
  `api/graph_builder.py` since rounds 20/21.
* **P2#9 (graph export) — STALE.** `GET /graph/export` (GraphML/GEXF)
  shipped round 20.
* **P0#1 (Neo4j tenant isolation) — REMAINS OPEN, deployment-scoped.**
  Requires per-tenant databases or a label-scoped Cypher regime — an
  infrastructure decision, not a code fix; the in-memory fallback
  remains tenant-safe.
* **P1#4 (incremental Neo4j sync / CDC), P2#7 (Cypher passthrough API),
  P2#8 (time-travel queries), P3 analytics/partitioning — REMAIN OPEN,
  product-scoped.** Content-addressed snapshots already provide the
  substrate for P2#8.
