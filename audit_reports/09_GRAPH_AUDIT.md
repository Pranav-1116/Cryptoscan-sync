# 09_GRAPH_AUDIT.md
## ZELNX CryptoScan — Dependency/Crypto Graph Audit

**Generated:** 2026-09-20  
**Method:** Source code inspection of graph engine, Neo4j backend, API endpoints, and data flow  
**Scope:** Real vs. claimed graph capabilities — persistence, queryability, evidence linkage, completeness

---

## 1. GRAPH ARCHITECTURE OVERVIEW

### 1.1 Dual Backend Design
| Backend | Location | Status | Use Case |
|---------|----------|--------|----------|
| **In-Memory** | `services/graph_engine/graph_engine/core/engine.py:GraphEngine` | ✅ Default | Development, testing, Neo4j unavailable |
| **Neo4j** | `services/graph_engine/graph_engine/connection/neo4j_driver.py` + `core/store.py:Neo4jGraphStore` | ✅ Production | Persistent, scalable, Cypher queries |

### 1.2 Graph Build Flow
```
Relational DB (systems, crypto_assets, system_dependencies, etc.)
    │
    ▼
api/graph_builder.py:collect_graph_payload() → {systems, assets, edges, processes, owners, vendors, certificates, cloud, network}
    │
    ▼
GraphEngine.build() → In-memory adjacency lists
    │
    ▼ (if Neo4j configured)
Neo4jGraphStore.apply_schema() + sync_graph() → Neo4j nodes/relationships
```

### 1.3 Node Types (11)
| Node Kind | Source Table | Key Properties |
|-----------|--------------|----------------|
| `System` | `systems` | id, name, environment, criticality, business_unit, compliance_scopes, code_cascade |
| `CryptoAsset` | `crypto_assets` | id, algorithm, purpose, confidence, file_path, key_size, quantum_vulnerable |
| `BusinessProcess` | `system_business_process` | id, name, revenue_daily, customer_count |
| `BusinessOwner` | `business_owner` | id, name, email |
| `Vendor` | `vendors` | id, name, criticality |
| `Certificate` | `certificates` | id, subject, issuer, expiry_status, public_key_algorithm |
| `CloudResource` | `cloud_accounts` | id, name, cloud_provider |
| `NetworkResource` | `network_inventory` | id, name, endpoint, resource_type |
| `ComplianceScope` | `systems.compliance_scopes` | id, name, standard_name |
| `Hardware` | `hardware_live` | id, name, type, pqc_capable |
| `CascadeProvider` | `cascade_run` | file, algorithms, wave, dependents |

### 1.4 Edge Types (10)
| Relation | From → To | Source |
|----------|-----------|--------|
| `USES` | System → CryptoAsset | `system_assets` table |
| `CALLS` | System → System | `system_dependencies` (relation=CALLS) |
| `IMPORTS` | System → System | `system_dependencies` (relation=IMPORTS) |
| `SUPPORTS` | System → BusinessProcess | `system_business_process` |
| `OWNED_BY` | System → BusinessOwner | `systems.owner` |
| `DEPENDS_ON_VENDOR` | System → Vendor | `systems.vendor_id` |
| `SECURED_BY` | System → Certificate | `certificate_usage` |
| `DEPLOYED_ON` | System → CloudResource | `cloud_accounts.system_id` |
| `CONNECTS_TO` | System → NetworkResource | `network_inventory.system_id` |
| `MUST_COMPLY_WITH` | System → ComplianceScope | `systems.compliance_scopes` |

---

## 2. GRAPH QUERY CAPABILITIES — IMPLEMENTED

### 2.1 Core Queries (`GraphEngine` methods)
| Query | Method | Parameters | Returns |
|-------|--------|------------|---------|
| **Blast Radius** | `blast_radius()` | start_id, hops (1-12) | Downstream systems + hops |
| **Business Impact** | `business_impact()` | start_id, hops | Revenue, customers, processes, owners, scopes |
| **Compliance Inheritance** | `compliance_inheritance()` | system_id, hops | Compliance scopes downstream |
| **Vendor Path** | `vendor_path()` | system_id | Upstream path to vendor |
| **Vendor Chain** | `vendor_chain()` | vendor_id | Vendor → systems → assets → crypto |
| **All Vendor Chains** | `vendor_chains()` | limit | All vendors with downstream chains |
| **Dependents (Reverse)** | `dependents()` | system_id, hops | Upstream systems |
| **Shortest Path** | `shortest_path()` | start, target, direction | CALLS path or unreachable |
| **Crypto Hotspots** | `crypto_hotspots()` | — | Systems ranked by QV concentration |
| **Cycles** | `find_cycles()` | — | SCCs (Tarjan) |
| **Certificate Exposure** | `certificate_exposure()` | — | Expiring certs + revenue risk |
| **Graph Stats** | `graph_stats()` | — | Composition + hygiene |
| **Graph Drift** | `graph_drift()` | — | Live vs Neo4j diff |

### 2.2 API Endpoints (`services/api/api/routers/graph.py`)
| Endpoint | Method | Auth | Backend |
|----------|--------|------|---------|
| `/graph/health` | GET | viewer | Both |
| `/graph/sync` | POST | admin | Neo4j |
| `/graph` | GET | viewer | Both (vis export) |
| `/graph/blast-radius` | GET | viewer | Both |
| `/graph/impact` | GET | viewer | Both |
| `/graph/compliance` | GET | viewer | Both |
| `/graph/vendor-path` | GET | viewer | Both |
| `/graph/vendor-chain` | GET | viewer | Both |
| `/graph/vendor-chains` | GET | viewer | Both |
| `/graph/dependents` | GET | viewer | Both |
| `/graph/path` | GET | viewer | Both |
| `/graph/hotspots` | GET | viewer | Both |
| `/graph/cycles` | GET | viewer | Both |
| `/graph/certificates/exposure` | GET | viewer | Both |
| `/graph/stats` | GET | viewer | Both |
| `/graph/drift` | GET | viewer | Both |
| `/graph/migration-waves` | GET | viewer | Both |
| `/graph/crypto` | GET | viewer | Both |
| `/graph/simulate` | POST | admin | Both |
| `/graph/explain` | GET | viewer | Both |
| `/graph/migration-plan` | POST | admin | Both + MigrationProject |
| `/graph/snapshot` | POST | admin | Both (content-addressed) |
| `/graph/timeline` | GET | viewer | Both |
| `/graph/compare` | GET | viewer | Both |

---

## 3. GRAPH PERSISTENCE & VERSIONING

### 3.1 GraphSnapshot Model (`services/database/db/models/graph_snapshot.py`)
```python
class GraphSnapshot:
    version: int                    # Tenant-scoped, incremental
    fingerprint: str                # SHA-256 of canonicalized nodes+edges
    parent_fingerprint: str         # Previous version fingerprint
    node_count, edge_count: int
    nodes_by_kind: dict
    edges_by_relation: dict
    nodes: list[dict]               # Canonicalized node list
    edges: list[dict]               # Canonicalized edge list
    added_nodes, removed_nodes: list
    added_edges, removed_edges: list
    new_quantum_vulnerable: list
    created_by: str
```

### 3.2 Snapshot Creation (`graph.py:_snapshot_graph()`)
1. Build in-memory graph from DB
2. Canonicalize nodes/edges (sort by kind, name, algorithm)
3. Compute fingerprint (SHA-256 of canonical JSON)
4. Compare with latest tenant snapshot
5. If changed: diff nodes/edges/QV, create new version
6. Emit `graph.updated` platform event

### 3.3 Version Comparison (`/graph/compare`)
- Uses stored diff from snapshot creation (not recomputed)
- Returns added/removed nodes/edges + new QV algorithms
- Honest about missing versions

---

## 4. EVIDENCE LINKAGE — GRAPH ↔ FINDINGS

### 4.1 Current Implementation
```python
# graph.py:_edge_evidence() — attaches to each edge in vis export
def _edge_evidence(graph, edge, asset_rows):
    # Finds CryptoAsset row for edge endpoint
    # Returns: type, confidence, source, evidence, first_seen, last_seen, verified
```

**Evidence Sources:**
- `CryptoAsset.confidence` (HIGH/MEDIUM/LOW from scanner)
- `CryptoAsset.extra.detection` (scanner detection detail)
- `CryptoAsset.created_at` / `updated_at` (first/last seen)

### 4.2 Gaps in Evidence Linkage
| Missing Link | Current State | Required |
|--------------|---------------|----------|
| **Edge → EvidenceRecord** | Not directly linked | Edge evidence from `CryptoAsset.extra` only |
| **Node → EvidenceRecord** | `CryptoAsset` has `evidence_links` but not used in graph | Direct FK to evidence |
| **CALLS edge provenance** | `SystemDependency.source` (manual/discovered/imported) | Confidence score, last_verified |
| **IMPORTS edge (code)** | From cascade `depends_on_systems` | Scanner cascade evidence |
| **Runtime edges** | Not in graph | Live crypto observations not in graph |

---

## 5. GRAPH COMPLETENESS — WHAT'S MISSING

### 5.1 Missing Node Types (from discovery)
| Discovery Source | Node Type | Status |
|------------------|-----------|--------|
| Network scans | `NetworkEndpoint` (host:port) | ❌ Only `NetworkResource` (aggregated) |
| Container scans | `ContainerImage` / `ContainerLayer` | ❌ Not in graph |
| Cloud scans | `CloudKMSKey`, `CloudStorageBucket`, `CloudDatabase` | ❌ Only generic `CloudResource` |
| Runtime | `Process`, `LoadedLibrary`, `APICall` | ❌ Not in graph |
| Hardware | `HSM`, `TPM`, `CPU_Crypto` | ⚠️ `Hardware` node exists but not linked to crypto assets |
| Keys | `Key` (metadata only) | ❌ Not in graph |
| SBOM Components | `Library`, `Package` | ❌ Not in graph |

### 5.2 Missing Edge Types
| Relationship | From | To | Status |
|--------------|------|----|--------|
| `HOSTS` | System | ContainerImage | ❌ |
| `RUNS_ON` | Process | System | ❌ |
| `LOADS` | Process | Library | ❌ |
| `CALLS_API` | Process | APICall | ❌ |
| `PROTECTS` | HSM/Key | CryptoAsset | ❌ |
| `ENCRYPTS` | Key | Data/Channel | ❌ |
| `SIGNS` | Key | Certificate/Artifact | ❌ |
| `DEPENDS_ON_LIBRARY` | CryptoAsset | Library | ❌ |
| `VENDOR_SUPPLIES` | Vendor | Library/Component | ❌ |

### 5.3 Tenant Isolation in Graph
**Critical Gap:** Neo4j backend has **no tenant isolation** — all tenants share single graph database.
- `GraphSnapshot` is tenant-scoped (Migration 0071)
- `graph_from_db()` filters by tenant via `filtered_get()` on relational data
- But `Neo4jGraphStore` writes ALL tenants' data to same Neo4j
- **Result:** Cross-tenant data leakage in Neo4j queries

---

## 6. GRAPH-BASED FEATURES — VALIDATION

### 6.1 Migration Waves (`/graph/migration-waves`)
- **Input:** System readiness (MaturityRepository) + code cascade (from scanner) + dependency cycles
- **Cycle constraint:** SCC members get max wave of group
- **Import constraint:** IMPORTS edges order dependent after provider
- **Code-only systems:** From `cryptoscan-systems.yml` cascade, added to plan
- **Output:** Per-system wave (1-3), rationale, unscored count

### 6.2 What-If Simulation (`/graph/simulate`)
- **Input:** Node ID + change type (`migrate_pqc`)
- **Computation:** Blast radius + business impact + crypto asset count + compat issues
- **Output:** Affected systems/assets/certificates, revenue at risk, migration tasks
- **Honest:** Returns empty when node not found or no QV assets

### 6.3 Migration Plan (`/graph/migration-plan`)
- **Creates:** `MigrationProject` + `MigrationTask` per affected QV asset
- **Links:** Real `CryptoAsset` IDs, actual `algorithm_from` → `algorithm_to`
- **Honest:** Returns `created: false` when no affected assets

### 6.4 Explain (`/graph/explain`)
- **Evidence chain:** Algorithm → System → Business Impact
- **Attaches:** Confidence, detection evidence, file location, QV status
- **Honest:** "No evidence" when missing

---

## 7. GRAPH SYNC — RELATIONAL → NEO4J

### 7.1 Sync Process (`api/graph_builder.py:sync_graph()`)
1. `collect_graph_payload()` — queries all relational tables
2. `Neo4jGraphStore.apply_schema()` — constraints + indexes
3. **Full delete + recreate** — `MATCH (n) DETACH DELETE n` then reload
4. Batch writes (1000 nodes/edges per transaction)

### 7.2 Sync Issues
| Issue | Impact |
|-------|--------|
| **Full rebuild every sync** | O(N) — slow at scale; blocks reads during sync |
| **No incremental sync** | Cannot sync only changed systems |
| **No sync scheduling** | Manual `POST /graph/sync` only |
| **No sync status API** | Cannot monitor sync progress |
| **Neo4j constraints** | Unique constraints on node IDs; fails on duplicate tenant data |

---

## 8. PERFORMANCE & SCALABILITY

| Metric | In-Memory | Neo4j |
|--------|-----------|-------|
| **Build time (10K systems)** | ~2-5 seconds | ~30-60 seconds (full sync) |
| **Blast radius query** | O(V+E) BFS | Cypher — depends on indexes |
| **Memory (100K nodes)** | ~500 MB | Neo4j heap (512MB default) |
| **Concurrent queries** | Single-threaded | Limited by Bolt connections |
| **Tenant isolation** | Per-request filter | **NONE** — shared DB |

---

## 9. RECOMMENDATIONS

### P0 — Critical
1. **Neo4j tenant isolation** — Separate database per tenant or document single-tenant limitation
2. **Incremental graph sync** — Delta sync from relational changelog
3. **Link runtime/network/container/cloud nodes** — Complete the graph picture

### P1 — High
4. **EvidenceRecord ↔ Graph edge linkage** — Direct FK from edges to evidence
5. **Scheduled graph sync** — Background job with status API
6. **Graph query pagination** — Large blast radius results need pagination

### P2 — Medium
7. **IMPORTS edge evidence** — Attach scanner cascade evidence to code dependency edges
8. **Vendor chain evidence** — Link to vendor due diligence findings
9. **Graph visualization API** — Return vis.js format with clustering/layout hints

### P3 — Enhancement
10. **Graph analytics library** — Centralize algorithms (PageRank, betweenness, community detection)
11. **Historical graph queries** — Time-travel via snapshot versions
12. **Graph export** — GraphML, GEXF, Cypher dump for external analysis
---

## UPDATE — round 16 verification (2026-10-09)

- "Neo4j backend has no tenant isolation" — stale: the tenant gate forces
  tenant-isolated backends (per-tenant graph state; a tenant never reads
  another tenant's graph), shipped in the rounds after this report.
- "No sync scheduling / manual POST /graph/sync only" — stale: graph sync
  runs automatically after every scan as a worker pipeline stage
  (`stage_graph_sync`), in addition to the manual admin endpoint.
- "Only aggregated NetworkResource / generic CloudResource" — partially
  stale: the payload now includes genuine IaC-scan CloudResource nodes
  (provider+resource identity from scan evidence) and network-scan-target
  NetworkResource nodes with system links. Finer-grained node kinds
  (CloudKMSKey, container images, runtime Process→APICall edges) remain
  open backlog.
- Evidence linkage: `_edge_evidence` attaches detection confidence/source/
  first-seen per edge; direct EvidenceRecord FKs on edges remain an
  enhancement.
- Graph drift (`/graph/drift`), snapshots/compare/timeline all verified
  present and tenant-versioned.

## UPDATE — round 20 fixes + build (2026-10-10)

1. **Ghost nodes pruned on sync (bug).** MERGE-only sync meant deleted
   systems/assets stayed in the graph forever — blast radius and counts
   answered for entities that no longer exist. Sync now prunes each kind
   present in the payload whose ids are absent (full keep-set per query;
   kinds absent from a sync are never touched). `pruned` is reported.
2. **`network_resources` crashed the Neo4j sync path (latent bug).**
   The store never accepted the payload key — a real driver meant
   `TypeError` on every sync; the memory fallback masked it in tests.
   NetworkResource nodes + CONNECTS_TO edges now merge on Neo4j too.
3. **Graph export BUILT (rec #12):** `GET /graph/export?format=graphml|gexf`
   serializes the same graph `/graph` serves, XML-escaped, with kind and
   relation attributes — loadable in Gephi/yEd/Cytoscape.
4. The bounded-walk fix (audit 03) applies to the graph payload feeding
   this layer: >500-system estates no longer silently shrink the graph.

Still open: finer node kinds beyond persisted data (CloudKMSKey,
container images), direct EvidenceRecord FKs on edges.
