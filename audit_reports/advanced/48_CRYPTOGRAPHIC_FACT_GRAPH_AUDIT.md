# 48_CRYPTOGRAPHIC_FACT_GRAPH_AUDIT.md
## ZELNX CryptoScan — Cryptographic Fact Graph Audit

**Generated:** 2026-09-20  
**Method:** Deep inspection of the complete relationship model for cryptographic facts  
**Scope:** Complete graph model — Asset → Application → Code → Function → Library → Algorithm → Key Type → Key Size → Protocol → Certificate → Endpoint → Network Flow → Hardware → HSM → Cloud KMS → Vendor → Evidence

---

## EXECUTIVE SUMMARY

| Graph Aspect | Score | Status |
|--------------|-------|--------|
| Node Types | 7/10 | 11 node types, missing key entities |
| Edge Types | 6/10 | 10 edge types, missing semantic edges |
| Evidence Linkage | 4/10 | Weak — asset.extra only |
| Query Capability | 8/10 | Comprehensive query surface |
| Fact Traceability | 4/10 | Cannot trace fact to source evidence |
| Semantic Relationships | 5/10 | Missing semantic edge types |
| Temporal Versioning | 8/10 | Content-addressed snapshots |
| Evidence Linkage | 4/10 | No EvidenceRecord FK on edges |

**Overall: 5.8/10** — Strong query capabilities, weak fact traceability and evidence linkage

---

## 1. GRAPH MODEL INVENTORY

### 1.1 Node Types (11 Implemented)

| Node Kind | Source Table | Key Properties | Count Est. |
|-----------|--------------|----------------|------------|
| `System` | `systems` | id, name, environment, criticality, business_unit, compliance_scopes, code_cascade | 1K-10K |
| `CryptoAsset` | `crypto_assets` | id, algorithm, purpose, confidence, file_path, key_size, quantum_vulnerable | 10K-100K |
| `BusinessProcess` | `system_business_process` | id, name, revenue_daily, customer_count | 100-1K |
| `BusinessOwner` | `business_owner` | id, name, email | 10-100 |
| `Vendor` | `vendors` | id, name, criticality | 10-1K |
| `Certificate` | `certificates` | id, subject, issuer, expiry_status, public_key_algorithm | 1K-10K |
| `CloudResource` | `cloud_accounts` | id, name, cloud_provider | 10-1K |
| `NetworkResource` | `network_inventory` | id, name, endpoint, resource_type | 100-10K |
| `ComplianceScope` | `systems.compliance_scopes` | id, name, standard_name | 10-100 |
| `Hardware` | `hardware_live` | id, name, type, pqc_capable | 10-1K |
| `CascadeProvider` | `cascade_run` | file, algorithms, wave, dependents | 1-100 |

### 1.2 Missing Critical Node Types

| Missing Node Type | Required For | Source Data Available |
|-------------------|--------------|----------------------|
| **Application** | Code-level asset | `RepoConfiguration`, `systems` |
| **Code Repository** | Source tracking | `RepoConfiguration` |
| **Code Function** | Fine-grained tracing | Scanner AST output |
| **Library** | Dependency tracking | `crypto_library_fingerprints` |
| **Package** | SBOM correlation | SBOM import data |
| **Code File** | Location tracing | Scanner `file_path` |
| **Code Function** | Call tracing | Scanner `class_name`, `method_name` |
| **API Endpoint** | API crypto tracing | API scanner output |
| **Database** | Data-at-rest crypto | Cloud scanner output |
| **Key** | Key lifecycle | `payment_crypto`, `certificate` |
| **Key Ring** | Key management | Cloud KMS, HSM |
| **HSM** | Hardware crypto | `hardware_live` |
| **Key Policy** | Key permissions | Cloud KMS policies |
| **Network Flow** | Traffic analysis | Network scanner |
| **API Call** | Runtime crypto | Runtime engine |
| **Process** | Runtime context | Runtime engine |
| **Container** | Container crypto | Container scanner |
| **Pod** | K8s workload | K8s scanner |
| **Namespace** | K8s boundaries | K8s scanner |
| **Cluster** | K8s boundaries | K8s scanner |
| **Image** | Container image | Container scanner |
| **Image Layer** | Layer analysis | Container scanner |
| **Base Image** | Supply chain | Container scanner |
| **Build Pipeline** | CI/CD crypto | CI/CD integration |
| **Developer** | Human factor | Git blame, SCM |
| **Team** | Ownership | Business units |
| **Project** | Grouping | Repositories |
| **Environment** | Boundaries | Systems, namespaces |

---

## 2. EDGE TYPES (10 Implemented)

### 2.1 Current Edge Types

| Relation | From → To | Source Table | Evidence Source |
|----------|-----------|--------------|-----------------|
| `USES` | System → CryptoAsset | `system_assets` | `CryptoAsset.extra.detection` |
| `CALLS` | System → System | `system_dependencies` (CALLS) | `source` field |
| `IMPORTS` | System → System | `system_dependencies` (IMPORTS) | `source` field |
| `SUPPORTS` | System → BusinessProcess | `system_business_process` | None |
| `OWNED_BY` | System → BusinessOwner | `systems.owner` | None |
| `DEPENDS_ON_VENDOR` | System → Vendor | `systems.vendor_id` | None |
| `SECURED_BY` | System → Certificate | `certificate_usage` | None |
| `DEPLOYED_ON` | System → CloudResource | `cloud_accounts.system_id` | None |
| `CONNECTS_TO` | System → NetworkResource | `network_inventory.system_id` | None |
| `MUST_COMPLY_WITH` | System → ComplianceScope | `systems.compliance_scopes` | None |

### 2.2 Missing Critical Edge Types

| Missing Edge | From → To | Required For | Source Data Available |
|--------------|-----------|--------------|----------------------|
| **DEFINES** | Code File → Function | Code tracing | Scanner AST |
| **CALLS** | Function → Function | Call graph | Scanner AST |
| **USES** | Function → Library | Dependency | Scanner imports |
| **USES** | Function → Crypto API | Crypto tracing | Scanner crypto calls |
| **USES** | Library → Algorithm | Library crypto | Fingerprinting |
| **IMPLEMENTS** | Library → Algorithm | Library crypto | Fingerprinting |
| **PROVIDES** | Cloud KMS → Key | Key hierarchy | Cloud scanner |
| **PROVIDES** | HSM → Key | Key hierarchy | Hardware scanner |
| **STORES** | Key Ring → Key | Key hierarchy | Cloud KMS, HSM |
| **MANAGES** | Key Policy → Key | Key permissions | Cloud KMS policies |
| **ENCRYPTS** | Key → Data | Data protection | Cloud KMS, App config |
| **SIGNS** | Key → Artifact | Signing | Certificate, code signing |
| **VERIFIES** | Key → Certificate | PKI | Certificate chain |
| **ISSUES** | CA → Certificate | PKI | Certificate chain |
| **VALIDATES** | Trust Store → Certificate | Trust | Trust store analysis |
| **TERMINATES** | TLS Endpoint → Certificate | TLS | Network scan |
| **NEGOTIATES** | Client ↔ Server | TLS handshake | Network probe |
| **CARRIES** | Network Flow → Protocol | Traffic | Network capture |
| **ROUTES** | Network Device → Flow | Topology | Network scan |
| **LOADS** | Process → Library | Runtime | Runtime engine |
| **EXECUTES** | Process → Function | Runtime | Runtime engine |
| **RUNS_ON** | Process → Host | Host mapping | Runtime, cloud |
| **DEPLOYS** | Container → Host | Deployment | Container, cloud |
| **ORCHESTRATES** | Orchestrator → Container | K8s | K8s scanner |
| **SCHEDULES** | Scheduler → Pod | K8s | K8s scanner |
| **EXPOSES** | Service → Endpoint | K8s | K8s scanner |
| **ROUTES** | Ingress → Service | K8s | K8s scanner |
| **BUILDS** | Pipeline → Image | CI/CD | CI/CD integration |
| **DEPLOYS** | Pipeline → Environment | CI/CD | CI/CD integration |
| **SCANS** | Scanner → Target | Scan metadata | Scan metadata |
| **PRODUCES** | Build → Artifact | Build | CI/CD |
| **SIGNS** | Key → Artifact | Signing | Build, cert |
| **VERIFIES** | Verifier → Artifact | Verification | Build, deploy |
| **ATTACKS** | Threat Actor → Asset | Threat intel | Threat intel |
| **EXPLOITS** | Vulnerability → Asset | Exploitation | Vuln scanner |
| **MITIGATES** | Control → Vulnerability | Remediation | Policy, remediation |

---

## 3. FACT TRACEABILITY — CRITICAL GAPS

### 3.1 Current Fact → Evidence Linkage

| Fact Type | Current Linkage | Gap |
|-----------|-----------------|-----|
| **Algorithm** | `CryptoAsset.algorithm` → `extra.detection` | No direct EvidenceRecord FK |
| **Key Size** | `CryptoAsset.key_size` | No EvidenceRecord FK |
| **Protocol** | `CryptoAsset.protocol` | No EvidenceRecord FK |
| **Certificate** | `Certificate` node | No EvidenceRecord FK |
| **Key Size (Cert)** | `Certificate.public_key_size` | No EvidenceRecord FK |
| **Protocol (TLS)** | `NetworkResource.tls_version` | No EvidenceRecord FK |
| **Cipher Suite** | `NetworkResource.cipher_suite` | No EvidenceRecord FK |
| **Library** | `CryptoAsset.library` (via extra) | No EvidenceRecord FK |
| **Algorithm (Network)** | `NetworkResource.cipher_suite` parsed | No EvidenceRecord FK |

**Critical:** **No direct foreign key from any graph node/edge to EvidenceRecord.**

### 3.2 Evidence Linkage on Edges

**File:** `services/api/api/routers/graph.py:_edge_evidence()`

```python
def _edge_evidence(graph, edge, asset_rows):
    asset_row = asset_rows.get(to_id) or asset_rows.get(from_id)
    confidence = node.get("confidence")
    evidence = node.get("extra", {}).get("detection", "")
    first_seen = asset_row.created_at
    last_seen = asset_row.updated_at
    verified = confidence == "HIGH"
    return {
        "type": edge.get("label"),
        "confidence": confidence,
        "source": "crypto_discovery" if label == "USES" else "inventory",
        "evidence": evidence,  # String only!
        "first_seen": first_seen,
        "last_seen": last_seen,
        "verified": verified
    }
```

**Gaps:**
- ❌ No `evidence_id` FK
- ❌ No `content_hash` on edge
- ❌ No `chain_hash` on edge
- ❌ Evidence is string only, not structured
- ❌ No link to `EvidenceRecord` table

---

## 4. FACT GRAPH QUERY CAPABILITIES

### 4.1 Implemented Queries

| Query | Endpoint | Can Answer |
|-------|----------|------------|
| Blast Radius | `/graph/blast-radius` | "What systems use this algorithm?" |
| Business Impact | `/graph/impact` | "What revenue at risk?" |
| Vendor Path | `/graph/vendor-path` | "What vendor provides this crypto?" |
| Vendor Chain | `/graph/vendor-chain` | "Vendor → systems → assets" |
| Dependents | `/graph/dependents` | "What systems depend on this?" |
| Shortest Path | `/graph/path` | "Call path between systems" |
| Crypto Hotspots | `/graph/hotspots` | "Systems with most QV crypto" |
| Cycles | `/graph/cycles` | "Dependency cycles" |
| Cert Exposure | `/graph/certificates/exposure` | "Expiring certs + revenue" |
| Migration Waves | `/graph/migration-waves` | "Migration ordering" |
| What-If Simulate | `/graph/simulate` | "Impact of changing this" |
| Explain Risk | `/graph/explain` | "Evidence chain for risk" |
| Migration Plan | `/graph/migration-plan` | "Create migration tasks" |

### 4.2 Questions CANNOT Answer

| Question | Missing Capability |
|----------|-------------------|
| "Show me the exact source code line where RSA-2048 is called" | No Code File → Function → Crypto API edges |
| "Which function calls the vulnerable library?" | No Function → Library edges |
| "Which certificate is used by which TLS endpoint?" | No Certificate → TLS Endpoint edge |
| "Which HSM protects which key?" | No HSM → Key edges |
| "Which Cloud KMS key encrypts which data?" | No KMS Key → Data edges |
| "Which function calls the crypto API?" | No Function → Crypto API edges |
| "Which library implements which algorithm?" | No Library → Algorithm edges |
| "Which certificate is used by which TLS endpoint?" | No Certificate → TLS Endpoint edge |
| "Which key encrypts which database column?" | No Key → Data edges |
| "Which process loads which library?" | No Process → Library edges |
| "Which container runs which process?" | No Container → Process edges |
| "Which pod runs which container?" | No Pod → Container edges |
| "Which build pipeline produced this image?" | No Pipeline → Image edges |
| "Which developer wrote this crypto code?" | No Developer → Code edges |
| "Which team owns this crypto function?" | No Team → Code edges |

---

## 5. SEMANTIC RELATIONSHIP GAPS

### 5.1 Crypto-Specific Semantic Gaps

| Missing Semantic | Current Representation | Needed |
|------------------|------------------------|--------|
| **Algorithm Implementation** | `USES` System → CryptoAsset | `IMPLEMENTS` Library → Algorithm, `CALLS` Function → Algorithm |
| **Key Hierarchy** | None | `PROVIDES` KMS/HSM → Key, `STORES` KeyRing → Key |
| **Certificate Chain** | `SECURED_BY` System → Certificate | `ISSUES` CA → Certificate, `VALIDATES` TrustStore → Certificate |
| **Protocol Negotiation** | None | `NEGOTIATES` Client ↔ Server, `TERMINATES` Endpoint → Certificate |
| **Key Usage** | None | `ENCRYPTS` Key → Data, `SIGNS` Key → Artifact |
| **Data Flow** | None | `CARRIES` Flow → Protocol, `ENCRYPTS` Key → Flow |
| **Runtime Binding** | None | `LOADS` Process → Library, `EXECUTES` Process → Function |
| **Deployment** | None | `DEPLOYS` Container → Host, `ORCHESTRATES` K8s → Container |
| **Build Provenance** | None | `BUILDS` Pipeline → Image, `PRODUCES` Build → Artifact |
| **Signing Chain** | None | `SIGNS` Key → Artifact, `VERIFIES` Verifier → Artifact |

---

## 5. EVIDENCE GRAPH — MISSING LAYER

### 5.1 Required Evidence Graph Layer

```python
# Required: Evidence as first-class graph nodes
EvidenceNode:
    evidence_id: UUID
    content_hash: SHA256
    chain_hash: SHA256
    chain_position: int
    collector: str
    source_type: SourceType
    timestamp: DateTime
    
# Edges:
Evidence → CryptoFact (SUPPORTS)
Evidence → Evidence (CHAINS_TO)
CryptoFact → Evidence (SUPPORTED_BY)
```

### 5.2 Current Evidence Graph — NONEXISTENT

| Evidence Graph Element | Status |
|------------------------|--------|
| Evidence as nodes | ❌ |
| Evidence chain edges | ❌ |
| Evidence → Fact edges | ❌ |
| Fact → Evidence edges | ❌ |
| Content hash on edges | ❌ |
| Chain hash on edges | ❌ |
| Evidence versioning | ❌ |

---

## 6. TEMPORAL FACT GRAPH

### 6.1 Graph Snapshots

**File:** `services/database/db/models/graph_snapshot.py`

```python
class GraphSnapshot:
    version: int
    fingerprint: str              # SHA-256 of canonicalized graph
    nodes: list[dict]             # Canonicalized nodes
    edges: list[dict]             # Canonicalized edges
    added_nodes, removed_nodes: list
    added_edges, removed_edges: list
    new_quantum_vulnerable: list
```

### 6.2 Temporal Queries

| Query | Endpoint | Capability |
|-------|----------|------------|
| Graph Timeline | `/graph/timeline` | Version history |
| Graph Compare | `/graph/compare` | Diff two versions |
| Graph Drift | `/graph/drift` | Live vs Neo4j |

**Gap:** No point-in-time fact queries (e.g., "What algorithms did System X use on 2026-01-01?")

---

## 7. FACT GRAPH — "WHERE EXACTLY" TEST

### 7.1 Test: "Where exactly is this cryptographic fact used?"

**Question:** "Where exactly is RSA-2048 key generation used?"

| Required Path | Current Graph | Status |
|---------------|---------------|--------|
| System → CryptoAsset (RSA-2048) | ✅ `USES` | ✅ |
| System → Code Repository | ❌ | ❌ |
| Repository → Code File | ❌ | ❌ |
| Code File → Function | ❌ | ❌ |
| Function → Crypto API Call | ❌ | ❌ |
| Crypto API Call → Algorithm | ❌ | ❌ |
| Algorithm → Key Size | ✅ (on CryptoAsset) | ✅ |
| Function → Library | ❌ | ❌ |
| Library → Algorithm Implementation | ❌ | ❌ |

**Result: CANNOT ANSWER "WHERE EXACTLY"**

---

### 7.2 Required Path for "Where Exactly"

```
System
  → DEPLOYS → Code Repository
    → CONTAINS → Code File
      → DEFINES → Function
        → CALLS → Crypto API
          → USES → Algorithm
            → HAS_KEY_SIZE → Key Size
        → USES → Library
          → IMPLEMENTS → Algorithm
```

**All missing.**

---

## 8. VENDOR & SUPPLY CHAIN GAPS

### 8.1 Current Vendor Edges

| Edge | From → To | Source |
|------|-----------|--------|
| `DEPENDS_ON_VENDOR` | System → Vendor | `systems.vendor_id` |

### 7.2 Missing Vendor Edges

| Missing Edge | From → To | Source Data |
|--------------|-----------|-------------|
| `SUPPLIES` | Vendor → Library | `vendor_crypto`, SBOM |
| `PROVIDES` | Vendor → Service | Cloud scanner |
| `SUPPLIES` | Vendor → Certificate | Vendor certs |
| `MAINTAINS` | Vendor → Library | Vendor intel |
| `PATCHES` | Vendor → Vulnerability | Vendor advisories |
| `NOTIFIES` | Vendor → Customer | Vendor notifications |

---

## 8. RECOMMENDATIONS

### P0 — Critical

1. **Add EvidenceRecord FK to all CryptoFact nodes** — Direct `evidence_id` on CryptoAsset, Certificate, NetworkResource
2. **Add EvidenceRecord FK to all edges** — `evidence_id`, `content_hash`, `chain_hash` on every edge
3. **Implement Evidence Graph Layer** — Evidence as first-class nodes with chain edges
4. **Add Code-Level Nodes** — CodeFile, Function, Library, Package nodes

### P1 — High

5. **Add Code-Level Edges** — DEFINES, CALLS, USES (Function→Library), IMPLEMENTS
6. **Add Key Hierarchy Edges** — PROVIDES (KMS/HSM→Key), STORES (KeyRing→Key), MANAGES (Policy→Key)
7. **Add Certificate Chain Edges** — ISSUES (CA→Cert), VALIDATES (TrustStore→Cert)
8. **Add Runtime Edges** — LOADS (Process→Library), EXECUTES (Process→Function), RUNS_ON (Process→Host)
9. **Add Deployment Edges** — DEPLOYS (Container→Host), ORCHESTRATES (K8s→Container), EXPOSES (Service→Endpoint)
9. **Add Build Edges** — BUILDS (Pipeline→Image), PRODUCES (Build→Artifact), SIGNS (Key→Artifact)

### P2 — Medium

10. **Add Threat Edges** — ATTACKS (Actor→Asset), EXPLOITS (Vuln→Asset), MITIGATES (Control→Vuln)
11. **Add Temporal Fact Queries** — Point-in-time fact reconstruction
12. **Add Evidence Graph** — Evidence as nodes with chain edges
13. **Add Semantic Edge Types** — Replace generic USES with crypto-specific semantics
14. **Add Evidence Hashes to Edges** — content_hash, chain_hash on every edge

### P3 — Enhancement

12. **GraphQL API for Fact Graph** — Flexible fact traversal
13. **Graph ML Features** — PageRank, betweenness, community detection
14. **Graph Export** — GraphML, GEXF, Cypher dump
15. **Point-in-Time Fact Queries** — "What algorithms did System X use on date X?"

---

## 9. VERDICT

**The graph can answer "WHAT" and "WHO" but NOT "WHERE EXACTLY" or "HOW".**

| Capability | Status |
|------------|--------|
| System-level crypto inventory | ✅ |
| Business impact | ✅ |
| Vendor chains | ✅ (manual edges) |
| Blast radius | ✅ |
| Migration waves | ✅ |
| Code-level tracing | ❌ |
| Function-level tracing | ❌ |
| Library implementation | ❌ |
| Key hierarchy | ❌ |
| Certificate chain | ❌ |
| Runtime binding | ❌ |
| Build provenance | ❌ |
| Evidence chain on graph | ❌ |
| "Where exactly" queries | ❌ |

**Root Cause:** Graph operates at System/Asset level only. No code-level, function-level, library-level, key-level, or evidence-level nodes/edges.

**Effort to Fix:** 8-12 weeks for complete fact graph with evidence linkage.

---

## 9. VERIFICATION EVIDENCE

| Finding | File |
|---------|------|
| GraphEngine | `services/graph_engine/graph_engine/core/engine.py` |
| Graph facade | `services/graph_engine/graph_engine/core/facade.py` |
| Graph router | `services/api/api/routers/graph.py` |
| Graph builder | `services/api/api/graph_builder.py` |
| Neo4j store | `services/graph_engine/graph_engine/core/store.py` |
| GraphSnapshot model | `services/database/db/models/graph_snapshot.py` |
| CryptoAsset model | `services/database/db/models/crypto_asset.py` |
| EvidenceRecord model | `services/database/db/models/evidence_record.py` |
| SystemAsset link | `services/database/db/models/system_asset.py` |
| SystemDependency | `services/database/db/models/system_dependency.py` |
| CertificateUsage | `services/database/db/models/certificate_usage.py` |
| CryptoHardwareLink | `services/database/db/models/cascade_extensions.py` |
| VendorDependency | `services/database/db/models/cascade_extensions.py` |
| Graph drift | `services/graph_engine/graph_engine/core/drift.py` |
| Migration waves | `services/agility/agility/roadmap.py` |
| CryptoAssetEvidence model | `services/database/db/models/crypto_asset_evidence.py` |