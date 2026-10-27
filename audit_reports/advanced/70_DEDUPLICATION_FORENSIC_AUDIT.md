# 70_DEDUPLICATION_FORENSIC_AUDIT.md
## ZELNX CryptoScan — Deduplication Forensic Audit

**Generated:** 2026-09-20  
**Method:** Deep inspection of deduplication logic across evidence pipeline, asset creation, graph building, and BOM generation  
**Scope:** Complete deduplication audit — assets, observations, evidence, dependencies, certificates, algorithms, libraries, network endpoints, cloud resources, BOM components

---

## EXECUTIVE SUMMARY

**Core Question:** *"Does ZELNX deduplicate correctly without accidentally destroying evidence?"*

**Answer:** **PARTIAL** — Evidence pipeline has content-hash deduplication, but **asset-level deduplication is inconsistent** across pipelines, and **critical deduplication logic is missing** in graph, BOMs, and cross-source correlation.

| Deduplication Area | Status | Score |
|--------------------|--------|-------|
| **Evidence Pipeline** | ✅ Content-hash based | 8/10 |
| **CryptoAsset Creation** | ⚠️ Partial | 5/10 |
| **Graph Node Deduplication** | ❌ Missing | 1/10 |
| **Graph Edge Deduplication** | ❌ Missing | 1/10 |
| **CBOM Component Deduplication** | ⚠️ Partial | 4/10 |
| **NBOM Component Deduplication** | ❌ Missing | 1/10 |
| **TechBOM Component Deduplication** | ❌ Missing | 1/10 |
| **Certificate Deduplication** | ⚠️ Partial | 4/10 |
| **Library Deduplication** | ❌ Missing | 1/10 |
| **Dependency Deduplication** | ❌ Missing | 1/10 |
| **Network Endpoint Deduplication** | ✅ Network scanner | 7/10 |
| **Cloud Resource Deduplication** | ❌ Missing | 1/10 |
| **Vendor Deduplication** | ❌ Missing | 1/10 |
| **Evidence Preservation** | ✅ Content-hash preserves | 8/10 |

**Overall: 2.8/10** — Evidence pipeline good, but asset/entity deduplication largely missing

---

## 1. EVIDENCE PIPELINE DEDUPLICATION — GOOD

### 1.1 Content-Hash Based Deduplication

**File:** `services/evidence/evidence/core/pipeline.py:process_findings()`

```python
# 1. Canonicalize finding (remove evidence_id, created_at, etc.)
# 2. Compute content_hash = SHA-256(canonical_json)
# 3. Deduplicate by content_hash (first wins)
# 4. Track duplicates_collapsed counter
# 5. Assign chain_position sequentially
# 6. Compute chain_hash = SHA-256(content_hash + previous_chain_hash)
```

### 1.2 Evidence Deduplication Quality

| Aspect | Implementation | Quality |
|--------|----------------|---------|
| **Content Hash** | SHA-256 of canonical JSON | ✅ Strong |
| **Canonicalization** | Sorted keys, no whitespace, excluded fields | ✅ Correct |
| **Deduplication Key** | content_hash (excludes metadata) | ✅ Correct |
| **First-Win Policy** | First occurrence kept | ✅ Correct |
| **Duplicate Counter** | `duplicates_collapsed` logged | ✅ Observable |
| **Chain Integrity** | Chain hash after dedup | ✅ Preserved |

### 1.3 Evidence Deduplication Gaps

| Gap | Impact |
|-----|--------|
| **No Cross-Scan Deduplication** | Each scan deduped independently |
| **No Cross-Source Deduplication** | Static vs Network vs Runtime not deduped |
| **No Semantic Deduplication** | Same logical fact, different representation = not deduped |
| **No Duplicate Evidence Linking** | Collapsed duplicates not linked to original |

---

## 2. CRYPTO ASSET DEDUPLICATION — PARTIAL

### 2.1 Asset Creation Deduplication

**File:** `services/database/db/repositories/asset_repository.py:replace_for_scan()`

```python
def replace_for_scan(self, scan_id, findings):
    # Deduplication key: finding.dedup_key or algorithm+file+line
    # If same dedup_key: merge scanner_ids, increment occurrence_count
    # BUT: Different key_size or algorithm = different dedup_key = separate assets
```

### 2.2 Asset Deduplication Gaps

| Gap | Impact |
|-----|--------|
| **No Cross-Scan Asset Deduplication** | `replace_for_scan` replaces per scan |
| **No Cross-Source Asset Deduplication** | Static + Network + Runtime = separate assets |
| **Dedup Key Sensitivity** | Different key_size = different asset |
| **No Semantic Deduplication** | Same algorithm, different representation = separate |
| **No Library Deduplication** | Library fingerprints not deduped across sources |
| **No Certificate Deduplication** | Same cert from network + source = separate |

---

## 3. GRAPH DEDUPLICATION — MISSING

### 3.1 Graph Node Deduplication — MISSING

**File:** `services/graph_engine/graph_engine/core/engine.py:GraphEngine.build()`

```python
def build(self, systems, assets, edges, ...):
    for system in systems:
        self.add_node(f"system:{system.id}", kind="System", ...)
    for asset in assets:
        self.add_node(f"asset:{asset.id}", kind="CryptoAsset", ...)
    # NO deduplication - each call to add_node creates/updates
```

**Missing:**
- ❌ No node deduplication by canonical identity
- ❌ Multiple sources can create duplicate System nodes
- ❌ Multiple sources can create duplicate CryptoAsset nodes
- ❌ No canonical node identity resolution

### 3.2 Graph Edge Deduplication — MISSING

```python
def add_edge(self, src, dst, relation):
    if (dst, relation) not in self.out[src]:
        self.out[src].append((dst, relation))
```

**Missing:**
- ❌ No edge deduplication across graph builds
- ❌ No edge versioning
- ❌ No edge provenance tracking
- ❌ Duplicate edges from different sources

---

## 4. CBOM COMPONENT DEDUPLICATION — PARTIAL

### 4.1 CBOM Generation Deduplication

**File:** `services/cbom/cbom/generator.py:_component()`

```python
def _component(self, record):
    # Uses record.id or evidence_id or finding_id as bom-ref
    # If multiple records have same bom-ref → duplicate components
```

### 4.2 CBOM Deduplication Gaps

| Gap | Impact |
|-----|--------|
| **No Cross-Record Deduplication** | Same algorithm from different scans = duplicate components |
| **No Cross-Source Deduplication** | Static + Network + Runtime = duplicates |
| **No Component Merging** | Duplicate components not merged |
| **No Component Identity Resolution** | Same algorithm = same component? |

---

## 5. CERTIFICATE DEDUPLICATION — PARTIAL

### 5.1 Certificate Deduplication

| Source | Deduplication | Status |
|--------|---------------|--------|
| Network Scan | Certificate fingerprint (SHA-256) | ✅ Per scan |
| Source Code | PEM parsing → fingerprint | ✅ Per scan |
| Cloud Scanner | Cloud cert ARN + fingerprint | ❌ Not deduped |
| Container Scan | Cert in image layers | ⚠️ Partial |
| Config Files | PEM in config | ⚠️ Partial |

**Gap:** Same certificate from network scan + cloud scan + source code = **3 separate certificate records**

---

## 6. LIBRARY DEDUPLICATION — MISSING

### 6.1 Library Fingerprinting Deduplication

**File:** `services/universal_crypto/universal_crypto/library_fingerprints.py`

```python
def fingerprint(self, imports, symbols, strings, constants, apis, dependencies):
    # Returns list of library matches
    # NO deduplication across calls
    # Same library from different sources = multiple entries
```

**Gaps:**
- ❌ No cross-source library deduplication
- ❌ No library version canonicalization
- ❌ No library identity across scans
- ❌ No library version deduplication

---

## 7. DEPENDENCY DEDUPLICATION — MISSING

### 7.1 Dependency Graph Deduplication

| Dependency Type | Deduplication | Status |
|-----------------|---------------|--------|
| **System → System (CALLS)** | ❌ | Duplicate edges |
| **System → System (IMPORTS)** | ❌ | Duplicate edges |
| **System → CryptoAsset (USES)** | ❌ | Duplicate edges |
| **System → Library** | ❌ | Not modeled |
| **Library → Algorithm** | ❌ | Not modeled |
| **Certificate → System** | ❌ | Duplicate edges |

---

## 8. NETWORK ENDPOINT DEDUPLICATION — GOOD

### 8.1 Network Scanner Deduplication

**File:** `services/network_scanner/network_scanner/core/scanner.py`

```python
# Network scanner deduplicates by endpoint_hash (host:port)
# Latest probe wins, earlier probes discarded
# Certificate fingerprint used for cert deduplication
```

**Good:** Network scanner has endpoint-level deduplication.

---

## 7. CLOUD RESOURCE DEDUPLICATION — MISSING

### 7.1 Cloud Resource Deduplication

| Cloud Resource | Deduplication | Status |
|----------------|---------------|--------|
| **AWS Resources** | ARN-based | ❌ |
| **Azure Resources** | Resource ID | ❌ |
| **GCP Resources** | Resource name | ❌ |
| **KMS Keys** | Key ARN/ID | ❌ |
| **Certificates** | ARN + fingerprint | ❌ |

---

## 8. VENDOR DEDUPLICATION — MISSING

### 8.1 Vendor Deduplication

| Vendor Aspect | Deduplication | Status |
|---------------|---------------|--------|
| **Vendor Identity** | Name matching | ❌ |
| **Vendor Products** | Product mapping | ❌ |
| **Vendor Sub-tier** | Sub-tier mapping | ❌ |

---

## 8. EVIDENCE PRESERVATION — GOOD

### 8.1 Evidence Integrity During Deduplication

**File:** `services/evidence/evidence/core/pipeline.py`

```python
# Duplicates collapsed by content_hash
# BUT: duplicates_collapsed counter logged
# Original evidence NOT destroyed (first wins)
# Chain hash computed AFTER deduplication
```

**Good:** Evidence integrity preserved. First occurrence kept with full evidence chain.

---

## 9. RECOMMENDATIONS

### P0 — Critical

1. **Implement Graph Node Deduplication** — Canonical node identity by canonical ID
2. **Implement Graph Edge Deduplication** — Canonical edge identity
3. **Implement Cross-Source Asset Deduplication** — Unified asset identity
4. **Implement Cross-Source Certificate Deduplication** — Fingerprint-based merge

### P1 — High

4. **Implement Cross-Source Library Deduplication** — Canonical library identity + versions
5. **Implement Cross-Source Certificate Deduplication** — Fingerprint-based merge
6. **Implement Graph Node/Edge Provenance** — Track source of each node/edge
7. **Implement Asset Identity Service** — Canonical asset identity service

### P2 — Medium

8. **Implement Semantic Deduplication** — Same logical fact, different representation
9. **Implement Deduplication Provenance** — Track what was deduped, from where
9. **Implement Deduplication Metrics** — Duplicate rates, false dedup rate
10. **Implement Cross-Scan Deduplication** — Global asset identity across scans

### P3 — Enhancement

11. **Fuzzy Deduplication** — Near-match detection with confidence
12. **Deduplication Policy Engine** - Configurable dedup rules
12. **Deduplication Audit Trail** - What was deduped, when, why
13. **Fuzzy Certificate Matching** - Near-match cert detection

---

## 8. VERDICT

**Evidence pipeline deduplication is excellent. Asset/entity deduplication is largely missing.** Graph, BOMs, certificates, libraries, dependencies, cloud resources, and vendors all lack cross-source deduplication.

| Deduplication Area | Status |
|--------------------|--------|
| Evidence Pipeline | ✅ Excellent |
| Network Endpoints | ✅ Good |
| CryptoAsset Creation | ⚠️ Partial |
| Graph Nodes | ❌ Missing |
| Graph Edges | ❌ Missing |
| CBOM Components | ⚠️ Partial |
| NBOM Components | ❌ Missing |
| TechBOM Components | ❌ Missing |
| Certificates | ⚠️ Partial |
| Libraries | ❌ Missing |
| Dependencies | ❌ Missing |
| Cloud Resources | ❌ Missing |
| Vendors | ❌ Missing |

**To fix:** 8-12 weeks for unified asset identity service, graph deduplication, cross-source deduplication, and semantic deduplication.

---

## 10. VERIFICATION EVIDENCE

| Finding | File |
|---------|------|
| Evidence Pipeline Dedup | `services/evidence/evidence/core/pipeline.py` |
| Content Hasher | `services/evidence/evidence/hashing/content_hasher.py` |
| Asset Repository | `services/database/db/repositories/asset_repository.py` |
| Graph Engine | `services/graph_engine/graph_engine/core/engine.py` |
| CBOM Generator | `services/cbom/cbom/generator.py` |
| Network Scanner | `services/network_scanner/network_scanner/core/scanner.py` |
| Library Fingerprinter | `services/universal_crypto/universal_crypto/library_fingerprints.py` |
| Certificate Intel | `services/universal_crypto/universal_crypto/certificate_intel.py` |
| Network Scanner | `services/network_scanner/network_scanner/core/scanner.py` |
| Cloud Scanner | `services/cloud_scanner/cloud_scanner/core/scanner.py` |
| Container Scanner | `services/container_scanner/container_scanner/core/scanner.py` |
| Graph Builder | `services/api/api/graph_builder.py` |
---

## Round 26 update (2026-10-10) — dedup claims re-verified

* **P0#3 / P1#7 (unified asset identity) — STALE.**
  `cp_asset_identities` provides canonical, tenant-scoped asset
  identities fused across sources (mac / hostname / cloud resource /
  …), with an identity resolver and confidence scoring.
* **P0#4 (certificate fingerprint merge) — STALE.** Certificates
  upsert by `fingerprint_sha256` across network scans and revocation
  checks.
* **P0#1/#2 (graph node/edge dedup) — STALE.** The graph is rebuilt
  from canonical DB rows (ghost-node pruning shipped round 20); node
  identity is row identity, so cross-source duplicates collapse at the
  source tables.
* **Finding-level semantic dedup — STALE** (the dedup engine's
  canonical identity merges "RSA-2048"/"rsa_2048" across scanners; the
  evidence pipeline additionally collapses byte-identical findings
  pre-chain, counted and logged).
* **REMAIN OPEN, product-scoped:** canonical library identity with
  version normalization across ecosystems, and richer
  deduplication-provenance surfaces (scanner_ids and evidence members
  are retained on merged assets today).
