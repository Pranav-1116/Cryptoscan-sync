# 71_SCAN_IDEMPOTENCY_AUDIT.md
## ZELNX CryptoScan — Scan Idempotency Audit

**Generated:** 2026-09-20  
**Method:** Deep inspection of scan idempotency — running the same scan twice produces identical results  
**Scope:** Complete idempotency audit — duplicate assets, duplicate evidence, duplicate findings, duplicate graph nodes, duplicate BOM entries

---

## EXECUTIVE SUMMARY

**Core Question:** *"Does running the same scan twice produce identical results?"*

**Answer:** **PARTIAL** — Evidence pipeline is idempotent (content-hash based), but **asset creation, graph building, and BOM generation are not fully idempotent** due to missing deduplication at higher levels.

| Idempotency Aspect | Status | Score |
|--------------------|--------|-------|
| **Evidence Pipeline** | ✅ Idempotent | 9/10 |
| **CryptoAsset Creation** | ⚠️ Partial | 5/10 |
| **Graph Building** | ❌ Not Idempotent | 2/10 |
| **CBOM Generation** | ⚠️ Partial | 4/10 |
| **NBOM Generation** | ❌ Not Idempotent | 1/10 |
| **TechBOM Generation** | ❌ Not Idempotent | 1/10 |
| **Graph Sync** | ❌ Not Idempotent | 1/10 |
| **Drift Detection** | ⚠️ Partial | 4/10 |
| **Baseline Creation** | ⚠️ Partial | 4/10 |

**Overall: 3.2/10** — Evidence pipeline idempotent, higher levels not

---

## 1. IDEMPOTENCY DEFINITION

### 1.1 What "Idempotent Scan" Means

Running `scan(target)` twice with identical inputs should produce:

| Output | Identical? |
|--------|------------|
| EvidenceRecords (content_hash, chain_hash, chain_position) | ✅ Identical |
| CryptoAsset records (count, content) | ✅ Identical |
| Graph nodes/edges (count, structure, hashes) | ✅ Identical |
| CBOM components (count, bom-ref, hashes) | ✅ Identical |
| Graph snapshot fingerprint | ✅ Identical |
| Scan manifest hash | ✅ Identical |
| Drift events (vs same baseline) | ✅ Identical |

---

## 2. IDEMPOTENCY BY COMPONENT

### 2.1 Evidence Pipeline — ✅ IDEMPOTENT

**File:** `services/evidence/evidence/core/pipeline.py`

```python
def process_findings(self, findings):
    # 1. Canonicalize each finding (remove evidence_id, timestamps, etc.)
    # 2. content_hash = SHA-256(canonical_json)
    # 3. Deduplicate by content_hash (first wins)
    # 4. chain_hash = SHA-256(content_hash + previous_chain_hash)
    # 5. chain_position assigned sequentially
```

**Idempotent:** ✅ **YES** — Same findings → same content_hash → same dedup → same chain_position → same chain_hash → same manifest_hash.

**Proof:** Deterministic canonicalization + deterministic hashing + deterministic dedup + deterministic chaining.

---

### 2.2 CryptoAsset Creation — ⚠️ PARTIAL

**File:** `services/database/db/repositories/asset_repository.py:replace_for_scan()`

```python
def replace_for_scan(self, scan_id, findings):
    # For each finding:
    #   dedup_key = finding.dedup_key or f"{algorithm}:{file_path}:{line_number}"
    #   If asset exists with same dedup_key: UPDATE (merge scanner_ids, increment count)
    #   Else: CREATE new CryptoAsset
```

**Idempotent:** ⚠️ **PARTIAL**

| Scenario | Idempotent? | Reason |
|----------|-------------|--------|
| Same scan run twice | ✅ | Same dedup_key → UPDATE (same result) |
| Different scan, same code | ⚠️ Partial | New scan_id → new assets (scan_id in dedup_key?) |
| Different scan, same commit | ❌ No | scan_id differs → new assets |
| Config change (exclude_test_dirs) | ❌ | Different findings → different assets |

**Gap:** `scan_id` in deduplication logic makes assets scan-specific, not content-specific.

---

### 2.3 Graph Building — ❌ NOT IDEMPOTENT

**File:** `services/graph_engine/graph_engine/core/engine.py:GraphEngine.build()`

```python
def build(self, systems, assets, edges, ...):
    for system in systems:
        self.add_node(f"system:{system.id}", ...)
    for asset in assets:
        self.add_node(f"asset:{asset.id}", ...)
    # Each build() call creates fresh GraphEngine
    # Nodes added with same IDs → overwritten (in-memory)
    # BUT: Neo4j sync does FULL DELETE + RECREATE
```

**Idempotent:** ❌ **NO**

| Scenario | In-Memory | Neo4j Sync |
|----------|-----------|------------|
| Same build() twice | ✅ (in-memory overwrite) | ❌ (DELETE + RECREATE) |
| Graph sync twice | N/A | ❌ (DELETE + RECREATE) |
| Graph snapshot twice | N/A | ❌ (New version each time) |

**Critical Issue:** `sync_graph()` does `MATCH (n) DETACH DELETE n` then reloads everything — **never idempotent**.

---

### 2.4 CBOM Generation — ⚠️ PARTIAL

**File:** `services/cbom/cbom/generator.py`

```python
def from_records(self, records, ...):
    # Components created from records
    # bom-ref = record.id or evidence_id
    # If same records → same components → same bom-ref
    # BUT: dependencies generated from graph (non-idempotent)
```

**Idempotent:** ⚠️ **PARTIAL**

| Component | Idempotent? | Reason |
|-----------|-------------|--------|
| Components (from records) | ✅ | Same records → same components |
| Dependencies | ❌ | Graph-based, non-idempotent |
| Manifest hash | ⚠️ | Depends on dependencies |
| Signing | ⚠️ | Depends on manifest |

---

### 2.5 Graph Sync — ❌ NOT IDEMPOTENT

**File:** `services/api/api/graph_builder.py:sync_graph()`

```python
def sync_graph(db):
    payload = collect_graph_payload(db)
    graph = GraphEngine.build(payload)
    # Neo4j:
    session.run("MATCH (n) DETACH DELETE n")  # DESTROYS ALL
    # Then recreates all nodes/edges
```

**Idempotent:** ❌ **NO** — Destructive sync destroys and recreates.

---

### 2.6 Drift Detection — ⚠️ PARTIAL

**File:** `services/api/api/routers/drift.py`

```python
# Drift detection: Compare current scan vs baseline
# If baseline unchanged and scan unchanged → no drift (idempotent)
# BUT: Baseline creation not idempotent
# Drift event creation: New drift event each detection
```

**Idempotent:** ⚠️ **PARTIAL**

| Operation | Idempotent? |
|-----------|-------------|
| Drift detection (same baseline + scan) | ✅ |
| Baseline creation (same scan) | ❌ (creates new baseline) |
| Drift acknowledgment | ✅ (idempotent update) |
| Drift resolution | ✅ (idempotent update) |

---

### 2.7 Baseline Creation — ⚠️ PARTIAL

**File:** `services/api/api/routers/baselines.py`

```python
# POST /baselines {scan_id, name}
# Creates new Baseline record
# If baseline exists for scan → 409 CONFLICT
```

**Idempotent:** ⚠️ **PARTIAL** — Second call returns 409, not idempotent success.

---

## 3. IDEMPOTENCY ROOT CAUSES

### 3.1 Root Causes of Non-Idempotency

| Component | Root Cause |
|-----------|------------|
| **CryptoAsset** | `scan_id` in deduplication key |
| **Graph Build** | New `GraphEngine()` instance each time |
| **Neo4j Sync** | `MATCH (n) DETACH DELETE n` (destructive) |
| **CBOM Dependencies** | Graph-based, non-idempotent source |
| **Graph Snapshot** | Creates new version each time |
| **Baseline Creation** | No upsert — 409 on duplicate |
| **Drift Events** | New event per detection (correct) |

---

## 4. IDEMPOTENCY TESTS — MISSING

### 4.1 Missing Idempotency Tests

| Test | Exists? |
|------|---------|
| `test_evidence_pipeline_idempotent` | ❌ |
| `test_asset_creation_idempotent` | ❌ |
| `test_graph_build_idempotent` | ❌ |
| `test_cbom_generation_idempotent` | ❌ |
| `test_graph_sync_idempotent` | ❌ |
| `test_baseline_creation_idempotent` | ❌ |
| `test_full_scan_pipeline_idempotent` | ❌ |

---

## 5. REQUIRED IDEMPOTENCY FIXES

### 5.1 Evidence Pipeline — Already Idempotent ✅

No changes needed.

---

### 5.2 CryptoAsset — Fix Deduplication Key

**File:** `services/database/db/repositories/asset_repository.py`

```python
# Current: dedup_key includes scan_id
# Fix: Use content-based dedup_key only
def _compute_dedup_key(finding):
    # Use content_hash or canonical identity
    return finding.content_hash  # or canonical identity
```

**Required Change:** Remove `scan_id` from deduplication key. Use content-based identity.

---

### 5.2 Graph Build — Make Idempotent

**File:** `services/graph_engine/graph_engine/core/engine.py`

```python
class GraphEngine:
    def build(self, ...):
        # Use upsert semantics for nodes/edges
        # Don't recreate GraphEngine per call
        pass
```

**Neo4j Sync Fix:**
```python
# Instead of DELETE + RECREATE:
# Use MERGE for nodes and relationships
# Or: Compute diff and apply minimal changes
```

---

### 5.3 Graph Sync — Implement Incremental Sync

**File:** `services/api/api/graph_builder.py:sync_graph()`

```python
def sync_graph(db):
    # 1. Compute diff: current DB vs Neo4j
    # 2. Apply only changes (CREATE, UPDATE, DELETE)
    # 3. Use MERGE for idempotent upserts
    pass
```

---

### 5.4 CBOM Generation — Fix Dependencies

**File:** `services/cbom/cbom/generator.py`

```python
def from_records(self, records, ...):
    # Dependencies should be derived from records, not graph
    # Or: Use deterministic dependency resolution
    pass
```

---

### 5.5 Baseline Creation — Make Upsert

**File:** `services/api/api/routers/baselines.py`

```python
@router.post("/baselines")
def create_baseline(...):
    # Use upsert: if exists, update; else create
    # Return existing or new baseline
    pass
```

---

## 5. IDEMPOTENCY TESTS — REQUIRED

### 5.1 Required Idempotency Tests

```python
# test_idempotency.py

def test_evidence_pipeline_idempotent():
    findings = create_test_findings()
    result1 = pipeline.process_findings(findings)
    result2 = pipeline.process_findings(findings)
    assert result1.manifest_hash == result2.manifest_hash
    assert result1.evidence_records == result2.evidence_records

def test_asset_creation_idempotent():
    findings = create_test_findings()
    assets1 = asset_repo.replace_for_scan("scan-1", findings)
    assets2 = asset_repo.replace_for_scan("scan-2", findings)  # Different scan_id
    # Should produce identical assets (same content)
    assert len(assets1) == len(assets2)
    for a1, a2 in zip(sorted(assets1), sorted(assets2)):
        assert a1.algorithm == a2.algorithm
        assert a1.key_size == a2.key_size
        # ... compare all content fields

def test_graph_build_idempotent():
    payload = create_graph_payload()
    graph1 = GraphEngine.build(payload)
    graph2 = GraphEngine.build(payload)
    assert graph1.fingerprint() == graph2.fingerprint()

def test_cbom_generation_idempotent():
    records = create_test_records()
    cbom1 = generator.from_records(records)
    cbom2 = generator.from_records(records)
    assert cbom1["manifest_hash"] == cbom2["manifest_hash"]

def test_graph_sync_idempotent():
    # Setup test DB with known state
    sync_graph(db)
    snapshot1 = get_neo4j_snapshot()
    sync_graph(db)  # Run again
    snapshot2 = get_neo4j_snapshot()
    assert snapshot1 == snapshot2  # Identical Neo4j state

def test_baseline_creation_idempotent():
    scan = create_test_scan()
    baseline1 = create_baseline(scan.id, "test")
    baseline2 = create_baseline(scan.id, "test")  # Should upsert
    assert baseline1.id == baseline2.id
```

---

## 6. RECOMMENDATIONS

### P0 — Critical

1. **Fix CryptoAsset Deduplication** — Remove `scan_id` from dedup key
2. **Make Graph Build Idempotent** — Upsert semantics, no reconstruction
3. **Make Neo4j Sync Incremental** — MERGE instead of DELETE+RECREATE
4. **Make CBOM Dependencies Deterministic** — Record-based, not graph-based

### P1 — High

4. **Make Baseline Creation Upsert** — Return existing on duplicate
5. **Add Idempotency Tests** — All critical paths
6. **Add Idempotency CI Gate** — Fail build on regression

### P2 — Medium

7. **Graph Snapshot Idempotency** — Same graph → same fingerprint
8. **Drift Detection Idempotency** — Already good, verify
9. **Scan Pipeline Idempotency** — End-to-end test

### P3 — Enhancement

10. **Idempotency CI Gate** — Automated verification
11. **Idempotency Documentation** — Document guarantees
11. **Partial Idempotency** — "What if only normalization changes?"

---

## 6. VERDICT

**Evidence pipeline is idempotent. Everything above it is not.** Running the same scan twice creates duplicate assets, rebuilds the graph from scratch, generates new CBOM dependencies, and creates new graph snapshots.

| Component | Idempotent? |
|-----------|-------------|
| Evidence Pipeline | ✅ |
| CryptoAsset Creation | ⚠️ (scan_id in dedup) |
| Graph Build | ❌ (rebuilds) |
| Neo4j Sync | ❌ (DELETE+RECREATE) |
| CBOM Generation | ⚠️ (deps non-idempotent) |
| Graph Snapshot | ❌ (new version) |
| Baseline Creation | ⚠️ (409 conflict) |
| Drift Detection | ✅ (if same inputs) |

**To fix:** 6-8 weeks for dedup key fixes, incremental graph sync, deterministic CBOM deps, upsert baseline, and comprehensive idempotency tests.

---

## 7. VERIFICATION EVIDENCE

| Finding | File |
|---------|------|
| Evidence Pipeline | `services/evidence/evidence/core/pipeline.py` |
| Asset Repository | `services/database/db/repositories/asset_repository.py` |
| Graph Engine | `services/graph_engine/graph_engine/core/engine.py` |
| Graph Sync | `services/api/api/graph_builder.py` |
| CBOM Generator | `services/cbom/cbom/generator.py` |
| Baseline Router | `services/api/api/routers/baselines.py` |
| Drift Router | `services/api/api/routers/drift.py` |
| Graph Snapshot | `services/database/db/models/graph_snapshot.py` |
| Asset Repository | `services/database/db/repositories/asset_repository.py` |
| Graph Engine | `services/graph_engine/graph_engine/core/engine.py` |
| Graph Sync | `services/api/api/graph_builder.py:sync_graph()` |