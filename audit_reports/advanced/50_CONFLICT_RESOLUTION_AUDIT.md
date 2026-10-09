# 50_CONFLICT_RESOLUTION_AUDIT.md
## ZELNX CryptoScan — Conflict Resolution Audit

**Generated:** 2026-09-20  
**Method:** Deep inspection of how contradictory evidence from different collectors is handled  
**Scope:** Evidence conflict detection, storage, resolution, provenance preservation, and user exposure

---

## EXECUTIVE SUMMARY

**Core Question:** *"What happens when different collectors disagree?"*

**Answer:** **Conflicts are silently stored with no detection, no resolution, and no user exposure.**

| Conflict Aspect | Status | Score |
|-----------------|--------|-------|
| Conflict Detection | ❌ Missing | 0/10 |
| Conflict Storage | ⚠️ Both stored | 2/10 |
| Evidence Preservation | ✅ Both preserved | 8/10 |
| Fact Overwrite | ❌ Neither overwritten | 5/10 (by accident) |
| Confidence Changes | ❌ No adjustment | 0/10 |
| Provenance Preservation | ✅ Both kept | 8/10 |
| User Exposure | ❌ Hidden | 0/10 |

**Overall: 2.3/10** — No conflict resolution mechanism exists

---

## 1. CONFLICT SCENARIOS — REAL WORLD

### 1.1 Typical Conflict Scenarios

| Scenario | Source A | Source B | Current Behavior |
|----------|----------|----------|------------------|
| **Algorithm Disagreement** | Source: RSA-2048 (Java) | Network: RSA-3072 (TLS cert) | Both stored as separate findings |
| **Key Size Disagreement** | Source: RSA-2048 | Network: RSA-3072 | Both stored |
| **Algorithm Type Disagreement** | Source: RSA-2048 | Network: ECDSA P-256 | Both stored |
| **Protocol Disagreement** | Config: TLS 1.2 | Network: TLS 1.3 | Both stored |
| **Certificate Disagreement** | Source: RSA-2048 cert | Network: ECDSA P-256 cert | Both stored |
| **Key Size Disagreement** | Cloud KMS: RSA-2048 | Source: RSA-4096 | Both stored |
| **Library Version** | SBOM: OpenSSL 3.0.11 | Binary: OpenSSL 1.1.1 | Both stored |
| **Algorithm Presence** | Source: AES-256 | Network: ChaCha20 | Both stored |

---

### 1.2 Why Conflicts Occur

| Cause | Example |
|-------|---------|
| **Different Perspectives** | Source = what's in code; Network = what's deployed |
| **Different Times** | Baseline scan vs current scan |
| **Different Abstractions** | Source = logical algorithm; Network = negotiated cipher |
| **Different Abstractions** | Source = algorithm; Network = cipher suite |
| **Different Deployments** | Staging vs Production |
| **Configuration Drift** | Config changed but not redeployed |
| **Library vs Application** | App uses library X; Library implements algorithm Y |

---

## 2. CONFLICT DETECTION — MISSING

### 2.1 Current: No Detection Logic

**File:** `services/evidence/evidence/core/pipeline.py:process_findings()`

```python
# Current deduplication: ONLY by content_hash
seen_hashes = set()
for finding, chash in hashed:
    if chash in seen_hashes:
        duplicates_collapsed += 1
        continue
    seen_hashes.add(chash)
    deduped.append((finding, chash))
```

**What this detects:** Byte-identical findings after canonicalization.

**What this MISSES:**
- Same logical fact, different values (RSA-2048 vs RSA-3072)
- Same asset, different algorithms (RSA vs ECDSA)
- Same algorithm, different key sizes
- Same certificate, different sources
- Network vs Source disagreement
- Runtime vs Static disagreement

### 2.2 No Conflict Detection Anywhere

| Component | Conflict Detection |
|-----------|-------------------|
| Evidence Pipeline | ❌ Only content_hash dedup |
| Normalization | ❌ Fallback to UNKNOWN |
| Policy Engine | ❌ Evaluates each finding independently |
| Graph Engine | ❌ Aggregates, no conflict flag |
| CBOM Generator | ❌ Includes all components |
| Drift Detection | ⚠️ Only baseline vs current |
| Universal Crypto | ❌ Fusion merges, no conflict flag |

---

## 3. CONFLICT STORAGE — BOTH PRESERVED

### 3.1 Current: Both Stored Silently

**EvidenceRecord Model:** Each finding gets its own row

```python
# Each finding → separate EvidenceRecord
# No conflict flag, no conflict_id, no resolution_status
class EvidenceRecord:
    scan_id: str
    content_hash: str
    chain_hash: str
    finding_data: dict  # Full finding including algorithm, key_size, etc.
    provenance: dict    # Source, collector, timestamp
    # NO conflict_id, conflict_type, resolution_status
```

**Result:** Conflicting findings coexist as separate rows with no linkage.

### 3.2 CryptoAsset Deduplication (Partial)

**File:** `services/database/db/repositories/asset_repository.py:replace_for_scan()`

```python
def replace_for_scan(self, scan_id, findings):
    # Deduplication key: finding.dedup_key or algorithm+file+line
    # If same dedup_key: merge scanner_ids, increment occurrence_count
    # BUT: Different key_size or algorithm = different dedup_key = separate assets
```

**Gap:** Logical conflicts (same location, different key_size) create separate CryptoAssets.

---

## 4. FACT OVERWRITE — NEITHER OVERWRITTEN (BY ACCIDENT)

### 4.1 Current: Append-Only

| Operation | Behavior |
|-----------|----------|
| New scan | New EvidenceRecords appended |
| New baseline | New Baseline row |
| Drift event | New DriftEvent row |
| CBOM ingest | New CryptoAssets (or replace_for_scan) |
| Graph sync | Full Neo4j wipe + rebuild |

**No fact ever overwritten** — but not by design, just append-only architecture.

### 4.2 Missing: Explicit Fact Resolution

| Scenario | Current | Should Be |
|----------|---------|-----------|
| Baseline approved, new scan contradicts | DriftEvent created | Explicit resolution workflow |
| Two scanners disagree on same fact | Both stored | Conflict flag + resolution |
| Source updated, old finding obsolete | Both stored | Supersession tracking |
| Manual correction | New finding | Supersession + audit |

---

## 5. CONFIDENCE CHANGES — NO ADJUSTMENT

### 5.1 Current: Static Confidence

**File:** `services/universal_crypto/universal_crypto/confidence.py`

```python
def score_evidence(evidence_list):
    # Weights per evidence type, diminishing returns
    # No conflict penalty, no source reputation, no freshness decay
```

### 5.2 Missing Confidence Adjustments

| Scenario | Current | Should Be |
|----------|---------|-----------|
| Conflict detected | No change | Reduce confidence for all conflicting |
| Higher authority source | No change | Boost confidence for authoritative |
| Stale evidence | No change | Decay confidence over time |
| Corroboration from independent source | Slight boost (diminishing returns) | Authority boost |
| Single source, no corroboration | No penalty | Reduce confidence |
| Stale evidence | No penalty | Exponential decay |

---

## 6. PROVENANCE PRESERVATION — GOOD BUT DISCONNECTED

### 6.1 Provenance Preserved Per Finding

**File:** `services/evidence/evidence/core/pipeline.py`

```python
provenance = {
    "collector": "static-multi-scanner-v1.0",
    "scan_id": "scan-uuid",
    "scan_timestamp": "2026-09-20T10:00:00Z",
    "git_context": {...},
    "detector": "java_parser",
    "extractor": "algorithm_extractor"
}
```

**Good:** Each finding keeps full provenance.

### 6.2 Gap: No Cross-Finding Provenance Link

| Missing | Impact |
|---------|--------|
| **Conflict provenance** | No link between conflicting findings |
| **Resolution provenance** | No record of how conflict resolved |
| **Supersession chain** | No link from old finding to new |
| **Correction audit** | No correction trail |

---

## 7. USER EXPOSURE — HIDDEN

### 7.1 Current: No Conflict UI/API

| Interface | Conflict Visibility |
|-----------|---------------------|
| **CBOM** | All components listed, no conflict flag |
| **Graph** | All nodes/edges shown, no conflict flag |
| **Findings Page** | All findings listed, no conflict grouping |
| **Drift Page** | Only baseline vs current, no multi-source |
| **Graph Explain** | Shows evidence for single path, no conflicts |
| **API** | No conflict endpoints |

### 7.2 What Users See vs Reality

| User View | Reality |
|-----------|---------|
| "RSA-2048 found in Payment API" | Also RSA-3072 in network, ECDSA in cert |
| "Compliance: FAIL" | Also PASS from another source |
| "Quantum Vulnerable: YES" | Also QUANTUM_SAFE from another source |
| "Single finding per location" | Multiple findings per location |

---

## 8. REQUIRED CONFLICT RESOLUTION MODEL

### 8.1 Conflict Data Model

```python
class EvidenceConflict:
    conflict_id: UUID
    conflict_type: ConflictType  # ALGORITHM_MISMATCH, KEY_SIZE_MISMATCH, PROTOCOL_MISMATCH, CERTIFICATE_MISMATCH, ALGORITHM_PRESENCE
    logical_fact: LogicalFact     # What is in conflict (algorithm, key_size, protocol, certificate)
    asset_identity: CanonicalAssetIdentity  # What asset this concerns
    
    conflicting_evidence: List[ConflictEvidence]
    detection_timestamp: DateTime
    detection_method: DetectionMethod  # AUTO_DETECT, USER_REPORT, POLICY_CHECK
    
    resolution: ConflictResolution | None
    resolved_by: str | None
    resolved_at: DateTime | None
    resolution_method: ResolutionMethod | None  # AUTHORITY_WINS, MANUAL, NEW_EVIDENCE, TIME_DECAY
    resolution_notes: str | None
    
    status: ConflictStatus  # OPEN, ACKNOWLEDGED, RESOLVED, FALSE_POSITIVE, SUPPRESSED
    severity: ConflictSeverity  # CRITICAL, HIGH, MEDIUM, LOW
```

### 8.2 Conflict Evidence

```python
class ConflictEvidence:
    evidence_id: UUID
    evidence_type: EvidenceType
    source: DiscoverySource
    claimed_value: Any          # The actual conflicting value
    confidence: float
    authority_level: AuthorityLevel
    provenance: Provenance
    content_hash: str
    chain_hash: str
```

### 8.3 Resolution Methods

| Method | Rule |
|--------|------|
| `AUTHORITY_WINS` | Highest authority level wins (certificate > network > source > heuristic) |
| `MANUAL` | Human reviewer decides |
| `NEW_EVIDENCE` | New evidence resolves (e.g., new scan confirms one) |
| `TIME_DECAY` | Stale evidence decays, fresh wins |
| `CORROBORATION` | Most corroborated wins (independent sources) |
| `MANUAL_OVERRIDE` | Explicit human decision recorded |

---

## 8. REQUIRED CONFLICT WORKFLOW

### 8.1 Detection → Resolution Flow

```
1. DETECTION
   ├── New evidence arrives
   ├── Compare against existing facts for same logical fact + asset
   ├── If values differ → CREATE Conflict
   └── Emit platform.conflict.detected event

2. NOTIFICATION
   ├── Alert asset owner, security analyst, business owner
   ├── Add to Conflict Dashboard
   └── Include in daily digest

3. TRIAGE
   ├── Auto-resolve if AUTHORITY_WINS applies
   ├── Queue for human review if MANUAL needed
   └── Defer if NEW_EVIDENCE expected

4. RESOLUTION
   ├── Record resolution method, actor, notes
   ├── Update fact confidence per resolution
   ├── Create resolution audit trail
   └── Emit platform.conflict.resolved event

5. SUPERSESSION
   ├── Link old findings to resolution
   ├── Update fact confidence per resolution
   └── Suppress resolved conflicts from default views
```

### 8.2 Required API Endpoints

| Endpoint | Purpose |
|----------|---------|
| `GET /conflicts` | List conflicts with filters |
| `GET /conflicts/{id}` | Conflict detail with all evidence |
| `POST /conflicts/{id}/resolve` | Resolve with method + notes |
| `POST /conflicts/{id}/suppress` | Suppress with reason |
| `GET /conflicts/{id}/evidence` | All conflicting evidence |
| `GET /conflicts/{id}/history` | Resolution history |
| `GET /assets/{id}/conflicts` | Conflicts for specific asset |

---

## 9. REQUIRED USER EXPOSURE

### 9.1 Conflict Dashboard

| View | Content |
|------|---------|
| **Conflict List** | Filterable by severity, status, asset, type |
| **Conflict Detail** | Side-by-side evidence comparison |
| **Conflict Timeline** | Detection → Triage → Resolution |
| **Asset Conflict View** | All conflicts for an asset |
| **System Conflict Summary** | Rollup per system |

### 9.2 Conflict-Aware Views

| View | Conflict Indicator |
|------|-------------------|
| **CBOM** | ⚠️ Badge on conflicted components |
| **Graph** | ⚠️ Red edge/node for conflicted |
| **Findings** | 🔴 Conflict badge, expandable |
| **Asset Detail** | ⚠️ Conflict count badge |
| **Drift Page** | Separate "Multi-source Conflicts" section |

---

## 10. RECOMMENDATIONS

### P0 — Critical

1. **Implement Conflict Detection** — Compare logical facts across sources at ingestion
2. **Add Conflict Data Model** — `EvidenceConflict`, `ConflictEvidence`, `ConflictResolution`
3. **Implement Authority-Based Resolution** — Certificate > Network > Source > Heuristic
3. **Add Conflict API + Dashboard** — Full CRUD + dashboard

### P1 — High

4. **Implement Confidence Adjustment** — Conflict penalty, authority boost, freshness decay
5. **Add Conflict Dashboard** — Full CRUD UI with evidence comparison
5. **Implement Auto-Resolution** — AUTHORITY_WINS, TIME_DECAY, CORROBORATION
6. **Add Conflict Notifications** — Real-time alerts for CRITICAL/HIGH conflicts

### P2 — Medium

7. **Conflict Suppression** — Suppress with reason, audit trail
8. **Conflict Suppression Expiry** — Auto-reopen after configurable time
8. **Cross-Source Correlation** — Link related conflicts across assets
9. **Conflict Analytics** — Recurring conflicts, systemic issues

### P3 — Enhancement

10. **ML-Assisted Resolution** — Learn from human resolutions
11. **Conflict Prediction** — Predict conflicts from scan patterns
12. **Conflict Simulation** — "What if this evidence changes?"
13. **Conflict Export** — STIX/JSON export for sharing

---

## 11. VERDICT

**ZELNX has ZERO conflict resolution capability.** Conflicts are silently stored as separate findings with no detection, no resolution, no confidence adjustment, and no user visibility.

| Capability | Status |
|------------|--------|
| Conflict Detection | ❌ Missing |
| Conflict Storage | ⚠️ Both stored, unlinked |
| Evidence Preservation | ✅ Both preserved |
| Fact Overwrite | ❌ Neither (accidental) |
| Confidence Adjustment | ❌ No adjustment |
| Provenance Preservation | ✅ Both preserved |
| User Exposure | ❌ Completely hidden |
| Resolution Workflow | ❌ Missing |
| Authority-Based Resolution | ❌ Missing |

**To fix:** 6-8 weeks for complete conflict resolution system with detection, model, API, dashboard, and authority-based resolution.

---

## 10. VERIFICATION EVIDENCE

| Finding | File |
|---------|------|
| EvidencePipeline deduplication | `services/evidence/evidence/core/pipeline.py` |
| EvidenceRecord model | `services/database/db/models/evidence_record.py` |
| CryptoAsset dedup | `services/database/db/repositories/asset_repository.py` |
| Confidence scoring | `services/universal_crypto/universal_crypto/confidence.py` |
| UniversalCryptoEngine fusion | `services/universal_crypto/universal_crypto/engine.py:_to_observations()` |
| Graph edge evidence | `services/api/api/routers/graph.py:_edge_evidence()` |
| CBOM generator | `services/cbom/cbom/generator.py` |
| Drift detection | `services/api/api/routers/drift.py` |
| AssetRepository replace_for_scan | `services/database/db/repositories/asset_repository.py` |
| Pipeline dedup | `services/evidence/evidence/core/pipeline.py:process_findings()` |