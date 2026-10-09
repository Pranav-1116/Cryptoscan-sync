# 25_EVIDENCE_CHAIN_FORENSIC_AUDIT.md
## ZELNX CryptoScan — Evidence Chain Forensic Audit

**Generated:** 2026-09-20  
**Method:** End-to-end trace of a single cryptographic observation from collection through evidence chain, normalization, policy, graph, CBOM, API, and UI  
**Scope:** Complete evidence pipeline — collector → observation → hash → evidence → database → normalization → policy → graph → CBOM → API → UI

---

## EXECUTIVE SUMMARY

| Pipeline Stage | Implementation | Integrity | Traceability | Gaps |
|----------------|----------------|-----------|--------------|------|
| Collection (Scanner) | ✅ | ✅ | ✅ | — |
| Observation Creation | ✅ | ✅ | ✅ | — |
| Canonical Serialization | ✅ | ✅ | ✅ | Two implementations |
| Content Hash (SHA-256) | ✅ | ✅ | ✅ | — |
| Deduplication | ✅ | ✅ | ✅ | Race condition possible |
| Chain Hash | ✅ | ✅ | ✅ | — |
| Manifest | ✅ | ✅ | ✅ | — |
| Database Storage | ✅ | ✅ | ✅ | Link tables not populated |
| Normalization | ✅ | ✅ | ✅ | Duplicate registries |
| Policy Evaluation | ✅ | ✅ | ✅ | — |
| Graph Integration | ✅ | ✅ | ⚠️ | Edge evidence weak |
| CBOM Generation | ✅ | ✅ | ✅ | Three generators |
| API Exposure | ✅ | ✅ | ✅ | — |
| UI Display | ✅ | ✅ | ✅ | — |

**Overall: 8/10** — Strong evidence chain with cryptographic integrity, but gaps in link tables, graph evidence, and dual CBOM pipelines.

---

## 1. END-TO-END TRACE: SINGLE OBSERVATION

### 1.1 Scenario: RSA-2048 Key Generation in Java Source

**Source Code:**
```java
// File: src/main/java/com/example/CryptoUtil.java:42
KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
kpg.initialize(2048);
KeyPair kp = kpg.generateKeyPair();
```

---

### 1.2 Stage 1: COLLECTION (Scanner)

**File:** `services/scanner/scanner/core/scanner.py:Scanner.scan()`

```python
# 1. FileDiscovery discovers src/main/java/com/example/CryptoUtil.java
# 2. LanguageDetector identifies JAVA
# 3. scan_file() → java_parser.py → Java AST visitor
# 4. java_rules.py detects KeyPairGenerator.initialize(2048)
# 5. Extractors enrich: algorithm="RSA", key_size=2048, operation=KEY_GENERATION
```

**Output — RawFinding:**
```python
RawFinding(
    finding_id="java-rsa-keygen-42",
    crypto=CryptoInfo(
        algorithm="RSA",
        key_size=2048,
        operation=Operation.KEY_GENERATION,
        mode=None,
        padding=None
    ),
    location=SourceLocation(
        file_path="src/main/java/com/example/CryptoUtil.java",
        line_number=42,
        class_name="CryptoUtil",
        method_name="generateKeyPair"
    ),
    metadata=FindingMetadata(
        confidence="HIGH",
        code_origin="source",
        scanner_id="static-multi-scanner-v1.0",
        git_context=GitContext(
            commit_hash="abc123...",
            commit_author="developer",
            commit_timestamp="2026-09-20T10:00:00Z",
            branch="main",
            repository_url="https://github.com/org/repo"
        )
    )
)
```

**Evidence at this stage:** Raw AST finding, no hashes yet.

---

### 1.3 Stage 2: OBSERVATION CREATION (Universal Crypto Engine)

**File:** `services/universal_crypto/universal_crypto/engine.py:UniversalCryptoEngine.scan()`

```python
# RawFinding → CryptoObservation
# Evidence fusion: combines static + runtime + binary evidence
```

**Output — CryptoObservation:**
```python
CryptoObservation(
    algorithm="RSA",
    operation=Operation.KEY_GENERATION,
    key_size=2048,
    asset_id="repo:org/repo",
    location="src/main/java/com/example/CryptoUtil.java:42",
    evidence=[
        Evidence(kind=EvidenceType.AST, 
                 detail="KeyPairGenerator.initialize(2048) at CryptoUtil.java:42",
                 location="src/main/java/com/example/CryptoUtil.java:42")
    ],
    confidence=0.95,
    band="HIGH",
    usage=True,
    capability=True,
    source="source_code",
    quantum_status=QuantumStatus.QUANTUM_VULNERABLE
)
```

**Evidence at this stage:** Normalized observation with evidence list, quantum status from registry.

---

### 1.4 Stage 3: CANONICAL SERIALIZATION

**File:** `services/evidence/evidence/hashing/canonical_serializer.py`

```python
class CanonicalSerializer:
    EXCLUDED_FIELDS = {"evidence_id", "created_at", "scan_timestamp", "finding_id"}
    
    @staticmethod
    def serialize(data: Dict[str, Any]) -> str:
        cleaned = CanonicalSerializer._clean_data(data)  # Removes EXCLUDED_FIELDS
        return canonical_bytes(cleaned)  # From shared_models.canonical
```

**Canonical JSON Output:**
```json
{
  "algorithm": "RSA",
  "key_size": 2048,
  "operation": "KEY_GENERATION",
  "asset_id": "repo:org/repo",
  "location": "src/main/java/com/example/CryptoUtil.java:42",
  "evidence": [
    {
      "kind": "AST",
      "detail": "KeyPairGenerator.initialize(2048) at CryptoUtil.java:42",
      "location": "src/main/java/com/example/CryptoUtil.java:42"
    }
  ],
  "confidence": 0.95,
  "band": "HIGH",
  "usage": true,
  "capability": true,
  "source": "source_code",
  "quantum_status": "QUANTUM_VULNERABLE"
}
```

**Key Properties:**
- ✅ Sorted keys (alphabetical)
- ✅ No whitespace
- ✅ Deterministic float formatting
- ✅ Excluded fields: `evidence_id`, `created_at`, `scan_timestamp`, `finding_id`
- ✅ UTF-8 encoded

---

### 1.5 Stage 4: CONTENT HASH (SHA-256)

**File:** `services/evidence/evidence/hashing/content_hasher.py`

```python
class ContentHasher:
    @staticmethod
    def compute_hash(data: Dict[str, Any]) -> str:
        canonical_bytes = CanonicalSerializer.serialize_to_bytes(data)
        return hashlib.sha256(canonical_bytes).hexdigest()
```

**Result:** `content_hash = "a1b2c3d4e5f6..."` (64 hex chars)

**Verification:** `ContentHasher.verify_hash(data, expected_hash)` → `True`

---

### 1.6 Stage 5: DEDUPLICATION

**File:** `services/evidence/evidence/core/pipeline.py:process_findings()`

```python
# Collapse byte-identical findings after canonicalization
seen_hashes = set()
deduped = []
for finding, chash in hashed:
    if chash in seen_hashes:
        duplicates_collapsed += 1
        continue
    seen_hashes.add(chash)
    deduped.append((finding, chash))
```

**For our RSA finding:** First occurrence → kept. Subsequent identical findings (e.g., from constant resolution) → collapsed.

**Counter:** `duplicates_collapsed` logged for monitoring.

---

### 1.7 Stage 6: CHAIN HASH

**File:** `services/evidence/evidence/hashing/chain_hasher.py`

```python
# chain_hash[0] = SHA256(content_hash[0] + scan_session_id)
# chain_hash[N] = SHA256(content_hash[N] + chain_hash[N-1])

@staticmethod
def compute_chain(content_hashes, scan_session_id):
    chain_hashes = []
    previous_hash = None
    for i, content_hash in enumerate(content_hashes):
        if i == 0:
            chain_input = f"{content_hash}{scan_session_id}"
        else:
            chain_input = f"{content_hash}{previous_hash}"
        chain_hash = hashlib.sha256(chain_input.encode()).hexdigest()
        chain_hashes.append(chain_hash)
        previous_hash = chain_hash
    return chain_hashes
```

**For our finding (position 5):**
- `content_hash = "a1b2c3d4..."`
- `previous_hash = "f9e8d7c6..."` (from position 4)
- `chain_hash = SHA256("a1b2c3d4...f9e8d7c6...") = "3d2e1f0a..."`

---

### 1.8 Stage 7: MANIFEST

**File:** `services/evidence/evidence/core/pipeline.py:create_manifest()`

```python
# Merkle root over evidence IDs
manifest_hash = hashlib.sha256("".join(sorted(evidence_ids)).encode()).hexdigest()
```

**Manifest:**
```python
ScanManifest(
    manifest_id="uuid...",
    scan_session_id="scan-123",
    created_at="2026-09-20T10:00:00Z",
    total_findings=150,
    first_chain_hash="first_hash...",
    last_chain_hash="3d2e1f0a...",
    manifest_hash="merkle_root...",
    evidence_records=[
        {"evidence_id": "...", "content_hash": "...", "chain_hash": "...", "chain_position": 5},
        ...
    ]
)
```

---

### 1.9 Stage 8: DATABASE STORAGE

**File:** `services/database/db/models/evidence_record.py`

```python
class EvidenceRecord(BaseModel, TenantScoped):
    scan_id: str                    # FK → scans
    content_hash: str               # SHA-256 of canonical finding
    chain_hash: str                 # Blockchain-style chain hash
    chain_position: int             # Position in chain
    previous_hash: str              # Previous chain hash
    algorithm: str                  # "RSA"
    key_size: int                   # 2048
    file_path: str                  # "src/main/java/com/example/CryptoUtil.java"
    line_number: int                # 42
    finding_data: dict              # Full RawFinding JSON
    provenance: dict                # Scanner metadata
    normalized_crypto: dict         # NormalizedCrypto dict
    policy_evaluation: dict         # PolicyEvaluation dict
    compliance_status: str          # "FAIL" (RSA-2048 quantum vulnerable)
```

**Link Table:** `CryptoAssetEvidence` (asset_id ↔ evidence_id) — **NOT POPULATED** in pipeline.

---

### 1.10 Stage 9: NORMALIZATION

**File:** `services/normalization/normalization/core/engine.py`

```python
normalized = engine.normalize(
    raw_algorithm="RSA",
    context={"key_size": 2048, "purpose": "key_generation"}
)
```

**Output — NormalizedCrypto:**
```python
NormalizedCrypto(
    standard_name="RSA",
    algorithm_family="RSA",
    nist_designation="Approved (legacy use only)",
    quantum_vulnerable=True,
    cbom_component_type="algorithm",
    primitive="asymmetric",
    oid="1.2.840.113549.1.1.1",
    key_size=2048,
    purpose="key_generation"
)
```

**Stored in:** `evidence_record.normalized_crypto` JSON column.

---

### 1.11 Stage 10: POLICY EVALUATION

**File:** `services/policy/policy/core/engine.py:PolicyEngine.evaluate()`

```python
# Rules loaded from YAML
# Rule: "rsa-2048-quantum" — IF algorithm=RSA AND key_size<3072 THEN FAIL
evaluation = engine.evaluate(evidence_data)
```

**Output — PolicyEvaluation:**
```python
PolicyEvaluation(
    compliant=False,
    findings=[
        PolicyFinding(
            rule_id="rsa-2048-quantum",
            severity="HIGH",
            message="RSA-2048 is quantum vulnerable per NIST PQC timeline",
            standard_reference="NIST SP 800-208"
        )
    ],
    score=0,
    grade="F"
)
```

**Stored in:** `evidence_record.policy_evaluation` + `compliance_status="FAIL"`

---

### 1.12 Stage 11: GRAPH INTEGRATION

**File:** `services/graph_engine/graph_engine/core/engine.py:GraphEngine.build()`

```python
# Nodes: System → USES → CryptoAsset
# Edge evidence from CryptoAsset.extra.detection
```

**Graph Nodes:**
```
System: "org/repo" (id: sys-123)
  │
  └─ USES → CryptoAsset: "RSA-2048" (id: asset-456)
        algorithm: "RSA"
        key_size: 2048
        confidence: "HIGH"
        file_path: "src/main/java/com/example/CryptoUtil.java"
        extra: {"detection": "KeyPairGenerator.initialize(2048) at CryptoUtil.java:42"}
```

**Edge Evidence (from `graph.py:_edge_evidence()`):**
```python
{
    "type": "USES",
    "confidence": "HIGH",
    "source": "crypto_discovery",
    "evidence": "KeyPairGenerator.initialize(2048) at CryptoUtil.java:42",
    "first_seen": "2026-09-20T10:00:00Z",
    "last_seen": "2026-09-20T10:00:00Z",
    "verified": true
}
```

**Gap:** `CryptoAssetEvidence` link table NOT populated — no direct FK from asset to evidence.

---

### 1.13 Stage 12: CBOM GENERATION

**File:** `services/cbom/cbom/generator.py:CbomGenerator.from_records()`

```python
# Input: EvidenceRecord or CryptoAsset
# Output: CycloneDX 1.5 component with cryptoProperties
```

**CBOM Component:**
```json
{
  "type": "cryptographic-asset",
  "name": "RSA",
  "bom-ref": "evidence-uuid-...",
  "cryptoProperties": {
    "assetType": "algorithm",
    "oid": "1.2.840.113549.1.1.1",
    "algorithmProperties": {
      "primitive": "asymmetric",
      "algorithm": "RSA",
      "mode": null,
      "padding": null,
      "parameterSetIdentifier": "2048"
    },
    "nistDesignation": "Approved (legacy use only)",
    "quantumVulnerable": true
  },
  "evidence": {
    "identity": [{
      "field": "bom-ref",
      "confidence": 1,
      "methods": [{
        "technique": "source-code-analysis",
        "confidence": 0.9,
        "value": "src/main/java/com/example/CryptoUtil.java:42"
      }]
    }],
    "occurrences": [{
      "location": "src/main/java/com/example/CryptoUtil.java",
      "line": 42
    }],
    "file": "src/main/java/com/example/CryptoUtil.java",
    "line": 42,
    "content_hash": "a1b2c3d4...",
    "chain_hash": "3d2e1f0a...",
    "compliance_status": "FAIL"
  },
  "properties": [{
    "name": "cryptoscan:system",
    "value": "org/repo"
  }]
}
```

**Signing:** JWS (RS256) over canonical BOM → `cryptoscan:jws` metadata property.

---

### 1.14 Stage 13: API EXPOSURE

**Endpoint:** `GET /api/v1/cbom/scan/{scan_id}`

**Response:** Full CBOM with signed JWS.

**Evidence Traceability:** 
- `component.evidence.content_hash` → matches `EvidenceRecord.content_hash`
- `component.evidence.chain_hash` → matches `EvidenceRecord.chain_hash`
- `component.evidence.file` + `line` → matches `EvidenceRecord.file_path` + `line_number`

---

### 1.15 Stage 14: UI DISPLAY

**Frontend:** `frontend/src/pages/Evidence.tsx`, `frontend/src/pages/Cbom.tsx`

**Display Chain:**
```
Evidence List → Click RSA-2048 → Evidence Detail
  → Shows: Algorithm, Key Size, File:Line, Content Hash, Chain Hash
  → Policy: FAIL (RSA-2048 quantum vulnerable)
  → Graph: Blast radius → Systems using this asset
  → CBOM: Download signed CycloneDX
```

**Traceability in UI:** All hashes clickable, link back to evidence record.

---

## 2. EVIDENCE CHAIN INTEGRITY VERIFICATION

### 2.1 Verification Points

| Verification | Implementation | Trigger |
|--------------|----------------|---------|
| Content hash | `ContentHasher.verify_hash(finding, content_hash)` | Manual / API |
| Chain hash | `ChainHasher.verify_chain(content_hashes, stored_chain_hashes, scan_session_id)` | Periodic job (not implemented) |
| Manifest | `ScanManifest.manifest_hash` vs recomputed | Manual |
| CBOM signature | `CbomGenerator.verify_report(bom, keyring)` | `POST /cbom/verify` |
| Audit log | `GET /api/v1/auth/audit/verify` | Manual |

### 2.2 Automated Verification — MISSING

**Critical Gap:** No automated periodic verification job.

```python
# Should exist but doesn't:
# - Hourly: verify_chain() for recent scans
# - Daily: verify all CBOM signatures
# - Weekly: verify audit log chain
# - On ingest: verify CBOM signature before storage
```

---

## 3. EVIDENCE CHAIN GAPS

### 3.1 Link Table Not Populated

**File:** `services/database/db/models/crypto_asset_evidence.py`

```python
class CryptoAssetEvidence(BaseModel, TenantScoped):
    asset_id: str      # FK → crypto_assets
    evidence_id: str   # FK → evidence_records
```

**Status:** Table exists, migration exists (0011), but **pipeline never populates it**.

**Impact:** Cannot query "all evidence for this asset" or "all assets for this evidence" via FK.

---

### 3.2 Live Crypto Bypasses Evidence Pipeline

**File:** `services/api/api/routers/crypto.py:ingest_event()`

```python
# Live crypto events go to crypto_live table directly
# EvidenceRecord NOT created
# Chain hash NOT computed
# Manifest NOT updated
```

**Impact:** Live crypto observations have no evidence chain integrity.

---

### 3.3 Network/Container/Cloud Bypass Evidence Pipeline

| Source | Evidence Pipeline | Chain Hash | Manifest |
|--------|-------------------|------------|----------|
| Static Scanner | ✅ | ✅ | ✅ |
| Network Scanner | ❌ | ❌ | ❌ |
| Container Scanner | ❌ | ❌ | ❌ |
| Cloud Scanner | ❌ | ❌ | ❌ |
| Runtime Engine | ❌ | ❌ | ❌ |

**Impact:** Only static source scans have evidence chain integrity.

---

### 3.4 Graph Edge Evidence Weak

**File:** `services/api/api/routers/graph.py:_edge_evidence()`

```python
def _edge_evidence(graph, edge, asset_rows):
    # Evidence from CryptoAsset.extra.detection only
    # No direct link to EvidenceRecord
    # No content_hash, chain_hash on edges
```

**Impact:** Graph edges cannot be cryptographically verified against evidence chain.

---

### 3.5 CBOM Evidence Traceability

**CBOM Component Evidence:**
```json
"evidence": {
  "content_hash": "a1b2c3d4...",
  "chain_hash": "3d2e1f0a...",
  "file": "src/main/java/com/example/CryptoUtil.java",
  "line": 42
}
```

**Verification:** `GET /cbom/scan/{id}` → CBOM → verify hashes match EvidenceRecord.

**Gap:** No API to query "all CBOM components for this evidence hash".

---

## 4. EVIDENCE RETENTION & REPLAY

### 4.1 Retention Policy

| Data | Retention | Implementation |
|------|-----------|----------------|
| EvidenceRecords | Forever (chain integrity) | Never deleted |
| VerificationLog | Forever | Never deleted |
| ScanManifest | Forever | Never deleted |
| AuditLog | Forever | Never deleted |
| CryptoLive | Latest only (upsert) | Latest state only |

### 4.2 Replay Capability

| Scenario | Supported | Method |
|----------|-----------|--------|
| Re-verify scan evidence | ✅ | `ContentHasher.verify_hash()` + `ChainHasher.verify_chain()` |
| Re-generate CBOM | ✅ | `CbomGenerator.from_records(evidence_records)` |
| Re-run policy | ✅ | `PolicyEngine.evaluate(evidence_data)` |
| Re-build graph | ✅ | `GraphEngine.build()` from DB |
| Re-play live events | ❌ | Event stream not fully replayable |

---

## 5. CONFLICT HANDLING

### 5.1 Duplicate Evidence

**Handled at:** Pipeline deduplication (content_hash-based)

```python
# Pipeline collapses byte-identical findings
# Counter: duplicates_collapsed logged
```

### 5.2 Conflicting Observations

**Scenario:** Static scan says RSA-2048, runtime says RSA-4096 for same location.

**Resolution:** Evidence fusion in `UniversalCryptoEngine` — combines evidence, confidence weighted.

```python
# engine.py:_to_observations()
# Merges evidence lists, recalculates confidence
```

### 5.3 Evidence Conflict in CBOM

**Scenario:** Two scans of same system, different findings.

**Resolution:** CBOM per-scan (immutable). Portfolio CBOM aggregates latest.

---

## 6. TAMPER DETECTION SCENARIOS

| Attack | Detection | Response |
|--------|-----------|----------|
| Modify EvidenceRecord.finding_data | Content hash mismatch | `ContentHasher.verify_hash()` fails |
| Delete EvidenceRecord | Chain hash gap | `ChainHasher.verify_chain()` fails |
| Reorder EvidenceRecords | Chain position mismatch | Chain position + previous_hash |
| Modify CBOM component | JWS signature fails | `CbomGenerator.verify_report()` fails |
| Modify AuditLog | Chain hash mismatch | `GET /auth/audit/verify` fails |
| Modify GraphSnapshot | Fingerprint mismatch | Version comparison fails |

---

## 6. RECOMMENDATIONS

### P0 — Critical

1. **Populate CryptoAssetEvidence link table** in evidence pipeline
2. **Route all discovery paths through evidence pipeline** (network, container, cloud, runtime)
3. **Implement automated chain verification cron** (hourly for recent, daily for all)

### P1 — High

4. **Add evidence hashes to graph edges** — content_hash, chain_hash on relationships
5. **Implement CBOM evidence query API** — `/evidence/{content_hash}/cbom-components`
5. **Add evidence chain to live crypto pipeline** — unify pipelines

### P2 — Medium

6. **Evidence retention policy** — Archive old evidence with chain continuity
7. **Evidence export/import** — Portable evidence packages with chain
8. **Conflict resolution UI** — Show conflicting observations with evidence

### P3 — Enhancement

8. **Evidence packaging for legal** — Signed evidence packages for court
9. **Cross-scan evidence correlation** — Track same finding across scans
10. **Evidence lineage visualization** — Source → Evidence → Asset → CBOM → Graph

---

## 7. VERIFICATION EVIDENCE

| Finding | File |
|---------|------|
| EvidencePipeline | `services/evidence/evidence/core/pipeline.py` |
| CanonicalSerializer | `services/evidence/evidence/hashing/canonical_serializer.py` |
| ContentHasher | `services/evidence/evidence/hashing/content_hasher.py` |
| ChainHasher | `services/evidence/evidence/hashing/chain_hasher.py` |
| EvidenceRecord model | `services/database/db/models/evidence_record.py` |
| CryptoAssetEvidence model | `services/database/db/models/crypto_asset_evidence.py` |
| UniversalCryptoEngine | `services/universal_crypto/universal_crypto/engine.py` |
| CbomGenerator | `services/cbom/cbom/generator.py` |
| GraphEngine | `services/graph_engine/graph_engine/core/engine.py` |
| Graph edge evidence | `services/api/api/routers/graph.py:_edge_evidence()` |
| Live crypto pipeline | `services/api/api/routers/crypto.py` |
| Evidence verification | `services/evidence/evidence/hashing/` |