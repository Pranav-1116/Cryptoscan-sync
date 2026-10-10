# 08_EVIDENCE_CBOM_HBOM_AUDIT.md
## ZELNX CryptoScan — Evidence Chain, CBOM & HBOM Audit

**Generated:** 2026-09-20  
**Method:** Source code inspection of evidence pipeline, CBOM generator, HBOM/NBOM implementation  
**Scope:** Actual implementation vs. CycloneDX 1.5 CBOM spec, evidence integrity requirements

---

## 1. EVIDENCE CHAIN — IMPLEMENTATION AUDIT

### 1.1 Pipeline Architecture (`services/evidence/evidence/core/pipeline.py`)

```python
EvidencePipeline.process_findings(findings) → EvidenceRecord[] + ScanManifest
```

| Step | Implementation | Integrity Mechanism |
|------|----------------|---------------------|
| **1. Normalize** | `finding.model_dump(mode="json")` → `safe_finding()` | Removes raw snippets, finding_id, timestamps |
| **2. Canonical JSON** | `CanonicalSerializer.serialize()` | Sorted keys, no whitespace, deterministic floats |
| **3. Content Hash** | `ContentHasher.compute_hash()` | SHA-256(canonical_bytes) |
| **4. Deduplicate** | `seen_hashes` set by content_hash | Collapses byte-identical findings; logs `duplicates_collapsed` |
| **5. Chain Hash** | `ChainHasher.compute_chain()` | `H(content_hash[0] + scan_session_id)`, `H(content_hash[i] + chain_hash[i-1])` |
| **6. Manifest** | `ScanManifest` | Merkle root: SHA-256(concat(evidence_ids)) |

### 1.2 EvidenceRecord Model (`services/database/db/models/evidence_record.py`)

| Field | Purpose | Populated By |
|-------|---------|--------------|
| `scan_id` | FK to Scan | Pipeline |
| `content_hash` | Tamper detection | Step 3 |
| `chain_hash` | Chain integrity | Step 5 |
| `chain_position` | Order verification | Step 5 |
| `previous_hash` | Link verification | Step 5 |
| `finding_data` | Full observation | RawFinding dump |
| `provenance` | Source, timestamp, collector | Scanner metadata |
| `normalized_crypto` | NormalizedCrypto dict | Normalization engine |
| `policy_evaluation` | PolicyEvaluation dict | Policy engine |
| `compliance_status` | PASS/FAIL/WARN | Policy engine |

### 1.3 Verification (`services/evidence/evidence/hashing/chain_hasher.py`)

```python
ChainHasher.verify_chain(content_hashes, stored_chain_hashes, scan_session_id) → bool
```

**Verification Log:** `VerificationLog` table records periodic verification results with `chain_valid`, `content_hashes_valid`, `details`.

### 1.4 Gaps in Evidence Chain

| Gap | Location | Risk |
|-----|----------|------|
| **No periodic verification job** | Not implemented | Chain corruption undetected until manual verify |
| **Live crypto bypasses pipeline** | `crypto_live` table separate | Live observations not in evidence chain |
| **Network/container/cloud bypass** | Separate tables | Only static scanner uses evidence pipeline |
| **Deduplication before chain** | Pipeline step 4 | Correct but race condition possible |
| **No evidence retention policy** | Never deleted | Chain integrity requires full retention |

---

## 2. CBOM IMPLEMENTATION — CYCLONEDX 1.5 SPEC COMPLIANCE

### 2.1 Generator (`services/cbom/cbom/generator.py:CbomGenerator`)

| Spec Requirement | Implementation | Status |
|------------------|----------------|--------|
| **bomFormat: "CycloneDX"** | Hardcoded | ✅ |
| **specVersion: "1.5"** | Hardcoded | ✅ |
| **serialNumber (urn:uuid)** | SHA-256(name) → UUID v4 format | ✅ |
| **metadata.timestamp** | ISO 8601 UTC | ✅ |
| **metadata.component (type: application)** | Name + version from input | ✅ |
| **metadata.tools** | `[{"name": "CryptoScan", "version": tool_version}]` | ✅ |
| **metadata.properties** | Custom properties (cryptoscan:*) | ✅ |
| **components[]** | One per crypto asset | ✅ |
| **components[].type: "cryptographic-asset"** | Hardcoded | ✅ |
| **components[].cryptoProperties** | Full implementation | ✅ |
| **cryptoProperties.assetType** | "algorithm" | ✅ |
| **cryptoProperties.oid** | `lookup_oid(algorithm)` | ✅ |
| **cryptoProperties.algorithmProperties.primitive** | `map_primitive()` | ✅ |
| **cryptoProperties.algorithmProperties.algorithm** | Original algorithm name | ✅ |
| **cryptoProperties.algorithmProperties.mode** | Mode from finding | ✅ |
| **cryptoProperties.algorithmProperties.padding** | Padding from finding | ✅ |
| **cryptoProperties.algorithmProperties.parameterSetIdentifier** | Key size as string | ✅ |
| **cryptoProperties.nistDesignation** | From NormalizedCrypto | ✅ |
| **cryptoProperties.quantumVulnerable** | From NormalizedCrypto | ✅ |
| **components[].evidence** | Occurrence + identity + file/line | ✅ |
| **dependencies[]** | Root → systems → assets | ✅ |
| **vulnerabilities[]** | Optional, from vulnerability feed | ✅ |

### 2.2 Signing — JWS (RFC 7515)

| Feature | Implementation | Status |
|---------|----------------|--------|
| **HS256 (legacy)** | `sign()` → HMAC-SHA256 | ✅ |
| **RS256/ES256 (asymmetric)** | `sign_jws()` → `cryptography` library | ✅ |
| **JWS Compact Serialization** | Header.Payload.Signature | ✅ |
| **kid header** | `CRYPTOSCAN_CBOM_KEY_ID` | ✅ |
| **Key rotation** | `CRYPTOSCAN_CBOM_RETIRED_SECRETS` | ✅ |
| **Verification** | `verify_report()` → check-by-check | ✅ |

**Signing Gap:** Production requires `CRYPTOSCAN_CBOM_PRIVATE_KEY` for asymmetric; falls back to HS256 if not set.

### 2.3 CBOM Endpoints (`services/api/api/routers/cbom.py`)

| Endpoint | Source | Dependencies Included |
|----------|--------|----------------------|
| `GET /cbom/scan/{id}` | EvidenceRecord | Cascade edges (provider files, systems, waves) |
| `GET /cbom/system/{id}` | CryptoAsset | Estate linkage (system deps both directions) |
| `GET /cbom/portfolio` | All located assets | Root → systems → assets + unassigned bucket |
| `POST /cbom/ingest` | Inline CBOM | Validates + signature gate + stores as assets |
| `POST /cbom/diff` | Two refs (scan/system/bom) | Component diff + version changes |
| `POST /cbom/verify` | Inline CBOM | Full verification report |
| `POST /cbom/custom` | Asset ID list | Optional vulns, evidence |

### 2.4 CBOM Gaps vs. Spec

| Spec Feature | Implementation | Gap |
|--------------|----------------|-----|
| **Services[]** | Not implemented | No service components in BOM |
| **Compositions[]** | Not implemented | No nested BOM references |
| **ExternalReferences[]** | Not implemented | No VCS, issue tracker, distribution links |
| **Licenses[]** | Not implemented | Crypto assets don't carry license |
| **Pedigree[]** | Not implemented | No ancestor/descendant/commit info |
| **Signature (enveloped)** | JWS in metadata.properties | Not standard CycloneDX signature |

---

## 3. HBOM / NBOM / TECHBOM — IMPLEMENTATION STATUS

### 3.1 HBOM (Hardware BOM)
**Status: ❌ NOT IMPLEMENTED**

| Evidence | Location |
|----------|----------|
| Frontend page exists | `frontend/src/pages/Hbom.tsx` (1.9K lines) |
| Backend router | **None found** — no `/hbom` in API routers |
| Generator | **None** — no `HbomGenerator` |
| Database model | **None** — no `HardwareBom` table |
| Hardware data source | `hardware_live` table exists (TPM, CPU caps, HSM) |

**Frontend shows:** "HBOM status UNKNOWN — no HBOM evidence" (honest unknown)

### 3.2 NBOM (Network BOM) — ✅ IMPLEMENTED
**Location:** `services/cbom/cbom/nbom.py` + `cbom.py:/cbom/nbom*`

| Feature | Implementation |
|---------|----------------|
| **Source** | `network_scan_runs.result.probes[]` → endpoints with TLS, cipher, cert |
| **Components** | Endpoints (type: "network-endpoint"), certificates, tunnels |
| **cryptoProperties** | TLS version, cipher suite, cert public key alg, key size |
| **Dependencies** | Endpoint → certificate → algorithm; tunnel → endpoints |
| **Cascade** | `/cbom/nbom/cascade` — blast radius from component ref |
| **Live endpoint** | `GET /cbom/nbom` — derives from stored network scans |

**Gap:** No passive network observation (only active probe results).

### 3.3 TechBOM (Technology BOM)
**Status: ⚠️ DUPLICATE IMPLEMENTATION**

| Evidence | Location |
|----------|----------|
| Router | `services/api/api/routers/techbom.py` (58K lines) |
| Models | `TechnologyBomSnapshot`, `TechnologyBomExport` |
| Generator | Appears to extend CBOM with technology components |
| Overlap | Duplicates CBOM logic; separate versioning, export, snapshot |

**Risk:** Two BOM systems (CBOM + TechBOM) with different generators, schemas, versioning.

---

## 4. EVIDENCE → CBOM TRACEABILITY

### 4.1 Traceability Chain
```
RawFinding (scanner)
    │
    ▼
EvidencePipeline → EvidenceRecord (content_hash, chain_hash, chain_position)
    │
    ▼
Normalization → NormalizedCrypto (standard_name, quantum_vulnerable, nist_designation)
    │
    ▼
CryptoAsset (deduplicated, occurrence_count, scanner_ids)
    │
    ▼
CbomGenerator._component() → CycloneDX component
    │
    ▼
component.cryptoProperties ← NormalizedCrypto fields
component.evidence ← EvidenceRecord fields (file, line, content_hash, chain_hash)
component.properties ← cryptoscan:system_id, cryptoscan:system
```

### 4.2 Missing Traceability Links
| Missing Link | Impact |
|--------------|--------|
| **EvidenceRecord → CryptoAsset** | `CryptoAssetEvidence` link table exists but not populated in pipeline |
| **CBOM component → EvidenceRecord** | `component.evidence.content_hash` + `chain_hash` present but not queryable |
| **CBOM → Scan provenance** | `metadata.properties.cryptoscan:scan_id` only on scan CBOM |
| **Policy evaluation → CBOM** | `policy_evaluation` in EvidenceRecord but not in CBOM component |

---

## 5. PROVENANCE & CONFIDENCE — PER OBSERVATION

### 5.1 Required Fields (per requirements)
| Field | EvidenceRecord | CBOM Component | Status |
|-------|----------------|----------------|--------|
| **source** | `provenance.collector` | `evidence.identity[].methods[].technique` | ✅ |
| **timestamp** | `created_at` | `evidence.identity[].methods[].value` (includes time) | ✅ |
| **collector** | `provenance.collector` | `evidence.identity[].methods[].technique` | ✅ |
| **evidence** | `finding_data` + `normalized_crypto` | `evidence.occurrences[]` + `file` + `line` | ✅ |
| **hash** | `content_hash` + `chain_hash` | `evidence.content_hash` + `chain_hash` | ✅ |
| **provenance** | `provenance` dict | `properties.cryptoscan:*` | ✅ |
| **confidence** | `confidence` field | Not directly in CBOM (in `evidence.identity[].confidence`) | ⚠️ Partial |
| **normalized representation** | `normalized_crypto` | `cryptoProperties` | ✅ |
| **relationship to asset** | `scan_id` + `file_path` | `properties.cryptoscan:system_id` | ✅ |
| **relationship to dependency** | `libraries` field | `dependencies[]` graph | ✅ |
| **relationship to business owner** | Not in EvidenceRecord | `properties.cryptoscan:system` → System.owner | ⚠️ Indirect |

### 5.2 Confidence in CBOM
- **EvidenceRecord.confidence:** HIGH/MEDIUM/LOW from scanner
- **CBOM component:** `evidence.identity[].methods[].confidence` set to 0.9 for source-code-analysis
- **Gap:** No aggregate confidence per component; binary/runtime evidence not differentiated in CBOM

---

## 6. INTEGRITY VERIFICATION — END-TO-END

### 6.1 Verification Points
| Verification | Implementation | Trigger |
|--------------|----------------|---------|
| **Evidence content hash** | `ContentHasher.verify_hash()` | Manual / API |
| **Evidence chain hash** | `ChainHasher.verify_chain()` | `VerificationLog` periodic |
| **CBOM signature** | `CbomGenerator.verify_report()` | `POST /cbom/verify` |
| **CBOM structure** | `CbomGenerator.validate()` | `POST /cbom/validate` |
| **Graph snapshot** | `GraphSnapshot.fingerprint` (SHA-256) | `POST /graph/snapshot` |
| **Audit log chain** | `AuthService.audit()` hash chain | `GET /api/v1/auth/audit/verify` |

### 6.2 Automated Verification — MISSING
| Should Verify | Current State |
|---------------|---------------|
| Evidence chain on every ingest | Only manual via `POST /cbom/verify` |
| CBOM signature on ingest | ✅ Enforced in `ingest_document()` |
| Graph snapshot on change | Manual `POST /graph/snapshot` |
| Drift detection on evidence | Not implemented |

---

## 7. CBOM DIFF & VERSIONING

### 7.1 Diff Implementation (`services/cbom/cbom/inventory.py:diff_records`)
- Compares two record sets by `bom-ref` (evidence_id)
- Output: added, removed, changed (with from/to versions)
- **Gap:** No semantic diff (algorithm change vs. version change vs. location change)

### 7.2 Versioning
| BOM Type | Versioning |
|----------|------------|
| Scan CBOM | Implicit via scan_id (immutable) |
| System CBOM | Implicit via system assets (latest) |
| Portfolio CBOM | Aggregate — no version |
| Graph Snapshot | Explicit version (content-addressed) |
| TechBOM | Explicit version + snapshot table |

---

## 8. RECOMMENDATIONS

### P0 — Critical
1. **Unify evidence pipeline** — All discovery paths (network, container, cloud, runtime) must feed evidence pipeline
2. **Implement HBOM** — Hardware BOM from `hardware_live` + `payment_crypto` HSM data
3. **Merge CBOM + TechBOM** — Single BOM service with type parameter

### P1 — High
4. **Automated evidence verification** — Periodic job verifying chain integrity
5. **Populate CryptoAssetEvidence** — Link table in pipeline for bidirectional traceability
6. **CBOM confidence propagation** — Aggregate evidence confidence to component level

### P2 — Medium
6. **Standard CycloneDX signature** — Implement enveloped signature per spec
7. **Compositions/ExternalReferences** — Add VCS, issue tracker, distribution links
8. **Semantic CBOM diff** — Classify changes (algorithm migration, version bump, location move)

### P3 — Enhancement
9. **Evidence retention policy** — Archive old evidence with chain continuity
10. **Provenance graph** — Full lineage from source → finding → evidence → asset → CBOM → graph
---

## UPDATE — round 16 verification + build (2026-10-09)

| Claim | Verdict |
|---|---|
| "HBOM not implemented — no router/generator/table" | 🕰 Stale — HBOM ships as a TechBOM layer (`GET /techbom?layer=hbom`) fed by the hardware service, plus the live `/live-scan/bom` HBOM the frontend page renders |
| "CryptoAssetEvidence link table not populated in pipeline" | 🕰 Stale — `AssetRepository.replace_for_scan` populates the links in bulk (one query for existing pairs) from each asset's `evidence_ids` |
| "No periodic verification job" | 🔧 Built round 15 — `GET /ops/evidence/chain-status` sweeps recent scans with the export verifier |
| "TechBOM duplicate implementation" | 🟢 By design — TechBOM is the layered unification (sbom/cbom/hbom/vendor/certificates) over the one CBOM core; separate snapshot tables are its versioning, not a fork |
| "No aggregate component confidence / semantic diff / compositions / externalReferences" | 🟡 Open enhancements (P2/P3 in the report's own ranking), unchanged |
| Drift follow-up | 🔧 Built round 16 — acknowledging a drift event can auto-open remediation tasks linked back to the drift (see audit 03 addendum) |

## UPDATE — round 20 build (2026-10-10)

- **P1#6 (CBOM confidence propagation): BUILT.** `_component` no longer
  hardcodes evidence-method confidence 0.9: the observation's recorded
  confidence propagates into the CycloneDX evidence block
  (HIGH/CONFIRMED→0.9, MEDIUM/LIKELY→0.6, LOW/TENTATIVE→0.3) and surfaces
  as a `cryptoscan:confidence` component property. Unrecorded confidence
  keeps the historical default — nothing is fabricated upward. 3 new
  tests in `test_generator.py`.
- Still open: standard enveloped signatures (P2#6), compositions /
  externalReferences (P2#7), semantic CBOM diff classification (P2#8) —
  unchanged from round-16 ranking.
