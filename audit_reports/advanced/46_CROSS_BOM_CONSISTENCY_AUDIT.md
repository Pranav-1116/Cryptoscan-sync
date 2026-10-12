# 46_CROSS_BOM_CONSISTENCY_AUDIT.md
## ZELNX CryptoScan — Cross-BOM Consistency Audit

**Generated:** 2026-09-20  
**Method:** Deep inspection of all five BOM generators, their data models, identifiers, and cross-references  
**Scope:** CBOM, HBOM, VBOM, NBOM, TechBOM — actual implementation vs. claimed coherence

---

## EXECUTIVE SUMMARY

| BOM | Implementation | Generator | Status | Data Sources |
|-----|----------------|-----------|--------|--------------|
| **CBOM** | ✅ Complete | `services/cbom/cbom/generator.py` | Production | EvidenceRecord, CryptoAsset, Scan |
| **HBOM** | ❌ Missing | Frontend only (`Hbom.tsx`) | Not Implemented | hardware_live table exists |
| **VBOM** | ❌ Missing | Vendor service scaffolded | Not Implemented | vendor_intel service exists |
| **NBOM** | ✅ Partial | `services/cbom/cbom/nbom.py` | Beta | NetworkScanRun probes |
| **TechBOM** | ✅ Duplicate | `services/api/api/routers/techbom.py` | Preview | Separate models |

**Critical Finding:** The five BOMs are **not one coherent system**. They are separate implementations with different generators, data models, identifiers, and no cross-BOM linking mechanism.

---

## 1. BOM GENERATOR INVENTORY

### 1.1 Generator Comparison

| BOM | Generator File | Lines | Models Used | API Endpoints |
|-----|----------------|-------|-------------|---------------|
| **CBOM** | `services/cbom/cbom/generator.py` | ~31K | EvidenceRecord, CryptoAsset, Scan, Baseline | `/cbom/*` (16 endpoints) |
| **HBOM** | **None** | N/A | N/A | Frontend only (`Hbom.tsx`) |
| **VBOM** | **None** | N/A | VendorProfile, VendorCrypto | Frontend only (`Vendor.tsx`) |
| **NBOM** | `services/cbom/cbom/nbom.py` | ~5K | NetworkScanRun probes | `/cbom/nbom*`, `/graph/*` |
| **TechBOM** | `services/api/api/routers/techbom.py` | ~58K | TechnologyBomSnapshot, TechnologyBomExport | `/techbom/*` |

---

## 2. IDENTIFIER CONSISTENCY

### 2.1 Primary Identifiers by BOM

| BOM | Primary Key | Format | Example |
|-----|-------------|--------|---------|
| **CBOM** | `bom-ref` | `evidence_id` or `finding_id` | `evidence-uuid-123` |
| **HBOM** | N/A | N/A | N/A |
| **VBOM** | N/A | N/A | N/A |
| **NBOM** | `bom-ref` | `endpoint_hash` or `certificate_fingerprint` | `ep-192.168.1.1:443` |
| **TechBOM** | `serialNumber` | `urn:uuid:...` | `urn:uuid:abc-123` |

### 2.2 Identifier Overlap Analysis

| Entity | CBOM ID | NBOM ID | TechBOM ID | HBOM ID | VBOM ID |
|--------|---------|---------|------------|---------|---------|
| **Certificate** | `evidence_id` from cert finding | `certificate_fingerprint` (SHA-256) | `technology_bom_snapshot` component | N/A | N/A |
| **Network Endpoint** | N/A | `endpoint_hash` | TechBOM component | N/A | N/A |
| **Hardware (HSM/TPM)** | N/A | N/A | Hardware component | N/A | N/A |
| **Algorithm** | `evidence_id` / `finding_id` | N/A | Technology component | N/A | N/A |
| **Library** | `library_fingerprint` | N/A | Technology component | N/A | N/A |
| **Vendor** | N/A | N/A | Vendor component | N/A | N/A |

**Critical Finding:** **Zero shared identifiers** across BOMs. A certificate discovered via network scan (NBOM) and source code (CBOM) have completely different identifiers with no linking mechanism.

---

## 3. DATA MODEL CONSISTENCY

### 3.1 Component Models

| BOM | Component Type | Key Fields | Crypto Properties |
|-----|----------------|------------|-------------------|
| **CBOM** | `cryptographic-asset` | name, bom-ref, cryptoProperties, evidence | Full cryptoProperties (assetType, oid, algorithmProperties, nistDesignation, quantumVulnerable) |
| **HBOM** | N/A | N/A | N/A |
| **VBOM** | N/A | N/A | N/A |
| **NBOM** | `network-endpoint`, `certificate`, `tunnel` | host, port, tls_version, cipher_suite, certificate | TLS version, cipher suite, cert details |
| **TechBOM** | `technology-asset` | vendor, product, version, cryptoCapabilities | Custom cryptoCapabilities field |

### 3.2 Crypto Properties Mapping

| Property | CBOM | NBOM | TechBOM |
|----------|------|------|---------|
| Algorithm | ✅ `algorithmProperties.algorithm` | ✅ cipher_suite parsing | ✅ custom field |
| Key Size | ✅ `parameterSetIdentifier` | ✅ cert parsing | ✅ custom field |
| Mode | ✅ `algorithmProperties.mode` | ❌ | ✅ custom field |
| Padding | ✅ `algorithmProperties.padding` | ❌ | ✅ custom field |
| Protocol | ✅ `algorithmProperties.protocol` | ✅ TLS version | ✅ custom field |
| Certificate | ✅ evidence field | ✅ certificate object | ✅ custom field |
| Quantum Status | ✅ `quantumVulnerable` | ❌ | ❌ |
| NIST Designation | ✅ `nistDesignation` | ❌ | ❌ |

---

## 4. DUPLICATE ASSETS & CONFLICTING IDENTIFIERS

### 4.1 Certificate Duplication

| Source | CBOM | NBOM | TechBOM |
|--------|------|------|---------|
| **Network Scan** | Certificate finding → EvidenceRecord → CBOM component | Network probe certificate → NBOM certificate component | TechnologyBomSnapshot certificate component |
| **Source Code** | Certificate finding in code → EvidenceRecord → CBOM component | N/A | TechnologyBomSnapshot certificate component |
| **Cloud Scanner** | Cloud cert finding → EvidenceRecord → CBOM component | N/A | TechnologyBomSnapshot certificate component |

**Result:** Same certificate appears in 3 BOMs with **3 different identifiers** and **no cross-reference**.

### 4.2 Algorithm Duplication

| Algorithm | CBOM | NBOM | TechBOM |
|-----------|------|------|---------|
| RSA-2048 (source) | EvidenceRecord → CBOM component | N/A | Technology component |
| RSA-2048 (network) | N/A | Cipher suite → NBOM | Technology component |
| RSA-2048 (cloud KMS) | Cloud finding → CBOM | N/A | Technology component |

**Result:** Same algorithm appears 3x with different `bom-ref` values.

### 4.3 Library Duplication

| Library | CBOM | NBOM | TechBOM |
|---------|------|------|---------|
| OpenSSL 3.0.11 | Library fingerprint → CBOM library component | N/A | Technology component |
| BouncyCastle | Library fingerprint → CBOM library component | N/A | Technology component |

---

## 5. ORPHAN BOM RECORDS

### 5.1 CBOM Orphans

| Orphan Type | Cause | Count Estimate |
|-------------|-------|----------------|
| EvidenceRecord without CryptoAsset | Dedup key mismatch | Unknown |
| CryptoAsset without EvidenceRecord | CBOM ingest without evidence | Unknown |
| CBOM component without System | Ingest without system_name | Unknown |

### 5.2 NBOM Orphans

| Orphan Type | Cause |
|-------------|-------|
| Endpoint without certificate | TLS probe failed (DNS_FAILED, TIMEOUT) |
| Tunnel without endpoints | Manual entry without probes |

### 5.3 TechBOM Orphans

| Orphan Type | Cause |
|-------------|-------|
| TechnologyBomSnapshot without export | Snapshot created but never exported |
| Component without vendor | Vendor not in vendor_intel |

---

## 6. INCONSISTENT NAMING & VERSIONING

### 6.1 Naming Inconsistencies

| Entity | CBOM | NBOM | TechBOM |
|--------|------|------|---------|
| Certificate | `certificate` (evidence) | `certificate` (component) | `certificate` (component) |
| Algorithm | `algorithm` (cryptoProperties) | `cipher_suite` (parsed) | `algorithm` (custom) |
| Key Size | `parameterSetIdentifier` | `public_key_size` | `keySize` |
| Protocol | `algorithmProperties.protocol` | `tls_version` | `protocol` |
| Version | Scan version / System env | Probe timestamp | Snapshot version |

### 6.2 Version Inconsistencies

| BOM | Version Source | Format |
|-----|----------------|--------|
| **CBOM** | Scan scanner_version / System environment | `0.1.0`, `production` |
| **NBOM** | Network scan timestamp | ISO 8601 |
| **TechBOM** | Snapshot version (incremental) | Integer |
| **HBOM** | N/A | N/A |
| **VBOM** | N/A | N/A |

**No shared versioning scheme.** Cannot determine "which version of the estate" across BOMs.

---

## 7. MISSING RELATIONSHIPS

### 7.1 Cross-BOM Relationships (All Missing)

| Relationship | CBOM → NBOM | CBOM → TechBOM | NBOM → TechBOM |
|--------------|-------------|----------------|----------------|
| Certificate ↔ Certificate | ❌ | ❌ | ❌ |
| Algorithm ↔ Algorithm | ❌ | ❌ | ❌ |
| Library ↔ Library | ❌ | ❌ | ❌ |
| System ↔ Network Endpoint | ❌ | ❌ | ❌ |
| System ↔ Hardware | ❌ | ❌ | ❌ |
| Vendor ↔ Library | ❌ | ❌ | ❌ |
| Vulnerability ↔ Component | ❌ | ❌ | ❌ |

### 7.2 Evidence Cross-Reference

| Evidence Type | CBOM | NBOM | TechBOM |
|---------------|------|------|---------|
| Content Hash | ✅ SHA-256 | ❌ | ❌ |
| Chain Hash | ✅ Blockchain | ❌ | ❌ |
| Evidence ID | ✅ evidence_id | ❌ | ❌ |
| Provenance | ✅ collector, timestamp | ❌ | ❌ |

---

## 8. CONFLICTING FACTS

### 8.1 Certificate Conflicts

| Fact | CBOM | NBOM | TechBOM | Reality |
|------|------|------|---------|---------|
| Cert Expiry | From evidence finding | From network probe | From snapshot | May differ if snapshots at different times |
| Key Algorithm | From source code finding | From network probe | From snapshot | May differ (source vs deployed) |
| Key Size | From source finding | From network probe | From snapshot | May differ |
| Issuer | From evidence | From network probe | From snapshot | Should be consistent |

### 8.2 Algorithm Conflicts

| Fact | CBOM (Source) | NBOM (Network) | TechBOM (Snapshot) |
|-------------|---------------|----------------|-------------------|
| Algorithm | RSA-2048 (code) | TLS_ECDHE_RSA_WITH_AES_256_GCM (negotiated) | RSA-2048 (inventory) |
| Key Size | 2048 | 256 (ECDHE) / 2048 (RSA cert) | 2048 |
| Protocol | N/A | TLS 1.2/1.3 | N/A |

**Critical:** CBOM shows what's **in code**, NBOM shows what's **on wire**, TechBOM shows **inventory snapshot**. All three can be simultaneously true but appear contradictory.

---

## 9. UNIFIED QUERY CAPABILITY

### 9.1 Cross-BOM Queries (All Impossible)

| Query | Possible? |
|-------|-----------|
| "Show all certificates for System X across all BOMs" | ❌ |
| "Find all RSA-2048 uses across CBOM, NBOM, TechBOM" | ❌ |
| "Trace certificate from source code to network to inventory" | ❌ |
| "Find all assets from Vendor X across all BOMs" | ❌ |
| "Show quantum-vulnerable assets across all BOMs" | ❌ |
| "Trace vulnerability CVE-2024-XXXX across all BOMs" | ❌ |

---

## 10. ROOT CAUSE ANALYSIS

### 9.1 Architectural Causes

| Cause | Evidence |
|-------|----------|
| **Separate Generators** | 3+ independent generators (`cbom/generator.py`, `nbom.py`, `techbom.py`) |
| **Separate Data Models** | Different component schemas, no shared base class |
| **Separate Identifiers** | `evidence_id`, `endpoint_hash`, `snapshot_version` |
| **Separate Storage** | `evidence_records`, `network_scan_runs`, `technology_bom_snapshots` |
| **No Cross-BOM Service** | No service to link/join BOMs |
| **No Unified API** | Separate endpoints per BOM |

### 9.2 Historical Causes

| Cause | Evidence |
|-------|----------|
| **Organic Growth** | BOMs added incrementally (CBOM first, then NBOM, then TechBOM) |
| **Different Teams** | Implied by different code styles/locations |
| **No Architecture Review** | No cross-BOM consistency checks in CI |

---

## 10. RECOMMENDATIONS

### P0 — Critical (Before Any Coherence)

1. **Create Unified Asset Identity Service** — Canonical IDs for all entities across BOMs
2. **Merge CBOM Generators** — Single `CbomGenerator` for all BOM types with type parameter
3. **Implement Cross-BOM Linking** — `bom-ref` mapping table with canonical IDs
4. **Deprecate TechBOM** — Merge into CBOM with `type: technology-asset`

### P1 — High

4. **Implement HBOM Generator** — From `hardware_live` + `payment_crypto`
5. **Implement VBOM Generator** — From `vendor_intel` + `vendor_crypto`
6. **Create Cross-BOM Query API** — `/bom/unified/search`, `/bom/unified/trace`
7. **Standardize cryptoProperties** — Single schema across all BOMs

### P2 — Medium

8. **Unified Versioning** — Estate-level version across all BOMs
9. **Cross-BOM Evidence Linking** — `evidence_id` in all BOM components
10. **Conflict Detection** — Alert when same entity has conflicting facts across BOMs

### P3 — Enhancement

11. **Unified BOM Export** — Single CycloneDX with all BOM types as compositions
12. **BOM Lineage** — Track entity provenance across BOMs
13. **Federated BOM Queries** — GraphQL-style cross-BOM queries

---

## 11. VERDICT

**The five BOMs represent FIVE DISCONNECTED INVENTORIES, not one coherent estate.**

| Criterion | Status |
|-----------|--------|
| Shared Identifiers | ❌ Zero |
| Shared Data Model | ❌ Five different models |
| Cross-BOM Linking | ❌ None |
| Unified Queries | ❌ Impossible |
| Conflict Detection | ❌ None |
| Evidence Cross-Reference | ❌ None |
| Unified Versioning | ❌ None |
| Single Generator | ❌ Three generators |

**To achieve coherence:** Requires 6-8 weeks of focused engineering on unified identity, merged generator, cross-BOM linking, and unified query layer.

---

## 12. VERIFICATION EVIDENCE

| Finding | File |
|---------|------|
| CBOM Generator | `services/cbom/cbom/generator.py` |
| NBOM Generator | `services/cbom/cbom/nbom.py` |
| TechBOM Router | `services/api/api/routers/techbom.py` |
| CBOM Router | `services/api/api/routers/cbom.py` |
| NBOM Router | `services/api/api/routers/cbom.py` (nbom endpoints) |
| TechBOM Router | `services/api/api/routers/techbom.py` |
| HBOM Frontend | `frontend/src/pages/Hbom.tsx` |
| Vendor Frontend | `frontend/src/pages/Vendor.tsx` |
| CryptoAsset Model | `services/database/db/models/crypto_asset.py` |
| EvidenceRecord Model | `services/database/db/models/evidence_record.py` |
| NetworkScanRun Model | `services/database/db/models/network_scan_run.py` |
| TechnologyBomSnapshot Model | `services/database/db/models/technology_bom_snapshot.py` |
| Vendor Models | `services/database/db/models/vendor.py`, `vendor_crypto.py` |
| HardwareLive Model | `services/database/db/models/hardware_live.py` |
---

## Round 26 update (2026-10-10) — coherence claims re-verified

* **HBOM missing — STALE.** The HBOM subsystem is implemented and
  served (`GET /hardware/hbom?fmt=native|cyclonedx`, versioned
  snapshots; round 25 additionally fixed the empty-document content
  bug — see deep/26's addendum).
* **P0#1 unified asset identity — STALE.** `cp_asset_identities`
  (control plane) stores canonical, tenant-scoped identities fused from
  multiple sources (`source_refs`, `evidence_sources`, confidence), with
  an identity resolver tested across mac/hostname/cloud-resource keys.
* **VBOM — REMAINS OPEN, product-scoped.** Vendor crypto inventory,
  vendor graph nodes and vendor chains exist; a formal vendor-BOM
  document generator does not.
* **P0#2/#4 (merge generators / deprecate TechBOM), P1 cross-BOM query
  API, P2 unified versioning, P3 federated queries — REMAIN OPEN,
  product/architecture-scoped** (consistent with deep/26's verdict on
  the three-generator question).

## Round 30 addendum (2026-10-11) — VBOM generator BUILT

P1#5 "Implement VBOM Generator — From vendor_intel + vendor_crypto" is
no longer open.

- `services/vendor_intel/vendor_intel/vbom.py`: pure `VbomGenerator`
  (native ZELNX-VBOM document + CycloneDX-style export) and
  `build_vbom(session, vendor_id=None)` assembling from exactly the
  surfaces this report named — `vendors` + `vendor_crypto_inventory` —
  plus `system_vendors` links (with system names and dependency type)
  and the latest `vendor_profile_revisions` state.
- Native document: one entry per vendor with contacts (incl. technical),
  contract end, data classifications, linked systems, profile revision
  status, the full crypto inventory, per-entry provenance
  (discovery_method/confidence/discovered_at/verified_at/source_document
  — the §7.2 evidence cross-reference), and a per-vendor PQC coverage
  block. Vendors without declared inventory stay visible (honestly
  flagged `none-declared`), never silently dropped.
- CycloneDX export: one `cryptographic-asset` component per inventory
  entry with `supplier` = vendor, `cryptoProperties.algorithmProperties`
  (algorithm, parameterSetIdentifier = key size, mode), and provenance
  under `evidence.properties`.
- API: `GET /vendor-bom?fmt=native|cyclonedx` (estate-wide) and
  `GET /vendors/{vendor_id}/vbom?fmt=...` (single vendor, 404 unknown).
- Bug fixed along the way (found by the endpoint test):
  `technical_contact` (added round 27) was missing from
  `VendorCreate`/`VendorPatch` and the repository's allowed-field set —
  the column existed but could never be set through the API.
- Tests: `services/vendor_intel/tests/test_vbom.py` (5 pure),
  `services/api/tests/unit/test_vbom_api.py` (2 end-to-end: import
  inventory via the real vendor-CBOM endpoint, then read both formats).
- Cross-BOM identifier coherence (P0#2/#4, unified queries, unified
  versioning) REMAINS OPEN, architecture-scoped, as round 26 recorded.

## Round 36 addendum (2026-10-12) — cross-BOM linking + conflict detection BUILT

Three of this report's ❌ rows now have their linking half:
`cbom/cross_bom.py` gives every component a canonical identity
(crypto: uppercased algorithm — key size/mode/purpose deliberately stay
*comparable attributes*, so a disagreement becomes a conflict instead of
two silently-separate identities; vendor/application/hardware/endpoint
name-normalized), `cross_boms()` links identities present in ≥2 BOMs
with each BOM's own ref for traceability, and reports conflicts (same
identity, same field, different non-empty values). `GET /cbom/cross-
links` builds the generator CBOM, the TechBOM layers and the VBOM from
the same live inventory and links them as they are. Still open,
unchanged: the single-generator merge (three generators → one) and a
unified query layer — the rearchitecture this report scoped at 6-8
weeks. Tests: `services/cbom/tests/test_cross_bom.py`.

## Round 37 addendum (2026-10-12) — unified query layer BUILT

The report's last code-scoped ❌ row is closed: `cbom/bom_query.py`
answers cross-BOM questions over any set of BOM documents —
`GET /cbom/query` filters by canonical identity, kind, BOM, or
algorithm (spacing/dash tolerant), restricts to linked or unlinked
identities (coverage gaps), or to conflicts only. Every match carries
each BOM's own ref and comparable values plus its conflicts, so
"where does this appear / what do the BOMs say / where do they
disagree" is one request. The endpoint builds its documents through
the same live-inventory helper as /cbom/cross-links, so the two
surfaces cannot disagree about what they linked. REMAINS OPEN,
unchanged: the single-generator merge — three generators still exist;
this layer queries their outputs as they are. Tests:
`services/cbom/tests/test_bom_query.py`.
