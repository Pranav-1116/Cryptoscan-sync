# 03_REAL_DATAFLOW.md
## ZELNX CryptoScan — Real Dataflow Trace

**Generated:** 2026-09-20  
**Method:** Source code tracing from entry points through each pipeline stage  
**Scope:** Actual implementation, not documented intent

---

## DATA FLOW OVERVIEW

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   SOURCE    │────▶│  DISCOVERY  │────▶│ OBSERVATION │────▶│  EVIDENCE   │
│  (code/bin/ │     │  (scanner)  │     │  (raw find) │     │  (pipeline) │
│   net/cld)  │     │             │     │             │     │             │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
       │                   │                   │                   │
       ▼                   ▼                   ▼                   ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        NORMALIZATION & STORAGE                          │
│  normalization → policy → crypto_asset → evidence_record → scan        │
└─────────────────────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      GRAPH & CBOM/HBOM                                  │
│  graph_engine ← crypto_asset ← cbom_generator ← evidence_record        │
└─────────────────────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    RISK → DRIFT → PQC → REMEDIATION                     │
│  quantum_risk → drift_detection → agility_score → remediation_rules    │
└─────────────────────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    REPORTING / API / UI                                 │
│  REST API → Frontend pages → Export (JSON/HTML/PDF)                    │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## STAGE 1: SOURCE → DISCOVERY

### 1.1 Static Source Scanner
**Entry Point:** `services/scanner/scanner/main.py:scan()` CLI command
**Core Orchestrator:** `services/scanner/scanner/core/scanner.py:Scanner.scan()`

| Step | File | Function/Class | Input | Output | DB Table |
|------|------|----------------|-------|--------|----------|
| 1 | `scanner/main.py` | `scan()` | `--source` or `--repo` | Click context | — |
| 2 | `scanner/core/scanner.py` | `Scanner.__init__()` | config, exclude_test_dirs | Scanner instance | — |
| 3 | `scanner/core/file_discovery.py` | `FileDiscovery.discover()` | root Path | `Iterator[Path]` (source files) | — |
| 4 | `scanner/core/language_detector.py` | `detect_languages_in_repo()` | root Path | `Set[str]` (languages) | — |
| 5 | `scanner/registry/language_scanners.py` | `scan_file()` | source_file, root | `List[RawFinding]` | — |
| 6 | `scanner/parsers/*.py` | Per-language parsers | file content | AST findings | — |
| 7 | `scanner/detectors/*.py` | Detectors (cipher, hmac, etc.) | AST nodes | RawFinding.crypto | — |
| 8 | `scanner/extractors/*.py` | Extractors | findings | enriched findings | — |
| 9 | `scanner/analysis/cascade.py` | `analyse_cascade()` | findings + manifests | CascadeResult | — |
| 10 | `scanner/core/scanner.py` | `Scanner.scan()` | all above | `ScanResult` | — |

**Key Transformation:** Source files → AST → RawFinding (algorithm, mode, key_size, location, confidence)
**Hash/Integrity:** None at this stage (raw findings)
**Error Handling:** Parse errors collected in `ScanResult.parse_errors`; one bad file doesn't sink scan

### 1.2 Network Scanner
**Entry Point:** `services/network_scanner/network_scanner/core/scanner.py:NetworkTlsScanner`
**Flow:** Target list → TLS probe → Certificate extraction → Probe results
**Output:** `NetworkScanRun` model with `result.probes[]` (endpoint, tls_version, cipher_suite, certificates[])
**DB Table:** `network_scan_runs`

### 1.3 Container Scanner
**Entry Point:** `services/container_scanner/container_scanner/core/scanner.py:ContainerScanner`
**Flow:** Dockerfile/packages/advisory feed → CVE matching → SBOM generation
**Output:** CycloneDX/SPDX SBOM + vulnerability matches
**DB Table:** `container_scans`

### 1.4 Cloud Scanner
**Entry Point:** `services/cloud_scanner/cloud_scanner/core/scanner.py:CloudScanner`
**Flow:** Cloud credentials → API calls (KMS, S3, RDS, etc.) → Crypto config inventory
**Output:** Cloud crypto assets
**DB Table:** `cloud_account` + related

---

## STAGE 2: DISCOVERY → OBSERVATION (RawFinding)

### 2.1 RawFinding Model
**File:** `shared/shared_models/shared_models/finding.py:RawFinding`

```python
class RawFinding:
    finding_id: str
    crypto: CryptoInfo          # algorithm, mode, key_size, padding, digest, operation
    location: SourceLocation    # file_path, line_number, class_name, method_name
    metadata: FindingMetadata   # confidence, code_origin, scanner_id, git_context
    git_context: GitContext     # commit, author, timestamp, branch, repo_url
```

### 2.2 Observation Creation (Universal Crypto Engine)
**File:** `services/universal_crypto/universal_crypto/engine.py:UniversalCryptoEngine.scan()`

| Input Source | Engine Component | Observation Type |
|--------------|------------------|------------------|
| source_code | `CryptoAstEngine.detect_file()` | AST-based algorithm |
| binaries | `BinaryCryptoDetector.analyze()` | Disassembly + strings |
| runtime | `RuntimeCryptoEngine.observe()` | API calls, loaded libs |
| tls | `TlsAnalysis.parse_server_hello()` | Cipher suite → algorithm |
| ssh | `SshAnalysis.analyze()` | KEX, cipher, MAC, host key |
| ipsec | `IpsecAnalysis.analyze()` | Encryption, integrity, DH group |
| certificates | `CertificateIntelligence.analyze_certificate()` | Public key alg, sig alg, expiry |
| key_metadata | `CertificateIntelligence.analyze_key_metadata()` | Key type, size, protection |
| libraries | `LibraryFingerprinter.fingerprint()` | Library identity + version |

**Output:** `CryptoObservation` (algorithm, operation, library, key_size, curve, protocol, asset_id, location, evidence[], confidence, band, usage, capability, quantum_status)

---

## STAGE 3: OBSERVATION → EVIDENCE (Pipeline)

### 3.1 Evidence Pipeline
**File:** `services/evidence/evidence/core/pipeline.py:EvidencePipeline.process_findings()`

| Step | Operation | Implementation | Hash/Integrity |
|------|-----------|----------------|----------------|
| 1 | Normalize to dict | `finding.model_dump(mode="json")` | — |
| 2 | Safe finding | `safe_finding()` removes raw snippets | Field exclusion |
| 3 | Canonical serialize | `CanonicalSerializer.serialize()` | Sorted keys, no whitespace |
| 4 | Content hash | `ContentHasher.compute_hash()` | SHA-256(canonical_bytes) |
| 5 | Deduplicate | `seen_hashes` set by content_hash | Collapses byte-identical |
| 6 | Chain hash | `ChainHasher.compute_chain()` | `H(content_hash[i] + chain_hash[i-1])` |
| 7 | Manifest | `ScanManifest` | Merkle root over evidence_ids |

### 3.2 EvidenceRecord Model (Persisted)
**File:** `services/database/db/models/evidence_record.py:EvidenceRecord`

| Field | Source | Purpose |
|-------|--------|---------|
| `scan_id` | ScanResult.scan_id | Foreign key to Scan |
| `content_hash` | Pipeline step 4 | Tamper detection |
| `chain_hash` | Pipeline step 6 | Chain integrity |
| `chain_position` | Pipeline step 6 | Order verification |
| `previous_hash` | Pipeline step 6 | Link verification |
| `finding_data` | RawFinding dump | Full observation |
| `provenance` | Scanner metadata | Source, timestamp, collector |
| `normalized_crypto` | Normalization output | NormalizedCrypto dict |
| `policy_evaluation` | Policy engine output | PolicyEvaluation dict |
| `compliance_status` | Policy engine | PASS/FAIL/WARN |

**Verification:** `VerificationLog` table records periodic chain verification results

---

## STAGE 4: EVIDENCE → NORMALIZATION

### 4.1 Normalization Engine
**File:** `services/normalization/normalization/core/engine.py:NormalizationEngine.normalize()`

| Input | Matcher | Output |
|-------|---------|--------|
| raw_algorithm + context | ExactMatcher (registry lookup) | NormalizedCrypto |
| raw_algorithm + context | PatternMatcher (regex) | NormalizedCrypto |
| unmatched | FallbackHandler | NormalizedCrypto (UNKNOWN family) |

**Enrichers (applied in order):**
1. `NISTEnricher` — NIST designation, FIPS status
2. `IANAEnricher` — IANA OID, TLS cipher suite mapping
3. `CBOMEnricher` — CBOM component type, quantum_vulnerable
4. `FamilyEnricher` — Algorithm family (RSA, ECC, AES, etc.)

**Output:** `NormalizedCrypto` with `standard_name`, `algorithm_family`, `nist_designation`, `quantum_vulnerable`, `cbom_component_type`, `primitive`, `oid`

### 4.2 Storage
**API:** `services/api/api/routers/cbom.py:cbom_ingest()` → `AssetRepository.replace_for_scan()`
**DB:** `CryptoAsset` model with `normalized_crypto` JSON column

---

## STAGE 5: NORMALIZATION → POLICY

### 5.1 Policy Engine
**File:** `services/policy/policy/core/engine.py:PolicyEngine.evaluate()`

| Step | Component | Operation |
|------|-----------|-----------|
| 1 | `RuleLoader` | Load YAML rules from `rules_directory` |
| 2 | `RuleValidator` | Validate condition schema, severity, references |
| 3 | `PolicyEvaluator` | Match evidence against enabled rules |
| 4 | Output | `PolicyEvaluation` (compliant, findings[], score) |

**Rule Condition Types:** `exact`, `pattern`, `family`, `composite` (AND/OR/NOT)
**Standard References:** NIST, FIPS, NSA-CNSA, PCI-DSS, HIPAA, ISO

### 5.2 Integration Point
**API:** `services/api/api/routers/cbom.py` → `ingest_document()` calls validation → `AssetRepository.replace_for_scan()` stores assets with `normalized_crypto` and `compliance_status`

---

## STAGE 6: POLICY → STORAGE (CryptoAsset)

### 6.1 CryptoAsset Model
**File:** `services/database/db/models/crypto_asset.py:CryptoAsset`

| Field | Source | Deduplication |
|-------|--------|---------------|
| `algorithm` | NormalizedCrypto.standard_name | — |
| `purpose` | NormalizedCrypto.purpose | — |
| `mode` | NormalizedCrypto.mode | — |
| `key_size` | NormalizedCrypto.key_size | — |
| `file_path` | EvidenceRecord.file_path | — |
| `line_number` | EvidenceRecord.line_number | — |
| `confidence` | EvidenceRecord.confidence | — |
| `occurrence_count` | Incremented on duplicate | `dedup_key` from CBOM ingest |
| `scanner_ids` | List of scanner IDs | Merged |
| `libraries` | Library fingerprint results | Merged |

**Deduplication Key:** `file_path + algorithm + line_number` (scanner) or `dedup_key` (CBOM ingest)

---

## STAGE 7: STORAGE → GRAPH

### 7.1 Graph Build
**File:** `services/graph_engine/graph_engine/core/engine.py:GraphEngine.build()`

| Source | Node Type | Edge Type |
|--------|-----------|-----------|
| System | System | — |
| CryptoAsset | CryptoAsset | System → USES → CryptoAsset |
| SystemDependency | System | System → CALLS → System |
| BusinessProcess | BusinessProcess | System → SUPPORTS → BusinessProcess |
| BusinessOwner | BusinessOwner | System → OWNED_BY → BusinessOwner |
| Vendor | Vendor | System → DEPENDS_ON_VENDOR → Vendor |
| Certificate | Certificate | System → SECURED_BY → Certificate |
| CloudResource | CloudResource | System → DEPLOYED_ON → CloudResource |
| NetworkResource | NetworkResource | System → CONNECTS_TO → NetworkResource |

**Sync:** `services/api/api/graph_builder.py:graph_from_db()` → `GraphEngine.build()` → `sync_graph()` writes to Neo4j

### 7.2 Graph Queries (Real-time)
| Query | Endpoint | Implementation |
|-------|----------|----------------|
| Blast radius | `GET /graph/blast-radius` | BFS downstream from system/asset |
| Business impact | `GET /graph/impact` | Revenue/customers/processes/owners at risk |
| Vendor chain | `GET /graph/vendor-chain` | Vendor → systems → assets → crypto |
| Migration waves | `GET /graph/migration-waves` | Readiness + dependency cycles |
| Drift | `GET /graph/drift` | Compare live graph vs Neo4j |

---

## STAGE 8: GRAPH → CBOM/HBOM

### 8.1 CBOM Generation
**File:** `services/cbom/cbom/generator.py:CbomGenerator.from_records()`

| Input | Transformation | Output |
|-------|----------------|--------|
| CryptoAsset[] / EvidenceRecord[] | `_component()` mapping | CycloneDX component with cryptoProperties |
| System dependencies | `_portfolio_dependencies()` | CycloneDX dependencies (root → systems → assets) |
| Cascade data | `_cascade_dependencies()` | Provider files, business systems, wave props |

**Signing:** `CbomGenerator.sign_jws()` — RFC 7515 JWS over canonical BOM
**Verification:** `CbomGenerator.verify_report()` — check-by-check report

### 8.2 NBOM (Network BOM)
**File:** `services/cbom/cbom/nbom.py:build_nbom()`
**Source:** `network_scan_runs.result.probes[]` → endpoints with TLS version, cipher, certificate
**Graph:** Endpoint → certificate → algorithm dependencies

### 8.3 HBOM / TechBOM
**Status:** HBOM minimal (frontend page only); TechBOM in `services/api/api/routers/techbom.py` (58K lines) — appears to be extended CBOM with technology components

---

## STAGE 9: CBOM → RISK (Quantum)

### 9.1 Quantum Risk Analysis
**File:** `services/quantum/quantum/risk.py:analyze_quantum_risk()`

| Input | Classification | Scoring Factors |
|-------|----------------|-----------------|
| algorithm + key_size + purpose | `classify()` → SHOR_VULNERABLE / GROVER_MARGINAL / CLASSICALLY_BROKEN / PQC_RESISTANT / UNKNOWN | base_vulnerability (0-100) |
| system context | `hndl_risk()` | retention_years, public_network, regulated, data_classifications |
| system criticality | `score_asset()` | sensitivity × HNDL multiplier × timeline × criticality_tier |

**Output:** Per-asset `quantum_risk_score` (0-100), risk_category, threat_type, migration_deadline, recommended_replacement

---

## STAGE 10: RISK → DRIFT

### 10.1 Drift Detection
**File:** `services/drift/drift/` (minimal — mainly API router)

**Flow:**
1. Baseline created from approved scan (`Baseline` model)
2. New scan compared against baseline
3. `DriftEvent` created with `drift_type` (ALGORITHM_CHANGED, KEY_SIZE_CHANGED, TLS_VERSION_CHANGED, CERTIFICATE_EXPIRING, NEW_FINDING, CONFIG_CHANGED)
4. Severity: CRITICAL/HIGH/MEDIUM/LOW
5. Resolution workflow: acknowledge → resolve/false-positive with audit trail

**API:** `GET /drift`, `GET /drift/digest`, `POST /drift/{id}/acknowledge|resolve|false-positive`

---

## STAGE 11: DRIFT → PQC READINESS

### 11.1 Agility Scoring
**File:** `services/agility/agility/system_score.py:score_system()`

**6 Factors:**
1. Algorithm hardcoded? (config-driven)
2. Crypto abstraction layer?
3. Algorithm negotiation?
4. Key management centralized?
5. PQC library available?
6. Crypto-specific tests?

**Output:** `agility_score` (0-100)

### 11.2 Migration Readiness
**File:** `services/agility/agility/readiness.py:assess_readiness()`

**5 Factors:**
1. Agility score (40%)
2. Dependency count (20%)
3. Crypto tests (20%)
4. Team capacity (15%)
5. Change freeze (5%)

**Output:** readiness_category (READY_NOW, READY_WITH_PREP, NOT_READY, BLOCKED), wave (1-3), blockers, prep_checklist, effort_weeks

### 11.3 Migration Waves (Graph-Constrained)
**File:** `services/api/api/routers/graph.py:graph_migration_waves()`
- Base wave from readiness_category
- Cycle constraint: all systems in SCC get max(wave) of group
- Import constraint: IMPORTS edges order dependent after provider

---

## STAGE 12: PQC → REMEDIATION

### 12.1 Remediation Engine
**File:** `services/remediation/remediation/engine.py:suggest_remediations()`

**Rule Matching:** Exact algorithm name or family prefix (longest-match-first)
**Priority:** P0 (classically broken) → P1 (deprecated) → P2 (PQC transition) → P3 (quantum marginal)

**Output:** Suggestions with `replace_with`, `guidance`, `effort`, `priority`, `category`
**Backlog:** `build_backlog()` groups by system, estimates effort

**Disclaimer:** "DETERMINISTIC SUGGESTION - NOT COMPLIANCE DETERMINATION"

---

## STAGE 13: REMEDIATION → REPORTING/API/UI

### 13.1 API Endpoints (Key)
| Endpoint | Router | Data Source |
|----------|--------|-------------|
| `GET /cbom/scan/{id}` | `cbom.py` | EvidenceRecord → CbomGenerator |
| `GET /cbom/system/{id}` | `cbom.py` | CryptoAsset → CbomGenerator |
| `GET /graph/blast-radius` | `graph.py` | GraphEngine (Neo4j/memory) |
| `GET /graph/impact` | `graph.py` | GraphEngine.business_impact() |
| `GET /drift` | `drift.py` | DriftRepository |
| `GET /crypto/live/state` | `crypto.py` | CryptoRepository (live state) |
| `POST /cbom/ingest` | `cbom.py` | IngestCbomRequest → validate → store |
| `GET /scans/{id}/report` | `scans.py` | Scan + EvidenceRecord + PolicyEvaluation |

### 13.2 Frontend Data Flow
**Pattern:** Page component → `api.lib.api` functions → `usePollingApi` / `useLive` / `useRealtime` → React state → UI components

**Example (CommandCenter):**
```
CommandCenter.tsx
  → useLive("/api/v1/live-scan/inventory")
  → useLive("/api/v1/control/agents")
  → usePollingApi(apiStatsSummary, 15000)
  → usePollingApi(apiLiveScanStatus, 5000)
  → useRealtime() (SSE/WebSocket events)
  → Derived KPIs (g.totalAssets, g.cryptoAssets, g.quantumVulnerable, etc.)
  → HeroKpi / LiveStat / Panel / Feed components
```

**Key Principle:** "Zero until real data exists" — dashboards show "UNKNOWN" not zeros

---

## DATA INTEGRITY MECHANISMS SUMMARY

| Stage | Mechanism | Verification |
|-------|-----------|--------------|
| Evidence | Content hash (SHA-256 canonical) | `ContentHasher.verify_hash()` |
| Evidence | Chain hash (blockchain) | `ChainHasher.verify_chain()` |
| Evidence | Manifest (Merkle root) | `ScanManifest.manifest_hash` |
| CBOM | JWS signature (RS256/ES256/HS256) | `CbomGenerator.verify_report()` |
| Graph | Content-addressed snapshots | `GraphSnapshot.fingerprint` (SHA-256) |
| Audit | Hash chain over audit entries | `GET /api/v1/auth/audit/verify` |
| Policy | Pack hash | `PolicyEngine.pack_hash()` |

---

## TRANSFORMATION FIDELITY — WHERE DATA CHANGES

| Transformation | Loss/Risk | Mitigation |
|----------------|-----------|------------|
| RawFinding → CryptoObservation | Unknown algorithms dropped | `unknown_detector` captures for review queue |
| CryptoObservation → EvidenceRecord | Raw snippets removed (safe_finding) | Evidence hash excludes snippets by design |
| EvidenceRecord → CryptoAsset | Deduplication collapses duplicates | `duplicates_collapsed` counter logged |
| CryptoAsset → NormalizedCrypto | Fallback to UNKNOWN family | FallbackHandler logs unmatched |
| NormalizedCrypto → PolicyEvaluation | Only enabled rules evaluated | Pack hash tracks rule set version |
| CryptoAsset → Graph | Only linked assets included | `SystemAsset` links required |
| Graph → CBOM | Only components with `bom-ref` | Generator requires `id`/`evidence_id` |

---

## DATA FLOW GAPS — MISSING CONNECTIONS

| Gap | From | To | Impact |
|-----|------|----|--------|
| **No runtime → graph** | Runtime crypto observations | GraphEngine | Live crypto not in blast radius |
| **No cloud → graph** | Cloud scanner assets | GraphEngine | Cloud crypto not in dependency graph |
| **No container → graph** | Container scan findings | GraphEngine | Container crypto not in graph |
| **No NBOM → graph** | Network scan endpoints | GraphEngine | Network crypto not in blast radius |
| **HBOM not implemented** | Hardware crypto (HSM/TPM) | CBOM/Graph | Hardware root of trust not in BOM |
| **Drift → remediation auto-linking** | DriftEvent | Remediation suggestions | Drift doesn't auto-generate remediation tasks |
| **Live scan → evidence chain** | Live crypto engine | Evidence pipeline | Live observations bypass evidence pipeline |

---

## CONCLUSION

The dataflow is **real and deterministic** for the static source scanning path (stages 1-8). The network, container, cloud, and runtime paths feed into the database but **do not fully integrate with the evidence chain, graph, and CBOM pipeline**. The live crypto engine (`universal_crypto`) maintains its own state (`crypto_live_states`) separate from the static scan evidence pipeline. This creates **two parallel truth systems** that are not fully reconciled.