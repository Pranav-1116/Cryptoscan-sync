# 51_OBSERVATION_FACT_RISK_AUDIT.md
## ZELNX CryptoScan — Observation → Fact → Risk Audit

**Generated:** 2026-09-20  
**Method:** Deep inspection of the conceptual layering from raw observation through normalized fact, cryptographic fact, exposure, risk, business impact, and remediation  
**Scope:** Complete pipeline — Observation → Normalized Fact → Cryptographic Fact → Exposure → Risk → Business Impact → Remediation

---

## EXECUTIVE SUMMARY

**Core Question:** *"Does ZELNX correctly separate OBSERVATION → NORMALIZED FACT → CRYPTOGRAPHIC FACT → EXPOSURE → RISK → BUSINESS IMPACT → REMEDIATION?"*

**Answer:** **PARTIAL** — The pipeline exists but layers are **incorrectly mixed** at multiple points.

| Layer | Implementation | Separation | Score |
|-------|----------------|------------|-------|
| **OBSERVATION** | ✅ RawFinding, CryptoObservation | ✅ Clean | 8/10 |
| **NORMALIZED FACT** | ⚠️ NormalizedCrypto + NormalizedCryptoEngine | ⚠️ Mixed with enrichment | 6/10 |
| **CRYPTOGRAPHIC FACT** | ⚠️ CryptoAsset + CryptoObservation | ❌ Mixed with Observation | 5/10 |
| **EXPOSURE** | ⚠️ Graph blast_radius + impact | ⚠️ Mixed with Risk | 5/10 |
| **RISK** | ⚠️ Quantum risk + Agility + Policy | ❌ Mixed with Exposure | 4/10 |
| **BUSINESS IMPACT** | ✅ Graph impact | ✅ Clean | 8/10 |
| **REMEDIATION** | ⚠️ Suggestions only | ❌ Mixed with Risk | 4/10 |

**Overall: 5.1/10** — Pipeline exists but layers are conflated

---

## 1. LAYER DEFINITIONS — WHAT SHOULD EXIST

### 1.1 Required Layer Definitions

| Layer | Definition | Input | Output | Responsibility |
|-------|------------|-------|--------|----------------|
| **OBSERVATION** | Raw, uninterpreted detection from a collector | Raw collector output | Structured observation with provenance | Collection |
| **NORMALIZED FACT** | Canonicalized, deduplicated, enriched observation | Observation + enrichment rules | Canonical fact with standard identity | Normalization |
| **CRYPTOGRAPHIC FACT** | Authoritative, evidence-backed cryptographic truth | Normalized facts + evidence fusion + conflict resolution | Authoritative crypto fact with evidence chain | Fact Resolution |
| **EXPOSURE** | Where and how the crypto fact is reachable/used | Crypto fact + topology + runtime context | Exposure map with reachability | Exposure Analysis |
| **RISK** | Probability × Impact of crypto fact being exploited | Exposure + threat intel + asset criticality | Risk score with components | Risk Assessment |
| **BUSINESS IMPACT** | Business consequences of risk materializing | Risk + asset ownership + business context | Revenue, regulatory, reputational impact | Business Analysis |
| **REMEDIATION** | Action plan to reduce risk | Risk + business impact + constraints | Prioritized action plan | Remediation Planning |

---

## 2. CURRENT PIPELINE — WHERE LAYERS MIX

### 2.1 Current Pipeline (Actual)

```
Source Code / Binary / Network / Cloud / Runtime
        ↓
SCANNER (RawFinding) ← OBSERVATION layer
        ↓
EVIDENCE PIPELINE (hash, chain, dedup) ← Still OBSERVATION
        ↓
NORMALIZATION ENGINE (NormalizedCrypto) ← NORMALIZED FACT layer
        ↓
POLICY ENGINE (PolicyEvaluation) ← MIXES Normalized Fact + Policy = RISK
        ↓
CRYPTO ASSET CREATION (CryptoAsset) ← MIXES Normalized Fact + Evidence = CRYPTO FACT
        ↓
GRAPH ENGINE (System → USES → CryptoAsset) ← EXPOSURE layer (partial)
        ↓
QUANTUM RISK ENGINE (quantum_risk_score) ← RISK layer (mixed with Exposure)
        ↓
AGILITY ENGINE (agility_score) ← RISK/AGILITY mixed
        ↓
REMEDIATION ENGINE (suggestions) ← REMEDIATION (mixed with Risk)
        ↓
GRAPH MIGRATION PLAN (migration tasks) ← REMEDIATION execution (missing)
```

---

### 2.2 Layer Mixing Points — CRITICAL MIXING POINTS

| Mixing Point | Layers Mixed | Evidence |
|--------------|--------------|----------|
| **PolicyEngine.evaluate()** | Normalized Fact + Policy → Compliance | `PolicyEvaluation` has both fact and compliance |
| **CryptoAsset creation** | NormalizedFact + Evidence → CryptoAsset | `CryptoAsset` has `normalized_crypto` + `evidence_links` |
| **QuantumRisk.score_asset()** | CryptoAsset + System → quantum_risk_score | Mixes Exposure (graph) + Vulnerability |
| **AgilityEngine.score_system()** | Evidence + Config → agility_score | Mixes Observation + Config = Agility |
| **RemediationEngine.suggest_remediations()** | PolicyEvaluation (FAIL) → suggestions | Mixes Compliance Failure = Remediation |
| **Graph blast_radius** | CryptoAsset + Graph → Exposure | Mixes Fact + Topology = Exposure |
| **Graph business_impact** | Exposure + BusinessProcess → Revenue | Mixes Exposure + Business = Impact |

---

## 3. LAYER-BY-LAYER ANALYSIS

### 3.1 OBSERVATION LAYER — ✅ CLEAN

**File:** `services/scanner/scanner/models/raw_finding.py` + `shared/shared_models/shared_models/finding.py`

```python
class RawFinding:
    finding_id: str
    crypto: CryptoInfo          # algorithm, mode, key_size, padding, operation
    location: SourceLocation    # file_path, line_number, class_name, method_name
    metadata: FindingMetadata   # confidence, code_origin, scanner_id, git_context
    git_context: GitContext     # commit, author, timestamp, branch, repo_url
```

**Clean:** Raw, uninterpreted, provenance-rich. No interpretation.

**Also:** `CryptoObservation` in `universal_crypto` — fuses multiple sources but still observation-level.

---

### 3.2 NORMALIZED FACT LAYER — ⚠️ MIXED WITH ENRICHMENT

**File:** `services/normalization/normalization/core/engine.py:NormalizationEngine.normalize()`

```python
def normalize(self, raw_algorithm, context):
    # 1. Exact match (registry)
    # 2. Pattern match (regex)
    # 3. Family match (prefix)
    # 4. Fallback → UNKNOWN
    # Then enrichers: NIST, IANA, CBOM, Family
```

**Output:** `NormalizedCrypto` with:
```python
NormalizedCrypto:
    standard_name: str
    algorithm_family: str
    nist_designation: str
    quantum_vulnerable: bool
    cbom_component_type: str
    primitive: str
    oid: str
```

**Mixing:** Enrichment (NIST, IANA, CBOM) happens **inside** normalization. Should be separate enrichment layer.

---

### 3.3 CRYPTOGRAPHIC FACT LAYER — ❌ MIXED WITH OBSERVATION

**Current:** `CryptoAsset` = NormalizedFact + Evidence + Compliance

```python
class CryptoAsset:
    algorithm: str                    # Normalized
    purpose: str                      # Normalized
    key_size: int                     # Normalized
    file_path: str                    # Observation location
    line_number: int                  # Observation location
    confidence: str                   # Observation confidence
    occurrence_count: int             # Deduplication count
    scanner_ids: List[str]            # Observation sources
    libraries: List[str]              # Normalized
    normalized_crypto: dict           # NormalizedCrypto dict
    compliance_status: str            # Policy result (RISK layer!)
    evidence_links: List[EvidenceLink] # Evidence (OBSERVATION layer!)
```

**Mixing:** `CryptoAsset` = Normalized Fact + Observation Evidence + Policy Result (Risk) all in one model.

**Required Separation:**
```
CryptographicFact:
    canonical_algorithm: str
    canonical_key_size: int
    canonical_mode: str
    canonical_purpose: str
    quantum_status: QuantumStatus
    nist_designation: str
    oid: str
    primitive: str
    authority_level: AuthorityLevel
    evidence_chain: EvidenceChainRef
    # NO location, NO scanner_ids, NO compliance_status
```

---

### 3.4 EXPOSURE LAYER — ⚠️ PARTIAL, MIXED WITH RISK

**Current:** Graph blast_radius + business_impact = Exposure + Risk mixed

**File:** `services/graph_engine/graph_engine/core/engine.py`

```python
def blast_radius(self, start_id, hops=5):
    # Returns downstream systems using this asset
    # This IS exposure analysis
    
def business_impact(self, start_id, hops=5):
    # Returns revenue, customers, processes at risk
    # This IS business impact analysis
```

**Mixing:** `blast_radius` = Exposure. `business_impact` = Business Impact. But called together, no clear separation in API.

**Required Separation:**
```
Exposure:
    reachable_systems: List[SystemRef]
    reachable_endpoints: List[EndpointRef]
    reachable_data_stores: List[DataStoreRef]
    attack_paths: List[AttackPath]
    reachability_confidence: float
    
Risk:
    exposure: ExposureRef
    threat_likelihood: float
    vulnerability_severity: VulnerabilitySeverity
    exploitability: ExploitabilityScore
    risk_score: float
    risk_components: RiskComponents
```

---

### 3.5 RISK LAYER — ❌ MIXED WITH EXPOSURE & COMPLIANCE

**Current:** Multiple risk scores, no unified risk model

| Risk Score | Source | Layer Mixing |
|------------|--------|--------------|
| `quantum_risk_score` | `quantum/risk.py:score_asset()` | Exposure + Vulnerability + Business |
| `compliance_status` | `PolicyEvaluation` | Compliance ≠ Risk |
| `agility_score` | `AgilityEngine` | Agility ≠ Risk |
| `drift severity` | `DriftEvent.severity` | Drift ≠ Risk |
| `vulnerability severity` | `Vulnerability.severity` | Vulnerability ≠ Risk |

**No unified Risk Model.** Each engine produces its own "risk-like" score.

**Required Unified Risk Model:**
```
Risk:
    risk_id: UUID
    cryptographic_fact: CryptographicFactRef
    exposure: ExposureRef
    threat_likelihood: ThreatLikelihood
    vulnerability: VulnerabilityRef
    exploitability: ExploitabilityScore
    impact: BusinessImpactRef
    risk_score: float (0-100)
    risk_components: RiskComponents
    calculation_version: str
    calculated_at: DateTime
```

---

### 3.6 BUSINESS IMPACT LAYER — ✅ CLEAN

**File:** `services/graph_engine/graph_engine/core/engine.py:business_impact()`

```python
def business_impact(self, start_id, hops=5):
    # 1. Blast radius → affected systems
    # 2. For each: sum BusinessProcess revenue_daily + customer_count
    # 3. Collect BusinessOwners via OWNED_BY edges
    # 4. Collect ComplianceScopes via MUST_COMPLY_WITH edges
```

**Clean:** Pure business impact from graph topology + business metadata. No crypto logic.

---

### 3.7 REMEDIATION LAYER — ❌ MIXED WITH RISK & COMPLIANCE

**Current:** `RemediationEngine.suggest_remediations()` takes `PolicyEvaluation` (FAIL) → suggestions

**File:** `services/remediation/remediation/engine.py`

```python
def suggest_remediations(findings):
    # Only processes findings with compliance_status in {FAIL, WARN}
    # Matches algorithm to hardcoded rules
    # Outputs suggestions with priority, effort, guidance
```

**Mixing:** 
- Input = Compliance Failure (Policy layer)
- Matching = Algorithm name (Fact layer)
- Output = Remediation (Remediation layer)

**Required Separation:**
```
RemediationInput:
    risk: RiskRef                    # Not compliance failure
    cryptographic_fact: FactRef
    exposure: ExposureRef
    business_impact: BusinessImpactRef
    constraints: RemediationConstraints

RemediationPlan:
    actions: List[RemediationAction]
    priority: Priority
    effort_estimate: EffortEstimate
    dependencies: List[RemediationDependency]
    verification_criteria: VerificationCriteria
```

---

## 4. LAYER MIXING — CONCRETE EVIDENCE

### 4.1 Concrete Mixing Examples

| Code Location | Layers Mixed | Problem |
|---------------|--------------|---------|
| `CryptoAsset.compliance_status` | Fact + Risk | Asset shouldn't know compliance |
| `CryptoAsset.normalized_crypto` | Fact + Normalization | Asset shouldn't store normalization |
| `CryptoAsset.evidence_links` | Fact + Observation | Asset shouldn't link to evidence |
| `PolicyEvaluation.compliant` | Fact + Policy | Evaluation shouldn't be on fact |
| `QuantumRisk.score_asset()` | Fact + Exposure + Business | Risk engine reaches into graph |
| `RemediationEngine.suggest_remediations()` | Compliance + Fact → Remediation | Remediation shouldn't read compliance |
| `GraphEngine.blast_radius()` | Fact + Topology | Exposure shouldn't need fact details |
| `CbomGenerator._component()` | Fact + Evidence + Normalization | CBOM shouldn't reach into evidence |

---

## 5. CORRECT ARCHITECTURE — REQUIRED SEPARATION

### 5.1 Required Layer Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    COLLECTION LAYER                          │
│  Scanners (Source, Binary, Network, Cloud, Runtime, Config) │
│  → RawFinding, CryptoObservation (with provenance)          │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                   EVIDENCE LAYER                             │
│  EvidencePipeline: hash → dedup → chain → manifest          │
│  → EvidenceRecord (immutable, hash-chained)                 │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                 NORMALIZATION LAYER                          │
│  NormalizationEngine: canonicalize algorithm names          │
│  Enrichers (separate): NIST, IANA, CBOM, Family             │
│  → NormalizedFact (canonical identity only)                 │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│              FACT RESOLUTION LAYER                           │
│  Conflict Detection → Authority Resolution → Evidence Fusion │
│  → CryptographicFact (authoritative, evidence-backed)       │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                  EXPOSURE LAYER                              │
│  GraphEngine: Fact + Topology + Runtime → Exposure Map      │
│  → ExposureMap (reachability, attack paths, attack surface) │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                   RISK LAYER                                 │
│  RiskEngine: Exposure + ThreatIntel + Vulnerability + Biz   │
│  → RiskAssessment (unified score + components)              │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│              BUSINESS IMPACT LAYER                           │
│  GraphEngine: Exposure + BusinessGraph → BusinessImpact     │
│  → BusinessImpact (revenue, customers, regulatory, rep)     │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                 REMEDIATION LAYER                            │
│  RemediationEngine: Risk + Constraints → RemediationPlan    │
│  → RemediationPlan (actions, priority, verification)        │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                 EXECUTION / VERIFICATION                     │
│  MigrationEngine: Plan → Tasks → Execution → Verification   │
│  → VerificationResult (rescan, compare, confirm)            │
└─────────────────────────────────────────────────────────────┘
```

---

## 6. MIXING CONSEQUENCES

### 6.1 Concrete Problems from Mixing

| Consequence | Example |
|-------------|---------|
| **Cannot change policy without touching assets** | Policy change requires CryptoAsset migration |
| **Cannot query "pure facts" without risk** | Every query returns compliance_status |
| **Cannot audit fact independently of risk** | Evidence mixed with compliance in CryptoAsset |
| **Cannot reuse facts across risk models** | Facts tied to specific risk calculation |
| **Cannot change risk model without data migration** | Risk logic embedded in asset model |
| **Remediation tied to compliance, not risk** | FAIL findings get remediation; WARN/INFO don't |
| **Cannot do "what-if" on facts alone** | Simulation requires full risk pipeline |
| **Evidence cannot be audited independently** | Evidence mixed into CryptoAsset model |

---

## 7. RECOMMENDATIONS

### P0 — Critical

1. **Separate CryptographicFact model** — Pure canonical fact, no location, no compliance, no evidence links
2. **Separate Exposure layer** — Graph queries return ExposureMap, not mixed with Risk
3. **Create unified Risk model** — Single RiskAssessment with components
4. **Separate Remediation from Compliance** — Remediation takes Risk, not PolicyEvaluation

### P1 — High

2. **Create NormalizedFact model** — Pure canonical identity, separate from enrichment
3. **Create Enrichment Layer** — NIST, IANA, CBOM, Family as separate enrichment passes
4. **Create Evidence Fusion Layer** — Conflict detection → Authority resolution → CryptographicFact
5. **Create Exposure Layer** — Graph queries return ExposureMap, separate from Risk

### P2 — Medium

6. **Unified Risk Model** — Single RiskAssessment with components
7. **Remediation Engine Redesign** — Input = Risk, Output = RemediationPlan
8. **Observation → Evidence → Fact → Exposure → Risk → Impact → Remediation** pipeline
8. **Layer-specific APIs** — `/facts`, `/exposure`, `/risk`, `/impact`, `/remediation`

### P3 — Enhancement

9. **Layer Versioning** — Track schema version per layer
10. **Cross-Layer Audit** — Verify no layer violations
11. **Layer Health Metrics** — Latency, error rate per layer

---

## 8. VERDICT

**Layers are significantly mixed.** The pipeline works but architectural boundaries are violated throughout.

| Layer Separation | Status |
|------------------|--------|
| Observation | ✅ Clean |
| Normalized Fact | ⚠️ Mixed with enrichment |
| Cryptographic Fact | ❌ Mixed with Observation + Risk |
| Exposure | ⚠️ Mixed with Risk |
| Risk | ❌ Mixed with Exposure + Compliance |
| Business Impact | ✅ Clean |
| Remediation | ❌ Mixed with Risk + Compliance |

**To fix:** 6-8 weeks for complete layer separation with clear boundaries, models, and APIs.

---

## 9. VERIFICATION EVIDENCE

| Finding | File |
|---------|------|
| RawFinding | `shared/shared_models/shared_models/finding.py` |
| CryptoObservation | `shared/shared_models/shared_models/observation.py` |
| NormalizationEngine | `services/normalization/normalization/core/engine.py` |
| NormalizedCrypto | `services/normalization/normalization/models/normalized_crypto.py` |
| CryptoAsset model | `services/database/db/models/crypto_asset.py` |
| PolicyEngine | `services/policy/policy/core/engine.py` |
| PolicyEvaluation | `services/policy/policy/models/policy_result.py` |
| QuantumRisk | `services/quantum/quantum/risk.py` |
| AgilityEngine | `services/agility/agility/system_score.py` |
| RemediationEngine | `services/remediation/remediation/engine.py` |
| GraphEngine | `services/graph_engine/graph_engine/core/engine.py` |
| GraphEngine blast_radius | `services/graph_engine/graph_engine/core/engine.py:blast_radius()` |
| GraphEngine business_impact | `services/graph_engine/graph_engine/core/engine.py:business_impact()` |
| RemediationEngine | `services/remediation/remediation/engine.py` |
| CbomGenerator | `services/cbom/cbom/generator.py:_component()` |
| UniversalCryptoEngine | `services/universal_crypto/universal_crypto/engine.py` |
| EvidencePipeline | `services/evidence/evidence/core/pipeline.py` |
| CryptoAsset model | `services/database/db/models/crypto_asset.py` |
| PolicyEvaluation model | `services/policy/policy/models/policy_result.py` |
## Round 27 update (2026-10-10) — separation verdicts re-verified

* **Unified Risk model (P0 #3) — shipped (round 19, re-verified):**
  `GET /risk/unified` and `/risk/systems` score the estate through one
  8-factor contract with env-configurable weights, versioned
  calculations, and per-system derivation signals (why a score is what
  it is, not just the number).
* **Exposure layer (P0 #2) — shipped (round 19):** bounded exposure
  path queries at `GET /exposure/paths` (entry-candidate system →
  dependency chain → crypto asset, weakest algorithm along the chain),
  honestly labeled as persisted-graph walks, not network topology.
* **CryptographicFact as a separate pure model (P0 #1) and
  Remediation-from-Risk (P0 #4) — still open, rearchitecture-scoped:**
  facts, locations, and evidence links remain fused in the
  `crypto_assets` row and the evidence pipeline's dedup model. Splitting
  them is a data-model rearchitecture of the core inventory, tracked in
  00_ROUND_STATUS, not a weekend build.

## Round 31 addendum (2026-10-11) — fact separation, read side BUILT

P0#1's first step shipped: `GET /facts/crypto` exposes cryptographic
facts as a pure read projection over evidence records (see the
round-31 addendum in advanced/48 for the full surface and the
deliberate scope: no scores, no asset coupling, write side
unchanged). The full rearchitecture of the fused `crypto_assets`
write side REMAINS OPEN as this report's round-27 addendum recorded.

## Round 35 addendum (2026-10-12) — fact store, write side BUILT (materialised slice)

P0#1's second step shipped: the cryptographic fact store now exists as a
materialised, rebuildable projection alongside the read model.

* `cryptographic_facts` table (migration 0085): one row per
  (algorithm, purpose, mode, parameters, file) fact with observation
  counts, hardcoded-key observations, scanner list, first/last seen,
  exact `evidence_ids`, `is_current`/`rebuilt_at` lifecycle stamps.
  Identity is verbatim (`""` for absent purpose/mode — never NULL) so
  unique constraints hold under every backend.
* `FactRepository.rebuild(file_paths=None)` recomputes rows from
  EvidenceRecords — full or per-file scope; facts whose evidence
  vanished in scope are marked stale (`is_current=false`,
  `observation_count=0`), never silently deleted.
* `POST /facts/rebuild` (admin, optional `file_prefix`) and the
  fail-soft `stage_facts` pipeline stage (runs after dedup; the live
  projection at `/facts/crypto` answers regardless, rebuild backfills).

The fused `crypto_assets` write side is STILL the system of record for
inventory; the full rearchitecture (single writer, asset decoupling)
remains open exactly as the round-27 addendum recorded. Tests:
`services/database/tests/unit/test_fact_store.py`,
`services/api/tests/unit/test_fact_store_api.py`,
`services/worker/tests/unit/test_fact_stage.py`.
