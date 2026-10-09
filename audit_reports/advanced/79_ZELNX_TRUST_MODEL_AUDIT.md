# 79_ZELNX_TRUST_MODEL_AUDIT.md
## ZELNX CryptoScan — Trust Model Audit

**Generated:** 2026-09-20  
**Method:** Deep inspection of trust model — what users should trust, separation of observed/verified/normalized/derived/inferred/predicted/recommended  
**Scope:** Complete trust model audit — trust boundaries, evidence grades, AI boundaries, deterministic vs probabilistic

---

## EXECUTIVE SUMMARY

**Core Question:** *"What should users trust in ZELNX? What is verified vs inferred?"*

**Answer:** **PARTIAL** — Strong evidence grading exists but **trust model is not explicitly communicated** in UI/API. AI boundaries are respected but not clearly surfaced.

| Trust Model Aspect | Status | Score |
|--------------------|--------|-------|
| **Evidence Grading** | ✅ Explicit (HIGH/MEDIUM/LOW) | 8/10 |
| **Verification Levels** | ✅ Explicit (VERIFIED/UNVERIFIED) | 8/10 |
| **AI Boundaries** | ✅ Enforced (policy engine) | 8/10 |
| **Trust Communication** | ❌ Missing in UI | 2/10 |
| **Evidence Provenance** | ✅ Explicit | 8/10 |
| **Deterministic vs Probabilistic** | ✅ Enforced | 8/10 |
| **Uncertainty Quantification** | ❌ Missing | 1/10 |
| **Trust Model Documentation** | ❌ Missing | 1/10 |
| **User-Facing Trust Indicators** | ❌ Missing | 1/10 |

**Overall: 4.0/10** — Strong internal model, not exposed to users

---

## 1. TRUST MODEL — INTERNAL vs EXTERNAL

### 1.1 Internal Trust Model (Strong)

**Evidence Grading (from `confidence.py`):**
```python
def score_evidence(evidence_list):
    weights = {
        EvidenceType.AST: 0.9,
        EvidenceType.CERTIFICATE: 0.95,
        EvidenceType.PROTOCOL: 0.95,
        EvidenceType.BINARY: 0.7,
        EvidenceType.LIBRARY: 0.6,
        EvidenceType.CONFIG: 0.6,
        EvidenceType.RUNTIME: 0.5,
    }
    # Diminishing returns for multiple same-type evidence
```

**Verification Levels (from `evidence.py`):**
```python
class VerificationStatus(Enum):
    VERIFIED = "verified"      # Direct observation, deterministic
    UNVERIFIED = "unverified"  # Inferred, heuristic, single source
```

**Deterministic Pipeline:**
```
OBSERVATION (deterministic collection)
    → NORMALIZATION (deterministic rules)
    → POLICY EVALUATION (deterministic YAML rules)
    → RISK SCORING (deterministic formula)
    → REMEDIATION (deterministic rules)
```
**No AI in decision path** — Enforced by architecture.

### 1.2 External Trust Communication — MISSING

| Trust Communication | Status |
|---------------------|--------|
| **Evidence Grade in UI** | ❌ Not shown |
| **Verification Level in UI** | ❌ Not shown |
| **AI Boundary Notice** | ❌ Not shown |
| **Deterministic Badge** | ❌ Not shown |
| **Uncertainty Indicators** | ❌ Not shown |
| **Evidence Provenance in UI** | ⚠️ Partial (API only) |
| **Confidence Score in UI** | ❌ Not shown |
| **Evidence Quality Badge** | ❌ Not shown |

---

## 2. EVIDENCE GRADING — DETAILED

### 2.1 Evidence Type Hierarchy (Authoritative → Inferential)

| Level | Evidence Type | Weight | Verification | Example |
|-------|---------------|--------|--------------|---------|
| **L1: DIRECT OBSERVATION** | CERTIFICATE, PROTOCOL, AST | 0.9-0.95 | Cryptographic verification | X.509 parsing, TLS handshake |
| **L2: CORROBORATED** | BINARY, LIBRARY | 0.6-0.7 | Multi-source confirmation | Binary disassembly + strings |
| **L3: DERIVED** | CONFIG | 0.6 | Parser correctness | Config file parsing |
| **L4: INFERRED** | RUNTIME | 0.5 | Sampling-based | LD_PRELOAD intercept |
| **L5: HEURISTIC** | UNKNOWN_DETECTOR | 0.1-0.4 | Statistical | Entropy analysis |

### 2.2 Evidence Fusion Rules

**File:** `services/universal_crypto/universal_crypto/engine.py:_to_observations()`

```python
# Evidence fusion logic:
# 1. Group by (asset_id, algorithm, operation)
# 2. Merge evidence from multiple sources
# 3. Recalculate confidence = weighted combination
# 4. Upgrade band if confidence crosses threshold
```

**Fusion Rules:**
- Same fact, multiple sources → Higher confidence
- Different sources, same algorithm → Corroboration
- Conflicting sources → Flag for review (NOT auto-resolved)
- Evidence chain preserved → Full traceability

---

## 3. VERIFICATION LEVELS — EXPLICIT BUT HIDDEN

### 3.1 Verification Status Enum

**File:** `shared/shared_models/shared_models/observation.py`

```python
class VerificationStatus(Enum):
    VERIFIED = "verified"      # Direct observation, deterministic
    UNVERIFIED = "unverified"  # Inferred, heuristic, single source
```

### 3.2 Verification in Practice

| Observation Source | Verification Level | Reason |
|--------------------|-------------------|--------|
| Static AST Detection | VERIFIED | Deterministic AST parsing |
| Binary Disassembly | VERIFIED | Deterministic disassembly |
| Network TLS Probe | VERIFIED | Live handshake capture |
| Certificate Parsing | VERIFIED | X.509 standard |
| Library Fingerprint | VERIFIED | Multi-class match |
| Runtime API Intercept | UNVERIFIED | Sampling-based |
| Config Parsing | VERIFIED | Deterministic parsing |
| Heuristic/Unknown | UNVERIFIED | Heuristic detection |

---

## 4. AI BOUNDARIES — ENFORCED BUT HIDDEN

### 4.1 Where AI is Used (Allowed)

| Component | AI Usage | Boundaries |
|-----------|----------|------------|
| **Remediation Engine** | Suggestions only | Labelled "DETERMINISTIC SUGGESTION" |
| **What-If Simulator** | Projections | Labelled "SIMULATION" |
| **Digital Twin Scenarios** | Projections | Labelled "HEURISTIC PROJECTION" |
| **Agility Simulation** | Projections | Labelled "SIMULATION" |
| **Anomaly Detection** | ⚠️ Stub only | Not in decision path |

### 4.2 Where AI is FORBIDDEN (Enforced)

| Forbidden Area | Enforcement |
|----------------|-------------|
| **Evidence Creation** | No AI in scanners/parsers |
| **Normalization** | Pure deterministic rules |
| **Policy Evaluation** | Pure YAML rule engine |
| **Compliance Determination** | Pure rule engine |
| **Evidence Hashing** | Pure SHA-256 |
| **Chain Hashing** | Pure SHA-256 |
| **Graph Building** | Pure deterministic rules |
| **Risk Scoring** | Deterministic formula |
| **Drift Detection** | Deterministic comparison |
| **Quantum Classification** | Registry lookup |

### 4.3 AI Boundary Enforcement

**Architecture Enforcement:**
```
SCANNERS (deterministic)
    → EVIDENCE PIPELINE (deterministic)
    → NORMALIZATION (deterministic)
    → POLICY ENGINE (deterministic YAML)
    → RISK SCORING (deterministic formula)
    → GRAPH (deterministic graph algorithms)
    → REMEDIATION (deterministic rules + AI SUGGESTIONS)
    → SIMULATOR (AI projections, labelled)
```

**AI Output Labelling:**
```python
# remediation/engine.py
LABEL = "DETERMINISTIC SUGGESTION - NOT COMPLIANCE DETERMINATION"

# simulator.py
# All outputs labelled "SIMULATION"
# digital_twin: "HEURISTIC PROJECTION - NOT PREDICTION"
```

---

## 4. UNCERTAINTY QUANTIFICATION — MISSING

### 4.1 Current: No Uncertainty Quantification

| Uncertainty Type | Quantified? | Exposed to User? |
|------------------|-------------|------------------|
| **Measurement Uncertainty** | ❌ | ❌ |
| **Sampling Uncertainty** | ❌ (runtime sampling) | ❌ |
| **Model Uncertainty** | ❌ (normalization rules) | ❌ |
| **Parameter Uncertainty** | ❌ (key size detection) | ❌ |
| **Classification Uncertainty** | ❌ (algorithm mapping) | ❌ |
| **Temporal Uncertainty** | ❌ (staleness) | ❌ |
| **Spatial Uncertainty** | ❌ (network topology) | ❌ |

### 4.2 Required Uncertainty Model

```python
class UncertaintyQuantification:
    measurement_uncertainty: float      # ±% for measurements
    sampling_uncertainty: float         # ±% for sampling
    model_uncertainty: float            # ±% for model assumptions
    parameter_uncertainty: float        # ±% for parameters
    classification_uncertainty: float   # ±% for classification
    temporal_uncertainty: float         # ±% for staleness
    spatial_uncertainty: float          # ±% for topology
    
    def combined_uncertainty(self) -> float:
        # RSS combination
        return sqrt(sum(u**2 for u in [
            self.measurement_uncertainty,
            self.sampling_uncertainty,
            self.model_uncertainty,
            self.parameter_uncertainty,
            self.classification_uncertainty,
            self.temporal_uncertainty,
            self.spatial_uncertainty,
        ]))
```

---

## 5. TRUST MODEL COMMUNICATION — MISSING IN UI

### 5.1 What Users See vs What Exists

| Trust Element | Exists Internally | Exposed in UI/API |
|---------------|-------------------|-------------------|
| Evidence Grade | ✅ (HIGH/MEDIUM/LOW) | ❌ |
| Verification Level | ✅ (VERIFIED/UNVERIFIED) | ❌ |
| AI Boundary | ✅ (Enforced) | ❌ |
| Deterministic Badge | ✅ (Enforced) | ❌ |
| Evidence Provenance | ✅ (API) | ⚠️ API only |
| Confidence Score | ✅ (0.0-1.0) | ❌ |
| Uncertainty Quantification | ❌ | ❌ |
| Evidence Quality Badge | ❌ | ❌ |
| Conflict Indicator | ❌ | ❌ |
| Evidence Chain Link | ✅ (API) | ❌ |

---

## 5. TRUST MODEL DOCUMENTATION — MISSING

### 5.1 Missing Documentation

| Document | Status |
|----------|--------|
| **Trust Model Specification** | ❌ Missing |
| **Evidence Grading Guide** | ❌ Missing |
| **Verification Level Definitions** | ❌ Missing |
| **AI Boundary Policy** | ❌ Missing |
| **Uncertainty Quantification Guide** | ❌ Missing |
| **User Trust Guide** | ❌ Missing |
| **Developer Trust Guide** | ❌ Missing |
| **Auditor Trust Guide** | ❌ Missing |

---

## 6. RECOMMENDATIONS

### P0 — Critical

1. **Expose Trust Model in UI** — Evidence grades, verification levels, AI badges
2. **Add Uncertainty Quantification** — Per-finding uncertainty scores
3. **Expose Trust Model in API** — `/trust-model` endpoint with full model
4. **Add AI Boundary Indicators** — Clear labels on all AI outputs

### P1 — High

4. **Implement Trust Model Documentation** — Spec, guide, examples
5. **Add Evidence Quality Badges** — UI badges for evidence quality
6. **Add Uncertainty Indicators** — Per-finding uncertainty visualization
7. **Add Conflict Indicators** — UI flags for conflicting evidence

### P2 — Medium

8. **Trust Model Documentation** — Spec, guide, examples
9. **User Trust Training** — Onboarding for trust model
10. **Trust Model API** — `/trust-model` endpoint with full model
11. **Evidence Quality API** — Per-finding quality metrics
10. **AI Boundary API** — `/ai-boundaries` endpoint

### P3 — Enhancement

11. **Trust Model Visualization** — Interactive trust model explorer
12. **Uncertainty Visualization** — Uncertainty heatmaps, confidence intervals
12. **Trust Model Testing** — Automated trust model validation
13. **Trust Model Evolution** — Versioned trust model with migration

---

## 6. VERDICT

**Strong internal trust model, completely invisible to users.** Evidence grading, verification levels, AI boundaries all enforced internally but not communicated.

| Trust Model Aspect | Internal | Exposed to Users |
|--------------------|----------|------------------|
| Evidence Grading | ✅ Explicit | ❌ Hidden |
| Verification Levels | ✅ Explicit | ❌ Hidden |
| AI Boundaries | ✅ Enforced | ❌ Hidden |
| Deterministic Pipeline | ✅ Enforced | ❌ Hidden |
| Uncertainty Quantification | ❌ Missing | ❌ Missing |
| Trust Communication | ❌ Missing | ❌ Missing |
| User-Facing Indicators | ❌ Missing | ❌ Missing |

**To fix:** 4-6 weeks for UI trust indicators, API trust model endpoint, uncertainty quantification, documentation.

---

## 7. VERIFICATION EVIDENCE

| Finding | File |
|---------|------|
| Evidence Grading | `services/universal_crypto/universal_crypto/confidence.py` |
| Evidence Fusion | `services/universal_crypto/universal_crypto/engine.py:_to_observations()` |
| Verification Levels | `shared/shared_models/shared_models/observation.py` |
| AI Boundaries | `services/universal_crypto/universal_crypto/engine.py` |
| Remediation Labels | `services/remediation/remediation/engine.py` |
| Simulator Labels | `services/universal_crypto/universal_crypto/simulator.py` |
| Digital Twin | `services/agility/agility/twin_scenarios.py` |
| Agility Simulation | `services/agility/agility/simulation.py` |
| Policy Engine | `services/policy/policy/core/engine.py` |
| Evidence Pipeline | `services/evidence/evidence/core/pipeline.py` |
| Normalization Engine | `services/normalization/normalization/core/engine.py` |
| Crypto Classifier | `services/universal_crypto/universal_crypto/classification.py` |