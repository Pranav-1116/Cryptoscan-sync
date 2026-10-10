# 64_CRYPTO_RISK_SCORING_FORENSIC_AUDIT.md
## ZELNX CryptoScan — Crypto Risk Scoring Forensic Audit

**Generated:** 2026-09-20  
**Method:** Deep inspection of all risk scoring components, methodologies, transparency, and auditability  
**Scope:** Complete risk scoring pipeline — Technical severity, Cryptographic weakness, Exposure, Asset criticality, Business criticality, PQC risk, Compliance impact, Exploitability, Data sensitivity, Migration difficulty

---

## EXECUTIVE SUMMARY

**Core Question:** *"Is ZELNX's risk scoring deterministic, rule-based, configurable, explainable, and auditable — with no black-box scoring?"*

**Answer:** **PARTIAL** — Multiple risk scores exist but **no unified risk model**. Scoring is fragmented across engines, with varying methodologies, missing factors, and limited explainability.

| Risk Score | Source | Deterministic | Explainable | Configurable | Auditable | Score |
|------------|--------|---------------|-------------|--------------|-----------|-------|
| **Quantum Risk** | `quantum/risk.py` | ✅ | ✅ | ⚠️ Partial | ✅ | 7/10 |
| **Compliance Risk** | `policy/engine.py` | ✅ | ✅ | ✅ | ✅ | 8/10 |
| **Agility Risk** | `agility/system_score.py` | ✅ | ✅ | ⚠️ | ✅ | 6/10 |
| **Drift Severity** | `drift/drift/` | ✅ | ✅ | ✅ | ✅ | 8/10 |
| **Vulnerability Severity** | `vulnerabilities` table | ⚠️ | ⚠️ | ❌ | ⚠️ | 4/10 |
| **Business Impact** | `graph/engine.py` | ✅ | ✅ | ❌ | ✅ | 7/10 |
| **Unified Risk** | ❌ Missing | ❌ | ❌ | ❌ | ❌ | 0/10 |

**Overall: 4.8/10** — Fragmented scores, no unified model, limited configurability, limited explainability

---

## 1. RISK SCORING LANDSCAPE — FRAGMENTED

### 1.1 Multiple Risk Scores (No Unified Model)

| Risk Score | Source Engine | Range | Purpose |
|------------|---------------|-------|---------|
| `quantum_risk_score` | `quantum/risk.py:score_asset()` | 0-100 | Quantum vulnerability |
| `compliance_status` | `policy/engine.py` | PASS/FAIL/WARN | Policy compliance |
| `agility_score` | `agility/system_score.py` | 0-100 | Crypto agility |
| `drift_severity` | `drift/drift/` | CRITICAL/HIGH/MEDIUM/LOW | Drift severity |
| `vulnerability.severity` | `vulnerabilities` table | CRITICAL/HIGH/MEDIUM/LOW | CVE severity |
| `business_impact.total_revenue_at_risk` | `graph/engine.py` | USD/day | Business impact |
| `risk_score` (drift) | `drift/drift/` | CRITICAL/HIGH/MEDIUM/LOW | Drift risk |

**Critical Gap:** **No unified risk model.** Seven different risk scores with different scales, methodologies, and purposes.

---

## 2. QUANTUM RISK SCORING — DETAILED ANALYSIS

### 2.1 Scoring Algorithm

**File:** `services/quantum/quantum/risk.py:score_asset()`

```python
def score_asset(asset, system, today, sector_criticality_weight):
    # 1. Base vulnerability (0-100) from classification
    # 2. Data sensitivity multiplier (1.0-2.0)
    # 4. HNDL multiplier (1.0-1.5) — retention + regulated + classifications
    # 5. Timeline multiplier (1.0-2.0) — years to 2030
    # 6. Criticality tier (1.0-1.5) — system criticality
    # 7. Sector weight (0.5-1.5) — optional sector profile
    
    score = min(100, base_vuln * sensitivity * hndl * timeline * criticality * sector)
```

### 2.2 Scoring Components Detail

| Component | Formula | Range | Configurable? |
|-----------|---------|-------|---------------|
| **Base Vulnerability** | Classification lookup | 0-100 | ❌ Hardcoded per category |
| **Data Sensitivity** | 1.0 (LOW) / 1.5 (MEDIUM) / 2.0 (HIGH) | 1.0-2.0 | ❌ Hardcoded |
| **HNDL Multiplier** | retention/regulated logic | 1.0-1.5 | ❌ Hardcoded thresholds |
| **Timeline** | Years to 2030: ≤2→2.0, ≤5→1.5, ≤10→1.2, else 1.0 | 1.0-2.0 | ❌ Hardcoded 2030 |
| **Criticality** | TIER-1/CRITICAL→1.5, HIGH→1.2, else 1.0 | 1.0-1.5 | ❌ Hardcoded tiers |
| **Sector Weight** | Sector profile scoring | 0.5-1.5 | ⚠️ External config |

### 2.3 Quantum Risk Output

```json
{
  "quantum_risk_score": 85,
  "risk_category": "CRITICAL",
  "threat_type": "SHOR_VULNERABLE",
  "base_vulnerability": 100,
  "hndl_risk": "CRITICAL",
  "data_sensitivity": "HIGH",
  "migration_deadline": "2028-01-01",
  "days_until_deadline": 500,
  "urgency": "IMMEDIATE",
  "recommended_replacement": "ML-KEM-768",
  "hybrid_mode_recommended": true,
  "calculation_version": "quantum-risk-v2.0"
}
```

### 2.4 Quantum Risk Gaps

| Gap | Impact |
|-----|--------|
| **Hardcoded 2030 Quantum Threat Year** | Not configurable, disputed timeline |
| **No Threat Actor Modeling** | APT vs criminal quantum capability |
| **No Exploitability Assessment** | PoC availability, weaponization |
| **No Forward Secrecy Consideration** | TLS 1.3 vs static RSA |
| **No Key Rotation Consideration** | Key rotation reduces HNDL window |
| **No Data Value Decay Model** | Data value decay over time |
| **No Compensating Controls** | TLS 1.3, certificate pinning, etc. |
| **Hardcoded 2030 Quantum Date** | Not configurable |

---

## 3. COMPLIANCE RISK — POLICY-BASED

### 3.1 Policy Engine Scoring

**File:** `services/policy/policy/core/engine.py:PolicyEngine.evaluate()`

```python
# Evaluates evidence against YAML rules
# Rules have: condition, severity, standard_reference
# Output: PolicyEvaluation (compliant, findings[], score)
```

### 3.2 Compliance Scoring

| Aspect | Implementation |
|--------|----------------|
| **Rule Matching** | Exact, Pattern, Family, Composite (AND/OR/NOT) |
| **Severity** | CRITICAL, HIGH, MEDIUM, LOW, INFO |
| **Standards** | NIST, FIPS, NSA-CNSA, PCI-DSS, HIPAA, ISO |
| **Scoring** | Not numeric — PASS/FAIL/WARN per rule |
| **Overall Score** | Not provided — only findings list |

**Gap:** No numeric compliance score, no risk-weighted compliance score.

---

## 4. AGILITY RISK — INVERSE AGILITY

### 4.1 Agility as Risk Proxy

**File:** `services/agility/agility/system_score.py`

```python
# 6 factors, 100 points max
# Factor 1: Algorithm Hardcoded (0-30)
# Factor 2: Config-Driven (0-20)
# Factor 3: Abstraction Layer (0-20)
# Factor 4: Algorithm Negotiation (0-15)
# Factor 5: Key Mgmt Centralized (0-20)
# Factor 6: PQC Library (0-15)
```

**Gap:** Agility score is **inverse risk proxy** but not integrated into unified risk model.

---

## 5. DRIFT RISK — SEVERITY-BASED

### 4.1 Drift Severity Classification

**File:** `services/drift/drift/`

```python
# Drift types with default severity:
# ALGORITHM_CHANGED (strong→weak) = CRITICAL
# KEY_SIZE_CHANGED (decrease) = HIGH
# TLS_VERSION_CHANGED (downgrade) = CRITICAL
# CERTIFICATE_EXPIRING (<30 days) = HIGH
# NEW_FINDING (quantum vulnerable) = HIGH
# CONFIG_CHANGED (weak config) = MEDIUM
```

**Gap:** Severity is rule-based but not integrated into unified risk.

---

## 5. VULNERABILITY RISK — CVE-BASED

### 5.1 Vulnerability Severity

**File:** `services/database/db/models/vulnerability.py`

```python
class Vulnerability:
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    # From CVE feed / advisory
```

**Gaps:**
- ❌ No CVSS score integration
- ❌ No EPSS (Exploit Prediction Scoring System)
- ❌ No exploitability assessment
- ❌ No patch availability tracking
- ❌ No workaround availability
- ❌ No compensating controls

---

## 6. BUSINESS IMPACT RISK — GRAPH-BASED

### 6.1 Business Impact Calculation

**File:** `services/graph_engine/graph_engine/core/engine.py:business_impact()`

```python
def business_impact(self, start_id, hops=5):
    # 1. Blast radius → affected systems
    # 2. Sum BusinessProcess.revenue_daily + customer_count
    # 3. Collect BusinessOwners via OWNED_BY
    # 4. Collect ComplianceScopes via MUST_COMPLY_WITH
```

**Output:** `total_revenue_at_risk`, `total_customers_at_risk`, `affected_processes`, `business_owners`, `compliance_scopes`

**Gap:** Not integrated into unified risk score.

---

## 6. UNIFIED RISK MODEL — MISSING

### 6.1 Required Unified Risk Model

```python
class UnifiedRiskAssessment:
    risk_id: UUID
    asset_id: UUID
    risk_score: float  # 0-100 unified
    components: RiskComponents
    calculated_at: DateTime
    calculation_version: str
    
class RiskComponents:
    # Technical Vulnerability (0-100)
    cryptographic_weakness: float
    quantum_vulnerability: float
    classical_vulnerability: float
    protocol_weakness: float
    config_weakness: float
    
    # Exposure (0-100)
    exposure_score: float
    internet_exposed: bool
    attack_surface: float
    
    # Threat (0-100)
    threat_likelihood: float
    exploitability: float
    threat_actor_capability: float
    poC_availability: float
    
    # Impact (0-100)
    business_impact: float
    revenue_at_risk: float
    customers_at_risk: int
    regulatory_exposure: float
    reputational_impact: float
    
    # Mitigation (reduces score)
    compensating_controls: float
    patch_availability: float
    workaround_availability: float
    detection_capability: float
    
    # Calculated
    final_risk_score: float
    risk_category: RiskCategory
    risk_components_detail: dict
```

---

## 6. RISK SCORING METHODOLOGY — ISSUES

### 6.1 Scoring Methodology Issues

| Issue | Current State | Problem |
|-------|---------------|---------|
| **No Unified Model** | 7 separate scores | Cannot compare/combine |
| **Inconsistent Scales** | 0-100, CRITICAL/HIGH, PASS/FAIL | Cannot aggregate |
| **No Weight Configuration** | Hardcoded weights | Cannot adjust for org context |
| **No Threat Modeling** | No threat actors | Cannot assess exploit likelihood |
| **No Exploitability** | No EPSS, PoC tracking | Cannot assess exploitability |
| **No Patch Management** | No patch tracking | Cannot assess remediation urgency |
| **No Compensating Controls** | Not modeled | Overstates risk |
| **No Data Value Decay** | Static sensitivity | Data value decays over time |
| **No Forward Secrecy** | Not considered | TLS 1.3 vs static RSA |
| **No Key Rotation** | Not considered | Rotation reduces exposure |

---

## 7. RISK SCORING CONFIGURABILITY — LIMITED

### 7.1 Current Configurability

| Parameter | Configurable? | Location |
|-----------|---------------|----------|
| Quantum Threat Year (2030) | ❌ Hardcoded | `quantum/risk.py` |
| Quantum Threat Year per Algorithm | ❌ | - |
| Data Sensitivity Weights | ❌ | `quantum/risk.py` |
| HNDL Thresholds | ❌ | `quantum/risk.py` |
| Timeline Multipliers | ❌ | `quantum/risk.py` |
| Criticality Tiers | ❌ | `quantum/risk.py` |
| Policy Rule Severity | ✅ YAML | Policy packs |
| Policy Rule Enabled | ✅ YAML | Policy packs |
| Agility Factor Weights | ❌ | `system_score.py` |
| Agility Factor Thresholds | ❌ | `system_score.py` |
| Drift Severity Mapping | ✅ Code | `drift/` |
| Business Impact Weights | ❌ | `graph/engine.py` |

---

## 7. EXPLAINABILITY — PARTIAL

### 8.1 Current Explainability

| Risk Score | Explainability |
|------------|----------------|
| Quantum Risk | ✅ Full breakdown in output |
| Compliance | ✅ Per-rule findings |
| Agility | ✅ Per-factor breakdown |
| Drift | ✅ Drift details |
| Business Impact | ✅ Revenue/customers breakdown |
| Vulnerability | ⚠️ CVE only |
| Unified | ❌ No unified explanation |

---

## 8. AUDITABILITY — PARTIAL

### 8.1 Audit Trail Coverage

| Risk Score | Audit Trail |
|------------|-------------|
| Quantum Risk | ❌ No calculation audit |
| Compliance | ✅ Policy pack hash + findings |
| Agility | ❌ No calculation audit |
| Drift | ✅ Drift acknowledgment audit |
| Business Impact | ❌ No calculation audit |
| Vulnerability | ⚠️ CVE source only |

---

## 8. RECOMMENDATIONS

### P0 — Critical

1. **Create Unified Risk Model** — Single `UnifiedRiskAssessment` with all components
2. **Implement Configurable Weighting** — All weights via configuration
3. **Add Threat Modeling** — Threat actor capabilities, exploitability
4. **Add Exploitability Scoring** — EPSS, PoC availability, weaponization

### P1 — High

4. **Add Compensating Controls** — TLS 1.3, cert pinning, segmentation
4. **Add Data Value Decay** — Time-based sensitivity decay
5. **Add Forward Secrecy Detection** — TLS 1.3 vs static RSA
6. **Add Key Rotation Impact** — Rotation reduces exposure window
7. **Add Configurable Quantum Timeline** — Per-algorithm threat years
8. **Add Patch/Workaround Availability** — Vendor patch status

### P2 — Medium

8. **Unified Risk API** — Single `/risk/assessment` endpoint
9. **Risk Calculation Audit Trail** — Full calculation audit trail
10. **Configurable Weights** — All weights via config
10. **Risk Decomposition API** — Component breakdown API
11. **Scenario Risk Simulation** — "What if" risk modeling
11. **Risk Trend Tracking** — Risk score history per asset

### P3 — Enhancement

12. **Monte Carlo Risk Simulation** — Probabilistic risk
13. **Risk Forecasting** — Trend-based risk prediction
13. **Peer Benchmarking** — Industry risk comparison
14. **Risk Appetite Integration** — Org risk appetite thresholds
15. **Regulatory Risk Mapping** — Regulatory requirement → risk mapping

---

## 9. VERDICT

**Risk scoring is fragmented, partially deterministic, partially explainable, poorly configurable, and poorly auditable.** No unified model exists.

| Risk Scoring Attribute | Status |
|------------------------|--------|
| **Deterministic** | ⚠️ Partial (some hardcoded) |
| **Rule-Based** | ⚠️ Partial (some hardcoded) |
| **Configurable** | ❌ Mostly hardcoded |
| **Explainable** | ⚠️ Partial (per-score only) |
| **Auditable** | ❌ No unified audit trail |
| **Unified Model** | ❌ Missing |
| **Threat Modeling** | ❌ Missing |
| **Exploitability** | ❌ Missing |
| **Compensating Controls** | ❌ Missing |
| **Data Decay** | ❌ Missing |

**To fix:** 8-12 weeks for unified risk model with configurable weights, threat modeling, exploitability, compensating controls, full audit trail, and unified API.

---

## 10. VERIFICATION EVIDENCE

| Finding | File |
|---------|------|
| Quantum Risk | `services/quantum/quantum/risk.py` |
| Policy Engine | `services/policy/policy/core/engine.py` |
| Agility Scoring | `services/agility/agility/system_score.py` |
| Drift Severity | `services/drift/drift/` |
| Business Impact | `services/graph_engine/graph_engine/core/engine.py` |
| Vulnerability Model | `services/database/db/models/vulnerability.py` |
| Drift Severity | `services/drift/drift/alerts/daily_digest.py` |
| Policy Engine | `services/policy/policy/core/engine.py` |
| Agility Scoring | `services/agility/agility/system_score.py` |
| Business Impact | `services/graph_engine/graph_engine/core/engine.py:business_impact()` |
| Graph Engine | `services/graph_engine/graph_engine/core/engine.py` |
| Quantum Risk | `services/quantum/quantum/risk.py` |
| Policy Engine | `services/policy/policy/core/engine.py` |
---

## UPDATE ADDENDUM — Round 19 (2026-10-10): unified model extended — configurable weights, system view, versioning

**Correction first (stale finding):** "no unified risk model exists" was
already false when this report was re-read — the §29b engine
(`services/universal_platform/universal_platform/risk.py`,
`GET /risk/unified`) fuses the eight blueprint factors (technical,
crypto, pqc, exposure, business criticality, dependency impact,
evidence confidence, threat) into one 0–100 CRITICAL/HIGH/MEDIUM/LOW
score with per-factor decomposition. What was genuinely missing from
this report's P0/P2 list is now built:

1. **Configurable weighting (P0 #2 / P2 #10):**
   `CRYPTOSCAN_RISK_WEIGHTS` (JSON env) re-weights any subset of the
   eight factors — named factors get absolute weights, the remainder is
   split proportionally among the rest, total always 1.0. Unrecognized
   names, non-numeric or negative values invalidate the whole override
   (fall back to documented defaults, reported via `weights_source`) —
   never silently half-applied.
2. **System-level unified risk (P2 #8/#11):** `GET /risk/systems` and
   `GET /risk/systems/{id}` derive the same eight factor levels from a
   system's persisted state — latest-scan evidence (registry
   designation, quantum impact, compliance, confidence), open drift
   events, CVEs, dependency edges, environment, criticality — and
   return the full decomposition plus the raw derivation `signals`
   (fail ratio, quantum-weighted ratio, unknown algorithms, …).
   Estate rollup + ranking included.
3. **Calculation audit trail (P2 #9):** every assessment is
   deterministic, stamped with `calculation_version`
   (`unified-risk-v1`) and `weights_source`, and self-describing (the
   response IS the audit trail: levels → points → weights → signals).

Still open from this report, honestly: threat-actor modeling and
exploitability/EPSS (no threat-intel feed in scope), compensating
controls, data-value decay, Monte Carlo/forecasting (P3). These need
external data sources or are speculative modeling — not buildable from
persisted state without inventing numbers.

Tests: `services/universal_platform/tests/test_unified_risk.py` (+5
weight/version tests, suite 40) and
`services/api/tests/unit/test_round19_risk_exposure_ownership.py`
(risk block: 6 tests).
