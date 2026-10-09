# 60_CRYPTO_AGILITY_FORENSIC_AUDIT.md
## ZELNX CryptoScan — Crypto Agility Forensic Audit

**Generated:** 2026-09-20  
**Method:** Deep inspection of crypto agility measurement, scoring, and modeling  
**Scope:** Complete agility model — Algorithm hardcoding, library coupling, protocol coupling, certificate coupling, HSM coupling, KMS coupling, vendor coupling, application coupling, configuration coupling

---

## EXECUTIVE SUMMARY

**Core Question:** *"Can ZELNX measure how easily an organization can replace cryptography?"*

**Answer:** **PARTIAL** — 6-factor agility scoring exists but **missing critical coupling dimensions** (HSM, KMS, vendor, protocol, certificate) and **no execution path** from score to agility improvement.

| Agility Dimension | Measured | Score | Evidence |
|-------------------|----------|-------|----------|
| **Algorithm Hardcoding** | ✅ Yes | 8/10 | Hardcoded key detector |
| **Config-Driven Crypto** | ✅ Yes | 7/10 | Config parsers |
| **Crypto Abstraction Layer** | ✅ Yes | 7/10 | Source analysis |
| **Algorithm Negotiation** | ✅ Yes | 7/10 | TLS/SSH config |
| **Key Management Centralized** | ✅ Yes | 7/10 | KMS/HSM detection |
| **PQC Library Available** | ✅ Yes | 6/10 | Library fingerprinting |
| **HSM Coupling** | ❌ Missing | 0/10 | No HSM coupling metric |
| **KMS Coupling** | ⚠️ Partial | 4/10 | KMS detection only |
| **Vendor Coupling** | ⚠️ Partial | 4/10 | Vendor detection only |
| **Protocol Coupling** | ⚠️ Partial | 4/10 | TLS/SSH config only |
| **Certificate Coupling** | ❌ Missing | 0/10 | No cert coupling metric |
| **Library Coupling** | ✅ Yes | 7/10 | Library fingerprinting |
| **Application Coupling** | ⚠️ Partial | 4/10 | Source analysis only |
| **Configuration Coupling** | ✅ Yes | 7/10 | Config parsers |

**Overall: 4.8/10** — Good foundation, missing critical coupling dimensions

---

## 1. AGILITY SCORING MODEL — CURRENT STATE

### 1.1 6-Factor Agility Score

**File:** `services/agility/agility/system_score.py:score_system()`

```python
def score_system(asset, system, evidence, libraries, dependencies, config):
    # Factor 1: Algorithm Hardcoded? (0-30 pts)
    # Factor 2: Config-Driven Crypto? (0-20 pts)
    # Factor 3: Crypto Abstraction Layer? (0-20 pts)
    # Factor 4: Algorithm Negotiation? (0-15 pts)
    # Factor 5: Key Management Centralized? (0-20 pts)
    # Factor 6: PQC Library Available? (0-15 pts)
    # Total: 100 pts
```

### 1.2 Factor Details

| Factor | Max Pts | Detection Method | Weight |
|--------|---------|------------------|--------|
| **1. Algorithm Hardcoded** | 30 | Hardcoded key detector + config analysis | 30% |
| **2. Config-Driven Crypto** | 20 | Config parsers (TLS, SSH, IPsec, app config) | 20% |
| **3. Crypto Abstraction Layer** | 20 | Source analysis (wrapper classes, interfaces) | 20% |
| **4. Algorithm Negotiation** | 15 | TLS/SSH/IPsec config (negotiation enabled) | 15% |
| **5. Key Management Centralized** | 20 | KMS/HSM usage, key metadata | 20% |
| **6. PQC Library Available** | 15 | Library fingerprinting (PQC libraries) | 15% |

### 1.3 Agility Categories

| Score | Category | Migration Effort |
|-------|----------|------------------|
| 80-100 | HIGH | Ready now |
| 60-79 | MEDIUM | 2-4 weeks prep |
| 40-59 | LOW | Significant refactor |
| 0-39 | VERY LOW | Major rewrite needed |

---

## 2. MISSING AGILITY DIMENSIONS

### 2.1 Missing Coupling Metrics

| Missing Dimension | Why Critical | Current State |
|-------------------|--------------|---------------|
| **HSM Coupling** | HSM firmware, API, key extraction | ❌ Not measured |
| **KMS Coupling** | KMS API, key policies, regions | ⚠️ KMS detected only |
| **Vendor Coupling** | Vendor lock-in, proprietary APIs | ⚠️ Vendor detected only |
| **Protocol Coupling** | TLS version lock-in, cipher lock-in | ⚠️ TLS config only |
| **Certificate Coupling** | Cert lifecycle, automation, ACME | ❌ Not measured |
| **Library Coupling** | Version pinning, transitive deps | ✅ Measured (partial) |
| **Application Coupling** | Code spread, call sites | ⚠️ Source analysis only |
| **Configuration Coupling** | Config drift, drift detection | ✅ Measured |
| **Certificate Lifecycle Coupling** | Cert automation, renewal, revocation | ❌ Not measured |
| **Key Lifecycle Coupling** | Rotation, expiry, destruction | ❌ Not measured |
| **Protocol Version Coupling** | TLS 1.0/1.1 lock-in | ⚠️ TLS config only |
| **Cipher Suite Coupling** | Cipher suite lock-in | ⚠️ TLS config only |
| **Key Derivation Coupling** | KDF lock-in (PBKDF2, HKDF, etc.) | ❌ Not measured |
| **Randomness Source Coupling** | Entropy source lock-in | ❌ Not measured |

---

## 3. AGILITY FACTOR ANALYSIS — GAPS

### 3.1 Factor 1: Algorithm Hardcoded (30 pts) — ✅ MEASURED

**Detection:** Hardcoded key detector + config analysis

```python
# agility/system_score.py
if any(row.get("is_hardcoded_key") for row in evidence):
    # Penalty applied
```

**Gap:** Only detects hardcoded keys, not hardcoded algorithms in logic (e.g., `if algo == "RSA"` branches).

---

### 3.2 Factor 2: Config-Driven Crypto (20 pts) — ✅ MEASURED

**Detection:** Config parsers (TLS, SSH, IPsec, app config)

```python
# Checks for externalized crypto config
```

**Gap:** Doesn't measure config drift over time or config validation.

---

### 3.3 Factor 3: Crypto Abstraction Layer (20 pts) — ⚠️ PARTIAL

**Detection:** Source analysis for wrapper classes, interfaces

```python
# Looks for wrapper classes, interfaces, facades
```

**Gaps:**
- ❌ Doesn't detect interface segregation (e.g., separate encrypt/sign interfaces)
- ❌ Doesn't detect dependency injection usage
- ❌ Doesn't measure abstraction leak (direct library calls bypassing wrapper)
- ❌ Doesn't measure testability of abstraction (mockable?)

---

### 3.3 Factor 4: Algorithm Negotiation (15 pts) — ⚠️ PARTIAL

**Detection:** TLS/SSH/IPsec config (negotiation enabled)

**Gaps:**
- ❌ Doesn't measure client-side negotiation capability
- ❌ Doesn't measure server-side preference ordering
- ❌ Doesn't measure fallback behavior (downgrade attacks)
- ❌ Doesn't measure negotiation timeout/failure handling
- ❌ Doesn't measure algorithm preference configuration

---

### 3.4 Factor 5: Key Management Centralized (20 pts) — ⚠️ PARTIAL

**Detection:** KMS/HSM usage, key metadata

**Gaps:**
- ❌ Doesn't measure KMS API coupling (AWS KMS vs Azure Key Vault vs GCP KMS)
- ❌ Doesn't measure key policy flexibility (rotation, expiry, access)
- ❌ Doesn't measure cross-region/cloud key portability
- ❌ Doesn't measure HSM vendor lock-in (Thales vs nCipher vs AWS CloudHSM)
- ❌ Doesn't measure key export/import capability
- ❌ Doesn't measure key ceremony automation

---

### 3.5 Factor 6: PQC Library Available (15 pts) — ⚠️ PARTIAL

**Detection:** Library fingerprinting for PQC libraries

**Gaps:**
- ❌ Doesn't measure PQC library maturity (experimental vs stable)
- ❌ Doesn't measure PQC algorithm coverage (KEM vs SIG vs both)
- ❌ Doesn't measure hybrid mode support
- ❌ Doesn't measure PQC library version compatibility
- ❌ Doesn't measure PQC hardware acceleration support

---

## 4. AGILITY SCORING — MISSING DIMENSIONS

### 4.1 Current 6-Factor Model vs Required Model

| Required Dimension | Current 6-Factor | Gap |
|--------------------|------------------|-----|
| Algorithm Hardcoding | ✅ Factor 1 | - |
| Config-Driven | ✅ Factor 2 | - |
| Abstraction Layer | ✅ Factor 3 | Partial |
| Algorithm Negotiation | ✅ Factor 4 | Partial |
| Key Management | ✅ Factor 5 | Partial |
| PQC Library | ✅ Factor 6 | Partial |
| **HSM Coupling** | ❌ | **Missing** |
| **KMS Coupling** | ❌ | **Missing** |
| **Vendor Coupling** | ❌ | **Missing** |
| **Protocol Coupling** | ❌ | **Missing** |
| **Certificate Coupling** | ❌ | **Missing** |
| **Key Lifecycle Coupling** | ❌ | **Missing** |
| **Certificate Lifecycle Coupling** | ❌ | **Missing** |
| **Protocol Version Coupling** | ❌ | **Missing** |
| **Cipher Suite Coupling** | ❌ | **Missing** |
| **Key Derivation Coupling** | ❌ | **Missing** |
| **Randomness Coupling** | ❌ | **Missing** |
| **Library Version Coupling** | ❌ | **Missing** |
| **Transitive Dependency Coupling** | ❌ | **Missing** |
| **Build Pipeline Coupling** | ❌ | **Missing** |
| **Deployment Coupling** | ❌ | **Missing** |

---

## 4. AGILITY MEASUREMENT — MISSING METRICS

### 4.1 Quantitative Metrics Missing

| Metric | Description | Measured? |
|--------|-------------|-----------|
| **Algorithm Switch Time** | Time to switch algorithm in config/code | ❌ |
| **Key Rotation Time** | Time to rotate key end-to-end | ❌ |
| **Certificate Renewal Time** | Time to renew/replace certificate | ❌ |
| **Library Upgrade Time** | Time to upgrade crypto library | ❌ |
| **Protocol Upgrade Time** | Time to enable TLS 1.3 / disable 1.0 | ❌ |
| **Certificate Rotation Time** | Time to rotate certificate fleet | ❌ |
| **Key Rotation Time** | Time to rotate key fleet | ❌ |
| **HSM Failover Time** | Time to failover to backup HSM | ❌ |
| **KMS Failover Time** | Time to failover to backup KMS | ❌ |
| **Vendor Switch Time** | Time to switch crypto vendor | ❌ |
| **Protocol Downgrade Resistance** | Time to prevent downgrade | ❌ |
| **Cipher Suite Agility** | Number of supported cipher suites | ❌ |
| **Algorithm Diversity** | Number of algorithms supported | ❌ |
| **Key Size Flexibility** | Range of supported key sizes | ❌ |
| **Curve Flexibility** | Number of supported curves | ❌ |

---

## 5. AGILITY SCORING — SCORING METHODOLOGY ISSUES

### 5.1 Scoring Issues

| Issue | Current | Problem |
|-------|---------|---------|
| **Additive Scoring** | Sum of factors | Factors not independent |
| **No Negative Scoring** | Only penalties | No bonus for excellence |
| **Static Weights** | Fixed weights | Context-dependent importance |
| **No Context Weighting** | Same for all systems | Critical systems need different weighting |
| **No Industry Benchmarking** | Internal only | No industry comparison |
| **No Trend Tracking** | Point-in-time | No trend analysis |

---

## 6. AGILITY SIMULATION — WHAT-IF ANALYSIS

### 6.1 Simulation Engine

**File:** `services/agility/agility/simulation.py`

```python
def simulate_migration(asset, target_algorithm, protocol, library, hardware, usage, current_agility):
    # Projects readiness/quantum/agility/risk impact
    # But doesn't simulate AGILITY IMPROVEMENT
```

**Gap:** Simulation only projects risk/readiness impact, **not agility improvement** from specific changes.

### 6.2 Missing Simulation Capabilities

| Simulation | Current | Needed |
|------------|---------|--------|
| **Algorithm Switch Impact** | ❌ | Simulate algorithm change on agility |
| **Library Upgrade Impact** | ❌ | Simulate library upgrade on agility |
| **Config Externalization Impact** | ❌ | Simulate config-driven crypto on agility |
| **Abstraction Layer Impact** | ❌ | Simulate wrapper on agility |
| **Key Management Centralization Impact** | ❌ | Simulate KMS/HSM centralization |
| **PQC Library Adoption Impact** | ❌ | Simulate PQC library adoption |
| **Abstraction Layer Refactor Impact** | ❌ | Simulate refactoring on agility |
| **Protocol Upgrade Impact** | ❌ | Simulate TLS 1.3 migration on agility |

---

## 6. AGILITY ROADMAP — PARTIAL

### 6.1 Roadmap Generation

**File:** `services/agility/agility/roadmap.py`

```python
# Generates migration waves based on:
# 1. Readiness category → base wave
# 2. Cycle constraints (SCC)
# 3. Import constraints (IMPORTS edges)
# 4. Code-only systems (cascade earliest_wave)
```

**Gap:** Roadmap is **migration waves only**, not agility improvement roadmap.

### 6.2 Missing Roadmap Elements

| Missing Element | Description |
|-----------------|-------------|
| **Agility Improvement Roadmap** | Steps to improve agility score |
| **Refactoring Prioritization** | Which refactoring gives most agility gain |
| **Investment Planning** | Cost/effort for each agility improvement |
| **Milestone Tracking** | Agility milestones with dates |
| **ROI Calculation** | Agility gain per engineering week |
| **Team Capacity Planning** | Team allocation for agility work |

---

## 7. DIGITAL TWIN — SCENARIO SIMULATION

### 7.1 Twin Scenarios

**File:** `services/agility/agility/twin_scenarios.py`

```python
# 10 scenario types:
# 1. Algorithm Migration
# 2. Certificate Expiry
# 3. Key Rotation
# 4. HSM Outage
# 5. Vendor Compromise
# 6. Protocol Deprecation
# 7. Compliance Change
# 8. Attack Path
# 9. PQC Migration
# 10. Agility Drift
```

**Gap:** Scenarios project **risk/readiness impact**, not **agility improvement**.

---

## 8. RECOMMENDATIONS

### P0 — Critical

1. **Add Missing Coupling Metrics** — HSM, KMS, Vendor, Protocol, Certificate, Key Lifecycle, Certificate Lifecycle
2. **Add Quantitative Agility Metrics** — Switch times, rotation times, upgrade times
3. **Fix Agility Factor Gaps** — Complete Factors 3, 4, 5, 6 measurements
4. **Implement Agility Simulation** — Simulate agility improvement from changes

### P1 — High

4. **Add Quantitative Metrics** — Switch times, rotation times, upgrade times
5. **Implement Agility Simulation Engine** — Simulate agility improvement from changes
5. **Add Industry Benchmarking** — Compare agility scores across industry
6. **Add Trend Tracking** — Agility score trends over time
7. **Implement Agility Improvement Roadmap** — Not just migration waves

### P2 — Medium

8. **Industry Benchmarking** — Compare against industry peers
9. **Agility Trend Tracking** — Historical agility scores
10. **Contextual Weighting** — Dynamic factor weights per system criticality
11. **Agility Improvement ROI** — Cost/benefit of agility investments
12. **Team Capacity Planning** — Resource allocation for agility work

### P3 — Enhancement

12. **Agility Maturity Model** — CMMI-style maturity levels
13. **Predictive Agility** — ML-based agility forecasting
14. **Agility Certification** — Agility maturity certification
13. **Cross-Org Benchmarking** — Anonymous industry comparison

---

## 9. VERDICT

**Agility scoring exists but measures only 6 of 20+ critical dimensions, with partial coverage even on those 6. No quantitative metrics, no simulation of agility improvement, no roadmap for agility improvement.**

| Agility Capability | Status |
|--------------------|--------|
| 6-Factor Scoring | ⚠️ Partial (4/6 partial) |
| 20+ Coupling Dimensions | ❌ 14 missing |
| Quantitative Metrics | ❌ None |
| Agility Simulation | ❌ None (only risk simulation) |
| Agility Roadmap | ❌ Missing (migration waves only) |
| Industry Benchmarking | ❌ Missing |
| Trend Tracking | ❌ Missing |
| ROI Calculation | ❌ Missing |

**To fix:** 8-12 weeks for complete agility model with 20+ dimensions, quantitative metrics, simulation engine, and improvement roadmap.

---

## 9. VERIFICATION EVIDENCE

| Finding | File |
|---------|------|
| Agility Scoring | `services/agility/agility/system_score.py` |
| Readiness Assessment | `services/agility/agility/readiness.py` |
| Migration Waves | `services/agility/agility/roadmap.py` |
| Simulation | `services/agility/agility/simulation.py` |
| Twin Scenarios | `services/agility/agility/twin_scenarios.py` |
| System Score | `services/agility/agility/system_score.py` |
| Trajectory | `services/agility/agility/trajectory.py` |
| Agility Router | `services/api/api/routers/agility.py` |
| Digital Twin | `services/digital_twin/` |
| Graph Migration Waves | `services/api/api/routers/graph.py:graph_migration_waves()` |
| Agility API | `services/api/api/routers/agility.py` |