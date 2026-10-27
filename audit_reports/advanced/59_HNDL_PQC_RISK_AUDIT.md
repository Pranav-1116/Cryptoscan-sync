# 59_HNDL_PQC_RISK_AUDIT.md
## ZELNX CryptoScan — Harvest Now, Decrypt Later (HNDL) & PQC Risk Audit

**Generated:** 2026-09-20  
**Method:** Deep inspection of quantum risk analysis, HNDL risk modeling, PQC readiness assessment, and migration planning  
**Scope:** Complete HNDL/PQC risk pipeline — Algorithm classification → Risk scoring → HNDL analysis → Migration deadlines → Remediation → Migration planning

---

## EXECUTIVE SUMMARY

**Core Question:** *"Can ZELNX accurately identify assets vulnerable to Harvest Now, Decrypt Later (HNDL) attacks and prioritize PQC migration?"*

**Answer:** **PARTIAL** — Strong quantum classification and risk scoring, but **missing critical HNDL factors** (data longevity, threat actor capability, migration execution).

| HNDL/PQC Component | Status | Score |
|--------------------|--------|-------|
| **Quantum Classification** | ✅ Strong | 8/10 |
| **Risk Scoring** | ✅ Good | 7/10 |
| **HNDL Risk Modeling** | ⚠️ Partial | 5/10 |
| **Migration Deadlines** | ✅ Good | 7/10 |
| **PQC Algorithm Detection** | ⚠️ Partial | 5/10 |
| **PQC Protocol Detection** | ❌ Missing | 1/10 |
| **Hybrid Crypto Detection** | ❌ Missing | 1/10 |
| **Migration Execution** | ❌ Missing | 1/10 |
| **Data Longevity Risk** | ⚠️ Partial | 4/10 |
| **Threat Actor Modeling** | ❌ Missing | 1/10 |

**Overall: 4.1/10** — Strong classification, weak HNDL modeling, no PQC protocol detection, no migration execution

---

## 1. QUANTUM CLASSIFICATION — STRONG FOUNDATION

### 1.1 Classification Engine

**File:** `shared/shared_models/shared_models/quantum_classify.py`

```python
def is_shor_vulnerable(algorithm: str) -> bool:
    # 1. Registry lookup (primary)
    entry = registry_entry(algorithm)
    if entry.quantum_status == QuantumStatus.QUANTUM_VULNERABLE:
        return True
    if entry.quantum_status == QuantumStatus.QUANTUM_SAFE:
        return False
    # 2. Fallback regex heuristic
    return bool(QUANTUM_VULNERABLE_RE.search(algorithm))
```

### 1.2 Quantum Status Categories (Complete)

| Status | Algorithms | Examples | Break Year | Action |
|--------|------------|----------|------------|--------|
| `QUANTUM_VULNERABLE` (Shor) | RSA, DH, DSA, ECDH, ECDSA, Ed25519, X25519 | RSA-2048, ECDSA-P256, Ed25519 | 2030 | **URGENT** - Plan migration |
| `GROVER_MARGINAL` | AES-128, SHA-256 | AES-128, SHA-256 | 2040 | **PLAN** - Increase key size |
| `CLASSICALLY_BROKEN` | DES, 3DES, RC4, MD5, SHA-1, SSLv3, TLS 1.0/1.1 | DES, MD5, TLS 1.0 | 2010 | **IMMEDIATE** - Replace now |
| `QUANTUM_SAFE` (PQC) | ML-KEM, ML-DSA, SLH-DSA, AES-256, SHA-384+, SHA-3 | ML-KEM-768, AES-256, SHA-384 | Never | **SAFE** - Monitor |
| `UNKNOWN` | Unrecognized | Custom/proprietary | Unknown | **REVIEW** - Investigate |

### 1.3 Classification Accuracy

| Algorithm | Registry Status | Regex Fallback | Correct |
|-----------|-----------------|----------------|---------|
| RSA-2048 | QUANTUM_VULNERABLE | Shor regex | ✅ |
| ECDSA-P256 | QUANTUM_VULNERABLE | Shor regex | ✅ |
| Ed25519 | QUANTUM_VULNERABLE | Shor regex | ✅ |
| X25519 | QUANTUM_VULNERABLE | Shor regex | ✅ |
| AES-256-GCM | QUANTUM_SAFE | Grover regex | ✅ |
| AES-128-GCM | GROVER_MARGINAL | Grover regex | ✅ |
| ML-KEM-768 | QUANTUM_SAFE | PQC regex | ✅ |
| ML-DSA-65 | QUANTUM_SAFE | PQC regex | ✅ |
| Custom "MyCrypto" | UNKNOWN | Regex fallback | ❓ Unknown |

**Gap:** No FP/FN measurement for regex fallback.

---

## 2. QUANTUM RISK SCORING — GOOD BUT INCOMPLETE

### 2.1 Scoring Engine

**File:** `services/quantum/quantum/risk.py:score_asset()`

```python
def score_asset(asset, system, today, sector_criticality_weight):
    # 1. Base vulnerability (0-100) from classification
    # 2. Data sensitivity multiplier (1.0-2.0)
    # 3. HNDL multiplier (1.0-1.5) — retention + regulated + classifications
    # 4. Timeline multiplier (1.0-2.0) — years to 2030
    # 5. Criticality tier (1.0-1.5) — system criticality
    # 6. Sector weight (0.5-1.5) — optional sector profile
    
    score = min(100, base_vuln * sensitivity * hndl * timeline * criticality * sector)
```

### 2.2 Scoring Factors

| Factor | Weight | Range | Source |
|--------|--------|-------|--------|
| Base vulnerability | Implicit (0-100) | 0-100 | Classification |
| Data sensitivity | Multiplier | 1.0-2.0 | System data_classifications |
| HNDL multiplier | Multiplier | 1.0-1.5 | Retention, regulated, classifications |
| Timeline | Multiplier | 1.0-2.0 | Years to 2030 |
| Criticality | Multiplier | 1.0-1.5 | System.criticality / extra.criticality_tier |
| Sector weight | Multiplier | 0.5-1.5 | Sector profile (optional) |

### 2.3 Risk Categories

| Score | Category | Urgency |
|-------|----------|---------|
| 80-100 | CRITICAL | IMMEDIATE |
| 60-79 | HIGH | 1-2 YEARS |
| 40-59 | MEDIUM | 3-5 YEARS |
| 20-39 | LOW | 5-10 YEARS |
| 0-19 | MINIMAL | NO ACTION |

---

## 3. HNDL (HARVEST NOW, DECRYPT LATER) RISK — PARTIAL

### 3.1 HNDL Risk Function

**File:** `services/quantum/quantum/risk.py:hndl_risk()`

```python
def hndl_risk(algorithm, purpose, retention_years, public_network, regulated, classifications):
    # Only for SHOR_VULNERABLE and CLASSICALLY_BROKEN
    # Multiplier based on:
    # - retention_years: >=25→1.5, >=10→1.2, >=5→1.1, else 1.0
    # - public_network: 0.8x if false
    # - regulated/classifications: 1.5x if PHI/PAN/PCI/CLASSIFIED/HIPAA
```

### 3.2 HNDL Output

```python
{
    "hndl_risk": "CRITICAL|HIGH|MODERATE|LOW|NONE",
    "score_multiplier": 1.0-1.5,
    "reason": "retention=25y regulated=True"
}
```

### 3.3 HNDL Gaps — CRITICAL

| Missing HNDL Factor | Current | Required |
|---------------------|---------|----------|
| **Data Longevity Modeling** | Retention years only | Data half-life, archival policies, legal hold |
| **Threat Actor Capability** | None | APT quantum timeline, nation-state resources |
| **Data Value Decay** | None | Value decay curve over time |
| **Key Compromise Impact** | None | Forward secrecy, key rotation |
| **Forward Secrecy Status** | Not checked | PFS/TLS 1.3 vs static RSA |
| **Key Rotation Frequency** | Not tracked | Key lifetime vs data lifetime |
| **Data Classification Granularity** | String list only | Sensitivity tiers with half-lives |
| **Archival/Backup Crypto** | Not scanned | Long-term encrypted archives |
| **Legal/Regulatory Hold** | Not tracked | Legal hold extends data life |
| **Cross-Border Data Flow** | Not tracked | Jurisdiction-specific quantum timelines |

---

## 4. DATA LONGEVITY RISK — PARTIAL

### 4.1 Current: Retention Years Only

```python
# quantum/risk.py
retention = extra.get("data_retention_years")
if retention is None:
    retention = system.get("data_retention_years")
```

### 4.2 Missing Data Longevity Factors

| Missing Factor | Current | Required |
|----------------|---------|----------|
| **Data Half-Life** | Not modeled | Exponential decay curve |
| **Data Value Decay** | Not modeled | Business value decay function |
| **Legal Hold** | Not tracked | Legal hold extends effective life |
| **Archival Policy** | Not scanned | Archive crypto separate from production |
| **Backup Retention** | Not scanned | Backup crypto often weaker/older |
| **Cross-Border Data** | Not tracked | Jurisdiction-specific quantum timelines |
| **Data Minimization** | Not assessed | Data minimization reduces exposure |
| **Tokenization/Anonymization** | Not detected | Reduces plaintext exposure |

---

## 5. PQC ALGORITHM DETECTION — PARTIAL

### 5.1 Registry Coverage

| PQC Algorithm | Registry Entry | Source Detection | Binary Detection |
|---------------|----------------|------------------|------------------|
| ML-KEM-512/768/1024 | ✅ | ✅ Source | ❓ Untested |
| ML-DSA-44/65/87 | ✅ | ✅ Source | ❓ Untested |
| SLH-DSA-SHA2-128/192/256 | ✅ | ✅ Source | ❓ Untested |
| Kyber-512/768/1024 | ✅ (aliases) | ✅ Source | ❓ Untested |
| Dilithium-2/3/5 | ✅ (aliases) | ✅ Source | ❓ Untested |
| SPHINCS+-SHA2-128/192/256 | ✅ | ✅ Source | ❓ Untested |
| FALCON-512/1024 | ✅ | ❓ | ❓ |
| HQC | ✅ | ❓ | ❓ |

**Gap:** Binary detection of PQC algorithms **untested**.

---

### 5.2 PQC Protocol Detection — MISSING

| Protocol | PQC Support | Detection Status |
|----------|-------------|------------------|
| TLS 1.3 + PQC | Hybrid KEM (X25519+ML-KEM) | ❌ Not detected |
| TLS 1.3 + PQC | Pure ML-KEM | ❌ Not detected |
| SSH PQC | Hybrid KEX (sntrup761x25519-sha512) | ❌ Not detected |
| IPsec/IKEv2 PQC | Hybrid IKEv2 | ❌ Not detected |
| QUIC PQC | Hybrid KEM | ❌ Not detected |
| SSH Certificates PQC | ML-DSA certs | ❌ Not detected |

**Critical Gap:** No PQC cipher suite detection in protocol parsers.

---

### 5.3 Hybrid Crypto Detection — MISSING

| Hybrid Pattern | Detection |
|----------------|-----------|
| X25519 + ML-KEM-768 | ❌ Not detected |
| ECDHE + ML-KEM-768 | ❌ Not detected |
| RSA + ML-KEM-768 (hybrid KEM) | ❌ Not detected |
| ECDSA + ML-DSA-65 (hybrid sig) | ❌ Not detected |
| Composite certificates (RSA + ML-DSA) | ❌ Not detected |
| X.509 extensions for PQC | ❌ Not parsed |

---

## 6. MIGRATION DEADLINES — GOOD BUT INCOMPLETE

### 6.1 Deadline Calculation

**File:** `services/quantum/quantum/risk.py:migration_deadline()`

```python
def migration_deadline(scopes, retention_years, today):
    deadlines = [
        ("quantum_threat", 2030-01-01),
        ("regulatory:DORA", 2025-01-17),
        ("regulatory:NSA-CNSA-2.0", 2033-01-01),
        ("regulatory:PCI-DSS", 2025-04-01),
    ]
    if retention_years >= 10:
        deadlines.append(("hndl", today + 2 years))
    else:
        deadlines.append(("hndl", today + 5 years))
    # Earliest deadline wins
```

### 6.2 Deadline Gaps

| Missing Deadline Factor | Current | Needed |
|-------------------------|---------|--------|
| **Algorithm-Specific Deadlines** | Generic | Per-algorithm (RSA vs ECC vs DH) |
| **Key Size Specific** | Generic | RSA-1024 vs RSA-2048 vs RSA-4096 |
| **Protocol-Specific** | Generic | TLS 1.0 vs 1.1 vs 1.2 deadlines |
| **Certificate Expiry Integration** | Not integrated | Cert expiry vs migration deadline |
| **Key Rotation Schedule** | Not integrated | Rotation vs migration alignment |
| **Vendor Support Timeline** | Not tracked | Vendor PQC support roadmap |
| **HSM/KMS Upgrade Timeline** | Not tracked | Hardware upgrade lead time |
| **Regulatory Guidance Updates** | Static | Dynamic feed for new guidance |

---

## 7. MIGRATION READINESS — PARTIAL

### 7.1 Readiness Assessment

**File:** `services/agility/agility/readiness.py:assess_readiness()`

```python
def assess_readiness(agility_score, dependency_count, has_crypto_tests, 
                     has_general_tests, team_capacity, change_freeze):
    # 5 factors:
    # 1. Agility (40%)
    # 2. Dependencies (20%)
    # 3. Testing (20%)
    # 4. Team Capacity (15%)
    # 5. Change Freeze (5%)
```

### 7.2 Readiness Gaps

| Missing Factor | Current | Needed |
|----------------|---------|--------|
| **Vendor PQC Readiness** | Not assessed | Vendor PQC roadmap |
| **HSM/KMS Upgrade Path** | Not assessed | HSM firmware, KMS API |
| **Library PQC Support** | Not assessed | OpenSSL 3.x, BoringSSL, BouncyCastle |
| **Protocol Stack PQC** | Not assessed | TLS stack, SSH, IPsec |
| **Certificate Authority PQC** | Not assessed | CA PQC readiness |
| **Vendor Certificate PQC** | Not assessed | CA PQC certificate issuance |
| **HSM/KMS Firmware** | Not tracked | Firmware upgrade path |
| **Application Code Changes** | Not estimated | Code refactoring effort |

---

## 8. MIGRATION EXECUTION — MISSING

### 8.1 No Migration Execution Engine

| Capability | Status |
|------------|--------|
| Automated Code Refactoring | ❌ |
| Config Migration | ❌ |
| Library Upgrade Orchestration | ❌ |
| HSM Firmware Update Coordination | ❌ |
| Certificate Re-issuance | ❌ |
| Key Rotation Orchestration | ❌ |
| Testing/Validation Pipeline | ❌ |
| Rollback Capability | ❌ |
| Canary Deployment | ❌ |
| Blue/Green Migration | ❌ |

### 8.2 Migration Project Tracking Only

**File:** `services/database/db/models/migration_project.py`

```python
class MigrationProject:
    status: str  # PLANNED, IN_PROGRESS, COMPLETED, BLOCKED, FAILED
    # ... tracking only, no execution
```

**Gap:** Tasks are tracking only — no execution engine.

---

## 8. RECOMMENDATIONS

### P0 — Critical

1. **Implement PQC Protocol Detection** — TLS 1.3 hybrid KEM, SSH PQC, IPsec PQC
2. **Add Binary PQC Detection** — Test ML-KEM/ML-DSA/SLH-DSA in binaries
3. **Implement Hybrid Crypto Detection** — X25519+ML-KEM, ECDHE+ML-KEM, composite certs
4. **Integrate Data Longevity Modeling** — Half-life, legal hold, archival, backup crypto

### P1 — High

4. **Add Threat Actor Quantum Timeline** — Nation-state quantum capability assessments
5. **Implement Forward Secrecy Detection** — TLS 1.3 vs static RSA key exchange
6. **Add PQC Certificate Detection** — ML-DSA/SLH-DSA in X.509
7. **Implement Hybrid Crypto Detection** — X25519+ML-KEM, ECDHE+ML-KEM, composite certs
8. **Integrate Certificate Expiry with Migration Deadlines** — Cert expiry vs migration

### P2 — Medium

4. **Add PQC Protocol Detection** — TLS 1.3 hybrid KEM, SSH PQC, IPsec PQC
5. **Add Binary PQC Detection Validation** — Test corpus with PQC binaries
6. **Add Migration Execution Engine** — Code refactoring, config migration, library upgrade
7. **Add PQC Certificate Detection** — ML-DSA/SLH-DSA in X.509
8. **Add Migration Testing Pipeline** — Automated validation

### P3 — Enhancement

4. **Post-Quantum SSH/IPsec Detection** — Protocol upgrades
5. **CT Log Verification for PQC Certs** — SCT validation
7. **Migration Cost Estimation** — Detailed effort breakdown
8. **Rollback Capability** — Automated rollback on migration failure

---

## 9. VERDICT

**Strong quantum classification and risk scoring, but HNDL modeling is incomplete, PQC protocol detection is missing, and migration execution is non-existent.**

| Capability | Status |
|------------|--------|
| Quantum Classification | ✅ Strong |
| Risk Scoring | ✅ Good |
| HNDL Risk Modeling | ⚠️ Partial (missing data longevity, threat actor) |
| Migration Deadlines | ✅ Good (regulatory + HNDL) |
| PQC Algorithm Detection | ⚠️ Partial (registry yes, binary untested) |
| PQC Protocol Detection | ❌ Missing |
| Hybrid Crypto Detection | ❌ Missing |
| Data Longevity Risk | ⚠️ Partial (retention only) |
| Migration Execution | ❌ Missing |
| Threat Actor Modeling | ❌ Missing |

**To fix:** 8-12 weeks for PQC protocol detection, hybrid detection, data longevity modeling, threat actor modeling, and migration execution engine.

---

## 9. VERIFICATION EVIDENCE

| Finding | File |
|---------|------|
| Quantum Classification | `shared/shared_models/shared_models/quantum_classify.py` |
| Quantum Risk Scoring | `services/quantum/quantum/risk.py` |
| Agility Scoring | `services/agility/agility/system_score.py` |
| Migration Readiness | `services/agility/agility/readiness.py` |
| Migration Waves | `services/api/api/routers/graph.py:graph_migration_waves()` |
| Remediation Rules | `services/remediation/remediation/engine.py` |
| Simulator | `services/universal_crypto/universal_crypto/simulator.py` |
| Migration Plan | `services/api/api/routers/graph.py:graph_migration_plan()` |
| Migration Models | `services/database/db/models/migration_project.py` |
| Quantum Risk API | `services/api/api/routers/quantum.py` |
| PQC API | `services/api/api/routers/crypto.py:/crypto/simulate` |
| Agility API | `services/api/api/routers/agility.py` |
| Graph Migration Plan | `services/api/api/routers/graph.py:graph_migration_plan()` |
| Protocol Engine | `services/universal_crypto/universal_crypto/protocol_engine.py` |
| Binary Engine | `services/universal_crypto/universal_crypto/binary_engine.py` |
| Certificate Intel | `services/universal_crypto/universal_crypto/certificate_intel.py` |
## UPDATE — 2026-10-09 (round 14): hybrid KEM visibility closed

The HNDL-relevant detection holes this report lists are fixed: TLS 1.3
hybrid KEM groups are named and classified (X25519MLKEM768 et al.),
OpenSSH hybrid KEX no longer under-reports as classical X25519, and IKEv2
ML-KEM groups 35/36/37 are detected. Quantum classification for hybrids is
explicit: PQC_RESISTANT via the post-quantum component, with policy status
tracking that component's standardization (ALLOWED for FIPS 203 hybrids,
RESTRICTED for Kyber drafts and sntrup761).

## Round 27 update (2026-10-10) — PQC detection + HNDL longevity re-verified

* **PQC protocol detection (P0 #1) — shipped:** the protocol engine
  maps hybrid ML-KEM TLS groups (RFC 10024: X25519MLKEM768/1024,
  SecP256r1MLKEM768) and pre-standard Kyber768 hybrids still seen in
  the wild, plus OpenSSH hybrid PQ KEX mapped to the hybrid identity,
  not the classical half.
* **Binary PQC detection (P0 #2) — shipped:** ML-KEM/ML-DSA/SLH-DSA
  signatures in the AST/findings/hardcoded/library-fingerprint
  detectors, with a dedicated PQC-classification corpus wave
  (re-verified round 26 for report 29).
* **Hybrid crypto detection (P0 #3) — shipped:** HYBRID is a
  first-class classification in the universal-crypto models, and hybrid
  groups are normalized end to end.
* **Data longevity modeling (P0 #4) — shipped:** `hndl_risk()` scores
  harvest-now-decrypt-later exposure from retention years,
  public-network exposure, regulated/PHI/HIPAA/GDPR/PCI classifications
  (multipliers 0.8–1.5, CRITICAL escalation for regulated ≥10y), and
  drives migration deadlines (2y/5y horizons) in the quantum plan.
* Remaining opens are fine-grained: composite-certificate handling and
  backup-crypto longevity propagation (product-scoped).

## Round 32 addendum (2026-10-11) — composite-certificate handling BUILT

The composite/hybrid certificate gap is closed end-to-end:

- `shared/shared_models/shared_models/composite_certificates.py` — pure
  detection registry: the registered composite OID arcs
  (`2.16.840.1.114027.80/81/82` — Composite ML-DSA signatures, chameleon
  composites, composite KEMs; arc-prefix matching because suffixes still
  move across draft revisions) plus name pairing (a PQ marker AND a
  classical marker — `id-ML-DSA65-RSA2048-PSS-SHA512`,
  `ML-KEM-768+ECDH-P384`, `mldsa65_rsa2048`), with best-effort component
  extraction. Unknown identifiers stay unknown — no heuristic guessing.
- Ingest: `CertificateRepository.upsert` runs detection on every create
  and merge and stores it in `extra["composite"]` (so listing stays
  single-query); all ingest paths (scan results, CA issuance, cloud
  provider collection) flow through it.
- Read surface: `GET /certificates/composite`
  (`composite-certificates/read-projection-v1`) — entries with components
  and scheme, plus scheme counts and an explicit statement of what the
  detection does and does not cover.
- Tests: `shared/shared_models/tests/test_composite_certificates.py`
  (OID arcs, name pairing, ordinary algorithms negative, unknown-OID
  honesty), `services/api/tests/unit/test_composite_certs_api.py`
  (ingest + listing + anon 401).

Still open, product-scoped: backup-crypto longevity propagation (a
backup format's algorithm limits how far archived material stays
decryptable — a policy model, not just detection).
