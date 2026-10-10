# 29_PQC_MIGRATION_READINESS_AUDIT.md
## ZELNX CryptoScan — PQC Migration Readiness Audit

**Generated:** 2026-09-20  
**Method:** Deep inspection of quantum risk analysis, agility scoring, migration waves, remediation guidance, and what-if simulation  
**Scope:** Quantum risk classification, agility scoring, migration readiness, remediation rules, what-if simulation, migration planning

---

## EXECUTIVE SUMMARY

| Component | Score | Status |
|-----------|-------|--------|
| Quantum Risk Classification | 8/10 | Registry-backed, deterministic |
| Quantum Risk Scoring | 7/10 | Multi-factor, HNDL-aware |
| Agility Scoring (6-factor) | 7/10 | Comprehensive factors |
| Migration Readiness (5-factor) | 7/10 | Good factors, no execution |
| Migration Waves | 8/10 | Cycle-constrained, readiness-based |
| Remediation Rules | 7/10 | 15 deterministic rules |
| What-If Simulation | 7/10 | Good projection, no execution |
| Migration Planning | 7/10 | Graph → MigrationProject integration |
| PQC Protocol Detection | 3/10 | Missing PQC TLS/SSH/IPsec |
| PQC Algorithm Detection | 5/10 | Registry has PQC, detection untested |

**Overall: 6.5/10** — Strong analysis, weak execution & PQC protocol detection

---

## 1. QUANTUM RISK CLASSIFICATION

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

### 1.2 Quantum Status Categories

| Status | Algorithms | Examples | Break Year |
|--------|------------|----------|------------|
| `QUANTUM_VULNERABLE` (Shor) | RSA, DH, DSA, ECDH, ECDSA, Ed25519, X25519 | RSA-2048, ECDSA-P256 | 2030 |
| `GROVER_MARGINAL` | AES-128, SHA-256 | AES-128, SHA-256 | 2040 |
| `CLASSICALLY_BROKEN` | DES, 3DES, RC4, MD5, SHA-1, SSLv3, TLS 1.0/1.1 | DES, MD5, TLS 1.0 | 2010 |
| `QUANTUM_SAFE` (PQC) | ML-KEM, ML-DSA, SLH-DSA, AES-256, SHA-384+ | ML-KEM-768, AES-256 | Never |
| `UNKNOWN` | Unrecognized | Custom/proprietary | Unknown |

### 1.3 Classification Accuracy

| Algorithm | Registry Status | Fallback | Correct |
|-----------|-----------------|----------|---------|
| RSA-2048 | QUANTUM_VULNERABLE | Shor regex | ✅ |
| ECDSA-P256 | QUANTUM_VULNERABLE | Shor regex | ✅ |
| Ed25519 | QUANTUM_VULNERABLE | Shor regex | ✅ |
| X25519 | QUANTUM_VULNERABLE | Shor regex | ✅ |
| AES-256-GCM | QUANTUM_SAFE | Grover regex | ✅ |
| AES-128-GCM | GROVER_MARGINAL | Grover regex | ✅ |
| ML-KEM-768 | QUANTUM_SAFE | PQC regex | ✅ |
| ML-DSA-65 | QUANTUM_SAFE | PQC regex | ✅ |
| Custom "MyCrypto" | UNKNOWN | Regex fallback | ❓ Unknown |

**Gap:** No false positive/negative measurement for fallback regex.

---

## 2. QUANTUM RISK SCORING

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

### 2.4 HNDL (Harvest Now Decrypt Later) Risk

**File:** `services/quantum/quantum/risk.py:hndl_risk()`

```python
def hndl_risk(algorithm, purpose, retention_years, public_network, regulated, classifications):
    # Only for SHOR_VULNERABLE and CLASSICALLY_BROKEN
    # Multiplier based on:
    # - retention_years: >=25→1.5, >=10→1.2, >=5→1.1, else 1.0
    # - public_network: 0.8x if false
    # - regulated/classifications: 1.5x if PHI/PAN/PCI/CLASSIFIED/HIPAA
```

**Output:** `hndl_risk` level (CRITICAL/HIGH/MODERATE/LOW/NONE) + multiplier.

---

### 2.5 Migration Deadline

**File:** `services/quantum/quantum/risk.py:migration_deadline()`

```python
def migration_deadline(scopes, retention_years, today):
    deadlines = [
        ("quantum_threat", 2030-01-01),
        ("regulatory:DORA", 2025-01-17),
        ("regulatory:NSA-CNSA-2.0", 2033-01-01),
        ("regulatory:PCI-DSS", 2025-04-01),
        ("hndl", today + 2y if retention>=10 else today + 5y)
    ]
    # Earliest deadline wins
    # Urgency: IMMEDIATE (≤180d), URGENT (≤365d), 1-2 YEARS, 3-5 YEARS
```

---

## 3. AGILITY SCORING (6-FACTOR)

### 3.1 Agility Engine

**File:** `services/agility/agility/system_score.py:score_system()`

```python
def score_system(asset, system, evidence, libraries, dependencies, config):
    # Factor 1: Algorithm hardcoded? (0-30 pts)
    # Factor 2: Config-driven crypto? (0-20 pts)
    # Factor 3: Crypto abstraction layer? (0-20 pts)
    # Factor 4: Algorithm negotiation? (0-15 pts)
    # Factor 5: Key management centralized? (0-20 pts)
    # Factor 6: PQC library available? (0-15 pts)
    # Total: 100 pts
```

### 3.2 Agility Factors

| Factor | Max Pts | Detection Method |
|--------|---------|------------------|
| 1. Algorithm Hardcoded | 30 | Evidence: `is_hardcoded_key`, config detection |
| 2. Config-Driven Crypto | 20 | Config parsers (TLS, SSH, IPsec, app config) |
| 3. Crypto Abstraction Layer | 20 | Source analysis (wrapper classes, interfaces) |
| 4. Algorithm Negotiation | 15 | TLS/SSH/IPsec config (negotiation enabled) |
| 5. Key Management Centralized | 20 | KMS/HSM usage, key metadata |
| 6. PQC Library Available | 15 | Library fingerprinting (PQC libraries) |

### 3.3 Agility Categories

| Score | Category | Migration Effort |
|-------|----------|------------------|
| 80-100 | HIGH | Ready now |
| 60-79 | MEDIUM | 2-4 weeks prep |
| 40-59 | LOW | Significant refactor |
| 0-39 | VERY LOW | Major rewrite needed |

---

## 4. MIGRATION READINESS (5-FACTOR)

### 4.1 Readiness Engine

**File:** `services/agility/agility/readiness.py:assess_readiness()`

```python
def assess_readiness(agility_score, dependency_count, has_crypto_tests, 
                     has_general_tests, team_capacity, change_freeze):
    # Factor 1: Agility (40%)
    # Factor 2: Dependencies (20%) — count → factor
    # Factor 3: Testing (20%) — crypto tests > general tests > none
    # Factor 4: Team Capacity (15%) — HIGH/MEDIUM/LOW
    # Factor 5: Change Freeze (5%) — boolean
```

### 4.2 Readiness Categories

| Score | Category | Recommendation | Wave | Effort (weeks) |
|-------|----------|----------------|------|----------------|
| ≥80 | READY_NOW | Start immediately | 1 | 0-1 |
| 60-79 | READY_WITH_PREP | 2-4 weeks prep | 2 | 2-4 |
| 40-59 | NOT_READY | 2-3 months work | 2 | 8-12 |
| <40 | BLOCKED | Resolve blockers first | 3 | 12-26 |

### 4.3 Blockers & Prep Checklist

**Blockers (auto-generated):**
- Change freeze active
- Agility < 40
- No crypto tests + agility < 60
- Dependencies > 10

**Prep Checklist (auto-generated):**
- Build crypto test suite
- Establish regression baseline
- Map/reduce dependencies
- Centralize crypto abstraction
- Secure dedicated engineering capacity
- Schedule after freeze lifts

---

## 5. MIGRATION WAVES (GRAPH-CONSTRAINED)

### 5.1 Wave Assignment

**File:** `services/api/api/routers/graph.py:graph_migration_waves()`

```python
# 1. Base wave from readiness (MaturityRepository)
# 2. Cycle constraint: SCC members get max(wave) of group
# 3. Import constraint: IMPORTS edges order dependent after provider
# 3. Code-only systems: from cascade_run (cryptoscan-systems.yml)
```

### 5.2 Wave Constraints

| Constraint | Implementation |
|------------|----------------|
| **Readiness** | Base wave from readiness_category |
| **Cycles (SCC)** | `merge_cycle_constraints()` — max wave in SCC |
| **Imports** | `apply_import_constraints()` — IMPORTS edges order dependent after provider |
| **Code-only systems** | Cascade `earliest_wave` from scanner |

### 5.3 Wave Output

```json
{
  "systems": [{
    "system_id": "sys-123",
    "name": "Payment API",
    "wave": 2,
    "readiness_category": "READY_WITH_PREP",
    "readiness_score": 65,
    "agility_score": 55,
    "rationale": "readiness 65/100; code: 3 crypto providers, cascade wave 2",
    "code_cascade": {"providers": 3, "weak_parameters": 1, "earliest_wave": 2}
  }],
  "unscored_systems": 5,
  "code_only_systems": 2
}
```

---

## 5. REMEDIATION RULES

### 5.1 Deterministic Rules (15 Rules)

**File:** `services/remediation/remediation/engine.py`

| Priority | Rule | Match | Replace With | Category | Effort |
|----------|------|-------|--------------|----------|--------|
| P0 | replace-des | DES | AES-256-GCM | CLASSICALLY_BROKEN | low |
| P0 | replace-3des | 3DES | AES-256-GCM | CLASSICALLY_BROKEN | low |
| P0 | replace-rc4 | RC4 | ChaCha20-Poly1305 | CLASSICALLY_BROKEN | low |
| P0 | replace-md5 | MD5 | SHA-256 | CLASSICALLY_BROKEN | low |
| P0 | replace-sslv3 | SSLv3 | TLS 1.3 | CLASSICALLY_BROKEN | medium |
| P1 | replace-sha1 | SHA-1 | SHA-256 | DEPRECATED | low |
| P1 | replace-tls10 | TLS 1.0 | TLS 1.3 | PROTOCOL_VERSION | medium |
| P1 | replace-tls11 | TLS 1.1 | TLS 1.3 | PROTOCOL_VERSION | medium |
| P1 | fix-ecb-mode | ECB mode | AES-256-GCM | WEAK_MODE | low |
| P2 | plan-rsa-pqc | RSA | ML-KEM-768/ML-DSA-65 | PQC_TRANSITION | high |
| P2 | plan-dsa-pqc | DSA | ML-DSA-65 | PQC_TRANSITION | high |
| P2 | plan-ecc-pqc | ECDH/ECDSA/Ed25519/X25519 | ML-KEM-768/ML-DSA-65 | PQC_TRANSITION | high |
| P2 | plan-dh-pqc | DH | ML-KEM-768 | PQC_TRANSITION | high |
| P3 | resize-aes128 | AES-128 | AES-256 | QUANTUM_MARGINAL | low |

### 5.2 Special Rules

| Rule | Trigger | Action |
|------|---------|--------|
| Hardcoded Key | `is_hardcoded_key=True` | P0: Remove key, use KMS/HSM |
| PQC Algorithm | Algorithm starts with ML-/KYBER/DILITHIUM | None (already PQC) |
| Manual Review | Policy FAIL but no rule matches | P3: Manual review |

### 5.3 Remediation Output

```json
{
  "count": 15,
  "suggestions": [{
    "evidence_id": "uuid...",
    "algorithm": "RSA",
    "purpose": "key_exchange",
    "file_path": "src/CryptoUtil.java",
    "line_number": 42,
    "replace_with": "ML-KEM-768 / ML-DSA-65",
    "guidance": "Plan hybrid RSA+PQC migration...",
    "effort": "high",
    "label": "DETERMINISTIC SUGGESTION - NOT COMPLIANCE DETERMINATION",
    "rule": "plan-rsa-pqc",
    "category": "PQC_TRANSITION",
    "priority": "P2"
  }],
  "rule_counts": {"plan-rsa-pqc": 5, "fix-ecb-mode": 3},
  "by_priority": {"P0": 2, "P1": 4, "P2": 8, "P3": 1},
  "backlog": { /* grouped by system, effort estimates */ }
}
```

**Disclaimer:** "DETERMINISTIC SUGGESTION - NOT COMPLIANCE DETERMINATION"

---

## 6. WHAT-IF SIMULATION

### 6.1 Simulation Engine

**File:** `services/universal_crypto/universal_crypto/simulator.py:MigrationSimulator.simulate()`

```python
def simulate(asset_id, current_algorithm, target_algorithm, 
             protocol, library, hardware, usage, current_agility):
    # Projects impact of algorithm migration on:
    # - Readiness score
    # - Quantum risk score
    # - Agility score
    # - Risk score
    # - Migration effort
```

### 6.2 Simulation Inputs

| Parameter | Description |
|-----------|-------------|
| `current_algorithm` | Current algorithm (e.g., "RSA-2048") |
| `target_algorithm` | Target PQC algorithm (e.g., "ML-KEM-768") |
| `protocol` | TLS, SSH, IPsec, etc. |
| `library` | Library name (OpenSSL, BoringSSL, etc.) |
| `hardware` | Hardware acceleration (AES-NI, QAT, HSM) |
| `usage` | Boolean — actively used |
| `current_agility` | Current agility score (0-100) |

### 6.2 Simulation Output

```json
{
  "asset_id": "asset-123",
  "current_algorithm": "RSA-2048",
  "target_algorithm": "ML-KEM-768",
  "projected": {
    "readiness_score": 85,
    "quantum_risk_score": 10,
    "agility_score": 75,
    "risk_score": 15
  },
  "current": {
    "readiness_score": 45,
    "quantum_risk_score": 85,
    "agility_score": 55,
    "risk_score": 75
  },
  "migration_effort": {
    "code_changes": 12,
    "config_changes": 3,
    "test_updates": 8,
    "estimated_weeks": 6
  },
  "compatibility_issues": [
    "TLS 1.2 requires hybrid KEM for RSA→ML-KEM transition",
    "Library OpenSSL 3.0+ required for ML-KEM"
  ],
  "hardware_requirements": [
    "HSM firmware update for ML-KEM support",
    "CPU with AES-NI for hybrid performance"
  ]
}
```

**Gap:** Simulation is projection only — no execution engine.

---

## 7. MIGRATION PLANNING INTEGRATION

### 7.1 Graph → Migration Plan

**Endpoint:** `POST /api/v1/graph/migration-plan`

```python
# 1. Blast radius from node (graph.blast_radius)
# 2. Collect affected QV CryptoAssets (USES edges)
# 3. Create MigrationProject in IntelligenceRepository
# 4. Create MigrationTask per affected asset
# 5. Return project_id, tasks_created, affected assets
```

**File:** `services/api/api/routers/graph.py:graph_migration_plan()`

```python
# Creates:
# - MigrationProject (name, system_id, algorithm_from, algorithm_to, status=PLANNED)
# - MigrationTask per asset (title, system_id, asset_id, algorithm_from/to, priority, source=AUTO)
```

**Output:**
```json
{
  "created": true,
  "project_id": "uuid...",
  "project_name": "PQC migration — migrate_pqc from asset-123",
  "tasks_created": 15,
  "affected": [{
    "asset_id": "asset-456",
    "algorithm_from": "RSA-2048",
    "system_id": "sys-123",
    "confidence": "HIGH",
    "file": "src/CryptoUtil.java"
  }]
}
```

---

## 8. PQC ALGORITHM DETECTION

### 8.1 Registry Coverage

| PQC Algorithm | Registry Entry | Detection |
|---------------|----------------|-----------|
| ML-KEM-512/768/1024 | ✅ | Source: ✅ Binary: ❓ |
| ML-DSA-44/65/87 | ✅ | Source: ✅ Binary: ❓ |
| SLH-DSA-SHA2-128/192/256 | ✅ | Source: ✅ Binary: ❓ |
| Kyber-512/768/1024 | ✅ (aliases) | Source: ✅ Binary: ❓ |
| Dilithium-2/3/5 | ✅ (aliases) | Source: ✅ Binary: ❓ |
| SPHINCS+-SHA2-128/192/256 | ✅ | Source: ✅ Binary: ❓ |
| FALCON-512/1024 | ✅ | Source: ❓ Binary: ❓ |
| HQC | ✅ | Source: ❓ Binary: ❓ |

**Gap:** Binary detection of PQC algorithms untested.

---

### 8.2 PQC Protocol Detection — MISSING

| Protocol | PQC Support | Status |
|----------|-------------|--------|
| TLS 1.3 + PQC | Hybrid KEM (X25519+ML-KEM) | ❌ Not detected |
| TLS 1.3 + PQC | Pure ML-KEM | ❌ Not detected |
| SSH PQC | Hybrid KEX (sntrup761x25519-sha512) | ❌ Not detected |
| IPsec/IKEv2 PQC | Hybrid IKEv2 | ❌ Not detected |
| QUIC PQC | Hybrid KEM | ❌ Not detected |

**Gap:** No PQC cipher suite detection in protocol parsers.

---

## 9. PQC MIGRATION EXECUTION — MISSING

### 9.1 Missing Execution Capabilities

| Capability | Status |
|------------|--------|
| Automated code refactoring | ❌ |
| Config migration | ❌ |
| Library upgrade orchestration | ❌ |
| HSM firmware update coordination | ❌ |
| Certificate re-issuance | ❌ |
| Key rotation orchestration | ❌ |
| Testing/validation pipeline | ❌ |
| Rollback capability | ❌ |
| Canary deployment | ❌ |

### 9.2 Migration Project Tracking

**Model:** `services/database/db/models/migration_project.py`

```python
class MigrationProject(BaseModel, TenantScoped):
    name: str
    system_id: str
    algorithm_from: str
    algorithm_to: str
    status: str  # PLANNED, IN_PROGRESS, COMPLETED, BLOCKED, FAILED
    owner: str
    progress: int  # 0-100
    started_at, completed_at: DateTime
```

**Tasks:** `services/database/db/repositories/migration_task_repository.py`

```python
class MigrationTask:
    project_id, title, system_id, asset_id
    algorithm_from, algorithm_to
    priority, status, source (AUTO/MANUAL)
    assigned_to, due_date
```

**Gap:** No execution engine — tasks are tracking only.

---

## 10. PQC READINESS REPORTING

### 10.1 API Endpoints

| Endpoint | Purpose |
|----------|---------|
| `GET /quantum/risk` | Quantum risk analysis for findings |
| `GET /pqc` | PQC readiness dashboard |
| `GET /pqc-map` | Visual PQC migration map |
| `GET /agility` | Agility scores |
| `GET /graph/migration-waves` | Migration waves |
| `POST /graph/migration-plan` | Create migration project |
| `POST /crypto/simulate` | What-if simulation |
| `POST /graph/migration-plan` | Create migration project from graph |

---

## 11. RECOMMENDATIONS

### P0 — Critical

1. **Implement PQC protocol detection** — TLS 1.3 hybrid KEM, SSH PQC, IPsec PQC
2. **Add binary PQC detection** — Test ML-KEM/ML-DSA/SLH-DSA in binaries
3. **Integrate drift → migration automation** — DriftEvent → MigrationTask

### P1 — High

3. **Build migration execution engine** — Code refactoring, config migration, library upgrade
4. **Add PQC cipher suite detection** — TLS 1.3 hybrid KEM, SSH PQC KEX
5. **Implement hybrid KEM detection** — X25519+ML-KEM, ECDHE+ML-KEM
6. **Add binary PQC detection validation** — Test corpus with PQC binaries

### P2 — Medium

4. **Add PQC certificate detection** — ML-DSA certs, SLH-DSA certs
4. **Implement migration execution engine** — Code refactoring, config migration
5. **Add PQC certificate detection** — ML-DSA/SLH-DSA in X.509
6. **Add migration testing pipeline** — Automated validation

### P3 — Enhancement

4. **Post-quantum SSH/IPsec detection** — Protocol upgrades
5. **CT log verification for PQC certs** — SCT validation
7. **Migration cost estimation** — Detailed effort breakdown
8. **Rollback capability** — Automated rollback on migration failure

---

## 12. VERIFICATION EVIDENCE

| Finding | File |
|---------|------|
| Quantum classification | `shared/shared_models/shared_models/quantum_classify.py` |
| Quantum risk scoring | `services/quantum/quantum/risk.py` |
| Agility scoring | `services/agility/agility/system_score.py` |
| Migration readiness | `services/agility/agility/readiness.py` |
| Migration waves | `services/api/api/routers/graph.py:graph_migration_waves()` |
| Remediation rules | `services/remediation/remediation/engine.py` |
| Simulator | `services/universal_crypto/universal_crypto/simulator.py` |
| Migration plan | `services/api/api/routers/graph.py:graph_migration_plan()` |
| Migration models | `services/database/db/models/migration_project.py` |
| Quantum risk API | `services/api/api/routers/quantum.py` |
| PQC API | `services/api/api/routers/crypto.py:/crypto/simulate` |
| Agility API | `services/api/api/routers/agility.py` |
| Graph migration plan | `services/api/api/routers/graph.py:graph_migration_plan()` |
---

## Round 26 update (2026-10-10) — PQC detection claims re-verified

* **P0#1/#4/#5 (PQC protocol + hybrid KEM detection) — STALE.** The
  scanner detects ML-KEM / ML-DSA / SLH-DSA / Kyber / Dilithium across
  Java (incl. JAR string scanning), .NET (assembly scanning), Go, C#,
  and config parsers; corpus wave 17 (`corpus_wave17_pqc.py`) pins the
  conventions — X25519MLKEM768 hybrids resolve to {MLKEM, X25519},
  liboqs calls map to concrete algorithms — across .NET 10, Go 1.24
  crypto/mlkem, Java 24 JEP 496/497, BouncyCastle and @noble/
  post-quantum. The network engine carries hybrid groups through
  enterprise tunnels/simulation/inventory.
* **P0#2 (binary PQC detection) — STALE.** `jar_string_scanner` and
  `assembly_scanner` (detectors) extract PQC algorithm identifiers from
  binary artifacts, validated by the same corpus.
* **P0#3 (drift → MigrationTask automation) — REMAINS OPEN,
  product-scoped** (the tracking models and repos exist; wiring event →
  task creation is an automation-policy decision, same item as deep/28
  P1#3).
* **§9 execution engine, PQC X.509 certificates, CT verification,
  cost estimation, rollback/canary — REMAIN OPEN, product-scoped**
  (execution engine is the standing product-level open item).
