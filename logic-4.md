# 🚀 CRYPTOSCAN PLATFORM — PART 4 (MONTHS 10-12)
## Maturity Phase: Crypto Agility + Quantum Risk + OT/ICS + Vendor Discovery + Advanced Analytics

---

## 📋 PART 4 OBJECTIVE

**Achieve operational maturity and future-readiness:**
- Build **crypto agility scoring** (how easy is it to change crypto?)
- Implement **quantum vulnerability deep analysis** (Shor's/Grover's impact, harvest-now-decrypt-later risk)
- Add **OT/ICS scanning** (SCADA, DCS, PLCs — operational technology crypto)
- Integrate **vendor crypto discovery** (IDEA2-style — what crypto do your vendors use?)
- Build **advanced analytics dashboard** (trends, forecasting, heat maps)
- Implement **exception management** (policy exceptions with approval workflow)
- Add **migration readiness assessment** (which systems can migrate now vs later?)

**NOT in scope for Part 4:**
- ❌ Automated migration execution (Part 5)
- ❌ CI/CD policy enforcement gates (Part 5)
- ❌ AI-powered recommendations (deferred indefinitely per requirements)

---

# 🗺️ MONTH 10: CRYPTO AGILITY SCORING + QUANTUM RISK ANALYSIS

---

## WEEK 37-38: CRYPTO AGILITY SCORING ENGINE

### 🎯 Goal
Score how "agile" each system is (can it adapt to new crypto requirements?)

### 📐 Architecture — Crypto Agility Scoring v1.0

```
┌─────────────────────────────────────────────────────────────┐
│           CRYPTO AGILITY SCORING ENGINE v1.0                │
│           (Deterministic Assessment Framework)              │
└─────────────────────────────────────────────────────────────┘

WHAT IS CRYPTO AGILITY:
  → Ability to quickly change cryptographic algorithms/keys
  → WITHOUT requiring code changes, recompilation, or downtime
  → Critical for: quantum migration, vulnerability response, compliance

AGILITY FACTORS (6 Categories):

┌──────────────────────────────────────────────────────────────┐
│ FACTOR 1: ALGORITHM CONFIGURABILITY                         │
│ (Is crypto configurable or hardcoded?)                      │
│                                                              │
│ SCORING:                                                     │
│   +30 points: Algorithm specified in external config        │
│              (config file, environment var, database)        │
│   +20 points: Algorithm in code but centralized             │
│              (single constant/enum, not scattered)           │
│   +10 points: Algorithm in code but parameterized           │
│              (function parameter, not hardcoded)             │
│    0 points: Algorithm hardcoded in multiple places         │
│   -20 points: Algorithm hardcoded AND obfuscated            │
│                                                              │
│ DETECTION METHOD:                                            │
│   FROM STATIC SCAN EVIDENCE:                                 │
│     evidence.source.file_path analysis:                     │
│       IF file_path matches config pattern:                  │
│         (*.yaml, *.properties, *.env, application.conf)     │
│         → +30 points                                         │
│                                                              │
│       IF file_path is constants/config class:               │
│         (CryptoConfig.java, constants.py, config.ts)        │
│         AND only ONE occurrence of algorithm:               │
│         → +20 points                                         │
│                                                              │
│       IF algorithm passed as parameter:                     │
│         (function signature contains "algorithm" param)     │
│         → +10 points                                         │
│                                                              │
│       IF algorithm is string literal in business logic:     │
│         → 0 points                                           │
│                                                              │
│   COUNT occurrences:                                         │
│     occurrences = COUNT(evidence_records                    │
│                         WHERE algorithm = X                 │
│                         AND system_id = Y)                  │
│     IF occurrences > 5:                                     │
│       → -10 points (scattered, hard to change)              │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ FACTOR 2: KEY MANAGEMENT ARCHITECTURE                       │
│ (How are keys managed?)                                      │
│                                                              │
│ SCORING:                                                     │
│   +30 points: Centralized KMS (AWS KMS, Azure Key Vault)    │
│   +25 points: HSM-backed key storage                        │
│   +20 points: HashiCorp Vault / enterprise secret manager   │
│   +15 points: OS keychain / credential manager              │
│   +10 points: Encrypted config file (key wrapped)           │
│    0 points: Keys in environment variables (plain)          │
│   -30 points: Keys hardcoded in source code                 │
│   -50 points: Keys committed to Git history                 │
│                                                              │
│ DETECTION METHOD:                                            │
│   FROM CLOUD SCAN:                                           │
│     IF system uses AWS KMS / Azure KeyVault:                │
│       cloud_findings WHERE resource_type = "KMS_KEY"        │
│       → +30 points                                           │
│                                                              │
│   FROM STATIC SCAN:                                          │
│     IF evidence.is_hardcoded_key = true:                    │
│       → -30 points                                           │
│                                                              │
│     IF code imports "HashiCorp Vault SDK":                  │
│       → +20 points                                           │
│                                                              │
│   FROM GIT HISTORY SCAN (optional — advanced):              │
│     git log --all -p | grep -i "password\|secret\|key"     │
│     IF secrets found in commit history:                     │
│       → -50 points (must rotate ALL keys!)                  │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ FACTOR 3: ABSTRACTION LAYER PRESENCE                        │
│ (Is there a crypto abstraction/wrapper?)                    │
│                                                              │
│ SCORING:                                                     │
│   +25 points: Custom crypto abstraction layer               │
│              (CryptoService, EncryptionManager class)        │
│   +20 points: Standard crypto library wrapper               │
│              (Apache Commons Crypto, Spring Security)        │
│   +10 points: Consistent library usage (single library)     │
│    0 points: Multiple crypto libraries mixed                │
│   -10 points: Direct crypto API calls scattered             │
│                                                              │
│ DETECTION METHOD:                                            │
│   ANALYZE CODE STRUCTURE:                                    │
│     crypto_calls = evidence_records for system              │
│     libraries = DISTINCT(evidence.crypto.library)           │
│                                                              │
│     IF COUNT(libraries) == 1:                               │
│       → +10 points (consistent)                             │
│     IF COUNT(libraries) > 3:                                │
│       → -10 points (fragmented)                             │
│                                                              │
│   LOOK FOR WRAPPER PATTERNS:                                │
│     IF class name matches:                                  │
│       (CryptoService, EncryptionUtil, CipherManager,        │
│        SecurityHelper, CryptoFacade)                        │
│       AND >50% of crypto calls go through this class:      │
│       → +25 points                                           │
│                                                              │
│   CHECK FOR STANDARD FRAMEWORKS:                            │
│     IF imports contain:                                      │
│       "org.apache.commons.crypto"                           │
│       "org.springframework.security.crypto"                 │
│       "cryptography.fernet" (Python high-level)             │
│       → +20 points                                           │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ FACTOR 4: DEPLOYMENT ARCHITECTURE                           │
│ (Can crypto be changed without redeployment?)               │
│                                                              │
│ SCORING:                                                     │
│   +25 points: Config hot-reload supported                   │
│              (app can reload config without restart)         │
│   +20 points: Containerized with external config            │
│              (ConfigMap/Secret in K8s)                       │
│   +15 points: Config externalized (12-factor app)           │
│   +10 points: Blue/green deployment capable                 │
│    0 points: Requires app restart for config change         │
│   -10 points: Requires rebuild/recompile                    │
│   -20 points: Statically linked binary (no config)          │
│                                                              │
│ DETECTION METHOD:                                            │
│   FROM SYSTEM METADATA:                                      │
│     IF system.deployment_type = "KUBERNETES":               │
│       AND exists ConfigMap/Secret for crypto config:        │
│       → +20 points                                           │
│                                                              │
│   FROM SOURCE SCAN:                                          │
│     IF code contains config reload logic:                   │
│       (signal handler, file watcher, periodic reload)       │
│       → +25 points                                           │
│                                                              │
│   FROM CONTAINER SCAN:                                       │
│     IF Dockerfile contains COPY crypto config:              │
│       → -10 points (baked into image)                       │
│     IF Dockerfile expects volume mount for config:          │
│       → +15 points (externalized)                           │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ FACTOR 5: TESTING & VALIDATION                              │
│ (Can crypto changes be tested safely?)                      │
│                                                              │
│ SCORING:                                                     │
│   +20 points: Automated crypto test suite exists            │
│   +15 points: Parameterized tests (test multiple algos)     │
│   +10 points: Integration tests cover crypto               │
│    0 points: No crypto-specific tests                       │
│   -10 points: No test coverage at all                       │
│                                                              │
│ DETECTION METHOD:                                            │
│   FROM SOURCE REPO SCAN:                                     │
│     search for test files:                                   │
│       (*Test.java, *_test.py, *.test.js, *_spec.rb)        │
│     IF test files contain crypto keywords:                  │
│       ("encrypt", "decrypt", "cipher", "crypto", "AES")     │
│       → +20 points                                           │
│                                                              │
│     IF test files use parameterized test framework:         │
│       (@ParameterizedTest, @pytest.mark.parametrize)        │
│       AND test multiple algorithms:                         │
│       → +15 points                                           │
│                                                              │
│   FROM CODE COVERAGE DATA (if available):                   │
│     IF crypto modules have >80% test coverage:              │
│       → +10 points bonus                                     │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ FACTOR 6: DOCUMENTATION & GOVERNANCE                        │
│ (Is crypto change process documented?)                      │
│                                                              │
│ SCORING:                                                     │
│   +15 points: Crypto change procedure documented            │
│   +10 points: Crypto inventory documented                   │
│   +10 points: Disaster recovery plan includes crypto        │
│    0 points: No documentation                                │
│                                                              │
│ DETECTION METHOD:                                            │
│   FROM REPO SCAN:                                            │
│     search documentation files:                              │
│       (README.md, SECURITY.md, docs/, wiki/)                │
│     IF contains crypto change procedure:                    │
│       ("crypto migration", "algorithm rotation",            │
│        "key rotation procedure")                            │
│       → +15 points                                           │
│                                                              │
│   FROM MANUAL INPUT:                                         │
│     system.metadata.has_crypto_docs = true/false            │
│     system.metadata.has_dr_plan = true/false                │
└──────────────────────────────────────────────────────────────┘

AGILITY SCORE CALCULATION:

┌──────────────────────────────────────────────────────────────┐
│ FINAL AGILITY SCORE                                          │
│                                                              │
│ raw_score = (                                                │
│   factor1_score +  # Algorithm configurability (max 30)     │
│   factor2_score +  # Key management (max 30)                │
│   factor3_score +  # Abstraction layer (max 25)             │
│   factor4_score +  # Deployment architecture (max 25)       │
│   factor5_score +  # Testing (max 20)                       │
│   factor6_score    # Documentation (max 15)                 │
│ )                                                            │
│                                                              │
│ max_possible = 145                                           │
│ min_possible = -80 (pathological case)                      │
│                                                              │
│ # Normalize to 0-100 scale                                   │
│ IF raw_score < 0:                                            │
│   normalized_score = 0                                       │
│ ELSE:                                                        │
│   normalized_score = (raw_score / max_possible) * 100       │
│                                                              │
│ # Apply ceiling                                              │
│ agility_score = MIN(normalized_score, 100)                  │
│                                                              │
│ # Categorization                                             │
│ IF agility_score >= 80:                                      │
│   category = "EXCELLENT" 🟢                                  │
│   description = "Highly agile. Crypto changes are safe,     │
│                  fast, and low-risk."                        │
│                                                              │
│ ELSE IF agility_score >= 60:                                │
│   category = "GOOD" 🟡                                       │
│   description = "Agile with minor friction. Some manual     │
│                  steps required."                            │
│                                                              │
│ ELSE IF agility_score >= 40:                                │
│   category = "MODERATE" 🟠                                   │
│   description = "Limited agility. Crypto changes require    │
│                  significant effort."                        │
│                                                              │
│ ELSE IF agility_score >= 20:                                │
│   category = "POOR" 🔴                                       │
│   description = "Low agility. Crypto changes are high-risk  │
│                  and time-consuming."                        │
│                                                              │
│ ELSE:                                                        │
│   category = "CRITICAL" ⛔                                   │
│   description = "Crypto is hardcoded and scattered.         │
│                  Migration extremely difficult."             │
└──────────────────────────────────────────────────────────────┘

DATABASE SCHEMA:

┌──────────────────────────────────────────────────────────────┐
│ TABLE: system_agility_scores                                │
│                                                              │
│ score_id              UUID PK                                │
│ system_id             UUID FK → systems                     │
│ agility_score         INT       0-100                        │
│ category              VARCHAR(20)  EXCELLENT, GOOD, etc     │
│ factor_scores         JSONB     {factor1: 25, factor2: 30...}│
│ recommendations       JSONB[]   Improvement suggestions      │
│ calculated_at         TIMESTAMP                              │
│ calculation_version   VARCHAR(20)  "agility-v1.0"           │
│                                                              │
│ # Store historical scores for trending                      │
│ created_at            TIMESTAMP                              │
└──────────────────────────────────────────────────────────────┘

ALTER TABLE systems ADD COLUMN current_agility_score INT;
ALTER TABLE systems ADD COLUMN agility_category VARCHAR(20);

CREATE INDEX idx_agility_score ON systems(current_agility_score DESC);

SCORING ALGORITHM (FULL):

┌──────────────────────────────────────────────────────────────┐
│ FUNCTION calculate_agility_score(system_id):                │
│                                                              │
│   # Gather all evidence for this system                     │
│   evidence = SELECT * FROM evidence_records                 │
│              JOIN asset_evidence_links USING (evidence_id)  │
│              JOIN crypto_assets USING (asset_id)            │
│              WHERE system_id = system_id;                   │
│                                                              │
│   system = SELECT * FROM systems WHERE system_id = ...;     │
│                                                              │
│   # Factor 1: Algorithm configurability                     │
│   factor1 = score_algorithm_configurability(evidence, system)│
│                                                              │
│   # Factor 2: Key management                                │
│   factor2 = score_key_management(evidence, system)          │
│                                                              │
│   # Factor 3: Abstraction layer                             │
│   factor3 = score_abstraction_layer(evidence, system)       │
│                                                              │
│   # Factor 4: Deployment architecture                       │
│   factor4 = score_deployment_architecture(system)           │
│                                                              │
│   # Factor 5: Testing                                        │
│   factor5 = score_testing(system)                           │
│                                                              │
│   # Factor 6: Documentation                                 │
│   factor6 = score_documentation(system)                     │
│                                                              │
│   raw_score = factor1 + factor2 + factor3 + factor4 +       │
│                factor5 + factor6                             │
│                                                              │
│   agility_score = normalize_score(raw_score, max=145)       │
│   category = categorize_score(agility_score)                │
│                                                              │
│   # Generate recommendations                                 │
│   recommendations = []                                       │
│   IF factor1 < 15:                                           │
│     recommendations.append({                                 │
│       factor: "Algorithm Configurability",                  │
│       issue: "Algorithms are hardcoded",                    │
│       recommendation: "Move algorithm selection to config file",│
│       effort: "MEDIUM",                                      │
│       impact: "+20 agility points"                          │
│     })                                                       │
│                                                              │
│   IF factor2 < 0:                                            │
│     recommendations.append({                                 │
│       factor: "Key Management",                             │
│       issue: "Hardcoded keys detected",                     │
│       recommendation: "Migrate to AWS KMS or HashiCorp Vault",│
│       effort: "HIGH",                                        │
│       impact: "+30 agility points",                         │
│       urgency: "CRITICAL"                                    │
│     })                                                       │
│                                                              │
│   IF factor4 < 10:                                           │
│     recommendations.append({                                 │
│       factor: "Deployment Architecture",                    │
│       issue: "Crypto config baked into container image",    │
│       recommendation: "Use Kubernetes ConfigMaps/Secrets",  │
│       effort: "LOW",                                         │
│       impact: "+15 agility points"                          │
│     })                                                       │
│                                                              │
│   # Store result                                             │
│   INSERT INTO system_agility_scores (                        │
│     system_id, agility_score, category,                     │
│     factor_scores, recommendations,                          │
│     calculated_at, calculation_version                      │
│   ) VALUES (                                                 │
│     system_id, agility_score, category,                     │
│     {factor1, factor2, factor3, factor4, factor5, factor6}, │
│     recommendations,                                         │
│     NOW(), "agility-v1.0"                                    │
│   );                                                         │
│                                                              │
│   UPDATE systems                                             │
│   SET current_agility_score = agility_score,                │
│       agility_category = category                           │
│   WHERE system_id = system_id;                              │
│                                                              │
│   RETURN agility_score;                                      │
└──────────────────────────────────────────────────────────────┘

DASHBOARD VIEW:

┌──────────────────────────────────────────────────────────────┐
│ CRYPTO AGILITY DASHBOARD                                     │
│                                                              │
│ ┌────────────────────────────────────────────────────────┐  │
│ │  ORGANIZATION AGILITY OVERVIEW                         │  │
│ ├────────────────────────────────────────────────────────┤  │
│ │                                                        │  │
│ │  Average Agility Score: 58/100 🟡 MODERATE            │  │
│ │                                                        │  │
│ │  Distribution:                                         │  │
│ │  🟢 EXCELLENT (80-100):  12 systems (8%)              │  │
│ │  🟡 GOOD (60-79):        47 systems (32%)             │  │
│ │  🟠 MODERATE (40-59):    68 systems (46%)             │  │
│ │  🔴 POOR (20-39):        18 systems (12%)             │  │
│ │  ⛔ CRITICAL (0-19):      3 systems (2%)              │  │
│ │                                                        │  │
│ │  [View Critical Systems] [View Recommendations]       │  │
│ └────────────────────────────────────────────────────────┘  │
│                                                              │
│ ┌────────────────────────────────────────────────────────┐  │
│ │  SYSTEMS RANKED BY AGILITY (Lowest First)             │  │
│ ├────────────────────────────────────────────────────────┤  │
│ │ System          │ Score │ Category │ Top Issue        │  │
│ ├─────────────────┼───────┼──────────┼──────────────────┤  │
│ │ legacy-payment  │  12   │ CRITICAL │ Hardcoded keys   │  │
│ │ old-auth-svc    │  18   │ CRITICAL │ No abstraction   │  │
│ │ file-processor  │  22   │ POOR     │ Static binary    │  │
│ │ api-gateway-v1  │  35   │ POOR     │ Scattered crypto │  │
│ │ ...                                                    │  │
│ └────────────────────────────────────────────────────────┘  │
│                                                              │
│ ┌────────────────────────────────────────────────────────┐  │
│ │  SYSTEM DETAIL: legacy-payment                         │  │
│ ├────────────────────────────────────────────────────────┤  │
│ │  Agility Score: 12/100 ⛔ CRITICAL                     │  │
│ │                                                        │  │
│ │  Factor Breakdown:                                     │  │
│ │  • Algorithm Configurability:  -10  (hardcoded)       │  │
│ │  • Key Management:             -30  (keys in code!)   │  │
│ │  • Abstraction Layer:            0  (direct API calls)│  │
│ │  • Deployment Architecture:     10  (containerized)   │  │
│ │  • Testing:                      0  (no tests)        │  │
│ │  • Documentation:                0  (none)            │  │
│ │                                                        │  │
│ │  RECOMMENDATIONS (4):                                  │  │
│ │                                                        │  │
│ │  1. 🔴 CRITICAL: Remove hardcoded keys                │  │
│ │     Effort: HIGH | Impact: +30 points                 │  │
│ │     Action: Migrate to AWS KMS                        │  │
│ │     Owner: Security team                               │  │
│ │     Deadline: IMMEDIATE (compliance violation)        │  │
│ │                                                        │  │
│ │  2. 🟠 HIGH: Externalize algorithm config             │  │
│ │     Effort: MEDIUM | Impact: +20 points               │  │
│ │     Action: Move to config file                       │  │
│ │     Owner: Development team                           │  │
│ │                                                        │  │
│ │  3. 🟡 MEDIUM: Add crypto abstraction layer           │  │
│ │     Effort: HIGH | Impact: +25 points                 │  │
│ │     Action: Create CryptoService wrapper              │  │
│ │                                                        │  │
│ │  4. 🟢 LOW: Add crypto test suite                     │  │
│ │     Effort: MEDIUM | Impact: +15 points               │  │
│ │                                                        │  │
│ │  ESTIMATED FINAL SCORE IF ALL FIXED: 82/100 🟢        │  │
│ └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

### ✅ Week 37-38 Deliverable

**Crypto agility scoring system:**
1. 6-factor agility assessment framework
2. Automated scoring algorithm (deterministic)
3. `system_agility_scores` table (historical tracking)
4. Agility dashboard (org-wide view + per-system detail)
5. Improvement recommendations (prioritized by impact)
6. Agility trending (track score changes over time)

**Testing:**
- Score 10 test systems (mix of modern microservices + legacy)
- Modern microservice: score = 85 (EXCELLENT) — K8s, externalized config, KMS
- Legacy monolith: score = 15 (CRITICAL) — hardcoded keys, no tests
- Dashboard shows: Org avg = 58 (MODERATE)
- View legacy system → see 4 recommendations
- Implement recommendation #1 (migrate to KMS) → rescore → score increases to 45

---

## WEEK 39-40: QUANTUM VULNERABILITY DEEP ANALYSIS

### 🎯 Goal
Detailed quantum risk assessment (beyond simple "RSA = vulnerable")

### 📐 Architecture — Quantum Risk Engine v2.0

```
┌─────────────────────────────────────────────────────────────┐
│         QUANTUM VULNERABILITY ANALYSIS ENGINE v2.0          │
│         (NIST PQC Standards + Academic Research)            │
└─────────────────────────────────────────────────────────────┘

QUANTUM THREAT MODEL:

┌──────────────────────────────────────────────────────────────┐
│ QUANTUM ALGORITHMS & IMPACT                                  │
│                                                              │
│ 1. SHOR'S ALGORITHM                                          │
│    Impact: Breaks RSA, ECDH, ECDSA, DH                     │
│    Type: Polynomial time factorization                      │
│    Result: COMPLETE BREAK of asymmetric crypto              │
│                                                              │
│ 2. GROVER'S ALGORITHM                                        │
│    Impact: Weakens symmetric crypto & hash functions        │
│    Type: Quadratic speedup for brute force                  │
│    Result: EFFECTIVE KEY LENGTH HALVED                      │
│    Example: AES-256 → 128-bit security against quantum      │
│                                                              │
│ 3. HARVEST NOW, DECRYPT LATER (HNDL)                        │
│    Threat: Adversary captures encrypted data TODAY          │
│    Goal: Decrypt LATER with quantum computer                │
│    Risk: Long-lived secrets (25+ year sensitivity)          │
└──────────────────────────────────────────────────────────────┘

QUANTUM VULNERABILITY ASSESSMENT:

┌──────────────────────────────────────────────────────────────┐
│ ALGORITHM QUANTUM VULNERABILITY TABLE                        │
│                                                              │
│ Algorithm    │ Quantum Threat │ Shor Impact │ Grover Impact │
│ ─────────────┼────────────────┼─────────────┼───────────────┤
│ RSA          │ CRITICAL       │ TOTAL BREAK │ N/A           │
│ ECDH         │ CRITICAL       │ TOTAL BREAK │ N/A           │
│ ECDSA        │ CRITICAL       │ TOTAL BREAK │ N/A           │
│ DH           │ CRITICAL       │ TOTAL BREAK │ N/A           │
│ DSA          │ CRITICAL       │ TOTAL BREAK │ N/A           │
│              │                │             │               │
│ AES-128      │ MODERATE       │ N/A         │ 64-bit sec    │
│ AES-192      │ LOW            │ N/A         │ 96-bit sec    │
│ AES-256      │ MINIMAL        │ N/A         │ 128-bit sec   │
│ ChaCha20     │ MINIMAL        │ N/A         │ 128-bit sec   │
│              │                │             │               │
│ SHA-256      │ MODERATE       │ N/A         │ 128-bit coll  │
│ SHA-384      │ LOW            │ N/A         │ 192-bit coll  │
│ SHA-512      │ MINIMAL        │ N/A         │ 256-bit coll  │
│              │                │             │               │
│ ML-KEM       │ RESISTANT      │ SAFE        │ SAFE          │
│ ML-DSA       │ RESISTANT      │ SAFE        │ SAFE          │
│ SLH-DSA      │ RESISTANT      │ SAFE        │ SAFE          │
└──────────────────────────────────────────────────────────────┘

QUANTUM RISK SCORING:

┌──────────────────────────────────────────────────────────────┐
│ QUANTUM RISK SCORE CALCULATION                               │
│                                                              │
│ FOR EACH crypto_asset:                                       │
│                                                              │
│   # Step 1: Base vulnerability score                        │
│   IF algorithm IN ["RSA", "ECDH", "ECDSA", "DH", "DSA"]:   │
│     base_vulnerability = 100  # Totally broken              │
│     threat_type = "SHOR_VULNERABLE"                         │
│                                                              │
│   ELSE IF algorithm == "AES" AND key_size == 128:           │
│     base_vulnerability = 50   # Weakened to 64-bit          │
│     threat_type = "GROVER_WEAKENED"                         │
│                                                              │
│   ELSE IF algorithm == "AES" AND key_size == 256:           │
│     base_vulnerability = 10   # Still 128-bit secure        │
│     threat_type = "GROVER_MINIMAL"                          │
│                                                              │
│   ELSE IF algorithm IN ["ML-KEM", "ML-DSA", "SLH-DSA"]:    │
│     base_vulnerability = 0    # Post-quantum safe           │
│     threat_type = "PQC_RESISTANT"                           │
│                                                              │
│   ELSE:                                                      │
│     base_vulnerability = 75   # Unknown, assume vulnerable  │
│     threat_type = "UNKNOWN"                                 │
│                                                              │
│   # Step 2: Data sensitivity modifier                       │
│   data_sensitivity_multiplier = 1.0                         │
│   IF system.data_classifications CONTAINS "PAN":            │
│     data_sensitivity_multiplier = 1.5  # Payment data       │
│   IF system.data_classifications CONTAINS "PHI":            │
│     data_sensitivity_multiplier = 1.5  # Health data        │
│   IF system.data_classifications CONTAINS "CLASSIFIED":     │
│     data_sensitivity_multiplier = 2.0  # Government secrets │
│                                                              │
│   # Step 3: Data retention modifier (HNDL risk)             │
│   # Longer retention = higher HNDL risk                     │
│   IF asset.purpose == "ENCRYPTION":                         │
│     data_retention_years = system.metadata.data_retention_years│
│     IF data_retention_years >= 25:                          │
│       hndl_multiplier = 1.5  # High HNDL risk               │
│     ELSE IF data_retention_years >= 10:                     │
│       hndl_multiplier = 1.2  # Moderate HNDL risk           │
│     ELSE:                                                    │
│       hndl_multiplier = 1.0  # Low HNDL risk                │
│   ELSE:                                                      │
│     hndl_multiplier = 1.0  # Not encryption, no HNDL risk   │
│                                                              │
│   # Step 4: Timeline to quantum threat                      │
│   # Based on NIST/NSA estimates                             │
│   current_year = 2024                                        │
│   quantum_threat_year_estimate = 2030  # Conservative       │
│   years_until_threat = quantum_threat_year_estimate - current_year│
│                                                              │
│   IF years_until_threat <= 2:                               │
│     timeline_multiplier = 2.0  # Imminent threat            │
│   ELSE IF years_until_threat <= 5:                          │
│     timeline_multiplier = 1.5  # Near-term threat           │
│   ELSE IF years_until_threat <= 10:                         │
│     timeline_multiplier = 1.2  # Medium-term threat         │
│   ELSE:                                                      │
│     timeline_multiplier = 1.0  # Long-term threat           │
│                                                              │
│   # Step 5: System criticality modifier                     │
│   IF system.criticality_tier == "TIER-1":                   │
│     criticality_multiplier = 1.5                            │
│   ELSE IF system.criticality_tier == "TIER-2":              │
│     criticality_multiplier = 1.2                            │
│   ELSE:                                                      │
│     criticality_multiplier = 1.0                            │
│                                                              │
│   # Final quantum risk score (0-100)                        │
│   quantum_risk_score = MIN(                                 │
│     base_vulnerability *                                     │
│     data_sensitivity_multiplier *                           │
│     hndl_multiplier *                                        │
│     timeline_multiplier *                                    │
│     criticality_multiplier,                                 │
│     100                                                      │
│   )                                                          │
│                                                              │
│   # Categorize risk                                          │
│   IF quantum_risk_score >= 80:                              │
│     risk_category = "CRITICAL"                              │
│     urgency = "IMMEDIATE"                                    │
│   ELSE IF quantum_risk_score >= 60:                         │
│     risk_category = "HIGH"                                  │
│     urgency = "1-2 YEARS"                                    │
│   ELSE IF quantum_risk_score >= 40:                         │
│     risk_category = "MEDIUM"                                │
│     urgency = "3-5 YEARS"                                    │
│   ELSE IF quantum_risk_score >= 20:                         │
│     risk_category = "LOW"                                   │
│     urgency = "5-10 YEARS"                                   │
│   ELSE:                                                      │
│     risk_category = "MINIMAL"                               │
│     urgency = "NO ACTION NEEDED"                            │
└──────────────────────────────────────────────────────────────┘

HNDL (HARVEST NOW, DECRYPT LATER) SPECIFIC ANALYSIS:

┌──────────────────────────────────────────────────────────────┐
│ HARVEST NOW, DECRYPT LATER RISK ASSESSMENT                  │
│                                                              │
│ QUESTION: Should this data be protected with PQC NOW?       │
│                                                              │
│ DECISION TREE:                                               │
│                                                              │
│   Is data encrypted with asymmetric crypto (RSA/ECDH)?      │
│     ├─ NO → HNDL risk = NONE                                │
│     └─ YES → Continue                                        │
│                                                              │
│   How long will this data remain sensitive?                 │
│     ├─ < 5 years  → HNDL risk = LOW                         │
│     ├─ 5-10 years → HNDL risk = MODERATE                    │
│     ├─ 10-25 years → HNDL risk = HIGH                       │
│     └─ 25+ years  → HNDL risk = CRITICAL                    │
│                                                              │
│   Is data already in transit over public networks?          │
│     ├─ NO (private network) → Reduce risk by 20%            │
│     └─ YES (internet) → Full risk                           │
│                                                              │
│   Is data subject to regulatory long-term protection?       │
│     (HIPAA, GDPR, classified data)                          │
│     ├─ NO → Current risk level                              │
│     └─ YES → Increase risk by 50%                           │
│                                                              │
│ HNDL DETECTION:                                              │
│   FROM CRYPTO ASSETS:                                        │
│     IF asset.algorithm IN ["RSA", "ECDH"]:                  │
│       AND asset.purpose == "KEY_EXCHANGE":                  │
│       AND system.data_retention_years > 10:                 │
│       AND system.network_type == "PUBLIC_INTERNET":         │
│       → HNDL_RISK = CRITICAL                                │
│       → RECOMMENDATION: "Implement hybrid PQC immediately"  │
│                                                              │
│   EXAMPLE:                                                   │
│     System: Healthcare records database                     │
│     Crypto: RSA-2048 for key exchange                       │
│     Data retention: 30 years (HIPAA requirement)            │
│     Network: Public internet (patient portal)               │
│     → HNDL Risk: CRITICAL                                    │
│     → Action: Deploy hybrid ML-KEM + RSA NOW               │
│     → Reason: Medical records must remain confidential      │
│               for patient lifetime (50+ years)              │
└──────────────────────────────────────────────────────────────┘

MIGRATION TIMELINE CALCULATOR:

┌──────────────────────────────────────────────────────────────┐
│ QUANTUM MIGRATION DEADLINE CALCULATOR                        │
│                                                              │
│ INPUT:                                                       │
│   crypto_asset (RSA-2048 in payment-api)                    │
│   system (payment-api)                                       │
│                                                              │
│ CALCULATE DEADLINE:                                          │
│                                                              │
│   # Factor 1: Regulatory deadlines                          │
│   regulatory_deadlines = []                                  │
│   IF "NSA-CNSA-2.0" IN system.compliance_scopes:            │
│     regulatory_deadlines.append("2033-01-01")  # NSA deadline│
│   IF "DORA" IN system.compliance_scopes:                    │
│     regulatory_deadlines.append("2025-01-17")  # DORA       │
│                                                              │
│   earliest_regulatory = MIN(regulatory_deadlines)           │
│                                                              │
│   # Factor 2: Data sensitivity deadline                     │
│   IF system.data_retention_years > 10:                      │
│     # Data must be protected before harvest risk            │
│     hndl_deadline = current_year + 2  # 2 years buffer      │
│   ELSE:                                                      │
│     hndl_deadline = current_year + 5                        │
│                                                              │
│   # Factor 3: Quantum threat estimate                       │
│   quantum_threat_deadline = 2030  # Conservative estimate   │
│                                                              │
│   # Take earliest (most restrictive)                        │
│   final_deadline = MIN(                                     │
│     earliest_regulatory,                                     │
│     hndl_deadline,                                          │
│     quantum_threat_deadline                                 │
│   )                                                          │
│                                                              │
│   days_remaining = (final_deadline - current_date).days     │
│                                                              │
│   RETURN {                                                   │
│     deadline_date: final_deadline,                          │
│     days_remaining: days_remaining,                         │
│     urgency: categorize_urgency(days_remaining),            │
│     reason: "Earliest of: regulatory, HNDL, quantum threat" │
│   }                                                          │
└──────────────────────────────────────────────────────────────┘

PQC REPLACEMENT RECOMMENDATIONS:

┌──────────────────────────────────────────────────────────────┐
│ POST-QUANTUM CRYPTOGRAPHY RECOMMENDATIONS                    │
│ (NIST FIPS 203, 204, 205)                                   │
│                                                              │
│ Current Algorithm → Recommended PQC Replacement              │
│ ─────────────────────────────────────────────────────────────│
│                                                              │
│ RSA (key exchange)     → ML-KEM-768 (FIPS 203)              │
│                          OR ML-KEM-1024 for high security   │
│                          Hybrid mode: RSA + ML-KEM          │
│                                                              │
│ ECDH (key exchange)    → ML-KEM-768 (FIPS 203)              │
│                          Hybrid mode: ECDH-P256 + ML-KEM    │
│                                                              │
│ RSA (signing)          → ML-DSA-65 (FIPS 204)               │
│                          OR ML-DSA-87 for high security     │
│                          Hybrid mode: RSA-PSS + ML-DSA      │
│                                                              │
│ ECDSA (signing)        → ML-DSA-65 (FIPS 204)               │
│                          OR SLH-DSA-128 (FIPS 205) for      │
│                          stateless signing                  │
│                                                              │
│ AES-128 (encryption)   → AES-256 (Grover-resistant)         │
│                          No PQC replacement needed          │
│                                                              │
│ SHA-256 (hashing)      → SHA-384 or SHA-512                 │
│                          (Grover-resistant at 192/256 bits) │
│                                                              │
│ HYBRID MODE RATIONALE:                                       │
│   → Protects against classical AND quantum threats          │
│   → Allows gradual ecosystem migration                      │
│   → Recommended by NIST for transition period               │
│   → Example: TLS 1.3 with hybrid key exchange:             │
│     Client sends: X25519 share + ML-KEM-768 share           │
│     Server derives: shared_secret = KDF(X25519 || ML-KEM)  │
└──────────────────────────────────────────────────────────────┘

DATABASE SCHEMA:

┌──────────────────────────────────────────────────────────────┐
│ ALTER TABLE crypto_assets ADD COLUMN quantum_risk JSONB;     │
│                                                              │
│ quantum_risk = {                                             │
│   quantum_risk_score: 85,          # 0-100                  │
│   risk_category: "CRITICAL",       # CRITICAL/HIGH/MEDIUM...│
│   threat_type: "SHOR_VULNERABLE",  # Shor/Grover/PQC/Unknown│
│   base_vulnerability: 100,         # Algorithm's base vuln  │
│   hndl_risk: "CRITICAL",          # Harvest-now risk        │
│   data_sensitivity: "HIGH",        # Based on data class    │
│   migration_deadline: "2025-01-17",# Earliest deadline      │
│   days_until_deadline: 347,        # Countdown              │
│   urgency: "IMMEDIATE",            # Action urgency         │
│   recommended_replacement: "ML-KEM-768",                     │
│   hybrid_mode_recommended: true,   # Use hybrid during transition│
│   calculation_timestamp: "2024-01-15T10:00:00Z",            │
│   calculation_version: "quantum-risk-v2.0"                  │
│ }                                                            │
└──────────────────────────────────────────────────────────────┘

DASHBOARD VIEW:

┌──────────────────────────────────────────────────────────────┐
│ QUANTUM RISK DASHBOARD                                       │
│                                                              │
│ ┌────────────────────────────────────────────────────────┐  │
│ │  ORGANIZATION QUANTUM READINESS                        │  │
│ ├────────────────────────────────────────────────────────┤  │
│ │                                                        │  │
│ │  Quantum-Vulnerable Assets: 1,247 (42% of total)      │  │
│ │  Post-Quantum Ready:         287 (10%)                │  │
│ │  Quantum-Resistant (AES-256): 1,408 (48%)             │  │
│ │                                                        │  │
│ │  HIGHEST RISK ASSETS (HNDL Threat)                    │  │
│ │  ┌──────────────────────────────────────────────────┐ │  │
│ │  │ Asset       │ System      │ Risk │ Deadline     │ │  │
│ │  ├─────────────┼─────────────┼──────┼──────────────┤ │  │
│ │  │ RSA-2048    │ health-db   │  95  │ 347 days ⚠️  │ │  │
│ │  │ ECDH-P256   │ payment-api │  92  │ 347 days ⚠️  │ │  │
│ │  │ RSA-4096    │ classified  │  88  │ 730 days     │ │  │
│ │  └──────────────────────────────────────────────────┘ │  │
│ │                                                        │  │
│ │  MIGRATION PROGRESS                                    │  │
│ │  ▓▓▓▓░░░░░░░░░░░░░░░░░░ 10% migrated to PQC           │  │
│ │  On track: NO ❌ (90% remaining, 347 days to DORA)    │  │
│ │                                                        │  │
│ │  [View Migration Plan] [Generate Executive Report]    │  │
│ └────────────────────────────────────────────────────────┘  │
│                                                              │
│ ┌────────────────────────────────────────────────────────┐  │
│ │  ASSET DETAIL: RSA-2048 in health-db                   │  │
│ ├────────────────────────────────────────────────────────┤  │
│ │                                                        │  │
│ │  QUANTUM RISK ANALYSIS                                 │  │
│ │                                                        │  │
│ │  Risk Score: 95/100 ⛔ CRITICAL                        │  │
│ │                                                        │  │
│ │  Threat Type: Shor's Algorithm                        │  │
│ │  → RSA-2048 completely broken by quantum computer     │  │
│ │  → Estimated break time: <1 day on CRQC              │  │
│ │    (Cryptographically Relevant Quantum Computer)      │  │
│ │                                                        │  │
│ │  HNDL (Harvest Now, Decrypt Later) Risk: CRITICAL     │  │
│ │  → Data retention: 30 years (HIPAA)                   │  │
│ │  → Data type: PHI (Protected Health Information)      │  │
│ │  → Network: Public internet (patient portal)          │  │
│ │  → Current encrypted traffic CAN be harvested NOW     │  │
│ │  → Adversary will decrypt with future quantum computer│  │
│ │                                                        │  │
│ │  DEADLINE ANALYSIS                                     │  │
│ │  • Regulatory: 2025-01-17 (DORA) — 347 days           │  │
│ │  • HNDL Risk: 2026-01-01 — 712 days                   │  │
│ │  • Quantum Threat: ~2030 — 2,190 days                 │  │
│ │  → EARLIEST: 2025-01-17 (DORA compliance)             │  │
│ │  → STATUS: ⚠️ URGENT — Less than 1 year remaining     │  │
│ │                                                        │  │
│ │  RECOMMENDED ACTION                                    │  │
│ │  Replace with: ML-KEM-768 (FIPS 203)                  │  │
│ │  Migration strategy: Hybrid mode (RSA + ML-KEM)       │  │
│ │  Estimated effort: 8 weeks                            │  │
│ │  Testing required: YES (performance + compatibility)  │  │
│ │  Downtime required: 2-hour maintenance window         │  │
│ │                                                        │  │
│ │  Business Impact if NOT fixed:                        │  │
│ │  • Compliance violation: DORA (€10M fine risk)        │  │
│ │  • Data breach risk: 2.1M patient records             │  │
│ │  • Reputation damage: HIGH                            │  │
│ │                                                        │  │
│ │  [Create Migration Ticket] [Notify Stakeholders]      │  │
│ └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

### ✅ Week 39-40 Deliverable

**Quantum risk analysis system:**
1. Quantum vulnerability scoring (0-100 scale, multi-factor)
2. Shor's algorithm impact assessment (RSA/ECDH/ECDSA = total break)
3. Grover's algorithm impact (AES-128 → 64-bit effective security)
4. HNDL (Harvest Now, Decrypt Later) risk assessment
5. Migration deadline calculator (regulatory + HNDL + quantum threat)
6. PQC replacement recommendations (NIST FIPS 203/204/205)
7. Hybrid mode guidance (classical + PQC during transition)
8. Quantum risk dashboard (org-wide + per-asset detail)

**Testing:**
- Analyze RSA-2048 in healthcare system (30-year data retention)
- Quantum risk score: 95 (CRITICAL)
- HNDL risk: CRITICAL (long-lived medical data)
- Deadline: 2025-01-17 (DORA compliance) — 347 days
- Recommendation: ML-KEM-768 hybrid mode
- Dashboard shows: 1,247 quantum-vulnerable assets (42% of inventory)
- Executive report: "90% of critical systems not quantum-ready, 347 days to deadline"

---

# 🗺️ MONTH 11: OT/ICS SCANNING + VENDOR DISCOVERY

---

## WEEK 41-42: OT/ICS PASSIVE SCANNER

### 🎯 Goal
Discover crypto in operational technology (SCADA, DCS, PLCs) — **PASSIVE ONLY** (safety-critical)

### 📐 Architecture — OT/ICS Passive Scanner

```
┌─────────────────────────────────────────────────────────────┐
│           OT/ICS PASSIVE CRYPTO SCANNER v1.0                │
│           (Read-Only — Zero Impact on OT Networks)          │
└─────────────────────────────────────────────────────────────┘

OT/ICS PROTOCOLS (Industrial):
  - Modbus TCP (port 502)
  - DNP3 (Distributed Network Protocol)
  - IEC 61850 (substation automation)
  - OPC-UA (industrial interoperability)
  - PROFINET (Siemens automation)
  - EtherNet/IP (Rockwell/Allen-Bradley)
  - BACnet (building automation)

SAFETY PRINCIPLE: NEVER ACTIVELY PROBE OT NETWORKS
  → No port scanning
  → No service enumeration
  → No packet injection
  → PASSIVE OBSERVATION ONLY

DEPLOYMENT: Network TAP (Test Access Point)

┌──────────────────────────────────────────────────────────────┐
│ OT/ICS NETWORK ARCHITECTURE                                  │
│                                                              │
│   ┌─────────────┐                                            │
│   │ SCADA HMI   │  (Human-Machine Interface)                │
│   └──────┬──────┘                                            │
│          │                                                   │
│          ▼                                                   │
│   ┌─────────────┐      ┌──────────────┐                     │
│   │ Network     │◀─────│ NETWORK TAP  │◀─── CryptoScan     │
│   │ Switch      │      │ (span port)  │     Observer        │
│   └──────┬──────┘      └──────────────┘                     │
│          │                                                   │
│     ┌────┴────┐                                              │
│     ▼         ▼                                              │
│   ┌───┐     ┌───┐     ┌───┐                                │
│   │PLC│     │PLC│ ... │PLC│  (Programmable Logic Controllers)│
│   └───┘     └───┘     └───┘                                │
│     │         │         │                                    │
│     ▼         ▼         ▼                                    │
│   ┌───────────────────────┐                                 │
│   │ PHYSICAL PROCESS      │  (pumps, valves, sensors)       │
│   │ (manufacturing line,  │                                 │
│   │  power plant, etc.)   │                                 │
│   └───────────────────────┘                                 │
│                                                              │
│ TAP CONFIGURATION:                                           │
│   → Mirror all traffic to CryptoScan observer               │
│   → Read-only (cannot send packets back to OT network)      │
│   → No MAC address on OT network (invisible)                │
└──────────────────────────────────────────────────────────────┘

PASSIVE PACKET CAPTURE:

┌──────────────────────────────────────────────────────────────┐
│ PACKET CAPTURE & ANALYSIS LOGIC                             │
│                                                              │
│ TECHNOLOGY: tcpdump / Wireshark (libpcap)                   │
│                                                              │
│ CAPTURE FILTER (only relevant protocols):                   │
│   port 502 or                 # Modbus TCP                  │
│   port 20000 or               # DNP3                        │
│   port 102 or                 # IEC 61850 MMS               │
│   port 4840 or                # OPC-UA                      │
│   port 44818                  # EtherNet/IP                 │
│                                                              │
│ PACKET PROCESSING:                                           │
│                                                              │
│   WHILE capturing:                                           │
│     packet = capture_next_packet()                          │
│                                                              │
│     # Parse protocol                                         │
│     IF packet.dst_port == 502:                              │
│       analyze_modbus_packet(packet)                         │
│     ELSE IF packet.dst_port == 4840:                        │
│       analyze_opcua_packet(packet)                          │
│     ELSE IF packet.dst_port == 20000:                       │
│       analyze_dnp3_packet(packet)                           │
│     ...                                                      │
└──────────────────────────────────────────────────────────────┘

PROTOCOL-SPECIFIC CRYPTO DETECTION:

┌──────────────────────────────────────────────────────────────┐
│ PROTOCOL 1: OPC-UA (Most crypto-capable OT protocol)        │
│                                                              │
│ OPC-UA SECURITY MODES:                                       │
│   1. None — No security                                     │
│   2. Sign — Message signing only                            │
│   3. SignAndEncrypt — Full crypto                           │
│                                                              │
│ DETECTION FROM PACKET:                                       │
│   opcua_header = parse_opcua_header(packet)                │
│                                                              │
│   security_mode = opcua_header.security_mode                │
│     → 0x00 = None (⚠️ NO CRYPTO)                            │
│     → 0x01 = Sign                                            │
│     → 0x02 = SignAndEncrypt                                 │
│                                                              │
│   IF security_mode == 0x02:  # SignAndEncrypt               │
│     security_policy_uri = opcua_header.security_policy_uri  │
│                                                              │
│     # Parse security policy URI                             │
│     # Example: "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256"│
│     IF "Basic256Sha256" IN security_policy_uri:             │
│       crypto_config = {                                      │
│         encryption: "AES-256-CBC",                          │
│         signing: "HMAC-SHA256",                             │
│         key_derivation: "P-SHA256"                          │
│       }                                                      │
│     ELSE IF "Basic128Rsa15" IN security_policy_uri:         │
│       crypto_config = {                                      │
│         encryption: "AES-128-CBC",                          │
│         signing: "HMAC-SHA1",                               │
│         key_exchange: "RSA-1024" # WEAK!                    │
│       }                                                      │
│                                                              │
│     finding = {                                              │
│       source: {                                              │
│         type: "OT_NETWORK_TRAFFIC",                         │
│         protocol: "OPC-UA",                                 │
│         src_ip: packet.src_ip,                              │
│         dst_ip: packet.dst_ip,                              │
│         device_type: identify_device_type(packet.src_ip)    │
│       },                                                     │
│       crypto: crypto_config,                                │
│       metadata: {                                            │
│         confidence: "MEDIUM",  # Passive inference          │
│         detection_method: "PASSIVE_PACKET_INSPECTION"       │
│       }                                                      │
│     }                                                        │
│                                                              │
│   ELSE IF security_mode == 0x00:  # No security!            │
│     finding = {                                              │
│       source: {...},                                         │
│       crypto: {                                              │
│         encryption: "NONE",                                 │
│         signing: "NONE"                                      │
│       },                                                     │
│       compliance_issue: "OT_UNENCRYPTED_TRAFFIC"            │
│     }                                                        │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ PROTOCOL 2: DNP3 Secure Authentication (SA)                │
│                                                              │
│ DNP3 is older protocol, security is optional extension      │
│                                                              │
│ DETECTION:                                                   │
│   dnp3_packet = parse_dnp3(packet)                          │
│   IF dnp3_packet.has_secure_authentication:                 │
│     # SA-v5 (DNP3 Secure Authentication version 5)          │
│     auth_algorithm = dnp3_packet.auth_algorithm             │
│       → 0x00 = No authentication                            │
│       → 0x01 = HMAC-SHA1 (deprecated)                       │
│       → 0x02 = HMAC-SHA256                                  │
│       → 0x03 = AES-GMAC                                     │
│                                                              │
│     finding = {                                              │
│       protocol: "DNP3-SA",                                  │
│       crypto: {                                              │
│         authentication: map_dnp3_auth(auth_algorithm),      │
│         purpose: "MESSAGE_AUTHENTICATION"                   │
│       }                                                      │
│     }                                                        │
│                                                              │
│   ELSE:  # No SA extension                                  │
│     finding = {                                              │
│       protocol: "DNP3",                                     │
│       crypto: "NONE",                                        │
│       compliance_issue: "OT_NO_AUTHENTICATION"              │
│     }                                                        │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ PROTOCOL 3: Modbus TCP (NO NATIVE CRYPTO)                  │
│                                                              │
│ Modbus TCP has NO built-in security                         │
│   → Often tunneled over TLS or VPN                          │
│   → Or runs on isolated network (security by isolation)     │
│                                                              │
│ DETECTION:                                                   │
│   modbus_packet = parse_modbus_tcp(packet)                 │
│                                                              │
│   # Check if wrapped in TLS                                 │
│   IF packet.is_tls_encrypted:                               │
│     tls_info = extract_tls_info(packet)                    │
│     finding = {                                              │
│       protocol: "Modbus-over-TLS",                          │
│       crypto: tls_info.cipher_suite,                        │
│       tls_version: tls_info.version                         │
│     }                                                        │
│                                                              │
│   ELSE:  # Plain Modbus (unencrypted)                       │
│     finding = {                                              │
│       protocol: "Modbus TCP",                               │
│       crypto: "NONE",                                        │
│       compliance_issue: "OT_UNENCRYPTED_MODBUS",            │
│       note: "Modbus has no native encryption. Consider TLS tunnel."│
│     }                                                        │
└──────────────────────────────────────────────────────────────┘

DEVICE IDENTIFICATION (FROM TRAFFIC):

┌──────────────────────────────────────────────────────────────┐
│ OT DEVICE FINGERPRINTING                                     │
│                                                              │
│ GOAL: Identify device type/vendor from network traffic      │
│                                                              │
│ METHOD 1: MAC Address OUI Lookup                            │
│   mac_prefix = packet.src_mac[:8]  # First 3 bytes          │
│   vendor = OUI_DATABASE.lookup(mac_prefix)                  │
│     → "00:1B:1B" = Siemens                                  │
│     → "00:00:BC" = Allen-Bradley (Rockwell)                 │
│     → "00:0E:8C" = Schneider Electric                       │
│                                                              │
│ METHOD 2: Protocol-Specific Headers                         │
│   IF protocol == "OPC-UA":                                  │
│     application_uri = opcua_header.application_uri          │
│       → "urn:Siemens:..." → Siemens PLC                     │
│       → "urn:ABB:..." → ABB device                          │
│                                                              │
│ METHOD 3: Behavioral Fingerprinting                         │
│   IF sends Modbus function code pattern [0x03, 0x06, 0x10]:│
│     → Likely Schneider Modicon PLC                          │
│                                                              │
│ RESULT:                                                      │
│   device_info = {                                            │
│     vendor: "Siemens",                                      │
│     device_type: "PLC",                                     │
│     model: "S7-1500" (if determinable),                     │
│     ip_address: packet.src_ip,                              │
│     mac_address: packet.src_mac                             │
│   }                                                          │
└──────────────────────────────────────────────────────────────┘

FIRMWARE VERSION DETECTION (ADVANCED):

┌──────────────────────────────────────────────────────────────┐
│ FIRMWARE CRYPTO VULNERABILITY MAPPING                        │
│                                                              │
│ Some OT protocols expose firmware version in packets:        │
│                                                              │
│ OPC-UA example:                                              │
│   server_info = opcua_session.get_server_info()            │
│   product_uri = server_info.product_uri                     │
│   software_version = server_info.software_version           │
│     → "Siemens SIMATIC S7-1500 / V2.8.2"                    │
│                                                              │
│ CROSS-REFERENCE WITH CVE DATABASE:                          │
│   cves = lookup_cves(vendor="Siemens",                      │
│                      product="SIMATIC S7-1500",             │
│                      version="2.8.2")                        │
│                                                              │
│   IF cves contains crypto vulnerabilities:                  │
│     finding.vulnerabilities = cves                          │
│     finding.severity = MAX(cve.cvss_score for cve in cves)  │
│                                                              │
│ EXAMPLE CVE:                                                 │
│   CVE-2020-15782: Siemens S7 crypto weakness                │
│   → Hardcoded encryption key in firmware                    │
│   → Affects versions < 2.9.0                                │
│   → CVSS: 9.1 (CRITICAL)                                    │
└──────────────────────────────────────────────────────────────┘

SAFETY CONSIDERATIONS:

┌──────────────────────────────────────────────────────────────┐
│ OT SAFETY GUARDRAILS (Built into Scanner)                   │
│                                                              │
│ 1. READ-ONLY MODE ENFORCED                                  │
│    scanner_mode = "PASSIVE_OBSERVATION"                     │
│    IF attempt_to_send_packet():                             │
│      RAISE SafetyException("OT scanner is read-only!")      │
│      HALT IMMEDIATELY                                        │
│                                                              │
│ 2. NO ACTIVE PROBING                                         │
│    forbidden_actions = [                                     │
│      "port_scan", "service_enumeration",                    │
│      "packet_injection", "arp_spoofing",                    │
│      "protocol_fuzzing"                                      │
│    ]                                                         │
│    ALL forbidden_actions → DISABLED in code                 │
│                                                              │
│ 3. RATE LIMITING (Even for passive capture)                 │
│    packet_processing_rate = 1000 packets/second MAX         │
│    IF rate exceeds limit:                                    │
│      → Drop excess packets (don't overwhelm analyzer)       │
│                                                              │
│ 4. AUDIT LOGGING                                             │
│    ALL scanner actions logged to immutable log              │
│    Log includes: timestamp, action, operator                │
│    Purpose: Prove to OT team that scanner is safe           │
│                                                              │
│ 5. EMERGENCY STOP                                            │
│    IF OT team requests halt:                                │
│      → Stop packet capture immediately                      │
│      → Close all network connections                        │
│      → Log shutdown event                                    │
│    Access: Physical button + remote API                     │
└──────────────────────────────────────────────────────────────┘

DATABASE SCHEMA:

┌──────────────────────────────────────────────────────────────┐
│ TABLE: ot_devices                                            │
│                                                              │
│ device_id            UUID PK                                 │
│ ip_address           INET                                    │
│ mac_address          MACADDR                                 │
│ vendor               VARCHAR(100)   Siemens, Rockwell, etc  │
│ device_type          VARCHAR(50)    PLC, HMI, RTU, etc      │
│ model                VARCHAR(100)   S7-1500, etc            │
│ firmware_version     VARCHAR(50)                             │
│ protocols_observed   TEXT[]         [OPC-UA, Modbus, DNP3]  │
│ first_seen           TIMESTAMP                               │
│ last_seen            TIMESTAMP                               │
│ location             VARCHAR(200)   Physical location        │
│ criticality          VARCHAR(20)    SAFETY_CRITICAL, etc    │
│ created_at           TIMESTAMP                               │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ TABLE: ot_crypto_findings                                    │
│                                                              │
│ finding_id           UUID PK                                 │
│ device_id            UUID FK → ot_devices                   │
│ protocol             VARCHAR(50)    OPC-UA, DNP3-SA, etc    │
│ crypto_config        JSONB          {encryption: ..., signing: ...}│
│ has_crypto           BOOLEAN        true if ANY crypto       │
│ security_level       VARCHAR(50)    NONE, SIGN, ENCRYPT     │
│ vulnerabilities      JSONB[]        CVEs if known            │
│ confidence           VARCHAR(20)    MEDIUM (passive)         │
│ observed_at          TIMESTAMP                               │
│ observation_count    INT            How many packets         │
└──────────────────────────────────────────────────────────────┘

DASHBOARD VIEW:

┌──────────────────────────────────────────────────────────────┐
│ OT/ICS CRYPTO INVENTORY DASHBOARD                            │
│                                                              │
│ ┌────────────────────────────────────────────────────────┐  │
│ │  OT NETWORK OVERVIEW                                   │  │
│ ├────────────────────────────────────────────────────────┤  │
│ │                                                        │  │
│ │  Total OT Devices: 87                                 │  │
│ │  • PLCs: 42                                            │  │
│ │  • HMIs: 12                                            │  │
│ │  • RTUs: 18                                            │  │
│ │  • Other: 15                                           │  │
│ │                                                        │  │
│ │  CRYPTO STATUS                                         │  │
│ │  🔴 No Crypto:         34 devices (39%)  ← CRITICAL!   │  │
│ │  🟡 Signed Only:       21 devices (24%)                │  │
│ │  🟢 Encrypted:         28 devices (32%)                │  │
│ │  ⚪ Unknown:            4 devices (5%)                 │  │
│ │                                                        │  │
│ │  VULNERABLE DEVICES                                    │  │
│ │  🔴 Critical CVEs:      8 devices                      │  │
│ │  🟠 High CVEs:         15 devices                      │  │
│ │                                                        │  │
│ │  [View Unencrypted Devices] [View CVEs]               │  │
│ └────────────────────────────────────────────────────────┘  │
│                                                              │
│ ┌────────────────────────────────────────────────────────┐  │
│ │  UNENCRYPTED OT DEVICES (CRITICAL)                     │  │
│ ├────────────────────────────────────────────────────────┤  │
│ │ Device         │ Type │ Protocol │ Location          │  │
│ ├────────────────┼──────┼──────────┼───────────────────┤  │
│ │ 10.0.2.15      │ PLC  │ Modbus   │ Production Line 3 │  │
│ │ 10.0.2.28      │ HMI  │ Modbus   │ Control Room A    │  │
│ │ 10.0.3.42      │ RTU  │ DNP3     │ Substation 7      │  │
│ │ ...                                                    │  │
│ └────────────────────────────────────────────────────────┘  │
│                                                              │
│ ⚠️  WARNING: OT findings are PASSIVE OBSERVATIONS          │  │
│     Confidence: MEDIUM                                      │  │
│     Recommendation: Verify with OT vendor before action     │  │
└──────────────────────────────────────────────────────────────┘
```

### ✅ Week 41-42 Deliverable

**OT/ICS passive scanner:**
1. Network TAP integration (passive observation)
2. Protocol parsers (OPC-UA, DNP3, Modbus, IEC 61850)
3. Crypto detection from packet inspection
4. Device fingerprinting (vendor, model, firmware from traffic)
5. OT device inventory database
6. OT crypto findings (with MEDIUM confidence label)
7. CVE cross-reference for OT firmware
8. Safety guardrails (read-only enforcement, emergency stop)
9. OT-specific dashboard (separate from IT crypto inventory)

**Testing:**
- Deploy passive tap on test OT network (isolated lab environment)
- Capture OPC-UA traffic → detect AES-256-CBC encryption
- Capture Modbus traffic → detect NO encryption
- Identify 15 devices (PLCs, HMIs) from MAC/protocol fingerprinting
- Dashboard shows: 8 unencrypted devices (flagged as critical)
- Verify: Scanner sent ZERO packets to OT network (read-only confirmed)

---

## WEEK 43-44: VENDOR CRYPTO DISCOVERY (IDEA2-Style)

### 🎯 Goal
Discover what crypto your third-party vendors use (supply chain transparency)

### 📐 Architecture — Vendor Crypto Discovery

```
┌─────────────────────────────────────────────────────────────┐
│         VENDOR CRYPTO DISCOVERY SYSTEM v1.0                 │
│         (Third-Party Risk Assessment — Crypto Layer)        │
└─────────────────────────────────────────────────────────────┘

CONCEPT (inspired by IDEA2):
  → You integrate with vendors (Stripe, Salesforce, AWS, etc.)
  → What crypto do THEY use for YOUR data?
  → Can you get SBOM/CBOM from vendors?
  → If vendor's crypto is weak, YOUR data is at risk

VENDOR DISCOVERY METHODS:

┌──────────────────────────────────────────────────────────────┐
│ METHOD 1: VENDOR API SCANNING                               │
│ (Scan vendor-provided APIs you connect to)                  │
│                                                              │
│ EXAMPLE: Payment Gateway (Stripe)                           │
│                                                              │
│ Your system calls: https://api.stripe.com/v1/charges        │
│                                                              │
│ SCAN:                                                        │
│   endpoint = "api.stripe.com:443"                           │
│   tls_info = probe_tls_endpoint(endpoint)                   │
│     → TLS version: 1.3                                       │
│     → Cipher: TLS_AES_256_GCM_SHA384                        │
│     → Certificate: DigiCert (expires 2025-06-15)            │
│                                                              │
│   finding = {                                                │
│     vendor: "Stripe",                                        │
│     integration_type: "API",                                │
│     endpoint: endpoint,                                      │
│     crypto: {                                                │
│       tls_version: "1.3",                                    │
│       cipher_suite: "AES-256-GCM",                          │
│       certificate_issuer: "DigiCert"                        │
│     },                                                       │
│     data_transmitted: ["PAN", "customer_email"],            │
│     data_classification: "PCI-DSS",                         │
│     compliance_requirement: "Vendor must use TLS 1.2+"      │
│   }                                                          │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ METHOD 2: VENDOR-PROVIDED SBOM/CBOM                         │
│ (Request crypto inventory from vendor)                      │
│                                                              │
│ PROCESS:                                                     │
│   1. Request SBOM (Software Bill of Materials) from vendor  │
│      → Increasingly common for enterprise contracts         │
│      → Many vendors now provide CycloneDX SBOMs             │
│                                                              │
│   2. Parse SBOM for crypto components                       │
│      IF SBOM contains cryptographic-asset components:       │
│        extract_crypto_from_sbom(sbom)                       │
│                                                              │
│   3. Import into CryptoScan vendor inventory                │
│                                                              │
│ EXAMPLE SBOM (CycloneDX from Vendor):                       │
│   {                                                          │
│     "components": [                                          │
│       {                                                      │
│         "type": "cryptographic-asset",                      │
│         "name": "TLS 1.3 for API",                          │
│         "cryptoProperties": {                                │
│           "algorithmProperties": {                          │
│             "primitive": "ae",                              │
│             "parameterSetIdentifier": "256",                │
│             "mode": "gcm"                                    │
│           }                                                  │
│         }                                                    │
│       },                                                     │
│       {                                                      │
│         "type": "cryptographic-asset",                      │
│         "name": "Data-at-Rest Encryption",                  │
│         "cryptoProperties": {                                │
│           "algorithmProperties": {                          │
│             "primitive": "ae",                              │
│             "parameterSetIdentifier": "256",                │
│             "mode": "gcm"                                    │
│           }                                                  │
│         },                                                   │
│         "properties": [                                      │
│           {"name": "key-management", "value": "AWS KMS"}    │
│         ]                                                    │
│       }                                                      │
│     ]                                                        │
│   }                                                          │
│                                                              │
│ IMPORT:                                                      │
│   FOR EACH component IN sbom.components:                    │
│     IF component.type == "cryptographic-asset":             │
│       vendor_crypto = parse_crypto_component(component)     │
│       INSERT INTO vendor_crypto_inventory (...)             │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ METHOD 3: VENDOR QUESTIONNAIRE                              │
│ (Automated security questionnaire)                          │
│                                                              │
│ CryptoScan can generate vendor questionnaire:               │
│                                                              │
│ QUESTIONS:                                                   │
│   1. What encryption do you use for data in transit?        │
│      □ TLS 1.2  □ TLS 1.3  □ Other: _______                │
│                                                              │
│   2. What encryption do you use for data at rest?           │
│      □ AES-256  □ AES-128  □ Other: _______                │
│                                                              │
│   3. How are encryption keys managed?                       │
│      □ HSM  □ Cloud KMS  □ Software  □ Other: _____        │
│                                                              │
│   4. Do you use post-quantum cryptography?                  │
│      □ Yes (specify: ______)  □ No  □ Planned (date: __)   │
│                                                              │
│   5. Can you provide a CBOM (Crypto Bill of Materials)?     │
│      □ Yes (attach)  □ No                                   │
│                                                              │
│   6. What is your crypto refresh/rotation policy?           │
│      Frequency: _____ (annually, quarterly, etc.)           │
│                                                              │
│ VENDOR RESPONSE PARSING:                                     │
│   responses = parse_questionnaire_response(vendor_form)     │
│   vendor_crypto_profile = {                                 │
│     vendor_name: responses.vendor_name,                     │
│     data_in_transit: responses.tls_version,                 │
│     data_at_rest: responses.encryption_algorithm,           │
│     key_management: responses.kms_type,                     │
│     pqc_status: responses.pqc_adoption,                     │
│     cbom_provided: responses.cbom_attached,                 │
│     last_assessment: NOW()                                   │
│   }                                                          │
│   INSERT INTO vendor_crypto_profiles (...)                  │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ METHOD 4: PUBLIC DOCUMENTATION SCRAPING (Automated)         │
│                                                              │
│ Many vendors publish security whitepapers:                  │
│   → AWS: "Encryption in AWS Services"                       │
│   → Stripe: "Security at Stripe"                            │
│   → Salesforce: "Trust and Compliance Documentation"        │
│                                                              │
│ SCRAPING LOGIC (NLP-based):                                  │
│   documentation_url = vendor.security_documentation_url     │
│   content = download_pdf_or_webpage(documentation_url)      │
│                                                              │
│   # Extract crypto keywords                                 │
│   crypto_mentions = extract_crypto_keywords(content)        │
│     → Regex patterns for: "AES-256", "TLS 1.3", "RSA-2048"  │
│     → NLP extraction: "We use _____ for encryption"         │
│                                                              │
│   vendor_crypto_info = {                                     │
│     vendor: vendor.name,                                     │
│     source: "PUBLIC_DOCUMENTATION",                         │
│     crypto_mentioned: crypto_mentions,                      │
│     confidence: "LOW",  # Not official API, just docs       │
│     last_scraped: NOW()                                      │
│   }                                                          │
│                                                              │
│ EXAMPLE EXTRACTION:                                          │
│   From AWS docs: "Amazon S3 uses AES-256 server-side encryption"│
│   → extracted: {algorithm: "AES-256", service: "S3"}        │
└──────────────────────────────────────────────────────────────┘

DATABASE SCHEMA:

┌──────────────────────────────────────────────────────────────┐
│ TABLE: vendors                                               │
│                                                              │
│ vendor_id            UUID PK                                 │
│ vendor_name          VARCHAR(200)   Stripe, AWS, Salesforce │
│ vendor_type          VARCHAR(50)    PAYMENT, CLOUD, SAAS    │
│ criticality          VARCHAR(20)    CRITICAL, HIGH, MEDIUM  │
│ contract_end_date    DATE           When contract expires   │
│ data_classifications TEXT[]         What data they handle   │
│ integration_type     VARCHAR(50)    API, DATABASE, FILE_TRANSFER│
│ primary_contact      VARCHAR(200)   Vendor contact email    │
│ security_contact     VARCHAR(200)   Vendor security team    │
│ last_assessment_date TIMESTAMP                               │
│ created_at           TIMESTAMP                               │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ TABLE: vendor_crypto_inventory                              │
│                                                              │
│ crypto_id            UUID PK                                 │
│ vendor_id            UUID FK → vendors                      │
│ crypto_use_case      VARCHAR(100)  "Data in transit", etc   │
│ algorithm            VARCHAR(50)   AES-256, TLS 1.3, etc    │
│ key_size             INT                                     │
│ mode                 VARCHAR(50)                             │
│ key_management       VARCHAR(100)  HSM, AWS KMS, etc        │
│ pqc_ready            BOOLEAN       Post-quantum ready?      │
│ discovery_method     VARCHAR(50)   API_SCAN, SBOM, etc      │
│ confidence           VARCHAR(20)   HIGH, MEDIUM, LOW        │
│ discovered_at        TIMESTAMP                               │
│ verified_at          TIMESTAMP     Vendor-confirmed date    │
│ source_document      TEXT          URL to source            │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ TABLE: vendor_integrations                                   │
│ (Which of YOUR systems integrate with which vendors)        │
│                                                              │
│ integration_id       UUID PK                                 │
│ system_id            UUID FK → systems (your system)        │
│ vendor_id            UUID FK → vendors                      │
│ integration_type     VARCHAR(50)   API, DATABASE, FILE      │
│ endpoint             VARCHAR(200)  Vendor API endpoint      │
│ data_flow_direction  VARCHAR(20)   SEND, RECEIVE, BOTH      │
│ data_types           TEXT[]        What data is shared      │
│ frequency            VARCHAR(50)   REALTIME, DAILY, etc     │
│ created_at           TIMESTAMP                               │
└──────────────────────────────────────────────────────────────┘

VENDOR RISK SCORING:

┌──────────────────────────────────────────────────────────────┐
│ VENDOR CRYPTO RISK SCORE                                     │
│                                                              │
│ FOR EACH vendor:                                             │
│                                                              │
│   # Risk Factor 1: Crypto strength                          │
│   IF vendor uses weak crypto (DES, MD5, TLS 1.0):           │
│     crypto_risk = 50                                         │
│   ELSE IF vendor uses moderate crypto (RSA-2048, AES-128):  │
│     crypto_risk = 25                                         │
│   ELSE IF vendor uses strong crypto (AES-256, TLS 1.3):     │
│     crypto_risk = 5                                          │
│                                                              │
│   # Risk Factor 2: PQC readiness                            │
│   IF vendor has NO PQC plan AND handles long-lived data:    │
│     pqc_risk = 30                                            │
│   ELSE IF vendor has PQC roadmap:                           │
│     pqc_risk = 10                                            │
│   ELSE IF vendor already uses PQC:                          │
│     pqc_risk = 0                                             │
│                                                              │
│   # Risk Factor 3: Data sensitivity                         │
│   IF vendor handles PCI/PHI/PII:                            │
│     data_risk_multiplier = 1.5                              │
│   ELSE:                                                      │
│     data_risk_multiplier = 1.0                              │
│                                                              │
│   # Risk Factor 4: Transparency                             │
│   IF vendor provides CBOM:                                   │
│     transparency_bonus = -10  # Reduces risk                │
│   ELSE IF vendor refuses crypto disclosure:                 │
│     transparency_penalty = +20                              │
│   ELSE:                                                      │
│     transparency_bonus = 0                                   │
│                                                              │
│   vendor_crypto_risk_score = (                              │
│     (crypto_risk + pqc_risk) * data_risk_multiplier +       │
│     transparency_bonus                                       │
│   )                                                          │
│                                                              │
│   IF vendor_crypto_risk_score > 70:                         │
│     vendor_risk_category = "HIGH"                           │
│     action = "Review vendor contract. Request upgrade."     │
│   ELSE IF vendor_crypto_risk_score > 40:                    │
│     vendor_risk_category = "MEDIUM"                         │
│     action = "Monitor. Plan contingency."                   │
│   ELSE:                                                      │
│     vendor_risk_category = "LOW"                            │
│     action = "No action needed."                            │
└──────────────────────────────────────────────────────────────┘

DASHBOARD VIEW:

┌──────────────────────────────────────────────────────────────┐
│ VENDOR CRYPTO RISK DASHBOARD                                 │
│                                                              │
│ ┌────────────────────────────────────────────────────────┐  │
│ │  VENDOR RISK OVERVIEW                                  │  │
│ ├────────────────────────────────────────────────────────┤  │
│ │                                                        │  │
│ │  Total Vendors: 47                                     │  │
│ │  🔴 HIGH RISK:     8 vendors (17%)                     │  │
│ │  🟠 MEDIUM RISK:  21 vendors (45%)                     │  │
│ │  🟢 LOW RISK:     18 vendors (38%)                     │  │
│ │                                                        │  │
│ │  PQC READINESS                                         │  │
│ │  • PQC Ready:        2 vendors (4%)                    │  │
│ │  • PQC Planned:     15 vendors (32%)                   │  │
│ │  • No PQC Plan:     30 vendors (64%) ⚠️                │  │
│ │                                                        │  │
│ └────────────────────────────────────────────────────────┘  │
│                                                              │
│ ┌────────────────────────────────────────────────────────┐  │
│ │  HIGH RISK VENDORS (Action Required)                   │  │
│ ├────────────────────────────────────────────────────────┤  │
│ │ Vendor        │ Risk │ Issue          │ Contract End │  │
│ ├───────────────┼──────┼────────────────┼──────────────┤  │
│ │ LegacyVendorX │  85  │ TLS 1.0        │ 2025-06-30   │  │
│ │ CloudProviderY│  72  │ No PQC plan    │ 2026-12-31   │  │
│ │ DataProcessorZ│  68  │ Weak key mgmt  │ 2024-09-15   │  │
│ └────────────────────────────────────────────────────────┘  │
│                                                              │
│ ┌────────────────────────────────────────────────────────┐  │
│ │  VENDOR DETAIL: LegacyVendorX                          │  │
│ ├────────────────────────────────────────────────────────┤  │
│ │  Risk Score: 85/100 🔴 HIGH                            │  │
│ │                                                        │  │
│ │  CRYPTO PROFILE                                        │  │
│ │  • Data in transit: TLS 1.0 ⚠️ (deprecated)            │  │
│ │  • Data at rest: AES-128-CBC                           │  │
│ │  • Key management: Software (not HSM)                  │  │
│ │  • PQC readiness: None                                 │  │
│ │                                                        │  │
│ │  DATA HANDLED                                          │  │
│ │  • PII (customer names, emails)                        │  │
│ │  • Transaction history                                 │  │
│ │  • Classification: CONFIDENTIAL                        │  │
│ │                                                        │  │
│ │  OUR INTEGRATIONS (3)                                  │  │
│ │  • payment-api (API, realtime)                         │  │
│ │  • reporting-service (API, daily)                      │  │
│ │  • customer-portal (API, realtime)                     │  │
│ │                                                        │  │
│ │  RISK FACTORS                                          │  │
│ │  • TLS 1.0 vulnerable to attacks (+50 risk)            │  │
│ │  • No PQC plan for long-term data (+30 risk)           │  │
│ │  • Handles PII (+25% multiplier)                       │  │
│ │  • Contract expires in 6 months                        │  │
│ │                                                        │  │
│ │  RECOMMENDED ACTIONS                                   │  │
│ │  1. ⚠️ IMMEDIATE: Request TLS 1.2+ upgrade            │  │
│ │     Deadline: Before contract renewal                  │  │
│ │  2. 🔴 HIGH: Request PQC roadmap                       │  │
│ │  3. 🟡 MEDIUM: Consider alternative vendors            │  │
│ │                                                        │  │
│ │  [Contact Vendor] [Schedule Review] [View Contract]   │  │
│ └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

### ✅ Week 43-44 Deliverable

**Vendor crypto discovery system:**
1. 4 discovery methods (API scan, SBOM import, questionnaire, doc scraping)
2. `vendors` table (vendor master data)
3. `vendor_crypto_inventory` table (what crypto vendors use)
4. `vendor_integrations` table (your systems ↔ vendors)
5. Vendor crypto risk scoring (0-100)
6. Vendor risk dashboard (high/medium/low risk vendors)
7. Vendor questionnaire generator (automated security assessment)
8. SBOM import (CycloneDX vendor SBOMs)
9. Integration with dependency graph (vendor nodes)

**Testing:**
- Add vendor: "StripePayments"
- Scan Stripe API endpoint → TLS 1.3, AES-256-GCM
- Import Stripe SBOM (if available) → extract crypto components
- Calculate vendor risk: 15 (LOW) — strong crypto, PQC roadmap
- Add vendor: "LegacyVendor" (uses TLS 1.0)
- Calculate vendor risk: 85 (HIGH) — weak crypto, no PQC
- Dashboard shows: 8 high-risk vendors requiring action
- Graph query: "payment-api → StripePayments" (dependency visualization)

---

# 🗺️ MONTH 12: ADVANCED ANALYTICS + EXCEPTION MANAGEMENT

---

## WEEK 45-46: ANALYTICS DASHBOARD v2.0

### 🎯 Goal
Advanced visualizations, trends, forecasting

### 📐 Architecture — Analytics Engine

```
┌─────────────────────────────────────────────────────────────┐
│         ADVANCED ANALYTICS DASHBOARD v2.0                   │
│         (Trends, Forecasting, Heat Maps, Insights)          │
└─────────────────────────────────────────────────────────────┘

ANALYTICS FEATURES:

┌──────────────────────────────────────────────────────────────┐
│ FEATURE 1: CRYPTO PORTFOLIO TRENDING                        │
│                                                              │
│ CHART: Algorithm Usage Over Time                            │
│                                                              │
│   │                                                          │
│ 100│  ████ RSA-2048 (declining)                             │
│   │  ████                                                    │
│  80│  ████░░░░                                               │
│   │  ████░░░░                                               │
│  60│  ████░░░░  ▓▓▓▓ AES-256-GCM (stable)                  │
│   │  ████░░░░  ▓▓▓▓                                         │
│  40│  ████░░░░  ▓▓▓▓                                         │
│   │  ████░░░░  ▓▓▓▓    ▒▒▒ ML-KEM (growing)               │
│  20│  ████░░░░  ▓▓▓▓    ▒▒▒                                │
│   │  ████░░░░  ▓▓▓▓    ▒▒▒                                │
│   └─────────────────────────────────────────────────────    │
│     2023    2023    2024    2024    2024                    │
│     Jan     Jul     Jan     Jul     Dec                     │
│                                                              │
│ DATA SOURCE:                                                 │
│   SELECT                                                     │
│     DATE_TRUNC('month', created_at) as month,               │
│     algorithm,                                               │
│     COUNT(*) as usage_count                                 │
│   FROM crypto_assets                                         │
│   WHERE created_at >= NOW() - INTERVAL '2 years'            │
│   GROUP BY month, algorithm                                 │
│   ORDER BY month, algorithm;                                │
│                                                              │
│ INSIGHTS (Auto-generated):                                   │
│   → "RSA-2048 usage declined 42% in last 12 months"        │
│   → "ML-KEM adoption increased 312% in last 6 months"      │
│   → "AES-256-GCM remains most common (stable at 38%)"      │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ FEATURE 2: COMPLIANCE TREND (Pass/Fail Over Time)          │
│                                                              │
│ CHART: Compliance Rate Trending                             │
│                                                              │
│  100%│                                    ██ Target: 95%     │
│      │                             ██████                    │
│   90%│                      ██████                           │
│      │               ██████                                  │
│   80%│        ██████                                         │
│      │ ██████                                                │
│   70%│                                                       │
│      └────────────────────────────────────────────────      │
│       Q1    Q2    Q3    Q4    Q1    Q2    Q3    Q4         │
│       2023  2023  2023  2023  2024  2024  2024  2024       │
│                                                              │
│ DATA SOURCE:                                                 │
│   SELECT                                                     │
│     DATE_TRUNC('quarter', calculated_at) as quarter,        │
│     compliance_status,                                       │
│     COUNT(*) as count                                        │
│   FROM system_agility_scores  -- Or policy evaluations      │
│   GROUP BY quarter, compliance_status;                      │
│                                                              │
│ CALCULATION:                                                 │
│   compliance_rate = (                                        │
│     COUNT(WHERE status = 'PASS') /                          │
│     COUNT(*)                                                 │
│   ) * 100                                                    │
│                                                              │
│ INSIGHT:                                                     │
│   → "Compliance improved 18% since crypto remediation started"│
│   → "On track to meet 95% target by Q2 2025"               │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ FEATURE 3: HEAT MAP (Crypto Risk by Business Unit)         │
│                                                              │
│ VISUALIZATION: Risk Heat Map                                │
│                                                              │
│         │ Finance │ Engineering │ Sales │ Operations │      │
│ ────────┼─────────┼─────────────┼───────┼────────────┤      │
│ CRITICAL│   🔴    │     🟢      │  🟡   │    🟢      │      │
│ HIGH    │   🟠    │     🟡      │  🟢   │    🟡      │      │
│ MEDIUM  │   🟢    │     🟢      │  🟢   │    🟢      │      │
│                                                              │
│ 🔴 = >10 critical issues                                     │
│ 🟠 = 5-10 critical issues                                    │
│ 🟡 = 1-4 critical issues                                     │
│ 🟢 = 0 critical issues                                       │
│                                                              │
│ INSIGHT:                                                     │
│   → Finance has 12 critical crypto issues (payment systems) │
│   → Engineering has 0 critical issues (modernized stack)    │
│                                                              │
│ DRILL-DOWN:                                                  │
│   Click Finance/CRITICAL cell →                             │
│     Shows: 12 RSA-2048 instances in payment-api             │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ FEATURE 4: FORECASTING (PQC Migration Timeline)            │
│                                                              │
│ CHART: Migration Progress Forecast                          │
│                                                              │
│  100%│                                          Target ──────│
│      │                                        ╱              │
│   80%│                                    ╱                  │
│      │                                ╱ Forecast             │
│   60%│                            ╱                          │
│      │                        ╱                              │
│   40%│ Actual          ──╱                                   │
│      │         ────                                          │
│   20%│ ────                                                  │
│      └────────────────────────────────────────────────      │
│       Now   +3mo  +6mo  +9mo  +12mo +15mo +18mo            │
│                                                              │
│ FORECASTING ALGORITHM:                                       │
│   historical_data = migration_progress_last_6_months        │
│   migration_rate = linear_regression(historical_data)       │
│     → Current rate: 4.2% per month                          │
│                                                              │
│   assets_remaining = 1247 quantum-vulnerable assets         │
│   assets_migrated_per_month = assets_remaining * 0.042      │
│   months_to_completion = assets_remaining / assets_migrated_per_month│
│     → 23.8 months (~2 years)                                │
│                                                              │
│   deadline = "2025-01-17" (DORA)                            │
│   months_until_deadline = 12                                │
│                                                              │
│   IF months_to_completion > months_until_deadline:          │
│     status = "AT RISK ⚠️"                                   │
│     gap = months_to_completion - months_until_deadline      │
│     recommendation = f"Accelerate by {gap} months"          │
│     required_rate = assets_remaining / months_until_deadline│
│     recommendation += f" (need {required_rate:.1%}/mo)"     │
│   ELSE:                                                      │
│     status = "ON TRACK ✅"                                  │
│                                                              │
│ INSIGHT:                                                     │
│   → "At current rate (4.2%/mo), completion in 24 months"   │
│   → "DORA deadline in 12 months"                            │
│   → "⚠️ AT RISK: Need to double migration speed"            │
│   → "Recommendation: Increase team by 3 engineers"          │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ FEATURE 5: TOP RECOMMENDATIONS (Prioritized)               │
│                                                              │
│ SMART RECOMMENDATIONS ENGINE                                 │
│                                                              │
│ ALGORITHM:                                                   │
│   issues = SELECT * FROM crypto_assets                      │
│             WHERE compliance_status = 'FAIL'                │
│             OR quantum_risk->>'risk_category' = 'CRITICAL'  │
│                                                              │
│   FOR EACH issue:                                            │
│     priority_score = (                                       │
│       business_context.revenue_at_risk * 0.3 +              │
│       quantum_risk.risk_score * 0.3 +                       │
│       (100 - agility_score) * 0.2 +  # Harder = higher priority│
│       compliance_severity * 0.2                             │
│     )                                                        │
│                                                              │
│   recommendations = []                                       │
│   FOR issue IN TOP 10 BY priority_score:                    │
│     recommendation = {                                       │
│       rank: N,                                              │
│       title: f"Migrate {issue.algorithm} in {issue.system}",│
│       impact: {                                              │
│         revenue_protected: issue.revenue_at_risk,           │
│         customers_protected: issue.customer_count,          │
│         compliance_improvement: calculate_compliance_delta()│
│       },                                                     │
│       effort: estimate_effort(issue),                       │
│       deadline: issue.quantum_risk.migration_deadline,      │
│       owner: issue.business_owner,                          │
│       action: generate_action_plan(issue)                   │
│     }                                                        │
│     recommendations.append(recommendation)                   │
│                                                              │
│ DASHBOARD DISPLAY:                                           │
│   ┌──────────────────────────────────────────────────────┐  │
│   │  TOP 10 RECOMMENDATIONS (By Priority)               │  │
│   ├──────────────────────────────────────────────────────┤  │
│   │                                                      │  │
│   │  1. 🔴 Migrate RSA-2048 in payment-api              │  │
│   │     Impact: $4.8M/day revenue protected             │  │
│   │     Effort: 8 weeks | Deadline: 347 days            │  │
│   │     Owner: Sarah Chen (VP Payments)                 │  │
│   │     [View Details] [Create Ticket] [Assign Team]   │  │
│   │                                                      │  │
│   │  2. 🔴 Remove hardcoded keys in legacy-auth         │  │
│   │     Impact: 1.2M customers protected                │  │
│   │     Effort: 2 weeks | Deadline: IMMEDIATE           │  │
│   │     Owner: Security Team                            │  │
│   │     [View Details] [Create Ticket]                  │  │
│   │                                                      │  │
│   │  3. 🟠 Upgrade TLS 1.0 in api-gateway               │  │
│   │     Impact: DORA compliance                         │  │
│   │     Effort: 1 week | Deadline: 347 days             │  │
│   │     Owner: Platform Team                            │  │
│   │     [View Details] [Create Ticket]                  │  │
│   │                                                      │  │
│   │  ... (7 more)                                        │  │
│   └──────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ FEATURE 6: EXECUTIVE SUMMARY (Auto-Generated)              │
│                                                              │
│ ONE-PAGE EXECUTIVE REPORT (PDF Export)                      │
│                                                              │
│ ┌────────────────────────────────────────────────────────┐  │
│ │  CRYPTOGRAPHIC RISK EXECUTIVE SUMMARY                  │  │
│ │  Organization: ACME Corporation                        │  │
│ │  Report Date: 2024-12-15                               │  │
│ │  Period: Q4 2024                                       │  │
│ ├────────────────────────────────────────────────────────┤  │
│ │                                                        │  │
│ │  OVERALL POSTURE: 🟡 MODERATE RISK                     │  │
│ │                                                        │  │
│ │  KEY METRICS:                                          │  │
│ │  • Total Crypto Assets: 2,947                          │  │
│ │  • Compliance Rate: 73% (↑ 8% from Q3)                │  │
│ │  • Quantum-Vulnerable: 1,247 assets (42%)              │  │
│ │  • PQC Adoption: 287 assets (10%)                      │  │
│ │                                                        │  │
│ │  CRITICAL ISSUES:                                      │  │
│ │  • 12 systems use deprecated RSA-2048 for PCI data    │  │
│ │  • 3 systems have hardcoded encryption keys           │  │
│ │  • 8 vendor integrations use weak crypto              │  │
│ │                                                        │  │
│ │  REGULATORY RISK:                                      │  │
│ │  • DORA compliance deadline: 347 days (Jan 17, 2025)  │  │
│ │  • At current pace: ⚠️ Will miss deadline by 12 months │  │
│ │  • Estimated non-compliance cost: €10M+ fines         │  │
│ │                                                        │  │
│ │  BUSINESS IMPACT:                                      │  │
│ │  • Revenue at Risk: $14.2M/day (if crypto fails)      │  │
│ │  • Customers at Risk: 8.7M                             │  │
│ │  • Critical Systems at Risk: 18                        │  │
│ │                                                        │  │
│ │  TOP 3 RECOMMENDATIONS:                                │  │
│ │  1. Accelerate PQC migration (double team size)       │  │
│ │  2. Remove hardcoded keys (IMMEDIATE — 2 weeks)       │  │
│ │  3. Upgrade vendor crypto (contract renewal leverage) │  │
│ │                                                        │  │
│ │  INVESTMENT REQUIRED:                                  │  │
│ │  • $2.1M for PQC migration program                    │  │
│ │  • 6 additional engineers for 18 months               │  │
│ │  • ROI: Avoid €10M+ regulatory fines                  │  │
│ │                                                        │  │
│ │  Prepared by: CryptoScan Platform                      │  │
│ │  Approved by: CISO                                     │  │
│ └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

### ✅ Week 45-46 Deliverable

**Advanced analytics dashboard:**
1. Algorithm usage trending (time-series charts)
2. Compliance rate trending (quarter-over-quarter)
3. Risk heat map (by business unit / system)
4. PQC migration forecast (linear regression)
5. Smart recommendations engine (prioritized top 10)
6. Executive summary generator (auto PDF export)
7. Drill-down capabilities (click chart → detailed view)
8. Export capabilities (CSV, JSON, PDF)

**Testing:**
- View trending chart: RSA-2048 declining 42% over 12 months
- View heat map: Finance has 12 critical issues, Engineering has 0
- View forecast: Current pace = 24 months to complete, deadline = 12 months (AT RISK)
- View recommendations: Top 3 show revenue impact + effort + deadline
- Generate executive report PDF → 1-page summary with all key metrics

---

## WEEK 47-48: EXCEPTION MANAGEMENT + MIGRATION READINESS

### 🎯 Goal
Formal exception workflow + migration readiness assessment

### 📐 Architecture — Exception Management

```
┌─────────────────────────────────────────────────────────────┐
│         POLICY EXCEPTION MANAGEMENT SYSTEM v1.0             │
│         (Formal Approval Workflow + Audit Trail)            │
└─────────────────────────────────────────────────────────────┘

EXCEPTION CONCEPT:
  → Sometimes you CAN'T fix a crypto issue immediately
  → Vendor dependency, legacy system, business constraint
  → Need formal exception process with:
    - Business justification
    - Risk acceptance
    - Compensating controls
    - Expiration date
    - Approval by authorized person (CISO, CTO, etc.)

DATABASE SCHEMA:

┌──────────────────────────────────────────────────────────────┐
│ TABLE: policy_exceptions                                     │
│                                                              │
│ exception_id         UUID PK                                 │
│ asset_id             UUID FK → crypto_assets                │
│ policy_rule_id       VARCHAR(50)  Which rule is excepted    │
│ exception_type       VARCHAR(50)  RISK_ACCEPTANCE,          │
│                                   COMPENSATING_CONTROL, etc │
│ justification        TEXT         Business reason           │
│ risk_statement       TEXT         Acknowledged risk         │
│ compensating_controls TEXT        Mitigations in place      │
│ requested_by         VARCHAR(100) Who requested             │
│ requested_at         TIMESTAMP                              │
│ approved_by          VARCHAR(100) Who approved (CISO)       │
│ approved_at          TIMESTAMP                              │
│ approval_signature   TEXT         Digital signature         │
│ expiration_date      DATE         Exception expires         │
│ review_frequency     VARCHAR(50)  QUARTERLY, ANNUALLY       │
│ last_reviewed        TIMESTAMP                              │
│ status               VARCHAR(50)  PENDING, APPROVED,        │
│                                   EXPIRED, REVOKED          │
│ created_at           TIMESTAMP                              │
│ updated_at           TIMESTAMP                              │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ TABLE: exception_reviews                                     │
│ (Periodic reviews of active exceptions)                     │
│                                                              │
│ review_id            UUID PK                                 │
│ exception_id         UUID FK → policy_exceptions            │
│ review_date          TIMESTAMP                              │
│ reviewer             VARCHAR(100)                            │
│ still_valid          BOOLEAN     Still needed?              │
│ notes                TEXT                                    │
│ action_taken         VARCHAR(50) RENEWED, REVOKED, etc      │
└──────────────────────────────────────────────────────────────┘

EXCEPTION WORKFLOW:

┌──────────────────────────────────────────────────────────────┐
│ EXCEPTION REQUEST FLOW                                       │
│                                                              │
│ STEP 1: User identifies non-compliant asset                 │
│   → Dashboard shows: "RSA-2048 in legacy-system: FAIL"      │
│   → User clicks: [Request Exception]                        │
│                                                              │
│ STEP 2: Exception request form                              │
│   ┌────────────────────────────────────────────────────┐   │
│   │  REQUEST POLICY EXCEPTION                          │   │
│   ├────────────────────────────────────────────────────┤   │
│   │                                                    │   │
│   │  Asset: RSA-2048 in legacy-payment-system          │   │
│   │  Failed Rule: PCI-DSS-4.0-R4.2.1 (Strong Crypto)   │   │
│   │                                                    │   │
│   │  Exception Type:                                   │   │
│   │  ◉ Risk Acceptance                                 │   │
│   │  ○ Compensating Controls                           │   │
│   │  ○ Temporary (pending fix)                         │   │
│   │                                                    │   │
│   │  Business Justification: *                         │   │
│   │  [Legacy system critical for Q4 revenue.          │   │
│   │   Replacement project approved for Q1 2025.        │   │
│   │   Cannot fix before year-end financial close.]     │   │
│   │                                                    │   │
│   │  Risk Statement: *                                 │   │
│   │  [Acknowledge risk of RSA-2048 vulnerability.     │   │
│   │   Data exposure limited to historical transactions.│   │
│   │   New transactions routed to new system.]          │   │
│   │                                                    │   │
│   │  Compensating Controls:                            │   │
│   │  [✓] Network segmentation (isolated VLAN)         │   │
│   │  [✓] Additional monitoring (IDS alerts)           │   │
│   │  [✓] Data encryption at rest (separate layer)     │   │
│   │  [ ] Other: _____________________________          │   │
│   │                                                    │   │
│   │  Requested Expiration Date: [2025-03-31]          │   │
│   │  Review Frequency: [Quarterly ▼]                  │   │
│   │                                                    │   │
│   │  Requested By: [john.manager@example.com]         │   │
│   │                                                    │   │
│   │  [Submit for Approval] [Cancel]                   │   │
│   └────────────────────────────────────────────────────┘   │
│                                                              │
│ STEP 3: Approval routing                                    │
│   exception.status = "PENDING"                              │
│   notification_sent_to = [CISO, CTO, Compliance Officer]   │
│                                                              │
│   Email to approvers:                                        │
│     "Policy exception requested by John Manager             │
│      for RSA-2048 in legacy-payment-system.                 │
│      Review: https://cryptoscan.local/exceptions/{id}       │
│      Approve or Reject by: 2024-12-20"                      │
│                                                              │
│ STEP 4: CISO reviews and approves                           │
│   ┌────────────────────────────────────────────────────┐   │
│   │  EXCEPTION REVIEW (CISO View)                      │   │
│   ├────────────────────────────────────────────────────┤   │
│   │                                                    │   │
│   │  Request: RSA-2048 exception for legacy-payment    │   │
│   │  Requested by: John Manager (Business Owner)       │   │
│   │  Date: 2024-12-15                                  │   │
│   │                                                    │   │
│   │  RISK ASSESSMENT (Auto-Generated):                 │   │
│   │  • Quantum Risk Score: 85 (CRITICAL)               │   │
│   │  • Revenue at Risk: $800K/day                      │   │
│   │  • Customers at Risk: 120K                         │   │
│   │  • Compliance Scopes: PCI-DSS, SOC2                │   │
│   │                                                    │   │
│   │  COMPENSATING CONTROLS:                            │   │
│   │  ✅ Network segmentation verified                  │   │
│   │  ✅ IDS monitoring active                          │   │
│   │  ✅ Data-at-rest encryption confirmed              │   │
│   │                                                    │   │
│   │  RECOMMENDATION:                                   │   │
│   │  ⚠️ APPROVE WITH CONDITIONS                        │   │
│   │  • Max duration: 90 days                           │   │
│   │  • Monthly reviews required                        │   │
│   │  • Replacement project must stay on schedule      │   │
│   │                                                    │   │
│   │  CISO Decision:                                    │   │
│   │  ◉ Approve (with conditions above)                 │   │
│   │  ○ Reject                                           │   │
│   │                                                    │   │
│   │  Approval Notes:                                   │   │
│   │  [Approved for 90 days. Security team to monitor  │   │
│   │   replacement project progress weekly.]            │   │
│   │                                                    │   │
│   │  Digital Signature: [Sign with PKI cert]          │   │
│   │  [Submit Approval]                                 │   │
│   └────────────────────────────────────────────────────┘   │
│                                                              │
│ STEP 5: Exception activated                                 │
│   UPDATE policy_exceptions                                  │
│   SET status = 'APPROVED',                                  │
│       approved_by = 'ciso@example.com',                     │
│       approved_at = NOW(),                                   │
│       approval_signature = CISO_DIGITAL_SIGNATURE,          │
│       expiration_date = '2025-03-31';                       │
│                                                              │
│   UPDATE crypto_assets                                      │
│   SET compliance_status = 'EXCEPTION'                       │
│   WHERE asset_id = ...;                                     │
│                                                              │
│   # Notification                                             │
│   send_email(john.manager@example.com,                      │
│               "Exception approved. Expires 2025-03-31")     │
│                                                              │
│ STEP 6: Periodic review (quarterly)                         │
│   CRON JOB:                                                  │
│     exceptions_due_review = SELECT * FROM policy_exceptions │
│                             WHERE status = 'APPROVED'       │
│                             AND last_reviewed + review_interval < NOW()│
│                                                              │
│     FOR exception IN exceptions_due_review:                 │
│       send_review_reminder(exception.approved_by)           │
│       CREATE exception_review record                        │
│                                                              │
│ STEP 7: Expiration handling                                 │
│   CRON JOB (daily):                                          │
│     expired_exceptions = SELECT * FROM policy_exceptions    │
│                          WHERE expiration_date <= TODAY()   │
│                          AND status = 'APPROVED'            │
│                                                              │
│     FOR exception IN expired_exceptions:                    │
│       UPDATE policy_exceptions                              │
│       SET status = 'EXPIRED'                                │
│       WHERE exception_id = exception.exception_id;          │
│                                                              │
│       UPDATE crypto_assets                                  │
│       SET compliance_status = 'FAIL'  # Back to failure     │
│       WHERE asset_id = exception.asset_id;                  │
│                                                              │
│       send_alert(exception.requested_by,                    │
│                  "Exception expired. Asset now non-compliant")│
└──────────────────────────────────────────────────────────────┘

MIGRATION READINESS ASSESSMENT:

┌──────────────────────────────────────────────────────────────┐
│ MIGRATION READINESS SCORE                                    │
│                                                              │
│ FOR EACH system:                                             │
│                                                              │
│   # Factor 1: Crypto agility score (from Week 37-38)        │
│   agility_factor = system.current_agility_score / 100       │
│     → Score 80 → factor 0.8 (highly ready)                  │
│     → Score 20 → factor 0.2 (not ready)                     │
│                                                              │
│   # Factor 2: Technical dependencies                        │
│   GRAPH QUERY:                                               │
│     dependency_count = COUNT(                               │
│       (system)-[:CALLS|DEPENDS_ON*1..3]->(other_system)    │
│     )                                                        │
│   IF dependency_count == 0:                                 │
│     dependency_factor = 1.0  # Isolated, easy to migrate    │
│   ELSE IF dependency_count <= 3:                            │
│     dependency_factor = 0.8  # Few dependencies             │
│   ELSE IF dependency_count <= 10:                           │
│     dependency_factor = 0.5  # Moderate dependencies        │
│   ELSE:                                                      │
│     dependency_factor = 0.2  # Highly coupled               │
│                                                              │
│   # Factor 3: Testing maturity                              │
│   IF system has crypto test suite:                          │
│     testing_factor = 1.0                                     │
│   ELSE IF system has general test suite:                    │
│     testing_factor = 0.6                                     │
│   ELSE:                                                      │
│     testing_factor = 0.2                                     │
│                                                              │
│   # Factor 4: Team capacity                                 │
│   # (Manual input or from project management system)        │
│   team_capacity = system.metadata.team_capacity             │
│     → "HIGH" → 1.0                                           │
│     → "MEDIUM" → 0.6                                         │
│     → "LOW" → 0.3                                            │
│                                                              │
│   # Factor 5: Business change freeze periods                │
│   IF system in change freeze (e.g., year-end):             │
│     freeze_factor = 0.5  # Half capacity                    │
│   ELSE:                                                      │
│     freeze_factor = 1.0                                      │
│                                                              │
│   # Final readiness score (0-100)                           │
│   readiness_score = (                                        │
│     agility_factor * 0.4 +                                  │
│     dependency_factor * 0.2 +                               │
│     testing_factor * 0.2 +                                  │
│     team_capacity * 0.15 +                                  │
│     freeze_factor * 0.05                                    │
│   ) * 100                                                    │
│                                                              │
│   # Categorize                                               │
│   IF readiness_score >= 80:                                 │
│     readiness_category = "READY_NOW"                        │
│     recommendation = "Can start migration immediately"      │
│   ELSE IF readiness_score >= 60:                            │
│     readiness_category = "READY_WITH_PREP"                 │
│     recommendation = "Needs 2-4 weeks prep"                │
│   ELSE IF readiness_score >= 40:                            │
│     readiness_category = "NOT_READY"                        │
│     recommendation = "Needs significant work (2-3 months)" │
│   ELSE:                                                      │
│     readiness_category = "BLOCKED"                          │
│     recommendation = "Cannot migrate until blockers resolved"│
│                                                              │
│   RETURN readiness_score, readiness_category, recommendation│
└──────────────────────────────────────────────────────────────┘

ALTER TABLE systems ADD COLUMN migration_readiness_score INT;
ALTER TABLE systems ADD COLUMN migration_readiness_category VARCHAR(50);

DASHBOARD VIEW:

┌──────────────────────────────────────────────────────────────┐
│ MIGRATION READINESS DASHBOARD                                │
│                                                              │
│ ┌────────────────────────────────────────────────────────┐  │
│ │  MIGRATION WAVE PLANNING                               │  │
│ ├────────────────────────────────────────────────────────┤  │
│ │                                                        │  │
│ │  WAVE 1 (Ready Now — Start Immediately)               │  │
│ │  ┌──────────────────────────────────────────────────┐ │  │
│ │  │ 12 systems ready for migration                   │ │  │
│ │  │ • api-gateway-v2 (score: 92)                      │ │  │
│ │  │ • reporting-service (score: 88)                   │ │  │
│ │  │ • customer-portal (score: 85)                     │ │  │
│ │  │ ... 9 more                                        │ │  │
│ │  │                                                   │ │  │
│ │  │ Est. effort: 6 weeks total                        │ │  │
│ │  │ [Create Wave 1 Project] [Assign Team]            │ │  │
│ │  └──────────────────────────────────────────────────┘ │  │
│ │                                                        │  │
│ │  WAVE 2 (Needs Prep — Start in 4 weeks)              │  │
│ │  ┌──────────────────────────────────────────────────┐ │  │
│ │  │ 21 systems (score: 60-79)                        │ │  │
│ │  │ Prep needed:                                      │ │  │
│ │  │ • Add crypto test suites (18 systems)             │ │  │
│ │  │ • Externalize config (12 systems)                 │ │  │
│ │  │ • Coordinate with vendors (5 integrations)        │ │  │
│ │  │                                                   │ │  │
│ │  │ Est. effort: 12 weeks total                       │ │  │
│ │  │ [Create Wave 2 Prep Tasks]                       │ │  │
│ │  └──────────────────────────────────────────────────┘ │  │
│ │                                                        │  │
│ │  WAVE 3 (Blocked — Resolve Issues First)             │  │
│ │  ┌──────────────────────────────────────────────────┐ │  │
│ │  │ 8 systems (score: <40)                           │ │  │
│ │  │ Blockers:                                         │ │  │
│ │  │ • legacy-payment: Vendor dependency (blocker)     │ │  │
│ │  │ • mainframe-bridge: No PQC library for COBOL      │ │  │
│ │  │ • third-party-api: Vendor not PQC-ready           │ │  │
│ │  │                                                   │ │  │
│ │  │ [View Blocker Details] [Request Exceptions]      │ │  │
│ │  └──────────────────────────────────────────────────┘ │  │
│ └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

### ✅ Week 47-48 Deliverable

**Exception management + migration readiness:**
1. Policy exception workflow (request → approval → review → expiration)
2. `policy_exceptions` table (formal exception records)
3. `exception_reviews` table (periodic review tracking)
4. Exception request form (web UI)
5. Approval workflow (CISO/CTO digital signature)
6. Expiration automation (exceptions auto-expire, asset returns to FAIL)
7. Exception audit trail (who approved, when, why)
8. Migration readiness scoring (5-factor assessment)
9. Migration wave planning dashboard (ready now, needs prep, blocked)
10. Readiness recommendations (what to fix to increase readiness)

**Testing:**
- Request exception for RSA-2048 in legacy-payment
- CISO approves with 90-day expiration
- Exception status: APPROVED (asset shows "EXCEPTION" instead of "FAIL")
- 90 days pass → exception expires → asset returns to FAIL → alert sent
- Calculate readiness: api-gateway-v2 = 92 (READY_NOW), legacy-payment = 25 (BLOCKED)
- Dashboard shows: 12 systems in Wave 1, 21 in Wave 2, 8 blocked

---

# 🎯 MONTH 10-12 COMPLETE END-TO-END SUMMARY

```
┌──────────────────────────────────────────────────────────────┐
│         PART 4 COMPLETE: MONTHS 10-12 DELIVERABLE            │
│         Operational Maturity + Future Readiness              │
└──────────────────────────────────────────────────────────────┘

ORGANIZATION NOW HAS:

1. CRYPTO AGILITY ASSESSMENT (Week 37-38)
   → Every system scored 0-100 for crypto agility
   → Identifies hardcoded crypto, scattered configs, no testing
   → Prioritized improvement recommendations

2. QUANTUM RISK ANALYSIS (Week 39-40)
   → Multi-factor quantum vulnerability scoring
   → Shor's algorithm impact (RSA/ECDH = total break)
   → Grover's algorithm impact (AES-128 → 64-bit effective)
   → HNDL (Harvest Now, Decrypt Later) risk assessment
   → Migration deadline calculator (regulatory + HNDL + quantum threat)
   → PQC replacement recommendations (ML-KEM, ML-DSA)

3. OT/ICS CRYPTO VISIBILITY (Week 41-42)
   → Passive scanning (ZERO impact on safety-critical systems)
   → Protocol-specific detection (OPC-UA, DNP3, Modbus, IEC 61850)
   → Device fingerprinting (vendor, model, firmware)
   → Unencrypted OT traffic detection
   → CVE mapping for OT firmware crypto vulnerabilities

4. VENDOR CRYPTO DISCOVERY (Week 43-44)
   → 4 discovery methods (API scan, SBOM, questionnaire, docs)
   → Vendor crypto risk scoring
   → Supply chain transparency (what crypto do vendors use?)
   → Vendor-specific compliance tracking

5. ADVANCED ANALYTICS (Week 45-46)
   → Algorithm usage trending (time-series)
   → Compliance rate trending
   → Risk heat maps (by business unit)
   → PQC migration forecasting (on-track vs at-risk)
   → Smart recommendations (top 10 prioritized actions)
   → Executive summary generator (auto PDF)

6. EXCEPTION MANAGEMENT (Week 47-48)
   → Formal exception request workflow
   → CISO/CTO approval with digital signature
   → Periodic review automation
   → Exception expiration (auto-revert to non-compliant)
   → Audit trail (who, when, why)

7. MIGRATION READINESS (Week 47-48)
   → 5-factor readiness assessment
   → Migration wave planning (ready now, needs prep, blocked)
   → Blocker identification
   → Effort estimation

EXAMPLE COMPLETE WORKFLOW:

Organization with 148 systems, 2,947 crypto assets:

1. Agility Assessment Run
   → 12 systems: EXCELLENT agility (80-100)
   → 47 systems: GOOD agility (60-79)
   → 68 systems: MODERATE agility (40-59)
   → 18 systems: POOR agility (20-39)
   → 3 systems: CRITICAL agility (0-19) — hardcoded keys, no tests

2. Quantum Risk Analysis
   → 1,247 assets (42%): Quantum-vulnerable (RSA, ECDH, ECDSA)
   → 287 assets (10%): PQC-ready
   → 1,413 assets (48%): Quantum-resistant (AES-256, SHA-512)
   → HNDL risk: 342 assets have critical HNDL risk (long-lived data)
   → Deadline: 347 days to DORA compliance

3. OT/ICS Scan (Manufacturing Plant)
   → 87 OT devices discovered
   → 34 devices (39%): NO crypto (unencrypted Modbus)
   → 28 devices (32%): Encrypted (OPC-UA with AES-256)
   → 8 devices: Critical CVEs in firmware

4. Vendor Crypto Assessment
   → 47 vendors assessed
   → 8 vendors: HIGH risk (weak crypto, no PQC plan)
   → Contract renewal leverage: Require TLS 1.3 + PQC roadmap

5. Migration Planning
   → Wave 1: 12 systems ready now (6 weeks)
   → Wave 2: 21 systems need prep (12 weeks)
   → Wave 3: 8 systems blocked (vendor dependencies)

6. Executive Report Generated
   → Compliance rate: 73% (↑ 8% from Q3)
   → At-risk status: Will miss DORA deadline by 12 months at current pace
   → Recommendation: Double team size, accelerate to 8.4%/month migration
   → Investment: $2.1M for PQC program
   → ROI: Avoid €10M+ fines + data breach risk mitigation

RESULT:
  ✅ Full crypto maturity assessment
  ✅ Quantum-readiness roadmap
  ✅ OT/ICS visibility (safety-first approach)
  ✅ Vendor supply chain transparency
  ✅ Data-driven migration planning
  ✅ Executive buy-in (business case proven)
  ✅ Formal exception handling (risk governance)
```