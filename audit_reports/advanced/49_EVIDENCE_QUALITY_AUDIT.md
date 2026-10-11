# 49_EVIDENCE_QUALITY_AUDIT.md
## ZELNX CryptoScan — Evidence Quality / Proof Strength Audit

**Generated:** 2026-09-20  
**Method:** Deep inspection of evidence classification, strength grading, and authoritative evidence determination  
**Scope:** Evidence strength classification across all discovery sources and evidence types

---

## EXECUTIVE SUMMARY

| Evidence Aspect | Score | Status |
|-----------------|-------|--------|
| Evidence Classification | 6/10 | Basic classification exists |
| Strength Grading | 5/10 | Confidence bands only |
| Authoritative Hierarchy | 4/10 | Not formally defined |
| Evidence Preservation | 8/10 | Chain hash integrity |
| Conflict Handling | 3/10 | Silent overwrite risk |
| Provenance Tracking | 7/10 | Good metadata |
| Replayability | 6/10 | Limited to static scanner |

**Overall: 5.5/10** — Evidence exists but no formal quality framework

---

## 1. EVIDENCE STRENGTH CLASSIFICATION

### 1.1 Current Classification (Implicit)

**File:** `services/evidence/evidence/core/pipeline.py` + `services/universal_crypto/universal_crypto/confidence.py`

```python
# Confidence bands (from confidence.py):
# HIGH: 0.8-1.0  - Direct observation, deterministic
# MEDIUM: 0.5-0.8 - Corroborated, partial
# LOW: 0.0-0.5   - Heuristic, inferred

# Evidence types (from EvidenceType enum):
AST, BINARY, CONFIG, CERTIFICATE, PROTOCOL, LIBRARY, RUNTIME
```

### 1.2 Evidence Strength Hierarchy (Current - Implicit)

| Rank | Evidence Type | Source | Confidence | Example |
|------|---------------|--------|------------|---------|
| 1 (Highest) | **SOURCE_CODE (AST)** | Static scanner | HIGH (0.9+) | `KeyPairGenerator.getInstance("RSA")` at line 42 |
| 2 | **CERTIFICATE (X.509)** | Network/Config scanner | VERIFIED (1.0) | Cert parsed via `cryptography` lib |
| 3 | **NETWORK_PROTOCOL (TLS)** | Active probe | VERIFIED (1.0) | ServerHello parsed |
| 4 | **BINARY (Disassembly)** | Binary scanner | MEDIUM-HIGH (0.7-0.9) | CAPSTONE disassembly |
| 5 | **LIBRARY_FINGERPRINT** | Binary/Source | MEDIUM (0.6-0.8) | Symbol/string matching |
| 6 | **CONFIGURATION** | Config parser | MEDIUM (0.6-0.8) | nginx.conf, k8s YAML |
| 7 | **RUNTIME_API** | Live engine | MEDIUM (0.5-0.7) | LD_PRELOAD intercept |
| 8 | **DEPENDENCY (SBOM)** | SBOM import | MEDIUM (0.5-0.7) | Lockfile parsing |
| 9 | **RUNTIME_LOADED** | Live engine | LOW-MEDIUM (0.4-0.6) | Library loaded but not used |
| 10 | **HEURISTIC/INFERRED** | Unknown detector | LOW (0.1-0.4) | High entropy strings |

---

## 2. AUTHORITATIVE EVIDENCE HIERARCHY — NOT FORMALIZED

### 2.1 Current State: No Explicit Hierarchy

**Current:** Evidence types have implicit confidence via `confidence.py:score_evidence()` but no formal authority ranking.

```python
# confidence.py:score_evidence() - simplified
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
    # Weighted average with diminishing returns
```

### 2.2 Missing: Formal Evidence Authority Model

**Required:** Explicit authority hierarchy with clear rules

| Authority Level | Evidence Type | Criteria | Override Rule |
|-----------------|---------------|----------|---------------|
| **LEVEL 1: DIRECT OBSERVATION** | X.509 Certificate parsing | Cryptographic verification via `cryptography` lib | Cannot be overridden |
| **LEVEL 1: DIRECT OBSERVATION** | TLS ServerHello parsing | RFC-compliant parsing via `cryptography` | Cannot be overridden |
| **LEVEL 1: DIRECT OBSERVATION** | AST detection | Deterministic AST traversal | Cannot be overridden |
| **LEVEL 2: CORROBORATED** | Binary disassembly + strings | Multiple independent indicators | Overridden by Level 1 |
| **LEVEL 2: CORROBORATED** | Library fingerprint (multi-class) | Imports + symbols + constants + strings | Overridden by Level 1 |
| **LEVEL 3: DERIVED** | Configuration parsing | Parser correctness | Overridden by Level 1,2 |
| **LEVEL 3: DERIVED** | SBOM import | Feed quality dependent | Overridden by Level 1,2 |
| **LEVEL 4: INFERRED** | Runtime loaded library | Library present but not used | Overridden by all above |
| **LEVEL 5: HEURISTIC** | High entropy string | Entropy > threshold | Overridden by all above |
| **LEVEL 6: UNVERIFIED** | Vendor documentation | No technical verification | Lowest authority |

---

## 3. EVIDENCE TYPE ANALYSIS

### 3.1 Evidence Quality by Type

| Evidence Type | Collection Method | Verification | Reproducibility | Authority |
|---------------|-------------------|--------------|-----------------|-----------|
| **SOURCE_CODE (AST)** | Deterministic AST traversal | Syntax verification | ✅ 100% | **HIGHEST** |
| **CERTIFICATE (X.509)** | `cryptography.x509` parsing | RFC 5280 compliant | ✅ 100% | **HIGHEST** |
| **NETWORK_PROTOCOL (TLS)** | Active probe + `cryptography` | RFC 8446 compliant | ✅ 100% (per probe) | **HIGHEST** |
| **BINARY (Disassembly)** | CAPSTONE disassembly | Instruction verification | ✅ Deterministic | HIGH |
| **BINARY (Strings)** | String extraction | Entropy + pattern | ⚠️ Context-dependent | MEDIUM-HIGH |
| **LIBRARY_FINGERPRINT** | Multi-class (imports, symbols, constants, APIs, deps) | Cross-reference | ⚠️ Version-dependent | MEDIUM-HIGH |
| **CONFIGURATION** | Parser per format (nginx, k8s, etc.) | Schema validation | ✅ Deterministic | MEDIUM-HIGH |
| **RUNTIME_API** | LD_PRELOAD / eBPF intercept | Runtime verification | ⚠️ Sampling-based | MEDIUM |
| **RUNTIME_LOADED** | `/proc/pid/maps` or similar | Library presence only | ✅ Deterministic | MEDIUM |
| **DEPENDENCY (SBOM)** | Lockfile parsing | Lockfile integrity | ✅ Deterministic | MEDIUM |
| **DEPENDENCY (Cloud API)** | Cloud provider API | API response | ✅ API contract | MEDIUM |
| **HARDWARE (TPM/CPU)** | CPUID, TPM quotes | Hardware attestation | ⚠️ Platform-dependent | MEDIUM |
| **HSM (PKCS#11)** | PKCS#11 queries | HSM response | ⚠️ HSM-dependent | MEDIUM |
| **VENDOR_DOCUMENTATION** | Manual entry / PDF parsing | Human verification | ❌ Non-deterministic | LOW |
| **HEURISTIC/UNKNOWN** | Entropy + pattern matching | Statistical | ⚠️ Probabilistic | LOWEST |

---

### 3.3 Evidence Quality Gaps

| Gap | Impact |
|-----|--------|
| **No formal authority ranking** | Conflicts resolved by confidence score only |
| **No evidence freshness tracking** | Old evidence weighted same as new |
| **No collector reputation** | All collectors treated equally |
| **No environment trust level** | Dev vs prod evidence weighted same |
| **No collector calibration** | No false positive rate per collector |
| **No evidence decay model** | Evidence never expires |

---

## 4. EVIDENCE CLASSIFICATION — CURRENT IMPLEMENTATION

### 4.1 EvidenceType Enum

**File:** `shared/shared_models/shared_models/enums.py` (implied from imports)

```python
class EvidenceType(Enum):
    AST = "ast"
    BINARY = "binary"
    CONFIG = "config"
    CERTIFICATE = "certificate"
    PROTOCOL = "protocol"
    LIBRARY = "library"
    RUNTIME = "runtime"
```

### 4.2 Evidence in Universal Crypto Engine

**File:** `services/universal_crypto/universal_crypto/engine.py`

```python
# Evidence creation per source:
_SOURCE_EVIDENCE_KIND = {
    "source_code": EvidenceType.AST,
    "binaries": EvidenceType.BINARY,
    "shared_libraries": EvidenceType.BINARY,
    "package_dependencies": EvidenceType.LIBRARY,
    "configuration": EvidenceType.CONFIG,
    "certificates": EvidenceType.CERTIFICATE,
    "keys_metadata": EvidenceType.CONFIG,
    "trust_stores": EvidenceType.CERTIFICATE,
    "network_protocols": EvidenceType.PROTOCOL,
    "tls_endpoints": EvidenceType.PROTOCOL,
    "ssh": EvidenceType.PROTOCOL,
    "ipsec": EvidenceType.PROTOCOL,
    "vpn": EvidenceType.PROTOCOL,
    "runtime": EvidenceType.RUNTIME,
    "libraries": EvidenceType.LIBRARY,
    "hardcoded_scan": EvidenceType.CONFIG,
    "randomness_scan": EvidenceType.RUNTIME,
    "custom_crypto": EvidenceType.BINARY,
    "key_metadata": EvidenceType.CONFIG,
}
```

---

## 5. EVIDENCE STRENGTH IN PRACTICE

### 5.1 Confidence Calculation

**File:** `services/universal_crypto/universal_crypto/confidence.py`

```python
def score_evidence(evidence_list):
    # Weighted by evidence type
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

**Band Assignment:**
```python
def band_for(confidence):
    if confidence >= 0.8: return "HIGH"
    elif confidence >= 0.5: return "MEDIUM"
    else: return "LOW"
```

### 5.2 Confidence Gaps

| Gap | Example |
|-----|---------|
| **No source reputation** | Unknown scanner = same weight as verified scanner |
| **No environment context** | Dev env finding = same weight as prod |
| **No temporal decay** | 2020 finding = same weight as 2026 |
| **No cross-source correlation bonus** | Same fact from 3 sources = only slightly higher |
| **No negative evidence** | Absence of evidence not tracked |

---

## 6. EVIDENCE CONFLICT RESOLUTION

### 6.1 Current: Silent Overwrite Risk

**File:** `services/evidence/evidence/core/pipeline.py`

```python
# Deduplication by content_hash - first wins
seen_hashes = set()
for finding, chash in hashed:
    if chash in seen_hashes:
        duplicates_collapsed += 1
        continue
    seen_hashes.add(chash)
    deduped.append((finding, chash))
```

**Problem:** Different sources with conflicting facts but same content_hash (rare) or different content_hash but same logical fact → both stored, no conflict flag.

### 6.2 Missing Conflict Detection

| Conflict Type | Detected? | Resolution |
|---------------|-----------|------------|
| Same fact, different values | ❌ | Both stored |
| Same asset, different algorithms | ❌ | Both stored |
| Network vs Source disagreement | ❌ | Both stored |
| Runtime vs Static disagreement | ❌ | Both stored |
| Certificate vs Network cert | ❌ | Both stored |

---

## 5. EVIDENCE PROVENANCE & REPLAYABILITY

### 5.1 Provenance Tracking (Good)

**File:** `services/evidence/evidence/core/pipeline.py` → `EvidenceRecord.provenance`

```python
provenance: dict = {
    "collector": "static-multi-scanner-v1.0",
    "scan_id": "scan-uuid",
    "scan_timestamp": "2026-09-20T10:00:00Z",
    "git_context": {
        "commit_hash": "abc123",
        "branch": "main",
        "repository_url": "https://github.com/org/repo"
    },
    "detector": "java_parser",
    "extractor": "algorithm_extractor"
}
```

### 5.2 Replayability

| Aspect | Supported | Method |
|--------|-----------|--------|
| **Re-verify evidence hash** | ✅ | `ContentHasher.verify_hash()` |
| **Re-verify chain hash** | ✅ | `ChainHasher.verify_chain()` |
| **Re-generate CBOM** | ✅ | `CbomGenerator.from_records()` |
| **Re-run policy** | ✅ | `PolicyEngine.evaluate()` |
| **Re-build graph** | ✅ | `GraphEngine.build()` |
| **Re-run scanner** | ⚠️ Partial | Source code: yes. Binary: yes. Network: requires target. Runtime: requires live env. |
| **Re-play live events** | ❌ | Event stream not fully replayable |

---

## 6. EVIDENCE QUALITY METRICS — NOT MEASURED

### 6.1 Missing Metrics

| Metric | Currently Tracked |
|--------|-------------------|
| False Positive Rate per detector | ❌ |
| False Negative Rate per detector | ❌ |
| Evidence freshness distribution | ❌ |
| Collector accuracy | ❌ |
| Evidence conflict rate | ❌ |
| Evidence decay over time | ❌ |
| Collector calibration | ❌ |
| Environment-specific accuracy | ❌ |

---

## 7. AUTHORITATIVE EVIDENCE DETERMINATION

### 7.1 Current: Confidence Score Only

**Problem:** A finding with 3 MEDIUM evidence pieces (confidence 0.65) beats 1 HIGH evidence piece (confidence 0.9) due to accumulation.

```python
# Simplified confidence accumulation:
total_confidence = 1 - product(1 - w_i)  # Diminishing returns
# 3 x MEDIUM (0.6 each) ≈ 0.94 > 1 x HIGH (0.95)
```

### 7.2 Required: Authority-Based Resolution

**Required Logic:**
```python
def resolve_conflict(evidence_list):
    # 1. Group by authority level
    # 2. Highest authority wins
    # 3. If same authority: highest confidence wins
    # 4. If tied: most recent wins
    # 5. Record conflict in audit log
```

---

## 8. EVIDENCE QUALITY RECOMMENDATIONS

### P0 — Critical

1. **Formalize Evidence Authority Hierarchy** — 6-level explicit model with override rules
2. **Implement Conflict Detection** — Flag contradictory evidence, don't silently store both
3. **Add Evidence Freshness Decay** — Time-based confidence decay
4. **Add Collector Calibration** — Track FP/FN per detector, weight accordingly

### P1 — High

4. **Add Evidence Freshness Decay** — Exponential decay based on age
5. **Add Cross-Source Correlation Bonus** — Same fact from independent sources = authority boost
6. **Add Negative Evidence Tracking** — Record "searched but not found"
7. **Implement Evidence Decay Model** — Exponential decay with half-life

### P2 — Medium

7. **Collector Calibration** — Track FP/FN per detector, auto-weight
8. **Environment Trust Levels** — Prod evidence > Staging > Dev
10. **Evidence Decay Model** — Configurable half-life per evidence type
11. **Evidence Quality Dashboard** — Per-collector FP/FN rates, calibration status

### P3 — Enhancement

12. **Evidence Lineage Visualization** — Source → Evidence → Fact → Finding
13. **Evidence Quality Scoring** — Composite score per finding
14. **Automated Evidence Validation** — Cross-check against known-good corpora

---

## 7. VERDICT

**Evidence exists but lacks a formal quality framework.** Evidence is collected with provenance and hashed for integrity, but:

| Missing | Impact |
|---------|--------|
| Formal authority hierarchy | Conflicts resolved by accumulation, not authority |
| Conflict detection | Contradictory evidence silently coexists |
| Freshness decay | Old evidence weighs same as new |
| Collector calibration | All collectors equal weight |
| Negative evidence | Absence not recorded |
| Authority-based resolution | Confidence accumulation wins |

**To fix:** 4-6 weeks for authority model, conflict detection, freshness decay, collector calibration.

---

## 8. VERIFICATION EVIDENCE

| Finding | File |
|---------|------|
| EvidencePipeline | `services/evidence/evidence/core/pipeline.py` |
| ContentHasher | `services/evidence/evidence/hashing/content_hasher.py` |
| ChainHasher | `services/evidence/evidence/hashing/chain_hasher.py` |
| CanonicalSerializer | `services/evidence/evidence/hashing/canonical_serializer.py` |
| EvidenceRecord model | `services/database/db/models/evidence_record.py` |
| UniversalCryptoEngine | `services/universal_crypto/universal_crypto/engine.py` |
| Confidence scoring | `services/universal_crypto/universal_crypto/confidence.py` |
| Evidence types | `shared/shared_models/shared_models/enums.py` |
| EvidenceType enum | `shared/shared_models/shared_models/observation.py` |
| Safe finding | `shared/shared_models/shared_models/safe_finding.py` |
| VerificationLog model | `services/database/db/models/verification_log.py` |
| ScanManifest | `services/evidence/evidence/models/scan_manifest.py` |
---

## UPDATE ADDENDUM — Round 19 (2026-10-10): authority hierarchy built

**P0 #1 (formalize evidence authority hierarchy) is now code.**
`services/normalization/normalization/authority.py` ships the explicit
6-level model this report asked for:

| Tier | Label | Provenance signal |
|---|---|---|
| 1 | RUNTIME | live/runtime scanners, eBPF/probe collectors, `source.type=RUNTIME` |
| 2 | BINARY | binary/ELF/JAR/container/image analyzers |
| 3 | STATIC | static/AST/tree-sitter/regex/semgrep scanners |
| 4 | DECLARED | cloud/config/IaC/terraform/pipeline collectors |
| 5 | MANUAL | manual/import/form collectors |
| 6 | UNRANKED | no recognizable provenance — never guessed |

It is wired into the conflict detector (`normalization/conflicts.py`):
every conflict from `GET /findings/conflicts` now carries an
`authority` annotation saying which observer the hierarchy would favor
and whether that preference is decisive (single highest tier) or a tie
needing a human/policy decision. Conflicts are still reported, never
auto-resolved — the model annotates, it does not override.

Also closed from this report's P0 list: #2 conflict detection was
already built (round 15). Remaining open: freshness decay (#3/#4),
collector calibration, negative-evidence tracking — product-level
enhancements, honestly tracked in 00_ROUND_STATUS.

Tests: `services/normalization/tests/unit/test_authority.py` (16 tests;
suite 139).

## Round 27 update (2026-10-10) — full P0 list re-verified; freshness decay built

* **Authority hierarchy (#1) — confirmed shipped** (round 19, re-read this
  round): `normalization/authority.py` defines the six RUNTIME/BINARY/
  STATIC/DECLARED/MANUAL/UNRANKED tiers over provenance tokens;
  `normalization/conflicts.py` annotates every conflict with the
  hierarchy's preference (decisive vs tie) — annotation, never override.
* **Conflict detection (#2) — confirmed shipped** (round 15): the three
  classes (ALGORITHM/PARAMETER/STATUS mismatch) at
  `GET /findings/conflicts`, within-scan and scan-vs-scan, with
  retracted evidence excluded so soft-deletes cannot manufacture
  conflicts.
* **Evidence freshness decay (#3/#4/#7) — NOW BUILT (this round).**
  `privacy/state.py` ships the exponential decay model this report
  asked for: `decay_factor(age, half_life) = 0.5 ** (age / half_life)`
  with **evidence-class-aware half-lives** (RUNTIME 7d, DECLARED/MANUAL
  30d, BINARY/STATIC 90d — runtime observations describe a system that
  keeps changing, artifact evidence persists), a **verified floor**
  (old verification decays but never silently becomes "no evidence"),
  and honest edges: never-observed → 0, clock skew → no decay.
  Wired end to end at `POST /security/intelligence/state`: the response
  now carries `decayed_confidence` next to the raw `confidence`, with
  replayable notes (age, half-life, factor). Tests:
  `services/privacy/tests/unit/test_state_engine.py` (+6) and
  `services/api/tests/unit/test_security_intelligence.py` (+1).
* **Still open, honestly:** collector calibration (#4 — needs FP/FN
  ground truth per detector), cross-source correlation bonus (#5),
  negative-evidence tracking (#6 — adjacent to the clean-scan baselines
  from round 23, but "searched and not found" records are not yet a
  first-class evidence type).

## Round 28 update (2026-10-10) — collector calibration + negative evidence built

* **Collector calibration (P0 #4) — NOW BUILT (this round).**
  `normalization/calibration.py` + `GET /findings/detectors/scorecards`
  calibrate every detector over recent scans through the two honest
  proxies production records: **retractions** (soft-deleted evidence —
  operator-judged false positives) and **authority losses** (the
  non-preferred side of *decisive* conflicts under the 6-tier
  hierarchy; ties are not detector failures). Tiers are deterministic
  (CALIBRATED / WATCH / DEGRADED, with INSUFFICIENT_DATA under 20
  observations — thin data is reported as thin, never scored) and each
  card carries a `reliability_multiplier` for consumers — annotation
  only, recorded confidence is never rewritten. The loss share is
  measured against the detector's own observation count, so one
  disagreement out of one conflict is not a pattern. Observer identity
  resolves from evidence provenance (`scanner_ids` → provenance →
  finding source), with unclaimed evidence surfaced as UNATTRIBUTED
  rather than hidden. Tombstones count toward retraction but never feed
  conflict detection. Tests: 9 unit
  (`services/normalization/tests/unit/test_calibration.py`) + 2 API
  (`services/api/tests/unit/test_round28_calibration.py`).
* **Negative evidence tracking (P1 #6) — NOW BUILT.**
  `GET /scans/{scan_id}/coverage` is the scan coverage statement: the
  full origin universe (source/test/generated/vendored/archive) with
  zero-observation origins explicitly listed, per-detector observation
  counts from evidence provenance, the unattributed count, and the
  clean-scan flag — absence is recorded and queryable, never inferred
  from silence. The method block states the honest edge: a zero can
  mean "searched, nothing found" or "origin not applicable to this
  target", and the payload says which question a zero answers.
* **Still open:** cross-source correlation bonus (P1 #5 — the
  corroboration bonus in `confidence_from_sources` covers part of it;
  a tier-aware authority boost remains), and labeled ground-truth
  calibration (would need FP/FN labels, not proxies).

## Round 29 update (2026-10-10) — cross-source correlation bonus built

* **Cross-source correlation bonus (P1 #5) — NOW BUILT (this round).**
  `normalization/corroboration.py` + `GET /findings/corroboration` are
  the complementary surface to conflict detection: where *independent*
  observers of the same site fully AGREE (same normalized algorithm and
  parameters), the agreed fact is reported with a tier-aware
  **suggested** confidence uplift — +0.05 for two same-tier observers,
  +0.10 when the agreement spans distinct authority tiers (a static
  scanner and a runtime probe obtained the fact by genuinely different
  methods), +0.15 capped for three or more. Conservative by
  construction: one scanner twice is duplication not corroboration;
  partial agreement is a conflict, not corroboration; observers without
  identity cannot establish independence so no uplift is suggested;
  retracted evidence never corroborates. Annotation only — recorded
  confidence is never rewritten. Cross-scan mode
  (`?compare_scan_id=`) corroborates across scans while keeping the
  same-instrument rule (one scanner in two scans is still one observer).
  Tests: 10 unit (`services/normalization/tests/unit/test_corroboration.py`)
  + 1 API test.

## Round 34 addendum (2026-10-11) — labeled ground-truth calibration BUILT

The "would need FP/FN labels, not proxies" remainder of P0#4 is closed:
the labels already existed — the hand-labeled accuracy corpus (21 files,
every case carrying the exact algorithm families a correct scanner must
report, hard negatives labeling any report as a false positive).

- `scripts/accuracy_benchmark.py` now carries per-finding detector
  reports (scanner id + reported family) through every case, alongside
  the existing TP/FN/FP family sets.
- `services/scanner/scanner/labeled_calibration.py` — pure
  `labeled_detector_metrics`: per-detector TP/FP/precision against the
  labels (hard negatives count every report as FP), FN deliberately
  scanner-level (which detector *should* have seen a family is a
  coverage question — per-detector recall is not fabricated), thin data
  reported as INSUFFICIENT_DATA with raw counts.
- `GET /findings/detectors/labeled-calibration` runs the corpus once per
  process (deterministic, hermetic) and surfaces the labeled calibration
  — explicitly separate from the production proxy scorecards: labeled
  metrics measure detectors on ground truth, scorecards measure them on
  real traffic. Both views, not either alone.
- Tests: `services/scanner/tests/unit/test_labeled_calibration.py` (5),
  `services/api/tests/unit/test_labeled_calibration_api.py` (3, over the
  real corpus).
