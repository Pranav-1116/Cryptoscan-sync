# 54_CRYPTO_ASSET_LIFECYCLE_AUDIT.md
## ZELNX CryptoScan — Crypto Asset Lifecycle Audit

**Generated:** 2026-09-20  
**Method:** Deep inspection of lifecycle state machine for cryptographic assets  
**Scope:** Complete lifecycle — DISCOVERED → VERIFIED → NORMALIZED → ACTIVE → BASELINED → AT_RISK → REMEDIATION → MIGRATED → RETIRED

---

## EXECUTIVE SUMMARY

**Core Question:** *"Do lifecycle states actually exist and are they enforced?"*

**Answer:** **PARTIAL** — States exist in code but **no enforced state machine** exists. Assets flow through stages but without formal transitions, guards, or audit trails.

| Lifecycle Stage | State Exists | Enforced | Transitions Guarded | Audit Trail | Score |
|-----------------|--------------|----------|---------------------|-------------|-------|
| **DISCOVERED** | ✅ | ❌ | ❌ | ✅ (evidence chain) | 6/10 |
| **VERIFIED** | ❌ Implicit | ❌ | ❌ | ❌ | 2/10 |
| **NORMALIZED** | ✅ (NormalizedCrypto) | ❌ | ❌ | ❌ | 4/10 |
| **ACTIVE** | ❌ Implicit | ❌ | ❌ | ❌ | 2/10 |
| **BASELINED** | ✅ (Baseline model) | ✅ (approval) | ✅ | ✅ | 8/10 |
| **AT_RISK** | ⚠️ Implicit (drift/risk) | ❌ | ❌ | ❌ | 3/10 |
| **REMEDIATION** | ⚠️ Partial (tasks) | ❌ | ❌ | ❌ | 3/10 |
| **MIGRATED** | ⚠️ Implicit (new scan) | ❌ | ❌ | ❌ | 2/10 |
| **RETIRED** | ❌ Missing | ❌ | ❌ | ❌ | 0/10 |

**Overall: 3.2/10** — No enforced lifecycle state machine

---

## 1. LIFECYCLE MODEL — CURRENT STATE

### 1.1 Current States (Implicit)

| Stage | Model/Field | Explicit State? | Transition Trigger |
|-------|-------------|-----------------|-------------------|
| **DISCOVERED** | `EvidenceRecord.created_at` + `CryptoAsset.created_at` | ❌ Implicit | Scan completes |
| **VERIFIED** | None | ❌ Missing | Never explicit |
| **NORMALIZED** | `CryptoAsset.normalized_crypto` populated | ❌ Implicit | Normalization runs |
| **ACTIVE** | `CryptoAsset` exists | ❌ Implicit | Asset created |
| **BASELINED** | `Baseline.status = APPROVED` | ✅ Explicit | Auditor approval |
| **AT_RISK** | `DriftEvent` exists + `quantum_risk_score` > threshold | ❌ Implicit | Drift detected / Risk calculated |
| **REMEDIATION** | `MigrationTask` exists | ⚠️ Partial | Task created |
| **MIGRATED** | New scan shows different algorithm | ❌ Implicit | New scan completes |
| **RETIRED** | Missing | ❌ Missing | Never |

### 1.2 State Machine — MISSING

**No formal state machine exists.** No:
- State transition table
- Transition guards
- State validation
- State history
- Illegal transition prevention

---

## 2. STAGE-BY-STAGE ANALYSIS

### 2.1 DISCOVERED — ⚠️ PARTIAL

**Evidence:** `EvidenceRecord.created_at`, `CryptoAsset.created_at`

```python
# EvidenceRecord created during scan
# CryptoAsset created via replace_for_scan()
```

**Gaps:**
- No explicit `DISCOVERED` state
- No discovery timestamp separate from scan timestamp
- No discovery source tracking on asset
- No discovery confidence separate from evidence confidence

---

### 2.2 VERIFIED — ❌ MISSING

**Required:** Explicit verification step between discovery and normalization

**What verification should mean:**
- Evidence chain verified (hash + chain)
- Provenance confirmed
- Collector authenticated
- Evidence integrity confirmed
- False positive review completed

**Current:** None of this exists as explicit step. Evidence goes straight to normalization.

---

### 2.3 NORMALIZED — ⚠️ IMPLICIT

**Evidence:** `CryptoAsset.normalized_crypto` populated

```python
# NormalizationEngine.normalize() → NormalizedCrypto
# Stored in CryptoAsset.normalized_crypto
```

**Gaps:**
- No `NORMALIZED` state flag
- No normalization timestamp on asset
- No normalization version tracking
- No normalization audit trail
- Can't query "which assets normalized with v2.3 rules"

---

### 2.4 ACTIVE — ❌ IMPLICIT

**Current:** Asset exists = Active

**Missing:**
- No `ACTIVE` state
- No activation timestamp
- No deactivation path
- No active/inactive distinction
- No maintenance window tracking

---

### 2.4 BASELINED — ✅ EXPLICIT

**File:** `services/database/db/models/baseline.py`

```python
class Baseline:
    scan_id: str                      # FK → scans (unique)
    name: str
    description: str | None
    approved_by: str | None
    approved_at: DateTime | None
    status: str                       # PENDING, APPROVED, SUPERSEDED, ARCHIVED
    component_count: int
    algorithms: dict                  # Counter of algorithms
```

**Good:** Explicit states (`PENDING`, `APPROVED`, `SUPERSEDED`, `ARCHIVED`), approval workflow, audit trail.

**Gap:** No automatic transition from `APPROVED` → `SUPERSEDED` when new baseline approved.

---

### 2.5 AT_RISK — ❌ IMPLICIT

**Current:** Derived from `DriftEvent` + `quantum_risk_score` > threshold

**No explicit state.** Risk calculated on-demand:

```python
# quantum/risk.py:score_asset()
# Returns risk_category: CRITICAL, HIGH, MEDIUM, LOW, MINIMAL
```

**Gaps:**
- No `AT_RISK` state on asset
- No risk threshold configuration per org
- No risk state transitions
- No risk acknowledgment workflow (only drift has this)
- No risk acceptance/exception workflow

---

### 2.6 REMEDIATION — ⚠️ PARTIAL

**Current:** `MigrationTask` model exists

**File:** `services/database/db/models/migration_project.py` + `migration_task_repository.py`

```python
class MigrationProject:
    status: str  # PLANNED, IN_PROGRESS, COMPLETED, BLOCKED, FAILED
    
class MigrationTask:
    status: str  # PENDING, IN_PROGRESS, COMPLETED, BLOCKED, FAILED
    priority: str  # P0, P1, P2, P3
    source: str  # AUTO, MANUAL
```

**Partial:** Task states exist but **no asset-level remediation state**.

**Gaps:**
- Asset doesn't know it's in remediation
- No remediation start/complete timestamps on asset
- No remediation progress tracking on asset
- No remediation verification step
- No rollback on remediation failure

---

### 2.7 MIGRATED — ❌ IMPLICIT

**Current:** Detected by new scan showing different algorithm

**No explicit state.** Detected via:
- New scan shows different algorithm
- New baseline approved
- Drift resolved

**Gaps:**
- No `MIGRATED` state
- No migration timestamp
- No migration verification
- No migration audit trail on asset
- No rollback to pre-migration state

---

### 2.8 RETIRED — ❌ MISSING

**Completely missing.** No concept of crypto asset retirement.

**Needed for:**
- Algorithm deprecated and removed
- Certificate expired and not renewed
- System decommissioned
- Key destroyed
- Certificate revoked

---

## 3. STATE MACHINE — MISSING

### 3.1 Required State Machine

```
DISCOVERED
    → (evidence verified) → VERIFIED
    → (evidence invalid) → FALSE_POSITIVE
    
VERIFIED
    → (normalized) → NORMALIZED
    → (evidence invalid) → FALSE_POSITIVE

NORMALIZED
    → (policy evaluated) → ACTIVE
    → (policy failed) → AT_RISK

ACTIVE
    → (baseline approved) → BASELINED
    → (drift detected) → AT_RISK
    → (decommissioned) → RETIRED

BASELINED
    → (drift detected) → AT_RISK
    → (new baseline) → BASELINED (superseded)
    → (decommissioned) → RETIRED

AT_RISK
    → (remediation started) → REMEDIATION
    → (risk accepted) → RISK_ACCEPTED
    → (false positive) → ACTIVE

REMEDIATION
    → (migration complete) → MIGRATED
    → (verification passed) → ACTIVE
    → (failed) → AT_RISK

MIGRATED
    → (verified) → ACTIVE
    → (baseline updated) → BASELINED

RETIRED
    → (terminal state)
    → (reintroduced) → DISCOVERED

RISK_ACCEPTED
    → (review period ended) → AT_RISK
    → (risk changed) → AT_RISK
```

---

### 3.2 Missing Guards

| Transition | Required Guard | Current |
|------------|----------------|---------|
| DISCOVERED → VERIFIED | Evidence chain valid + provenance confirmed | ❌ |
| VERIFIED → NORMALIZED | Normalization successful | ❌ |
| NORMALIZED → ACTIVE | Policy evaluation complete | ❌ |
| ACTIVE → BASELINED | Auditor approval | ✅ (baseline approval) |
| ACTIVE → AT_RISK | Drift detected OR risk threshold exceeded | ❌ (implicit) |
| AT_RISK → REMEDIATION | Remediation task created | ⚠️ Partial (task creation) |
| REMEDIATION → MIGRATED | Migration task complete | ❌ |
| MIGRATED → ACTIVE | Verification scan passed | ❌ |
| Any → RETIRED | Decommission confirmed | ❌ |

---

## 4. LIFECYCLE TIMESTAMPS — MISSING

### 4.1 Current Timestamps

| Model | Timestamps |
|-------|------------|
| `CryptoAsset` | `created_at`, `updated_at` |
| `EvidenceRecord` | `created_at` |
| `Baseline` | `created_at`, `updated_at`, `approved_at` |
| `DriftEvent` | `detected_at` |
| `MigrationProject` | `created_at`, `updated_at` |
| `MigrationTask` | `created_at`, `updated_at` |

### 4.2 Missing Lifecycle Timestamps

| Missing Timestamp | Needed For |
|-------------------|------------|
| `verified_at` | Time to verification |
| `normalized_at` | Normalization latency |
| `activated_at` | Activation tracking |
| `baselined_at` | Baseline currency |
| `at_risk_at` | Risk exposure duration |
| `remediation_started_at` | Remediation duration |
| `migrated_at` | Migration completion |
| `retired_at` | Asset retirement |
| `state_changed_at` | General state transitions |

---

## 5. STATE HISTORY — MISSING

### 5.1 No State History

**Current:** Only `updated_at` on models. No state transition log.

### 5.2 Required State History

```python
class AssetStateHistory:
    asset_id: UUID
    from_state: LifecycleState | None
    to_state: LifecycleState
    triggered_by: str           # User, system, scan, policy
    trigger_id: UUID | None     # Scan ID, baseline ID, task ID
    trigger_type: TriggerType   # SCAN, BASELINE, DRIFT, TASK, MANUAL
    metadata: dict              # Context (risk score, drift details, etc.)
    timestamp: DateTime
```

---

## 6. LIFECYCLE QUERIES — IMPOSSIBLE

### 6.1 Impossible Queries

| Query | Possible? |
|-------|-----------|
| "Show all assets currently AT_RISK" | ❌ No AT_RISK state |
| "Show assets in REMEDIATION > 30 days" | ❌ No remediation state on asset |
| "Time from DISCOVERED to BASELINED" | ❌ No timestamps |
| "Assets RETIRED this quarter" | ❌ No RETIRED state |
| "Assets in REMEDIATION > 60 days" | ❌ No remediation state on asset |
| "Average time to BASELINED" | ❌ No baselined_at on asset |
| "Assets that skipped VERIFIED" | ❌ No VERIFIED state |
| "Assets that went ACTIVE → AT_RISK → REMEDIATION → ACTIVE" | ❌ No state history |

---

## 6. LIFECYCLE EVENTS — MISSING

### 6.1 No Lifecycle Events

**Current:** Platform events exist for some operations but not lifecycle transitions.

**Platform Events (from `api/events/platform_events.py`):**
- `SCAN_STARTED`, `SCAN_COMPLETED`, `SCAN_FAILED`
- `BASELINE_APPROVED`
- `DRIFT_DETECTED`
- `SCAN_PHASE`
- `GRAPH_UPDATED`

**Missing Lifecycle Events:**
- `ASSET_DISCOVERED`
- `ASSET_VERIFIED`
- `ASSET_NORMALIZED`
- `ASSET_ACTIVATED`
- `ASSET_BASELINED`
- `ASSET_AT_RISK`
- `ASSET_REMEDIATION_STARTED`
- `ASSET_MIGRATED`
- `ASSET_RETIRED`
- `ASSET_REINTRODUCED`

---

## 7. RECOMMENDATIONS

### P0 — Critical

1. **Define Explicit Lifecycle State Enum** — `DISCOVERED, VERIFIED, NORMALIZED, ACTIVE, BASELINED, AT_RISK, REMEDIATION, MIGRATED, RETIRED, FALSE_POSITIVE, RISK_ACCEPTED`
2. **Add State Field to CryptoAsset** — `lifecycle_state` with transition guards
3. **Implement State Machine** — Transition guards, validation, history
4. **Add Lifecycle Timestamps** — `verified_at`, `normalized_at`, `activated_at`, `baselined_at`, `at_risk_at`, `remediation_started_at`, `migrated_at`, `retired_at`

### P1 — High

4. **Implement State History Table** — `AssetStateHistory` with full audit trail
5. **Add Lifecycle Events** — Platform events for each transition
6. **Add Transition Guards** — Prevent illegal transitions (e.g., RETIRED → ACTIVE)
7. **Add Lifecycle API** — `GET /assets/{id}/lifecycle`, `POST /assets/{id}/transition`

### P2 — Medium

7. **Lifecycle Dashboard** — Visual state machine, transition metrics
8. **SLA Tracking per State** — Time in each state, SLA compliance
9. **Automated Transitions** — Auto ACTIVE→AT_RISK on drift, auto RETIRED on decommission
9. **State-Based Access Control** — Different permissions per state

### P3 — Enhancement

10. **Lifecycle Visualization** — Asset timeline view
11. **Predictive State Transitions** — ML-based risk prediction
11. **Lifecycle Templates** — Standard lifecycles per asset class
12. **Cross-Asset Lifecycle Dependencies** — Parent asset state affects children

---

## 7. VERDICT

**No enforced lifecycle state machine exists.** Assets flow through stages implicitly with no formal states, transitions, guards, history, or audit trail. Only `Baseline` has explicit states with approval workflow.

| Lifecycle Capability | Status |
|----------------------|--------|
| Explicit States | ❌ (only Baseline) |
| State Machine | ❌ Missing |
| Transition Guards | ❌ Missing |
| State History | ❌ Missing |
| Lifecycle Timestamps | ❌ Mostly missing |
| Lifecycle Events | ❌ Missing |
| Lifecycle Queries | ❌ Impossible |
| Transition Guards | ❌ Missing |
| State-Based Access | ❌ Missing |

**To implement:** 6-8 weeks for complete lifecycle state machine with states, transitions, guards, history, events, and API.

---

## 8. VERIFICATION EVIDENCE

| Finding | File |
|---------|------|
| CryptoAsset model | `services/database/db/models/crypto_asset.py` |
| EvidenceRecord model | `services/database/db/models/evidence_record.py` |
| Baseline model | `services/database/db/models/baseline.py` |
| DriftEvent model | `services/database/db/models/drift_event.py` |
| MigrationProject model | `services/database/db/models/migration_project.py` |
| MigrationTask model | `services/database/db/models/migration_project.py` (TaskRepository) |
| EvidencePipeline | `services/evidence/evidence/core/pipeline.py` |
| NormalizationEngine | `services/normalization/normalization/core/engine.py` |
| Baseline router | `services/api/api/routers/baselines.py` |
| Drift router | `services/api/api/routers/drift.py` |
| Migration router | `services/api/api/routers/graph.py:migration_plan` |
| Platform events | `services/api/api/events/platform_events.py` |
| CryptoAsset repository | `services/database/db/repositories/asset_repository.py` |
| BaselineRepository | `services/database/db/repositories/baseline_repository.py` |
| MigrationTaskRepository | `services/database/db/repositories/migration_task_repository.py` |
## UPDATE — 2026-10-09: lifecycle state machine built

`crypto_assets.lifecycle_state` (migration 0073) implements the state machine
this report found missing:

`DISCOVERED -> VERIFIED -> ACTIVE -> DEPRECATED -> RETIRED`

* DISCOVERED is the only state the pipeline writes on its own.
* Transitions are validated server-side against a rules table
  (`LIFECYCLE_TRANSITIONS` in `api/routers/inventory.py`); illegal jumps get
  409 with the allowed set.
* RETIRED is terminal by design — a retired algorithm that reappears is a
  *reintroduction* (see the update on report 69), not a resurrection.
* Every transition requires a reason and emits an audited platform event
  (`inventory.asset_lifecycle`).
* API: `POST /inventory/assets/{id}/lifecycle`; the unified inventory lists
  and filters by `lifecycle_state`.

## Round 27 update (2026-10-10) — lifecycle state machine re-verified

* **State enum + field + machine (P0 #1/#2/#3) — shipped:** crypto
  assets carry `lifecycle_state` (DISCOVERED → VERIFIED → ACTIVE →
  DEPRECATED → RETIRED) with transitions guarded by the inventory
  router's rules table — no skipping to ACTIVE from DISCOVERED, no
  resurrection from RETIRED (a retired algorithm that reappears is a
  *reintroduction*, handled by the retirement registry, round 24).
  `POST /inventory/assets/{id}/lifecycle` validates, audits the
  transition with its reason, and emits a platform event; the listing
  filters by state.
* **Lifecycle timestamps (P0 #4) — open, deliberately:** explicit
  `verified_at`/`baselined_at`/... columns are not shipped; the
  transition history lives in the audited event trail (actor, reason,
  from/to, timestamp per transition). Deriving the columns from that
  trail is straightforward if a query surface ever needs them — the
  truth source already exists.

## Round 32 addendum (2026-10-11) — P0#4 lifecycle timestamps BUILT as derived projection

The deliberately-open "no verified_at/deprecated_at columns" item now has
its query surface, derived exactly the way this report anticipated
("derive from the audited transition trail; the truth source already
exists"):

- `GET /inventory/assets/{id}/lifecycle/timeline`
  (model `lifecycle-timeline/derived-v1`): the full audited transition
  trail (`inventory.asset_lifecycle` platform events — from/to state,
  reason, actor, timestamp, event id) plus
  `derived_timestamps.{verified,active,deprecated,retired}_at` = the most
  recent audited transition INTO each state. Re-activation moves
  `active_at` forward; pre-trail history is honestly absent, not
  fabricated.
- Denormalised columns remain a deliberate non-choice: a derived
  projection cannot drift from the trail it reads.
- Tests: `services/api/tests/unit/test_lifecycle_timeline_api.py`
  (empty trail → all nulls; DISCOVERED→VERIFIED→ACTIVE→DEPRECATED walk
  with per-state derivation; per-asset isolation; 404/401).
