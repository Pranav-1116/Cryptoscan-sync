# 61_PQC_MIGRATION_DEPENDENCY_AUDIT.md
## ZELNX CryptoScan — PQC Migration Dependency Audit

**Generated:** 2026-09-20  
**Method:** Deep inspection of migration dependency graph construction and migration ordering capabilities  
**Scope:** Complete migration dependency analysis — Application → Library → Crypto API → Algorithm → Certificate → HSM → Vendor → Protocol → PQC Replacement

---

## EXECUTIVE SUMMARY

**Core Question:** *"Can ZELNX build a migration dependency graph and calculate migration ordering from actual dependencies?"*

**Answer:** **PARTIAL** — Graph engine has dependency edges and migration waves, but **missing critical dependency types** (library→algorithm, certificate→app, key→app, HSM→key, vendor→library) and **no migration execution engine**.

| Dependency Type | Modeled | Score | Evidence |
|-----------------|---------|-------|----------|
| **System → System (CALLS)** | ✅ | 8/10 | `system_dependencies` table |
| **System → System (IMPORTS)** | ✅ | 8/10 | `system_dependencies` table |
| **System → CryptoAsset (USES)** | ✅ | 7/10 | `system_assets` table |
| **System → BusinessProcess** | ✅ | 8/10 | `system_business_process` |
| **System → Certificate** | ✅ | 7/10 | `certificate_usage` table |
| **System → Vendor** | ✅ | 7/10 | `vendor_id` on System |
| **System → CloudResource** | ✅ | 7/10 | `cloud_accounts.system_id` |
| **System → NetworkResource** | ✅ | 7/10 | `network_inventory.system_id` |
| **Library → Algorithm** | ❌ Missing | 0/10 | Library fingerprinting only |
| **Library → Crypto API** | ❌ Missing | 0/10 | Not modeled |
| **Function → Library** | ❌ Missing | 0/10 | Not modeled |
| **Function → Crypto API** | ❌ Missing | 0/10 | Not modeled |
| **Certificate → Application** | ❌ Missing | 0/10 | No Cert→App edge |
| **Certificate → TLS Endpoint** | ❌ Missing | 0/10 | No Cert→Endpoint edge |
| **Key → Application** | ❌ Missing | 0/10 | No Key→App edge |
| **HSM → Key** | ❌ Missing | 0/10 | No HSM→Key edge |
| **KMS → Key** | ❌ Missing | 0/10 | No KMS→Key edge |
| **Vendor → Library** | ❌ Missing | 0/10 | No Vendor→Library edge |
| **Vendor → Certificate** | ❌ Missing | 0/10 | No Vendor→Cert edge |
| **Protocol → Algorithm** | ⚠️ Partial | 4/10 | TLS cipher suite mapping only |
| **Key → Certificate** | ❌ Missing | 0/10 | No Key→Cert edge |
| **Key → Data** | ❌ Missing | 0/10 | No Key→Data edge |
| **Protocol → Algorithm** | ⚠️ Partial | 4/10 | Cipher suite mapping only |

**Overall: 3.2/10** — Good system-level dependencies, missing code/key/cert/library-level dependencies

---

## 1. DEPENDENCY GRAPH — CURRENT STATE

### 1.1 Current Dependency Edges (10 Types)

| Relation | From → To | Source Table | Evidence |
|----------|-----------|--------------|----------|
| `USES` | System → CryptoAsset | `system_assets` | `CryptoAsset.extra.detection` |
| `CALLS` | System → System | `system_dependencies` (CALLS) | `source` field |
| `IMPORTS` | System → System | `system_dependencies` (IMPORTS) | `source` field |
| `SUPPORTS` | System → BusinessProcess | `system_business_process` | None |
| `OWNED_BY` | System → BusinessOwner | `systems.owner` | None |
| `DEPENDS_ON_VENDOR` | System → Vendor | `systems.vendor_id` | None |
| `SECURED_BY` | System → Certificate | `certificate_usage` | None |
| `DEPLOYED_ON` | System → CloudResource | `cloud_accounts.system_id` | None |
| `CONNECTS_TO` | System → NetworkResource | `network_inventory.system_id` | None |
| `MUST_COMPLY_WITH` | System → ComplianceScope | `systems.compliance_scopes` | None |

### 1.2 Missing Critical Dependency Edges (20+ Types)

| Missing Edge | From → To | Required For | Source Data Available |
|--------------|-----------|--------------|----------------------|
| `DEFINES` | Code File → Function | Code tracing | Scanner AST |
| `CALLS` | Function → Function | Call graph | Scanner AST |
| `USES` | Function → Library | Dependency | Scanner imports |
| `USES` | Function → Crypto API | Crypto tracing | Scanner crypto calls |
| `USES` | Library → Algorithm | Library crypto | Fingerprinting |
| `IMPLEMENTS` | Library → Algorithm | Library crypto | Fingerprinting |
| `PROVIDES` | Cloud KMS → Key | Key hierarchy | Cloud scanner |
| `PROVIDES` | HSM → Key | Key hierarchy | Hardware scanner |
| `STORES` | Key Ring → Key | Key hierarchy | Cloud KMS, HSM |
| `MANAGES` | Key Policy → Key | Key permissions | Cloud KMS policies |
| `ENCRYPTS` | Key → Data | Data protection | Cloud KMS, App config |
| `SIGNS` | Key → Artifact | Signing | Certificate, code signing |
| `VERIFIES` | Key → Certificate | PKI | Certificate chain |
| `ISSUES` | CA → Certificate | PKI | Certificate chain |
| `VALIDATES` | Trust Store → Certificate | Trust | Trust store analysis |
| `TERMINATES` | TLS Endpoint → Certificate | TLS | Network scan |
| `NEGOTIATES` | Client ↔ Server | TLS handshake | Network probe |
| `CARRIES` | Network Flow → Protocol | Traffic | Network capture |
| `ROUTES` | Network Device → Flow | Topology | Network scan |
| `LOADS` | Process → Library | Runtime | Runtime engine |
| `EXECUTES` | Process → Function | Runtime | Runtime engine |
| `RUNS_ON` | Process → Host | Host mapping | Runtime, cloud |
| `DEPLOYS` | Container → Host | Deployment | Container, cloud |
| `ORCHESTRATES` | Orchestrator → Container | K8s | K8s scanner |
| `SCHEDULES` | Scheduler → Pod | K8s | K8s scanner |
| `EXPOSES` | Service → Endpoint | K8s | K8s scanner |
| `ROUTES` | Ingress → Service | K8s | K8s scanner |
| `BUILDS` | Pipeline → Image | CI/CD | CI/CD integration |
| `DEPLOYS` | Pipeline → Environment | CI/CD | CI/CD integration |
| `PRODUCES` | Build → Artifact | Build | CI/CD |
| `SIGNS` | Key → Artifact | Signing | Build, cert |
| `VERIFIES` | Verifier → Artifact | Verification | Build, deploy |
| `ATTACKS` | Threat Actor → Asset | Threat intel | Threat intel |
| `EXPLOITS` | Vulnerability → Asset | Exploitation | Vuln scanner |
| `MITIGATES` | Control → Vulnerability | Remediation | Policy, remediation |

---

## 2. MIGRATION DEPENDENCY GRAPH — CURRENT CAPABILITIES

### 2.1 Current Migration Wave Calculation

**File:** `services/api/api/routers/graph.py:graph_migration_waves()`

```python
# 1. Base wave from readiness (MaturityRepository)
# 2. Cycle constraint: SCC members get max wave
# 3. Import constraint: IMPORTS edges order dependent after provider
# 4. Code-only systems: from cascade_run.earliest_wave
```

### 2.2 Wave Calculation Logic

| Factor | Implementation | Gap |
|--------|----------------|-----|
| **Readiness Base Wave** | `wave_for(readiness_category)` | No business criticality |
| **Cycle Constraint** | `merge_cycle_constraints()` | SCC max wave |
| **Import Constraint** | `apply_import_constraints()` | IMPORTS edges only |
| **Code-Only Systems** | Cascade `earliest_wave` | Scanner cascade only |

### 2.3 Wave Assignment Output

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

## 3. MIGRATION DEPENDENCY ANALYSIS — GAPS

### 3.1 Missing Dependency Types for Migration

| Dependency | Needed For Migration | Status |
|------------|---------------------|--------|
| **Library → Algorithm** | Which library implements vulnerable algorithm | ❌ |
| **Function → Library** | Which code calls vulnerable library | ❌ |
| **Function → Crypto API** | Which code calls vulnerable crypto API | ❌ |
| **Certificate → Application** | Which app uses expiring cert | ❌ |
| **Certificate → TLS Endpoint** | Which endpoint uses expiring cert | ❌ |
| **Key → Application** | Which app uses compromised key | ❌ |
| **HSM → Key** | Which keys in compromised HSM | ❌ |
| **KMS → Key** | Which keys in compromised KMS | ❌ |
| **Vendor → Library** | Which libraries from compromised vendor | ❌ |
| **Protocol → Algorithm** | Which cipher suites use broken algorithm | ⚠️ Partial |
| **Key → Certificate** | Which certs signed by compromised key | ❌ |
| **Key → Data** | Which data encrypted by compromised key | ❌ |

---

### 3.2 Migration Ordering — Current vs Required

| Aspect | Current | Required |
|--------|---------|----------|
| **Ordering Basis** | Readiness + Cycles + Imports | Dependency graph + Business criticality + Regulatory deadlines |
| **Cycle Handling** | SCC max wave | SCC must migrate together |
| **Import Constraints** | IMPORTS edges only | All dependency types |
| **Business Priority** | Not considered | Revenue, customers, regulatory |
| **Regulatory Deadlines** | Not in wave calc | PCI-DSS, DORA, CNSA 2.0 |
| **Revenue Impact** | Not in wave calc | Revenue at risk per system |
| **Cert Expiry** | Not in wave calc | Cert expiry vs migration |
| **Key Rotation** | Not in wave calc | Key rotation schedule |
| **Vendor Roadmap** | Not considered | Vendor PQC readiness |

---

## 4. MIGRATION PLANNING — GRAPH → PROJECT

### 4.1 Graph → Migration Plan Integration

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
# Creates MigrationProject + MigrationTask per affected asset
# Links: real CryptoAsset IDs, actual algorithm_from → algorithm_to
```

### 4.2 Migration Plan Gaps

| Gap | Impact |
|-----|--------|
| **No Dependency-Aware Task Ordering** | Tasks created but not ordered by dependencies |
| **No Parallelization Analysis** | Cannot identify parallelizable tasks |
| **No Critical Path Analysis** | No critical path in migration graph |
| **No Resource Contention** | Team capacity not considered |
| **No Vendor Coordination** | Vendor migration not modeled |
| **No Certificate Renewal Coordination** | Cert renewal vs migration timing |
| **No Key Rotation Coordination** | Key rotation vs migration timing |
| **No Rollback Plan** | No rollback dependency analysis |

---

## 5. MIGRATION EXECUTION — MISSING

### 5.1 Current: Tracking Only

**Models:** `MigrationProject`, `MigrationTask` (in `intelligence_repository.py`)

```python
class MigrationProject:
    status: str  # PLANNED, IN_PROGRESS, COMPLETED, BLOCKED, FAILED
    
class MigrationTask:
    status: str  # PENDING, IN_PROGRESS, COMPLETED, BLOCKED, FAILED
    priority: str  # P0, P1, P2, P3
    source: str  # AUTO, MANUAL
```

**Gap:** Tasks are **tracking only** — no execution engine.

### 5.2 Missing Execution Capabilities

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
| Vendor Coordination | ❌ |
| Certificate Re-issuance Automation | ❌ |
| Key Rotation Automation | ❌ |

---

## 6. VENDOR & SUPPLY CHAIN DEPENDENCIES — MISSING

### 6.1 Current Vendor Edges

| Edge | From → To | Source |
|------|-----------|--------|
| `DEPENDS_ON_VENDOR` | System → Vendor | `systems.vendor_id` |

### 6.2 Missing Vendor Dependency Edges

| Missing Edge | From → To | Source Data |
|--------------|-----------|-------------|
| `SUPPLIES` | Vendor → Library | `vendor_crypto`, SBOM |
| `PROVIDES` | Vendor → Service | Cloud scanner |
| `SUPPLIES` | Vendor → Certificate | Vendor certs |
| `MAINTAINS` | Vendor → Library | Vendor intel |
| `PATCHES` | Vendor → Vulnerability | Vendor advisories |
| `NOTIFIES` | Vendor → Customer | Vendor notifications |

---

## 7. CERTIFICATE & KEY DEPENDENCIES — MISSING

### 7.1 Certificate Dependencies

| Missing Edge | From → To | Needed For |
|--------------|-----------|------------|
| `TERMINATES_TLS` | TLS Endpoint → Certificate | Cert → Endpoint mapping |
| `USES_CERTIFICATE` | Application → Certificate | App → Cert mapping |
| `ISSUES` | CA → Certificate | PKI chain |
| `VALIDATES` | TrustStore → Certificate | Trust validation |
| `SIGNS` | Key → Certificate | Signing chain |
| `VERIFIES` | Key → Certificate | Verification chain |

### 7.2 Key Dependencies

| Missing Edge | From → To | Needed For |
|--------------|-----------|------------|
| `PROVIDES` | HSM → Key | HSM key inventory |
| `PROVIDES` | KMS → Key | KMS key inventory |
| `STORES` | KeyRing → Key | Key hierarchy |
| `MANAGES` | KeyPolicy → Key | Key permissions |
| `ENCRYPTS` | Key → Data | Data protection |
| `SIGNS` | Key → Artifact | Signing chain |
| `VERIFIES` | Key → Certificate | Verification chain |
| `DERIVES` | ParentKey → ChildKey | Key derivation |

---

## 8. MIGRATION SIMULATION — WHAT-IF ONLY

### 8.1 Simulation Engine

**File:** `services/universal_crypto/universal_crypto/simulator.py`

```python
def simulate(asset_id, current_algorithm, target_algorithm, 
             protocol, library, hardware, usage, current_agility):
    # Projects impact on:
    # - Readiness score
    # - Quantum risk score
    # - Agility score
    # - Risk score
    # - Migration effort
```

**Gap:** Simulation projects **impact only**, not migration path or dependency ordering.

---

## 9. RECOMMENDATIONS

### P0 — Critical

1. **Add Library → Algorithm Edge** — `IMPLEMENTS` from library fingerprinting
2. **Add Function → Library Edge** — `USES` from scanner imports
3. **Add Function → Crypto API Edge** — `CALLS` from scanner crypto calls
4. **Add Certificate → TLS Endpoint Edge** — `TERMINATES_TLS` from network probe
5. **Add Certificate → Application Edge** — `USES_CERTIFICATE` from cert usage
6. **Add Key → Application Edge** — `USES_KEY` from key usage tracking

### P1 — High

2. **Add HSM → Key Edge** — `PROVIDES` from hardware scanner
3. **Add KMS → Key Edge** — `PROVIDES` from cloud scanner
4. **Add Vendor → Library Edge** — `SUPPLIES` from vendor intel
5. **Add Protocol → Algorithm Edge** — `USES` from cipher suite mapping
5. **Add Key → Certificate Edge** — `SIGNS` from cert parsing
6. **Add Key → Data Edge** — `ENCRYPTS` from data flow analysis

### P2 — Medium

3. **Implement Dependency-Aware Migration Ordering** — Topological sort with business priority
4. **Add Critical Path Analysis** — Longest dependency chain in migration
7. **Add Parallelization Analysis** — Independent task identification
8. **Add Resource Contention Analysis** — Team capacity per task
9. **Add Vendor Coordination Model** — Vendor migration dependencies

### P3 — Enhancement

10. **Critical Path Visualization** — Longest dependency chain visualization
11. **What-If Migration Simulation** — "What if we migrate X first?"
12. **Rollback Dependency Analysis** — Reverse dependencies for rollback
13. **Vendor Coordination Workflow** — Vendor migration coordination

---

## 10. VERDICT

**ZELNX has good system-level dependencies but lacks the code/key/cert/library-level dependencies needed for precise migration ordering.**

| Dependency Level | Coverage |
|------------------|----------|
| System ↔ System | ✅ Good |
| System ↔ CryptoAsset | ✅ Good |
| System ↔ Certificate | ✅ Good |
| System ↔ Vendor | ✅ Good |
| System ↔ Cloud/Network | ✅ Good |
| Library → Algorithm | ❌ Missing |
| Function → Library | ❌ Missing |
| Function → Crypto API | ❌ Missing |
| Certificate → Application | ❌ Missing |
| Certificate → TLS Endpoint | ❌ Missing |
| Key → Application | ❌ Missing |
| HSM/KMS → Key | ❌ Missing |
| Vendor → Library | ❌ Missing |
| Protocol → Algorithm | ⚠️ Partial |

**To fix:** 8-12 weeks for complete migration dependency graph with code/key/cert/library-level edges, dependency-aware ordering, and execution engine.

---

## 10. VERIFICATION EVIDENCE

| Finding | File |
|---------|------|
| GraphEngine | `services/graph_engine/graph_engine/core/engine.py` |
| Graph Router | `services/api/api/routers/graph.py` |
| Graph Builder | `services/api/api/graph_builder.py` |
| SystemDependency Model | `services/database/db/models/system_dependency.py` |
| SystemAsset Model | `services/database/db/models/system_asset.py` |
| CertificateUsage Model | `services/database/db/models/certificate_usage.py` |
| System Model | `services/database/db/models/system.py` |
| CryptoAsset Model | `services/database/db/models/crypto_asset.py` |
| Vendor Model | `services/database/db/models/vendor.py` |
| Migration Project | `services/database/db/models/migration_project.py` |
| Migration Task | `services/database/db/repositories/migration_task_repository.py` |
| Graph Migration Waves | `services/api/api/routers/graph.py:graph_migration_waves()` |
| Graph Migration Plan | `services/api/api/routers/graph.py:graph_migration_plan()` |
| Graph Blast Radius | `services/graph_engine/graph_engine/core/engine.py:blast_radius()` |
| Graph Engine Business Impact | `services/graph_engine/graph_engine/core/engine.py:business_impact()` |
| Scanner Imports | `services/scanner/scanner/parsers/` (import detection) |
| Library Fingerprinting | `services/universal_crypto/universal_crypto/library_fingerprints.py` |
| Crypto Calls | `services/scanner/scanner/detectors/` (detectors) |
---

## Round 26 update (2026-10-10) — dependency-edge claims re-verified

Several of the "missing critical dependency types" exist today:
`CryptoHardwareLink` (hardware/HSM → crypto asset), `VendorDependency`
(vendor edges), `certificate_usage` (certificate → application), cloud
KMS key inventory (KMS → key, `inventory/cloud_kms.py`), and the
round-18 transitive crypto propagation gives library-level dependency →
algorithm paths in the cascade. **REMAIN OPEN, product-scoped:**
Function/Library/Key as first-class graph nodes with CALLS/IMPLEMENTS/
SIGNS/ENCRYPTS edges (a code-level fact graph — see advanced/48's
addendum) and the migration execution engine (the standing product
open).

## Round 30 addendum (2026-10-11) — dependency-aware ordering + execution control plane BUILT

§4.2's "No Dependency-Aware Task Ordering / No Parallelization
Analysis / No Rollback Plan" and §5.1's "tracking only" verdict are no
longer accurate for the control plane:

- Pure engine: `services/database/db/migration_execution.py` (lives in
  the shared db kernel so repositories import it without a db→api
  inversion). Kahn staging groups tasks into parallelizable stages and
  REJECTS cycles with the cycle path; critical-path = longest
  dependency chain; ready-set = TODO tasks whose deps are all
  DONE/SKIPPED (a SKIPPED dependency satisfies — a withdrawn task
  cannot block the chain forever); unknown dependency references are
  surfaced, never silently dropped; a transition matrix gates status
  moves, with DONE/SKIPPED→TODO allowed only through the explicit
  rollback path.
- DB: migration 0082 adds `migration_tasks.depends_on` (JSON id list);
  the repository's linker cycle-checks BEFORE persisting.
- Rollback plan (executed, not just planned): rolling back a task
  transitively reverts DONE dependents to TODO and BLOCKS in-progress
  dependents with the reason naming the rolled-back dependency; project
  progress recomputes from tasks automatically.
- Auto-derivation: `POST /migrations/{id}/dependencies/auto` derives
  task ordering from `system_dependencies` edges (parent CALLS child →
  the callee's tasks become dependencies of the caller's tasks),
  validated as one batch — a batch that would close a cycle is rejected
  whole.
- API: `GET /migrations/{id}/execution-plan` (stages, parallelization,
  critical path with titles, ready set, per-task blockers, unknown
  refs, cycle), `POST /migrations/tasks/{id}/start` (409 with the
  blocking chain until deps are satisfied), `/complete` (only from
  IN_PROGRESS), `/rollback` (reason required), `POST
  /migrations/{id}/execute/advance` (bulk wave kickoff of the ready
  set), `POST /migrations/{id}/tasks/{tid}/dependencies`.
- Tests: `services/api/tests/unit/test_migration_execution.py` (14
  pure) + `test_migration_execution_api.py` (2 end-to-end lifecycles:
  gating/advance/rollback cascade, and system-edge auto-derivation).
- HONESTLY STILL OPEN (deployment-scoped, as §5.2 correctly scoped):
  automated code refactoring, config migration, library upgrade
  orchestration, HSM firmware coordination, certificate re-issuance,
  key rotation, canary/blue-green — these need live infrastructure
  targets; this round built the execution control plane over
  operator-driven state, not the actuators.
