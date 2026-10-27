# 28_CRYPTO_DRIFT_FORENSIC_AUDIT.md
## ZELNX CryptoScan — Crypto Drift Forensic Audit

**Generated:** 2026-09-20  
**Method:** Deep inspection of drift detection, baseline management, comparison logic, acknowledgment workflow, and daily digest  
**Scope:** Complete drift pipeline — baseline creation → scan comparison → drift detection → acknowledgment/resolution → digest → audit

---

## EXECUTIVE SUMMARY

| Component | Score | Status |
|-----------|-------|--------|
| Baseline Management | 7/10 | Good CRUD, approval workflow |
| Comparison Logic | 6/10 | Basic diff, no semantic analysis |
| Drift Detection | 6/10 | Type classification, severity |
| Acknowledgment Workflow | 8/10 | Full audit trail |
| Daily Digest | 7/10 | Aggregation, but no scheduling |
| API Coverage | 8/10 | Complete CRUD + actions |
| Evidence Linkage | 5/10 | DriftEvent → EvidenceRecord indirect |
| Automated Detection | 4/10 | Manual baseline approval only |
| Real-time Drift | 3/10 | No continuous monitoring |
| Drift Evidence | 5/10 | Details in JSON, no hashes |

**Overall: 5.8/10** — Functional drift management but limited automation and semantic depth

---

## 1. DRIFT ARCHITECTURE

### 1.1 Core Models

**File:** `services/database/db/models/drift_event.py`

```python
class DriftEvent(BaseModel, TenantScoped):
    current_scan_id: str              # FK → scans
    baseline_id: str                  # FK → baselines
    drift_type: str                   # ALGORITHM_CHANGED, KEY_SIZE_CHANGED, etc.
    severity: str                     # CRITICAL, HIGH, MEDIUM, LOW, INFO
    detected_at: DateTime
    resolution_status: str            # OPEN, ACKNOWLEDGED, RESOLVED, FALSE_POSITIVE
    drift_details: dict               # JSON with before/after details
    resolved_by: str | None
    resolution_notes: str | None
```

**File:** `services/database/db/models/baseline.py`

```python
class Baseline(BaseModel, TenantScoped):
    scan_id: str                      # FK → scans (unique)
    name: str
    description: str | None
    approved_by: str | None
    approved_at: DateTime | None
    status: str                       # PENDING, APPROVED, SUPERSEDED, ARCHIVED
    component_count: int
    algorithms: dict                  # Counter of algorithms
```

---

### 1.2 Drift Types

| Drift Type | Description | Detection |
|------------|-------------|-----------|
| `ALGORITHM_CHANGED` | Algorithm added/removed/changed | Component diff |
| `KEY_SIZE_CHANGED` | Key size increased/decreased | Key size diff |
| `TLS_VERSION_CHANGED` | TLS version upgraded/downgraded | Protocol diff |
| `CERTIFICATE_EXPIRING` | Cert near expiry (<30 days) | Validity check |
| `NEW_FINDING` | New crypto finding vs baseline | Component added |
| `CONFIG_CHANGED` | Crypto config changed | Config diff |
| `LIBRARY_CHANGED` | Library version changed | Library diff |
| `CERTIFICATE_CHANGED` | Certificate replaced/renewed | Cert diff |

---

## 2. BASELINE MANAGEMENT

### 2.1 Baseline Creation

**File:** `services/api/api/routers/baselines.py`

```python
# POST /baselines
# Input: scan_id, name, description
# Creates Baseline from Scan
# Status: PENDING (requires approval)
```

**Process:**
1. Scan completes → `status=COMPLETED`
2. User reviews scan findings
3. User creates baseline: `POST /baselines {scan_id, name}`
4. Baseline status: `PENDING`
5. Approver reviews: `POST /baselines/{id}/approve`
5. Baseline status: `APPROVED`

### 2.2 Baseline Approval

**File:** `services/api/api/routers/baselines.py:approve_baseline()`

```python
# Requires: auditor or admin role
# Sets: approved_by, approved_at, status=APPROVED
# Emits: platform.baseline.approved event
# Audit: baseline.approve with actor, baseline_id
```

**Gap:** No automated baseline creation (e.g., "first clean scan becomes baseline").

---

### 2.3 Baseline Lifecycle

| Status | Transition | Trigger |
|--------|------------|---------|
| `PENDING` → `APPROVED` | `POST /baselines/{id}/approve` | Auditor/Admin |
| `APPROVED` → `SUPERSEDED` | New baseline approved for same system | New baseline |
| `APPROVED` → `ARCHIVED` | Manual | Admin |
| `SUPERSEDED` → `ARCHIVED` | Auto after retention | Not implemented |

---

## 3. DRIFT DETECTION & COMPARISON

### 3.1 Comparison Engine

**File:** `services/cbom/cbom/inventory.py:diff_records()`

```python
def diff_records(left_records, right_records):
    # Compares two record sets by bom-ref (evidence_id)
    # Returns: added, removed, changed
```

**Comparison Logic:**
```python
# Matching key: bom-ref (evidence_id) or algorithm+file+line
left_map = {r.get("bom-ref") or f"{r['algorithm']}:{r['file_path']}:{r['line_number']}": r for r in left_records}
right_map = {r.get("bom-ref") or f"{r['algorithm']}:{r['file_path']}:{r['line_number']}": r for r in right_records}

added = [r for k, r in right_map.items() if k not in left_map]
removed = [r for k, r in left_map.items() if k not in right_map]
changed = []
for k, r in right_map.items():
    if k in left_map:
        diff = _compute_field_diff(left_map[k], r)
        if diff:
            changed.append({"bom-ref": k, "diff": diff})
```

### 3.2 Drift Detection Trigger

**Current:** Manual — drift detected when new scan compared to approved baseline.

**File:** `services/api/api/routers/drift.py` — No automated drift detection endpoint.

**Gap:** No automated drift detection on scan completion.

**Required Flow (Missing):**
```
Scan Completes
    ↓
System has APPROVED baseline?
    ↓ Yes
Compare new scan evidence vs baseline evidence
    ↓
Generate DriftEvents for differences
    ↓
Emit platform.drift.detected event
    ↓
Notify subscribers (auditor, business owner)
```

---

### 3.3 Drift Details Structure

**File:** `services/database/db/models/drift_event.py:drift_details`

```json
{
  "drift_type": "ALGORITHM_CHANGED",
  "left": {
    "algorithm": "RSA",
    "key_size": 2048,
    "file_path": "src/CryptoUtil.java",
    "line_number": 42
  },
  "right": {
    "algorithm": "RSA",
    "key_size": 4096,
    "file_path": "src/CryptoUtil.java",
    "line_number": 42
  },
  "field_changes": [
    {"field": "key_size", "from": 2048, "to": 4096}
  ],
  "evidence_ids": {
    "left": "evidence-uuid-1",
    "right": "evidence-uuid-2"
  }
}
```

**Gap:** No `content_hash` or `chain_hash` references to evidence chain.

---

### 3.4 Severity Classification

**File:** `services/drift/drift/alerts/daily_digest.py` (implied logic)

| Drift Type | Default Severity | Escalation Rules |
|------------|------------------|------------------|
| `ALGORITHM_CHANGED` (weak→strong) | LOW | — |
| `ALGORITHM_CHANGED` (strong→weak) | CRITICAL | Immediate alert |
| `KEY_SIZE_CHANGED` (decrease) | HIGH | — |
| `KEY_SIZE_CHANGED` (increase) | LOW | — |
| `TLS_VERSION_CHANGED` (downgrade) | CRITICAL | Immediate alert |
| `TLS_VERSION_CHANGED` (upgrade) | LOW | — |
| `CERTIFICATE_EXPIRING` (<30 days) | HIGH | 30/14/7 day reminders |
| `CERTIFICATE_EXPIRING` (<7 days) | CRITICAL | Immediate alert |
| `NEW_FINDING` (quantum vulnerable) | HIGH | — |
| `NEW_FINDING` (classically broken) | CRITICAL | Immediate alert |
| `CONFIG_CHANGED` (weak config) | MEDIUM | — |
| `LIBRARY_CHANGED` (vulnerable version) | HIGH | — |

---

## 4. ACKNOWLEDGMENT WORKFLOW

### 4.1 Acknowledgment API

**File:** `services/api/api/routers/drift.py:acknowledge()`

```python
@router.post("/{drift_id}/acknowledge")
def acknowledge(drift_id, body: AckBody, user=Depends(require_auditor)):
    row = repo.acknowledge(drift_id, user, notes=body.notes)
    # Audit: drift.acknowledge with actor, drift_id, notes
```

**States:** `OPEN` → `ACKNOWLEDGED` → `RESOLVED` / `FALSE_POSITIVE`

### 4.2 Resolution

```python
@router.post("/{drift_id}/resolve")
def resolve_drift(drift_id, body: AckBody, user=Depends(require_auditor)):
    row = repo.resolve(drift_id, user, notes=body.notes)
    # Audit: drift.resolve

@router.post("/{drift_id}/false-positive")
def false_positive(drift_id, body: AckBody, user=Depends(require_auditor)):
    row = repo.mark_false_positive(drift_id, user, notes=body.notes)
    # Audit: drift.false_positive
```

### 4.3 Audit Trail

**File:** `services/api/api/routers/drift.py:_audit()`

```python
def _audit(db, actor, action, drift_id, body):
    UserRepository(db).audit(
        actor, action, target_type="drift_event", target_id=drift_id,
        detail={"notes": body.notes if body else None}
    )
    db.commit()
```

**Audit Chain:** Hash-chained via `AuthService.audit()` → `chain_hash = SHA256(prev + payload)`

---

## 5. DAILY DIGEST

### 5.1 Digest Generation

**File:** `services/drift/drift/alerts/daily_digest.py:build_digest()`

```python
def build_digest(events, window_hours=24):
    # Groups events by:
    # - severity
    # - drift_type
    # - system
    # Returns:
    {
        "window_hours": 24,
        "total_events": N,
        "by_severity": {"CRITICAL": 3, "HIGH": 5, ...},
        "by_type": {"ALGORITHM_CHANGED": 2, "CERTIFICATE_EXPIRING": 5},
        "by_system": {"payment-api": 3, "customer-portal": 1},
        "critical_events": [...],  # Top 10 CRITICAL
        "summary": "12 drift events in 24h: 2 CRITICAL, 5 HIGH, 5 MEDIUM"
    }
```

### 5.2 Digest Delivery

**Endpoint:** `GET /drift/digest?hours=24`

**Delivery Channels:** Not automated — manual API call.

**Gap:** No scheduled delivery (email, webhook, Slack).

---

## 6. DRIFT API ENDPOINTS

| Endpoint | Method | Auth | Roles | Description |
|----------|--------|------|-------|-------------|
| `/drift` | GET | Session | Any | List with filters (severity, status, scan_id, type) |
| `/drift/digest` | GET | Session | Any | Daily digest |
| `/drift/{id}/acknowledge` | POST | Session | Auditor | Acknowledge with notes |
| `/drift/{id}/resolve` | POST | Session | Auditor | Resolve with notes |
| `/drift/{id}/false-positive` | POST | Session | Auditor | Mark false positive |

---

## 6. DRIFT REPOSITORY

**File:** `services/database/db/repositories/drift_repository.py`

```python
class DriftRepository:
    def list_events(self, severity, status, scan_id, drift_type, page, page_size):
        # Tenant-scoped query with filters
    
    def list_since(self, since, page_size):
        # For digest: events since timestamp
    
    def acknowledge(self, drift_id, user, notes):
        # UPDATE status=ACKNOWLEDGED, resolved_by, resolution_notes
    
    def resolve(self, drift_id, user, notes):
        # UPDATE status=RESOLVED, resolved_by, resolution_notes
    
    def mark_false_positive(self, drift_id, user, notes):
        # UPDATE status=FALSE_POSITIVE, resolved_by, resolution_notes
```

---

## 7. DRIFT EVIDENCE & TRACEABILITY

### 7.1 Current Traceability

| Link | Implementation |
|------|----------------|
| DriftEvent → Baseline | `baseline_id` FK |
| DriftEvent → Current Scan | `current_scan_id` FK |
| DriftEvent → Evidence | `drift_details.evidence_ids` (JSON) |
| DriftEvent → EvidenceRecord | **No direct FK** — JSON only |
| DriftEvent → Evidence Chain | **No hashes** — no content/chain hash |

### 7.2 Missing Traceability

| Missing Link | Impact |
|--------------|--------|
| DriftEvent → EvidenceRecord (FK) | Cannot verify evidence integrity |
| DriftEvent → content_hash | Cannot verify evidence integrity |
| DriftEvent → chain_hash | Cannot verify chain integrity |
| DriftEvent → EvidenceRecord (direct FK) | Join via JSON only |

---

## 8. AUTOMATED DRIFT DETECTION — MISSING

### 8.1 Current State

| Capability | Implemented |
|------------|-------------|
| Automated baseline creation | ❌ |
| Scan-to-baseline comparison on completion | ❌ |
| Real-time drift detection | ❌ |
| Drift event emission on detection | ❌ |
| Automated notification | ❌ |
| Drift-based policy gate | ❌ |

### 8.2 Required Implementation

```python
# Missing: services/api/api/routers/scans.py:scan_completed()
def on_scan_complete(scan_id):
    scan = ScanRepository(db).get(scan_id)
    system = SystemRepository(db).get_by_scan(scan_id)
    if not system:
        return
    
    baseline = BaselineRepository(db).get_approved_for_system(system.id)
    if not baseline:
        return  # No baseline, no drift detection
    
    # Compare scan evidence vs baseline evidence
    current_evidence = EvidenceRepository(db).get_all_for_scan(scan_id)
    baseline_evidence = EvidenceRepository(db).get_all_for_scan(baseline.scan_id)
    
    drift_events = compare_evidence(baseline_evidence, current_evidence)
    
    for drift in drift_events:
        DriftRepository(db).create(drift)
        emit_platform_event("DRIFT_DETECTED", ...)
```

---

## 8. REAL-TIME DRIFT MONITORING

### 8.1 Monitor Daemon

**File:** `scripts/run_monitor.py`

```python
# MonitorDaemon runs every MONITOR_TICK_SECONDS (default 30s)
# Checks watch-list targets:
# - Network targets (TLS probes)
# - Cloud accounts (config drift)
# - Repository scans (scheduled)
# - Container images (scheduled)
```

**Current:** Re-scans targets on schedule, creates new scans.

**Gap:** Does not compare against baseline automatically — creates new scans but no drift comparison.

---

## 9. DRIFT TYPES — SEMANTIC GAPS

### 9.1 Missing Drift Types

| Missing Drift Type | Example |
|--------------------|---------|
| `CERTIFICATE_REVOKED` | OCSP/CRL shows revoked |
| `CERTIFICATE_REPLACED` | New cert with different subject/issuer |
| `KEY_ROTATED` | Same algorithm, new key material |
| `ALGORITHM_DEPRECATED` | Algorithm now deprecated by policy |
| `POLICY_VIOLATION_NEW` | New finding violates policy |
| `POLICY_VIOLATION_RESOLVED` | Previous violation now compliant |
| `DEPENDENCY_ADDED` | New crypto dependency |
| `DEPENDENCY_REMOVED` | Crypto dependency removed |
| `VENDOR_COMPROMISE` | Vendor certificate/key compromised |

### 9.2 Semantic Diff Missing

| Current | Needed |
|---------|--------|
| Field-level diff | ✅ |
| Semantic classification | ❌ |
| Migration direction | ❌ (upgrade/downgrade) |
| Risk delta | ❌ |
| Migration effort estimate | ❌ |

---

## 10. DRIFT REPOSITORY QUERIES

### 10.1 Query Patterns

| Query | Index Used | Performance |
|-------|------------|-------------|
| `list_events(severity, status, scan_id, drift_type)` | `scan_id`, `severity`, `status` | OK |
| `list_since(timestamp)` | `detected_at` | OK for recent |
| `get(drift_id)` | PK | OK |

### 10.2 Missing Indexes

| Index Needed | Reason |
|--------------|--------|
| `(severity, status)` | Dashboard filters |
| `(baseline_id, resolution_status)` | Baseline drift tracking |
| `(detected_at, severity)` | Time-range + severity queries |

---

## 10. DRIFT RESOLUTION TRACKING

### 10.1 Metrics Not Tracked

| Metric | Currently Tracked |
|--------|-------------------|
| Mean time to acknowledge (MTTA) | ❌ |
| Mean time to resolve (MTTR) | ❌ |
| False positive rate | ❌ |
| Recurring drift (same finding) | ❌ |
| Drift recurrence by system | ❌ |
| Drift by severity trend | ❌ |

---

## 11. INTEGRATION GAPS

### 11.1 Missing Integrations

| Integration | Status |
|-------------|--------|
| Drift → Remediation task creation | ❌ Manual |
| Drift → Migration task creation | ❌ Manual |
| Drift → Ticketing (Jira/ServiceNow) | ❌ Not implemented |
| Drift → SIEM (Splunk/Elastic) | ❌ Not implemented |
| Drift → PagerDuty/Slack/Email | ❌ Manual digest only |
| Drift → Policy gate (CI/CD block) | ❌ Not implemented |

### 11.2 Drift → Remediation (Missing)

```python
# Should exist:
@router.post("/drift/{id}/create-remediation-task")
def create_remediation_task(drift_id, user=Depends(require_auditor)):
    # Creates MigrationTask from DriftEvent
    # Links drift_id to task
    # Assigns to system owner
```

---

## 12. RECOMMENDATIONS

### P0 — Critical

1. **Implement automated drift detection** — On scan completion vs approved baseline
2. **Add evidence chain to DriftEvent** — content_hash, chain_hash, EvidenceRecord FK
3. **Implement drift event emission** — Platform event on detection

### P1 — High

2. **Add semantic drift classification** — Upgrade/downgrade, migration direction
3. **Implement drift → remediation task automation** — Auto-create MigrationTask
4. **Add scheduled digest delivery** — Email, webhook, Slack
4. **Add drift metrics** — MTTA, MTTR, false positive rate, recurrence

### P2 — Medium

4. **Add missing drift types** — CERTIFICATE_REVOKED, KEY_ROTATED, etc.
4. **Implement drift → ticketing integration** — Jira, ServiceNow
5. **Add drift-based policy gate** — Block deployment on CRITICAL drift
5. **Add recurrence detection** — Same finding drifting repeatedly

### P3 — Enhancement

4. **Semantic drift analysis** — Migration direction, risk delta, effort estimate
4. **Drift correlation** — Related drifts across systems
4. **Drift forecasting** — Predict drift based on trends
4. **Drift visualization** — Timeline, heatmap, trend charts

---

## 11. VERIFICATION EVIDENCE

| Finding | File |
|---------|------|
| DriftEvent model | `services/database/db/models/drift_event.py` |
| Baseline model | `services/database/db/models/baseline.py` |
| Drift router | `services/api/api/routers/drift.py` |
| Drift repository | `services/database/db/repositories/drift_repository.py` |
| Daily digest | `services/drift/drift/alerts/daily_digest.py` |
| Baseline router | `services/api/api/routers/baselines.py` |
| Monitor daemon | `scripts/run_monitor.py` |
| Monitor tick | `services/monitor/` |
| Evidence comparison | `services/cbom/cbom/inventory.py:diff_records()` |
| Drift types | `services/drift/drift/__init__.py` (empty — types in model) |
---

## Round 25 update (2026-10-10) — P0s re-verified: automated detection + event emission exist

* **P0#1 (automated drift detection on scan completion) — STALE.**
  `worker/pipeline/stage_drift.py` runs on every scan completion against
  the approved baseline (plus inventory drift since R23), and the
  monitor's reintroduction/SLA sweeps (R24) cover the between-scans
  surface.
* **P0#3 (drift event emission) — STALE.** `stage_drift` publishes
  `drift.event` on the platform event bus per detection; the R24 SLA
  sweep additionally emits `drift.sla_breach` and alert-routes CRITICAL/
  HIGH crossings.
* **P1#4 (drift metrics) — STALE for MTTA/MTTR/false-positive** (R23
  `GET /drift/sla`, honest `acknowledged_at` stamps, migration 0079).
  Recurrence detection (P2#5) remains open, product-scoped.
* **P0#2 (evidence chain on DriftEvent) — PARTIALLY ADDRESSED, remains
  open in the strict sense.** DriftEvent carries `current_scan_id` /
  `baseline_id` FKs and the drift API joins EvidenceRecords by scan; the
  events do not embed content/chain hashes directly. With this round's
  `evidence_refs` on graph edges and the chain-verification sweep, the
  underlying records are verifiable — but per-event hash embedding
  remains an enrichment decision.
* **P1#2 (semantic drift classification), P1#3 (auto MigrationTask),
  P1#4b (scheduled digest delivery channels), P2 ticketing/policy-gate**
  — product-scoped (the R22 semantic CBOM diff covers the CBOM level:
  ALGORITHM/PARAMETER/VERSION/LOCATION_CHANGED).
