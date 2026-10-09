# 69_CRYPTO_REINTRODUCTION_AUDIT.md
## ZELNX CryptoScan — Crypto Reintroduction Audit

**Generated:** 2026-09-20  
**Method:** Deep inspection of reintroduction detection capabilities for weak/removed cryptography  
**Scope:** Complete reintroduction detection audit — detection logic, alerting, historical tracking, and workflow

---

## EXECUTIVE SUMMARY

**Core Question:** *"Can ZELNX detect when weak/removed cryptography is reintroduced?"*

**Answer:** **NO** — ZELNX has **zero reintroduction detection capability**. Removed algorithms, expired certificates, retired keys, deprecated protocols, and revoked certificates can be reintroduced without detection.

| Reintroduction Type | Detection | Alerting | Workflow | Score |
|---------------------|-----------|----------|----------|-------|
| **Algorithm Reintroduced** | ❌ | ❌ | ❌ | 0/10 |
| **Certificate Reintroduced** | ❌ | ❌ | ❌ | 0/10 |
| **Key Reintroduced** | ❌ | ❌ | ❌ | 0/10 |
| **Protocol Reintroduced** | ❌ | ❌ | ❌ | 0/10 |
| **Certificate Reintroduced (Revoked)** | ❌ | ❌ | ❌ | 0/10 |
| **Weak Config Reintroduced** | ❌ | ❌ | ❌ | 0/10 |
| **Vendor Reintroduced** | ❌ | ❌ | ❌ | 0/10 |

**Overall: 0/10** — Zero reintroduction detection capability

---

## 1. REINTRODUCTION SCENARIOS — WHAT SHOULD BE DETECTED

### 1.1 Algorithm Reintroduction

| Scenario | Example | Risk |
|----------|---------|------|
| **SHA-1 Reintroduced** | Developer adds SHA-1 for "compatibility" | High — collision attacks |
| **MD5 Reintroduced** | Legacy code path uses MD5 | Critical — collision attacks |
| **RSA-1024 Reintroduced** | Legacy key generation path | Critical — factorable |
| **DES/3DES Reintroduced** | Legacy encryption path | Critical — broken |
| **RC4 Reintroduced** | Legacy TLS cipher | Critical — broken |
| **TLS 1.0 Reintroduced** | Legacy compatibility flag | High — POODLE, BEAST |
| **SSLv3 Reintroduced** | Legacy compatibility | Critical — POODLE |

### 1.2 Certificate Reintroduction

| Scenario | Example | Risk |
|----------|---------|------|
| **Expired Cert Renewed with Same Key** | Cert expires, renewed with same private key | Medium — key compromise window |
| **Revoked Cert Reissued** | CA reissues revoked cert | Critical — trust violation |
| **Expired Cert Reused** | Expired cert deployed to new endpoint | High — trust violation |
| **Self-Signed Cert Reused** | Dev self-signed cert deployed to prod | High — trust violation |

### 1.3 Key Reintroduction

| Scenario | Example | Risk |
|----------|---------|------|
| **Retired Key Reused** | Destroyed key restored from backup | Critical — key compromise |
| **Compromised Key Reused** | Known compromised key redeployed | Critical — active compromise |
| **Weak Key Regenerated** | RSA-1024 regenerated | Critical — factorable |
| **Deprecated Key Type** | DSA key regenerated | High — deprecated |

### 1.4 Protocol Reintroduction

| Scenario | Example | Risk |
|----------|---------|------|
| **TLS 1.0 Re-enabled** | Legacy client support flag | High — POODLE, BEAST |
| **SSLv3 Re-enabled** | Legacy client support | Critical — POODLE |
| **DTLS 1.0 Enabled** | Legacy DTLS | High |
| **Weak Cipher Suite Enabled** | RC4, DES, 3DES enabled | Critical |

### 1.5 Certificate Reintroduction (Revoked)

| Scenario | Example | Risk |
|----------|---------|------|
| **Revoked Cert Reissued** | CA reissues revoked serial | Critical — trust violation |
| **CRL/OCSP Bypass** | Revoked cert accepted | Critical — trust violation |
| **CT Log Bypass** | Cert not logged to CT | Medium |

### 1.6 Weak Config Reintroduction

| Scenario | Example | Risk |
|----------|---------|------|
| **TLS 1.0 Re-enabled** | Config rollback | High |
| **Weak Cipher Enabled** | RC4/3DES re-enabled | Critical |
| **Short Key Size** | RSA-1024 allowed | Critical |
| **Weak Hash** | SHA-1/MD5 allowed | High |

### 1.6 Vendor Reintroduction

| Scenario | Example | Risk |
|----------|---------|------|
| **Removed Vendor Re-added** | Compromised vendor re-added | High |
| **Malicious Library Re-added** | Compromised library re-added | Critical |

---

## 2. CURRENT STATE — ZERO DETECTION

### 2.1 Current Capabilities

| Reintroduction Type | Detection Logic | Alerting | Workflow |
|---------------------|-----------------|----------|----------|
| **Algorithm** | ❌ | ❌ | ❌ |
| **Certificate** | ❌ | ❌ | ❌ |
| **Key** | ❌ | ❌ | ❌ |
| **Protocol** | ❌ | ❌ | ❌ |
| **Config** | ❌ | ❌ | ❌ |
| **Vendor** | ❌ | ❌ | ❌ |

### 2.2 Why Detection Fails

| Missing Component | Description |
|-------------------|-------------|
| **Historical State Tracking** | No asset timeline to know what was removed |
| **Retirement Tracking** | No record of what was explicitly removed |
| **Deprecation Registry** | No registry of deprecated/removed items |
| **Reintroduction Detection Logic** | No comparison logic |
| **Alerting Rules** | No alerting rules for reintroduction |
| **Workflow** | No reintroduction response workflow |

---

## 3. REQUIRED REINTRODUCTION DETECTION MODEL

### 3.1 Required Data Model

```python
class RetiredAssetRegistry:
    """Registry of explicitly retired/deprecated assets"""
    asset_id: UUID
    asset_type: AssetType  # ALGORITHM, CERTIFICATE, KEY, PROTOCOL, CONFIG, VENDOR
    identifier: str        # Algorithm name, cert fingerprint, key ID, etc.
    retired_at: DateTime
    retired_by: str
    reason: str            # DEPRECATED, COMPROMISED, EXPIRED, REPLACED, POLICY
    retired_by_policy: str | None  # Policy rule that caused retirement
    replacement: str | None       # What replaced it (e.g., "ML-KEM-768")
    metadata: dict

class ReintroductionEvent:
    event_id: UUID
    asset_type: AssetType
    identifier: str
    detected_at: DateTime
    detected_by: DetectionSource  # SCAN, MONITOR, MANUAL, ALERT
    previous_state: AssetState    # RETIRED, DEPRECATED, REVOKED, EXPIRED
    current_state: AssetState     # ACTIVE, DETECTED
    evidence: List[EvidenceRef]   # What proves reintroduction
    severity: Severity            # CRITICAL, HIGH, MEDIUM, LOW
    status: DetectionStatus       # NEW, ACKNOWLEDGED, INVESTIGATING, RESOLVED, FALSE_POSITIVE
    assigned_to: str | None
    acknowledged_at: DateTime | None
    acknowledged_by: str | None
    resolution: Resolution | None
```

### 3.2 Detection Logic

```python
class ReintroductionDetector:
    def __init__(self, retired_registry: RetiredAssetRegistry):
        self.retired_registry = retired_registry
    
    def check_for_reintroductions(self, current_findings: List[Finding]) -> List[ReintroductionEvent]:
        """Check all current findings against retired registry"""
        events = []
        for finding in current_findings:
            # Normalize finding identifier
            identifier = self._normalize_identifier(finding)
            asset_type = self._determine_asset_type(finding)
            
            # Check if this identifier was previously retired
            retired_entry = self.retired_registry.lookup(asset_type, identifier)
            if retired_entry:
                # REINTRODUCTION DETECTED
                event = ReintroductionEvent(
                    asset_type=finding.asset_type,
                    identifier=identifier,
                    detected_at=datetime.now(timezone.utc),
                    detected_by=DetectionSource.SCAN,
                    previous_state=retired_entry.reason,
                    current_state=AssetState.ACTIVE,
                    evidence=[finding.evidence_id],
                    severity=self._calculate_severity(finding, retired_entry),
                )
                events.append(event)
        return events
    
    def _calculate_severity(self, finding, retired_entry):
        # CRITICAL: Compromised key, broken algorithm, revoked cert
        # HIGH: Deprecated algorithm, weak config, expired cert
        # MEDIUM: Deprecated protocol, weak config
        # LOW: Cosmetic reintroduction
        pass
```

---

## 3. RETIREMENT TRACKING — MISSING

### 3.1 Required Retirement Tracking

| Event | Current Tracking | Required Tracking |
|-------|------------------|-------------------|
| **Algorithm Deprecated** | ❌ | Policy rule + timestamp |
| **Algorithm Removed** | ❌ | Retirement event + reason |
| **Certificate Expired** | ⚠️ Monitor only | Expiry + non-renewal |
| **Certificate Revoked** | ❌ | Revocation event + reason |
| **Key Destroyed** | ❌ | Destruction event + verification |
| **Key Compromised** | ❌ | Compromise event + rotation |
| **Protocol Deprecated** | ❌ | Policy rule + timestamp |
| **Protocol Disabled** | ❌ | Disable event + reason |
| **Vendor Removed** | ❌ | Removal event + reason |
| **Config Hardened** | ❌ | Config change + validation |

### 3.2 Required Retirement Registry

```python
class RetirementRegistry:
    def register_retirement(self, asset: RetiredAssetRegistry):
        """Register an asset as explicitly retired"""
        pass
    
    def is_retired(self, asset_type: AssetType, identifier: str) -> bool:
        """Check if asset was previously retired"""
        pass
    
    def get_retirement_info(self, asset_type: AssetType, identifier: str) -> RetiredAssetRegistry | None:
        """Get retirement details"""
        pass
```

---

## 4. REINTRODUCTION DETECTION WORKFLOW

### 4.1 Detection → Alert → Workflow

```
1. DETECTION (Scan/Monitor)
   ↓
2. MATCH against Retirement Registry
   ↓
3. CREATE ReintroductionEvent
   ↓
4. SEVERITY CALCULATION
   ↓
5. ALERT GENERATION
   ├── CRITICAL → Page security team + business owner
   ├── HIGH → Alert security team + business owner
   ├── MEDIUM → Alert security team
   └── LOW → Log only
   ↓
6. ACKNOWLEDGMENT WORKFLOW
   ├── Assign to security analyst
   ├── Acknowledge (with notes)
   ├── Investigate (root cause)
   ├── Remediate (remove/block)
   ├── Verify (rescan)
   ├── Close (with evidence)
   ↓
7. RESOLUTION
   ├── Mark resolved
   ├── Document root cause
   ├── Update retirement registry (if new retirement)
   └── Update detection rules (if new pattern)
```

---

## 5. SEVERITY CALCULATION

### 5.1 Severity Matrix

| Reintroduction Type | Base Severity | Escalation Factors |
|---------------------|---------------|-------------------|
| **Compromised Key Reused** | CRITICAL | Active exploitation, data breach |
| **Revoked Cert Reissued** | CRITICAL | Trust violation, MITM risk |
| **Broken Algorithm (MD5, DES, RC4)** | CRITICAL | Known broken, active exploits |
| **Deprecated Algorithm (SHA-1, RSA-1024)** | HIGH | Known attacks, compliance |
| **Deprecated Protocol (TLS 1.0, SSLv3)** | HIGH | POODLE, BEAST, compliance |
| **Weak Config Reintroduced** | HIGH | Downgrade attack surface |
| **Expired Cert Reused** | HIGH | Trust violation |
| **Deprecated Algorithm (RSA-1024)** | HIGH | Factorable |
| **Deprecated Protocol (DTLS 1.0)** | MEDIUM | Limited exposure |
| **Deprecated Config** | MEDIUM | Increased attack surface |
| **Vendor Reintroduced** | MEDIUM | Supply chain risk |

---

## 6. ALERTING & NOTIFICATION

### 6.1 Required Alerting Channels

| Severity | Channels | Escalation |
|----------|----------|------------|
| **CRITICAL** | PagerDuty, Slack, Email, SMS | 5 min → Security Lead → CISO |
| **HIGH** | Slack, Email | 15 min → Security Analyst → Security Lead |
| **MEDIUM** | Slack, Email | 1 hour → Security Analyst |
| **LOW** | Slack | 4 hours → Security Analyst |

### 5.2 Alert Content

```python
class ReintroductionAlert:
    event_id: UUID
    severity: Severity
    asset_type: AssetType
    identifier: str
    description: str
    detected_at: DateTime
    evidence: List[EvidenceRef]
    retired_info: RetiredAssetRegistry
    affected_systems: List[SystemRef]
    business_owners: List[BusinessOwnerRef]
    security_owners: List[SecurityOwnerRef]
    suggested_actions: List[str]
    runbook_url: str
```

---

## 6. REINTRODUCTION RESPONSE WORKFLOW

### 6.1 Response Phases

```
1. ACKNOWLEDGE (5 min - 1 hour)
   ├── Security analyst acknowledges
   ├── Assigns to investigator
   └── Starts investigation timer

2. INVESTIGATE (15 min - 2 hours)
   ├── Root cause: How was it reintroduced?
   ├── Scope: How many systems affected?
   ├── Blast radius: Business impact
   └── Evidence collection

3. REMEDIATE (1 hour - 24 hours)
   ├── Immediate: Block/remove reintroduced asset
   ├── Short-term: Deploy fix (config, code, cert)
   ├── Long-term: Prevent recurrence (policy, automation)
   └── Update retirement registry

4. VERIFY (30 min - 2 hours)
   ├── Rescan affected systems
   ├── Confirm removal
   ├── Verify no other reintroductions
   └── Evidence collection

5. CLOSE (with evidence)
   ├── Document root cause
   ├── Document remediation
   ├── Update detection rules
   ├── Update retirement registry
   └── Close with evidence package
```

---

## 7. RECOMMENDATIONS

### P0 — Critical

1. **Implement Retirement Registry** — Track all retired/deprecated assets
2. **Implement Reintroduction Detector** — Scan-time + monitor-time detection
3. **Implement Severity Calculation** — Risk-based severity matrix
4. **Implement Alerting** — Critical/High/Medium/Low with escalation

### P1 — High

4. **Implement Reintroduction Workflow** — Detect → Alert → Investigate → Remediate → Verify → Close
5. **Implement Alerting** — PagerDuty, Slack, Email with escalation
5. **Add Reintroduction Dashboard** — Detection dashboard with status
6. **Implement Historical State Tracking** — Asset timeline with retirement events

### P2 — Medium

8. **Automated Remediation** — Auto-block reintroduced assets
8. **Reintroduction Prevention** — CI/CD gate to prevent reintroduction
9. **Historical State Reconstruction** — Reconstruct retirement history from scans
10. **Cross-Asset Correlation** — Detect coordinated reintroductions

### P3 — Enhancement

11. **ML-Based Anomaly Detection** — Unusual reintroduction patterns
11. **Predictive Reintroduction** — Predict likely reintroductions
12. **Cross-Org Reintelligence Sharing** — Industry reintroduction sharing
12. **Reintroduction Simulation** — "What if this asset is reintroduced?"

---

## 8. VERDICT

**ZERO reintroduction detection capability.** No retirement tracking, no detection logic, no alerting, no workflow.

| Capability | Status |
|------------|--------|
| Retirement Tracking | ❌ Missing |
| Reintroduction Detection | ❌ Missing |
| Severity Calculation | ❌ Missing |
| Alerting | ❌ Missing |
| Response Workflow | ❌ Missing |
| Historical State Tracking | ❌ Missing |
| Dashboard | ❌ Missing |

**To implement:** 6-8 weeks for complete reintroduction detection system with registry, detector, alerting, workflow, and dashboard.

---

## 8. VERIFICATION EVIDENCE

| Finding | File |
|---------|------|
| Drift Detection | `services/drift/drift/` (drift types only) |
| Baseline Model | `services/database/db/models/baseline.py` |
| DriftEvent Model | `services/database/db/models/drift_event.py` |
| Drift Router | `services/api/api/routers/drift.py` |
| Drift Repository | `services/database/db/repositories/drift_repository.py` |
| Graph Engine | `services/graph_engine/graph_engine/core/engine.py` |
| Drift Types | `services/drift/drift/__init__.py` (empty) |
| Evidence Pipeline | `services/evidence/evidence/core/pipeline.py` |
| Baseline Router | `services/api/api/routers/baselines.py` |
| Scan Model | `services/database/db/models/scan.py` |
## UPDATE — 2026-10-09: reintroduction detection built (scan-time)

The Detect -> Alert -> Investigate -> Remediate -> Verify -> Close workflow's
detection half now exists:

* **Registry:** `retired_assets` table (migration 0073) records deliberate
  retirements — algorithm + scope (FILE / ASSET / ALGORITHM), reason, actor,
  optional provenance to the remediation task that verified the fix.
* **Detector:** `services/remediation/remediation/reintroduction.py` (pure,
  no DB) matches scan evidence against active retirements.
* **Severity routing** per this report §"Alerting": hardcoded key or policy
  FAIL -> CRITICAL (page), WARN -> HIGH (alert), clean reappearance -> MEDIUM
  (log). Worst match wins.
* **API:** `POST /retirements` (auditor), `GET /retirements`,
  `POST /retirements/{id}/lift` (auditor, reason recorded, kept for trail),
  and `POST /retirements/check/{scan_id}` (auditor) which emits one
  severity-routed platform event per detection.
* Malformed registry rows (ASSET scope without asset id, unknown scope)
  deliberately never match — a bad row cannot silently watch everything.
* Still open (monitor-time): the registry is checked per scan on demand;
  continuous background checking across monitor cycles remains follow-up.
