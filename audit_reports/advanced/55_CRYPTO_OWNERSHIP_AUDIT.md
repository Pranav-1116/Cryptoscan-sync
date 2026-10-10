# 55_CRYPTO_OWNERSHIP_AUDIT.md
## ZELNX CryptoScan — Crypto Ownership Audit

**Generated:** 2026-09-20  
**Method:** Deep inspection of ownership model across all cryptographic assets and systems  
**Scope:** Complete ownership model — Organization, Business Unit, Application Owner, Technical Owner, Security Owner, Vendor, Environment

---

## EXECUTIVE SUMMARY

**Core Question:** *"Who owns this cryptographic risk?"*

**Answer:** **PARTIAL** — Ownership exists at System level but **not at individual crypto asset level**. Ownership is coarse-grained, single-owner, and lacks technical/business separation.

| Ownership Aspect | Status | Score |
|------------------|--------|-------|
| System Ownership | ✅ Explicit | 8/10 |
| Asset Ownership | ❌ Via System only | 3/10 |
| Certificate Ownership | ❌ String only | 2/10 |
| Business Owner Mapping | ✅ BusinessOwner model | 8/10 |
| Technical Owner | ❌ Missing | 0/10 |
| Security Owner | ❌ Missing | 0/10 |
| Multi-owner Support | ❌ Single only | 2/10 |
| Ownership History | ❌ Missing | 0/10 |
| Environment-scoped Ownership | ❌ Missing | 0/10 |
| Delegated Ownership | ❌ Missing | 0/10 |

**Overall: 2.5/10** — Ownership model is coarse and incomplete

---

## 1. CURRENT OWNERSHIP MODEL

### 1.1 System-Level Ownership

**File:** `services/database/db/models/system.py`

```python
class System:
    id: str
    name: str
    owner: str                    # BusinessOwner email (string)
    business_unit: str | None     # BusinessUnit name (string)
    criticality: str | None       # CRITICAL, HIGH, MEDIUM, LOW
    environment: str | None       # PRODUCTION, STAGING, DEVELOPMENT
    compliance_scopes: List[str]  # PCI-DSS, HIPAA, etc.
    extra: dict | None            # Additional metadata
```

**Ownership via:** `owner` (string email) → `BusinessOwner` table

### 1.2 Business Owner Model

**File:** `services/database/db/models/business_owner.py`

```python
class BusinessOwner:
    id: str
    name: str
    email: str
    # Links via SystemBusinessProcess → System
```

**Link:** `SystemBusinessProcess` table links Systems ↔ BusinessProcesses ↔ BusinessOwners

### 1.3 Crypto Asset Ownership — VIA SYSTEM ONLY

**File:** `services/database/db/models/crypto_asset.py`

```python
class CryptoAsset:
    # NO direct owner field
    # Ownership via SystemAsset link table:
    # SystemAsset.system_id → System.owner → BusinessOwner
```

**Gap:** No direct ownership on CryptoAsset. Must traverse: `CryptoAsset → SystemAsset → System → owner → BusinessOwner`

---

## 2. OWNERSHIP GAPS

### 2.1 Missing Owner Types

| Owner Type | Current | Needed |
|------------|---------|--------|
| **Business Owner** | ✅ (System level) | ✅ |
| **Technical Owner** | ❌ | Dev team, platform team |
| **Security Owner** | ❌ | Security team, AppSec |
| **Compliance Owner** | ❌ | Compliance team |
| **Operational Owner** | ❌ | SRE, DevOps |
| **Executive Sponsor** | ❌ | C-level accountability |
| **Vendor Contact** | ❌ | Vendor relationship manager |

### 2.2 Single Owner Only

```python
# System.owner = single string email
# No multi-owner support
# No role-based ownership (technical vs business)
# No ownership percentages
# No ownership delegation
```

**Impact:** Cannot represent shared ownership (e.g., Platform team + App team co-own)

---

### 2.3 Certificate Ownership — STRING ONLY

**File:** `services/database/db/models/certificate.py`

```python
class Certificate:
    owner: str  # Just a string, no FK
    # No link to BusinessOwner, System, or Vendor
```

**Gap:** Certificate ownership is a free-text string with no validation or relationships.

---

### 2.4 Certificate Usage — LINK ONLY

**File:** `services/database/db/models/certificate_usage.py`

```python
class CertificateUsage:
    certificate_id: str
    system_id: str
    # Links certificate to system, but no ownership info
```

**Gap:** CertificateUsage links cert to system, but ownership still only via System.owner

---

### 2.5 Vendor Ownership — MISSING

**File:** `services/database/db/models/vendor.py`

```python
class Vendor:
    id: str
    name: str
    criticality: str
    # NO owner field
    # NO contact person
    # NO relationship manager
```

**Gap:** Vendor has no ownership info at all.

---

## 3. OWNERSHIP RELATIONSHIPS

### 3.1 Current Relationship Graph

```
BusinessOwner (email, name)
    ← owns → System (owner string)
        ← uses → CryptoAsset (via SystemAsset)
        ← uses → Certificate (via CertificateUsage)
        ← depends_on → Vendor (no owner)
        ← supports → BusinessProcess
            ← owned_by → BusinessOwner
```

### 3.2 Missing Relationships

| Missing Relationship | Impact |
|----------------------|--------|
| **CryptoAsset → Technical Owner** | Cannot alert dev team |
| **CryptoAsset → Security Owner** | Cannot alert security team |
| **Certificate → Technical Owner** | Cannot alert cert renewal to right team |
| **Vendor → Relationship Manager** | Cannot contact vendor owner |
| **Key → Key Custodian** | No key custodian concept |
| **Algorithm → Subject Matter Expert** | No crypto SME mapping |
| **Environment-scoped Ownership** | Dev vs Prod different owners |

---

## 4. OWNERSHIP METADATA — MISSING

### 4.1 Missing Ownership Metadata

| Metadata | Current | Needed |
|----------|---------|--------|
| **Ownership Type** | None | PRIMARY, SECONDARY, DELEGATED, EMERGENCY |
| **Ownership Start Date** | None | When ownership began |
| **Ownership End Date** | None | When ownership ended |
| **Ownership Source** | None | MANUAL, AUTO_DISCOVERED, CMDB_SYNC, HR_SYNC |
| **Ownership Confidence** | None | HIGH, MEDIUM, LOW |
| **Ownership Approval** | None | APPROVED, PENDING, REJECTED |
| **Delegation Chain** | None | Who delegated to whom |
| **Escalation Path** | None | Who to escalate to |
| **On-Call Schedule** | None | Who's on call for this asset |

---

## 5. OWNERSHIP HISTORY — MISSING

### 5.1 No Ownership Audit Trail

| Missing | Impact |
|---------|--------|
| **Ownership Change Log** | Cannot track when/why ownership changed |
| **Previous Owners** | Cannot see previous owners |
| **Ownership Transfer Reason** | Cannot audit why ownership changed |
| **Ownership Approval Trail** | Cannot verify approval process |
| **Ownership Dispute Resolution** | Cannot resolve disputes |

---

## 6. ENVIRONMENT-SCOPED OWNERSHIP — MISSING

### 6.1 Current: Single Owner Per System

```python
# System has ONE owner regardless of environment
# System.environment = "PRODUCTION" | "STAGING" | "DEVELOPMENT"
# But owner is same for all environments
```

### 6.2 Required: Environment-Scoped Ownership

| Environment | Business Owner | Technical Owner | Security Owner |
|-------------|----------------|-----------------|----------------|
| PRODUCTION | VP Payments | Platform Team Lead | AppSec Lead |
| STAGING | Engineering Manager | Senior Engineer | Security Engineer |
| DEVELOPMENT | Team Lead | Developer | Security Champion |

**Current:** Impossible — single owner field.

---

## 7. DELEGATED OWNERSHIP — MISSING

### 7.1 No Delegation Model

| Delegation Type | Current | Needed |
|-----------------|---------|--------|
| **Permanent Delegation** | ❌ | Delegate ownership to team member |
| **Temporary Delegation** | ❌ | Vacation coverage, on-call |
| **Emergency Delegation** | ❌ | Incident response |
| **Project-based Delegation** | ❌ | Migration project ownership |
| **Automatic Expiry** | ❌ | Delegation expires after N days |

---

## 8. OWNERSHIP DISCOVERY — MISSING

### 8.1 No Automated Ownership Discovery

| Discovery Source | Implemented |
|------------------|-------------|
| Git blame / code ownership | ❌ |
| GitHub CODEOWNERS | ❌ |
| GitLab CODEOWNERS | ❌ |
| Jira component ownership | ❌ |
| ServiceNow CMDB | ❌ |
| HR system (manager → team) | ❌ |
| LDAP/AD group membership | ❌ |
| Okta/Entra ID groups | ❌ |
| PagerDuty schedules | ❌ |
| Opsgenie schedules | ❌ |
| ServiceNow assignment groups | ❌ |

---

## 9. OWNERSHIP IN WORKFLOWS

### 9.1 Current Workflow Integration

| Workflow | Owner Involvement |
|----------|-------------------|
| **Scan Trigger** | Scanner role (not owner) |
| **Baseline Approval** | Auditor role (not owner) |
| **Drift Acknowledgement** | Auditor role (not owner) |
| **Drift Resolution** | Auditor role (not owner) |
| **Remediation Planning** | Security Analyst (not owner) |
| **Remediation Execution** | Developer (technical owner, but not tracked) |
| **Verification** | Security Analyst (not owner) |
| **Baseline Approval** | Auditor (not business owner) |

**Gap:** Business owners never involved in crypto workflows.

---

### 9.2 Required Owner Workflows

| Workflow | Owner Action |
|----------|--------------|
| **Risk Notification** | Auto-alert business owner on CRITICAL/HIGH risk |
| **Drift Acknowledgement** | Business owner MUST acknowledge (not just auditor) |
| **Remediation Prioritization** | Business owner sets priority |
| **Remediation Approval** | Business owner approves plan |
| **Migration Sign-off** | Business owner signs off migration |
| **Risk Acceptance** | Business owner formally accepts risk |
| **Certificate Renewal** | Technical owner notified, business owner informed |
| **Key Rotation** | Technical owner executes, security owner verifies |

---

## 10. "WHO OWNS THIS CRYPTO RISK?" — TEST

### 10.1 Test Scenario: RSA-2048 in Payment API

| Question | Answerable? | How |
|----------|-------------|-----|
| Who is the business owner? | ✅ | `System.owner` → `BusinessOwner` |
| Who is the technical owner? | ❌ | Not tracked |
| Who is the security owner? | ❌ | Not tracked |
| Who approved the baseline? | ✅ | `Baseline.approved_by` |
| Who acknowledged the drift? | ✅ | `DriftEvent.acknowledged_by` (but auditor, not owner) |
| Who is responsible for remediation? | ❌ | Not assigned |
| Who approved the remediation plan? | ❌ | Not tracked |
| Who executed the remediation? | ❌ | Not tracked |
| Who verified the remediation? | ❌ | Not tracked |
| Who signed off migration? | ❌ | Not tracked |

**Answer:** Can only answer 2/10 ownership questions.

---

## 11. RECOMMENDATIONS

### P0 — Critical

1. **Add Technical Owner to System** — `technical_owner` field (FK to User/Team)
2. **Add Security Owner to System** — `security_owner` field (FK to User/Team)
3. **Add Direct Ownership to CryptoAsset** — `owner_id`, `technical_owner_id`, `security_owner_id`
4. **Add Ownership to Certificate** — Structured ownership with FKs
5. **Add Ownership to Vendor** — Relationship manager, technical contact

### P1 — High

4. **Implement Multi-Owner Support** — `SystemOwnership` link table with roles
5. **Add Environment-Scoped Ownership** — Ownership per environment
6. **Add Delegated Ownership** — Temporary/permanent delegation with expiry
7. **Add Ownership History** — Audit trail of all ownership changes

### P2 — Medium

8. **Implement Automated Ownership Discovery** — Git blame, CODEOWNERS, HR sync
9. **Add Ownership to Workflows** — Owner notifications, approvals, sign-offs
10. **Add Ownership Metadata** — Type, source, confidence, approval, delegation chain
11. **Implement Environment-Scoped Ownership** — Per-environment owners

### P3 — Enhancement

12. **Ownership Dashboard** — Visual ownership map
12. **Ownership Analytics** — Ownership concentration, gaps, conflicts
13. **Ownership Certification** — Periodic ownership review/certification
13. **Delegation Workflow** — Request/approve/expire delegation

---

## 10. VERDICT

**Ownership model is coarse, single-owner, system-level only.** Cannot answer "who owns this crypto risk?" for individual assets, certificates, or keys. Business owners exist but are disconnected from crypto workflows. Technical/security ownership completely missing.

| Capability | Status |
|------------|--------|
| Business Owner (System) | ✅ |
| Technical Owner | ❌ |
| Security Owner | ❌ |
| Asset-Level Ownership | ❌ |
| Certificate Ownership | ❌ |
| Vendor Ownership | ❌ |
| Multi-Owner | ❌ |
| Environment-Scoped | ❌ |
| Delegation | ❌ |
| Ownership History | ❌ |
| Automated Discovery | ❌ |
| Workflow Integration | ❌ |

**To fix:** 6-8 weeks for complete ownership model with multi-owner, environment-scoped, delegated ownership, history, discovery, and workflow integration.

---

## 8. VERIFICATION EVIDENCE

| Finding | File |
|---------|------|
| System model | `services/database/db/models/system.py` |
| BusinessOwner model | `services/database/db/models/business_owner.py` |
| SystemAsset link | `services/database/db/models/system_asset.py` |
| CryptoAsset model | `services/database/db/models/crypto_asset.py` |
| Certificate model | `services/database/db/models/certificate.py` |
| CertificateUsage model | `services/database/db/models/certificate_usage.py` |
| Vendor model | `services/database/db/models/vendor.py` |
| BusinessProcess model | `services/database/db/models/business_process.py` |
| SystemBusinessProcess | `services/database/db/models/system_business_process.py` |
| SystemDependency | `services/database/db/models/system_dependency.py` |
| CryptoAssetEvidence | `services/database/db/models/crypto_asset_evidence.py` |
| BusinessOwner repository | `services/database/db/repositories/business_owner_repository.py` |
| SystemRepository | `services/database/db/repositories/system_repository.py` |
---

## UPDATE ADDENDUM — Round 19 (2026-10-10): ownership roles built

**P0 #1/#2 (technical + security owner on System) are now code.**
Migration `0077_system_ownership` adds `systems.technical_owner` and
`systems.security_owner` (String 200, nullable) next to the existing
free-text `owner` — the report's exact accountability split: technical
owner answers "who changes the crypto", security owner answers "who
accepts the risk".

Surfaces:

- `POST /systems` and `PATCH /systems/{id}` accept all three owner
  fields; CMDB import (`upsert_imported`) carries them through with
  fill-if-empty semantics like every other field.
- **Ownership changes are audited** (P1 #7-lite): any effective change
  to `owner`/`technical_owner`/`security_owner` via PATCH writes a
  `system.ownership_change` audit-chain entry recording old → new per
  field. Same-value patches are not audited; non-ownership patches are
  not audited as ownership changes.

Remaining open from this report: direct CryptoAsset/Certificate owner
FKs (#3/#4), the `SystemOwnership` multi-owner link table with roles
and delegation (#4/#6), environment-scoped ownership (#5), automated
ownership discovery from CODEOWNERS/git blame (#8) — product decisions
with real schema cost, tracked in 00_ROUND_STATUS.

Tests: `services/api/tests/unit/test_round19_risk_exposure_ownership.py`
(ownership block: 4 tests).

## Round 27 update (2026-10-10) — direct ownership built on assets, certificates, vendors

* **System owners (P0 #1/#2) — already shipped (round 19, re-verified):**
  `systems.technical_owner` / `security_owner` next to the business
  `owner`, surfaced through the inventory and risk surfaces.
* **Direct ownership on CryptoAsset (P0 #3) — NOW BUILT (this round).**
  Migration 0080 adds `owner` / `technical_owner` / `security_owner` to
  `crypto_assets` (same free-form identity convention as the System
  fields — the platform has no user directory to FK against).
  `POST /inventory/assets/{asset_id}/ownership` assigns them under the
  same audited-write + asset-level grant-check path as the lifecycle
  transitions (round 22 inheritance applies), requires a reason, emits
  a platform event with before/after, and only changes supplied fields.
  The unified inventory listing now carries the three owner fields on
  crypto rows.
* **Certificate ownership (P0 #4) — NOW BUILT.** Migration 0080 adds
  `owner` / `technical_contact` to `certificates`;
  `POST /certificates/{fingerprint}/ownership` (permission
  `certificates.manage`) with audit trail — a certificate with no usage
  links used to have nobody to notify at expiry. The certificate
  listing carries the fields.
* **Vendor contacts (P0 #5) — NOW BUILT.** Vendors already had
  `primary_contact` (commercial) and `security_contact`; migration
  0080 adds `technical_contact` — the party answering crypto questions
  (algorithms, protocols, key handling). Assigned via
  `POST /vendors/{vendor_id}/ownership` (auditor-gated, audited).
* **Still open (P1+):** multi-owner link table with roles,
  environment-scoped ownership, delegation with expiry, and automated
  ownership discovery (CODEOWNERS / git blame / HR sync) — all
  product-scoped, tracked in 00_ROUND_STATUS.
* Tests: `services/api/tests/unit/test_round27_ownership.py` (7:
  assignment + partial-update semantics + reason-required + 404s +
  viewer-403 for all three surfaces) and the migration-chain guard in
  `services/database/tests/unit/test_schema_ensure.py`.
