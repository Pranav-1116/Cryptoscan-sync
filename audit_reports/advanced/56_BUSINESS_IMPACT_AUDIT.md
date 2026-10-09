# 56_BUSINESS_IMPACT_AUDIT.md
## ZELNX CryptoScan — Business Impact Audit

**Generated:** 2026-09-20  
**Method:** Deep inspection of business impact modeling, connectivity from crypto findings to business services, owners, revenue, and regulatory exposure  
**Scope:** Complete business impact chain — Weak algorithm → Affected application → Business service → Business owner → Criticality → Regulatory exposure → PQC migration priority

---

## EXECUTIVE SUMMARY

**Core Question:** *"Can ZELNX connect cryptographic findings to business impact?"*

**Answer:** **PARTIAL** — Strong graph-based impact analysis exists but **missing key connections** from crypto findings to business services and regulatory exposure.

| Impact Aspect | Status | Score |
|---------------|--------|-------|
| Graph-Based Impact | ✅ Strong | 8/10 |
| Revenue at Risk | ✅ Calculated | 8/10 |
| Customer Impact | ✅ Calculated | 7/10 |
| Business Process Mapping | ✅ Exists | 7/10 |
| Business Owner Link | ✅ Via System | 7/10 |
| Crypto → Service Trace | ❌ Missing | 2/10 |
| Regulatory Exposure | ⚠️ Partial | 4/10 |
| Crypto Finding → Business Service | ❌ Broken | 2/10 |
| Compliance Scope Impact | ⚠️ Partial | 4/10 |
| Migration Priority | ✅ Wave-based | 7/10 |
| Executive Reporting | ✅ Templates | 7/10 |

**Overall: 5.5/10** — Strong graph engine, broken crypto-to-business traceability

---

## 1. BUSINESS IMPACT ARCHITECTURE

### 1.1 Current Impact Model (Graph-Based)

**File:** `services/graph_engine/graph_engine/core/engine.py:business_impact()`

```python
def business_impact(self, start_id, hops=5):
    # 1. Blast radius from start node
    # 2. For each affected system:
    #    - Sum BusinessProcess.revenue_daily
    #    - Sum BusinessProcess.customer_count
    #    - Collect BusinessOwners via OWNED_BY edges
    #    - Collect ComplianceScopes via MUST_COMPLY_WITH edges
    return {
        "total_revenue_at_risk": float,
        "total_customers_at_risk": int,
        "affected_processes": List[str],
        "business_owners": List[str],
        "compliance_scopes": List[str],
        "systems": List[SystemImpact]
    }
```

### 1.2 Current Impact Chain (Partial)

```
CryptoAsset (algorithm, quantum_vulnerable)
    ↓ USES edge
System (criticality, business_unit, owner)
    ↓ SUPPORTS edge
BusinessProcess (revenue_daily, customer_count)
    ↓ OWNED_BY edge
BusinessOwner (name, email)
    ↓ MUST_COMPLY_WITH edge
ComplianceScope (PCI-DSS, HIPAA, etc.)
```

**Broken Link:** `CryptoAsset` → `BusinessProcess` — No direct path. Must traverse: `CryptoAsset` → `SystemAsset` → `System` → `BusinessProcess`

---

## 2. CRYPTO FINDING → BUSINESS SERVICE — BROKEN

### 2.1 Current Path (Broken)

| Step | Current | Status |
|------|---------|--------|
| Crypto Finding → EvidenceRecord | ✅ | Direct FK |
| EvidenceRecord → CryptoAsset | ✅ | Via `replace_for_scan` |
| CryptoAsset → System | ⚠️ | Via `SystemAsset` link table |
| System → BusinessProcess | ✅ | Via `SystemBusinessProcess` |
| BusinessProcess → BusinessOwner | ✅ | Via `SystemBusinessProcess` + `System.owner` |

**Critical Gap:** `CryptoAsset` → `System` requires `SystemAsset` link which is **not always populated**. CryptoAssets from CBOM ingest, network scans, or live crypto may not have `SystemAsset` links.

### 2.2 Missing Direct Paths

| Missing Path | Impact |
|--------------|--------|
| `CryptoAsset` → `BusinessProcess` (direct) | Must traverse 3 hops |
| `EvidenceRecord` → `BusinessProcess` | No direct path |
| `Finding` → `BusinessService` | No business service concept |
| `Certificate` → `BusinessProcess` | Via `CertificateUsage` → `System` only |
| `NetworkResource` → `BusinessProcess` | Via `NetworkInventory.system_id` only |
| `CloudResource` → `BusinessProcess` | Via `CloudAccount.system_id` only |
| `DriftEvent` → `BusinessProcess` | Via `current_scan_id` → `EvidenceRecord` → ... (5 hops) |

---

## 3. BUSINESS ENTITY MODEL

### 3.1 Current Business Entities

| Entity | Model | Key Fields | Relationships |
|--------|-------|------------|---------------|
| **System** | `System` | `criticality`, `business_unit`, `owner`, `environment`, `compliance_scopes` | `SystemAsset`, `SystemDependency`, `SystemBusinessProcess` |
| **BusinessProcess** | `BusinessProcess` | `name`, `revenue_daily`, `customer_count` | `SystemBusinessProcess`, `BusinessOwner` |
| **BusinessOwner** | `BusinessOwner` | `name`, `email` | `SystemBusinessProcess` (via `SystemBusinessProcessMap`) |
| **BusinessUnit** | String on System | `business_unit` | No separate model |
| **ComplianceScope** | String list on System | `compliance_scopes` | No separate model |
| **BusinessProcessMap** | `SystemBusinessProcessMap` | `process_id`, `system_id` | Many-to-many |

### 3.2 Missing Business Entities

| Missing Entity | Needed For |
|----------------|------------|
| **BusinessService** | Service-level abstraction (not System) |
| **Application** | Code-level entity (not System) |
| **ServiceEndpoint** | API/network endpoint abstraction |
| **DataStore** | Database, queue, cache abstraction |
| **BusinessCapability** | Capability model (not process) |
| **BusinessUnit** | Proper entity (not string) |
| **ComplianceFramework** | Proper entity (not string list) |
| **RegulatoryRequirement** | Requirement-level tracking |
| **Control** | Control implementation tracking |
| **RiskAppetite** | Per business unit risk tolerance |

---

## 4. REVENUE & CUSTOMER IMPACT — CALCULATED BUT INDIRECT

### 4.1 Current Calculation

**File:** `services/graph_engine/graph_engine/core/engine.py:business_impact()`

```python
def business_impact(self, start_id, hops=5):
    # 1. Get blast radius systems
    # 2. For each system:
    #    revenue += BusinessProcess.revenue_daily (via SUPPORTS)
    #    customers += BusinessProcess.customer_count (via SUPPORTS)
    # 3. Collect owners via OWNED_BY
    # 4. Collect compliance scopes via MUST_COMPLY_WITH
```

### 4.2 Calculation Gaps

| Gap | Impact |
|-----|--------|
| **No revenue attribution per crypto asset** | Revenue summed at system level only |
| **No customer segmentation** | Total customers only, no segmentation |
| **No revenue per crypto algorithm** | Cannot say "RSA-2048 puts $XM/day at risk" |
| **No revenue per certificate** | Certificate expiry impact unknown |
| **No revenue per protocol** | TLS 1.0 vs 1.3 revenue impact unknown |
| **No revenue per key size** | RSA-2048 vs RSA-4096 revenue impact unknown |
| **No revenue per library** | OpenSSL vs BoringSSL revenue impact unknown |

---

## 4. REGULATORY EXPOSURE — PARTIAL

### 4.1 Current Regulatory Mapping

**File:** `services/graph_engine/graph_engine/core/engine.py:compliance_inheritance()`

```python
def compliance_inheritance(self, system_id, hops=5):
    # Returns compliance scopes from blast radius
    # Via MUST_COMPLY_WITH edges
```

### 4.2 Regulatory Coverage

| Regulation | Mapped | Gap |
|------------|--------|-----|
| **PCI-DSS** | ✅ String on System | No requirement-level mapping |
| **HIPAA** | ✅ String on System | No requirement-level mapping |
| **GDPR** | ✅ String on System | No requirement-level mapping |
| **SOX** | ✅ String on System | No requirement-level mapping |
| **DORA** | ✅ String on System | No requirement-level mapping |
| **NIST CSF** | ❌ | Not tracked |
| **ISO 27001** | ❌ | Not tracked |
| **FIPS 140** | ⚠️ Partial | Policy packs reference |
| **NSA CNSA 2.0** | ⚠️ Partial | Policy packs reference |
| **PCI-P2PE** | ❌ | Not tracked |
| **SWIFT CSP** | ❌ | Not tracked |

### 4.3 Missing Regulatory Impact

| Missing | Impact |
|---------|--------|
| **Requirement-level mapping** | Cannot say "RSA-2048 violates PCI-DSS 3.2.1" |
| **Compensating controls** | No tracking of mitigating controls |
| **Compliance gap per algorithm** | Cannot prioritize by regulatory urgency |
| **Audit evidence per requirement** | Cannot generate requirement-level evidence packages |
| **Regulatory deadline tracking** | No deadline tracking per regulation |

---

## 5. CRYPTO FINDING → REGULATORY EXPOSURE — BROKEN

### 5.1 Current Path (Broken)

```
Crypto Finding (RSA-2048, quantum_vulnerable)
    → CryptoAsset (quantum_vulnerable=True)
    → System (via SystemAsset) ← BROKEN LINK
    → System.compliance_scopes (PCI-DSS, HIPAA)
    → Regulatory exposure inferred
```

**Broken:** `CryptoAsset` → `System` via `SystemAsset` link not guaranteed.

---

## 6. MIGRATION PRIORITY — WAVE-BASED

### 6.1 Current Migration Priority

**File:** `services/api/api/routers/graph.py:graph_migration_waves()`

```python
# 1. Readiness from MaturityRepository (agility + dependencies + testing)
# 2. Base wave from readiness_category
# 3. Cycle constraint: SCC members get max wave
# 4. Import constraint: IMPORTS edges order dependent after provider
# 4. Code-only systems: from cascade_run.earliest_wave
```

### 6.2 Migration Priority Gaps

| Gap | Impact |
|-----|--------|
| **No business criticality in wave calc** | Revenue/customer impact not in wave |
| **No regulatory deadline in wave calc** | PCI-DSS deadline not in wave |
| **No revenue at risk in wave calc** | High-revenue systems not prioritized |
| **No regulatory deadline tracking** | PCI-DSS 2025 deadline not in waves |
| **No business owner input** | Wave assigned without owner input |

---

## 7. EXECUTIVE REPORTING — TEMPLATES EXIST

### 7.1 Report Templates (6 Types)

**File:** `services/api/api/routers/report_templates.py` + `services/api/api/routers/scans.py:generate_report()`

| Template | Purpose | Business Impact Included |
|----------|---------|-------------------------|
| **Executive Summary** | C-suite overview | ✅ Revenue, risk summary |
| **Compliance Detail** | Requirement-level | ⚠️ Partial |
| **Technical Detail** | Findings list | ❌ No business context |
| **Migration Plan** | Wave-based plan | ⚠️ Wave only |
| **Risk Assessment** | Risk scores | ✅ Revenue at risk |
| **Drift Report** | Drift events | ⚠️ Partial |

### 7.2 Reporting Gaps

| Gap | Impact |
|-----|--------|
| **No "RSA-2048 costs $X/day"** | Cannot quantify algorithm risk |
| **No "Certificate expiry affects $Y revenue"** | Cannot quantify cert risk |
| **No "TLS 1.0 exposes $Z customers"** | Cannot quantify protocol risk |
| **No "Library X vulnerability affects $W revenue"** | Cannot quantify library risk |
| **No business owner sign-off in reports** | No owner accountability in output |

---

## 8. MISSING BUSINESS IMPACT CONNECTIONS

### 8.1 Critical Missing Connections

| From | To | Missing |
|------|----|---------|
| CryptoAsset | BusinessProcess | Direct link |
| CryptoAsset | BusinessOwner | Direct link |
| CryptoAsset | Revenue | Per-algorithm revenue |
| CryptoAsset | Regulatory Requirement | Requirement-level |
| Certificate | BusinessProcess | Direct link |
| Certificate | Revenue | Expiry revenue impact |
| NetworkResource | BusinessProcess | Direct link |
| DriftEvent | BusinessProcess | Direct link |
| DriftEvent | Regulatory Requirement | Direct link |
| DriftEvent | Revenue | Drift revenue impact |
| Vulnerability | BusinessProcess | Direct link |
| MigrationTask | BusinessOwner | Owner assignment |
| MigrationTask | BusinessImpact | Impact estimation |

---

## 9. RECOMMENDATIONS

### P0 — Critical

1. **Add Direct CryptoAsset → BusinessProcess Link** — `CryptoAsset.business_process_id` FK
2. **Add CryptoAsset → Revenue Mapping** — Per-algorithm revenue attribution
3. **Add Certificate → BusinessProcess Link** — `Certificate.business_process_id`
4. **Add DriftEvent → Business Impact** — Direct drift-to-impact mapping

### P1 — High

4. **Implement BusinessService Entity** — Separate from System, crypto-aware
5. **Add RegulatoryRequirement Entity** — Requirement-level tracking
6. **Add Requirement-Level Compliance Mapping** — Finding → Requirement mapping
7. **Add Revenue Per Algorithm/Certificate/Protocol** — Per-crypto revenue attribution
8. **Add Business Owner to Migration Tasks** — Owner assignment on tasks

### P2 — Medium

9. **Business Capability Model** — Capability-based (not process-based) impact
10. **Regulatory Deadline Tracking** — Per-regulation deadline tracking
10. **Compensating Controls Tracking** — Mitigating controls per finding
11. **Business Owner Sign-off in Reports** — Owner accountability in output
12. **Executive Dashboard** — Revenue-at-risk by business service

### P3 — Enhancement

13. **Scenario Modeling** — "What if RSA-2048 fails? Revenue impact = $X"
14. **Monte Carlo Risk Simulation** — Probabilistic revenue impact
15. **Regulatory Change Impact** — "New regulation X affects Y algorithms"
15. **Cost-Benefit Analysis** — Remediation cost vs risk reduction

---

## 10. VERDICT

**Strong graph engine calculates revenue at risk, but crypto findings cannot reliably trace to business services, revenue, or regulatory requirements.**

| Connection | Status |
|------------|--------|
| System → BusinessProcess | ✅ |
| BusinessProcess → Revenue | ✅ |
| BusinessProcess → Owner | ✅ |
| System → Compliance Scopes | ✅ |
| CryptoAsset → System | ❌ (link not guaranteed) |
| CryptoAsset → BusinessProcess | ❌ (no direct link) |
| CryptoAsset → Revenue | ❌ (no attribution) |
| CryptoAsset → Regulatory Req | ❌ (string only) |
| Certificate → BusinessProcess | ❌ |
| DriftEvent → Business Impact | ❌ |
| Finding → Business Service | ❌ |

**To fix:** 4-6 weeks for direct crypto-to-business links, revenue attribution, regulatory requirement model, and executive reporting.

---

## 10. VERIFICATION EVIDENCE

| Finding | File |
|---------|------|
| GraphEngine business_impact | `services/graph_engine/graph_engine/core/engine.py:business_impact()` |
| GraphEngine compliance_inheritance | `services/graph_engine/graph_engine/core/engine.py:compliance_inheritance()` |
| GraphEngine migration_waves | `services/api/api/routers/graph.py:graph_migration_waves()` |
| System model | `services/database/db/models/system.py` |
| BusinessProcess model | `services/database/db/models/business_process.py` |
| BusinessOwner model | `services/database/db/models/business_owner.py` |
| SystemBusinessProcess | `services/database/db/models/system_business_process.py` |
| SystemBusinessProcessMap | `services/database/db/models/system_business_process_map.py` |
| CryptoAsset model | `services/database/db/models/crypto_asset.py` |
| SystemAsset link | `services/database/db/models/system_asset.py` |
| CertificateUsage | `services/database/db/models/certificate_usage.py` |
| Report templates | `services/api/api/routers/report_templates.py` |
| Scan report | `services/api/api/routers/scans.py:generate_report()` |
| AssetRepository | `services/database/db/repositories/asset_repository.py` |
| SystemRepository | `services/database/db/repositories/system_repository.py` |