# 13_MISSING_FEATURES.md
## ZELNX CryptoScan — Missing Features Audit

**Generated:** 2026-09-20  
**Method:** Requirements analysis from product objectives vs. actual implementation  
**Scope:** Features claimed, implied, or required for "production-grade cryptography threat-intelligence platform"

---

## 1. MISSING CORE FEATURES (Product Objectives)

### 1.1 HBOM (Hardware Bill of Materials) — **COMPLETELY MISSING**
| Aspect | Status | Required For |
|--------|--------|--------------|
| **Backend generator** | ❌ Not implemented | Product objective |
| **Database model** | ❌ Not implemented | Persistence |
| **API endpoints** | ❌ Not implemented | Integration |
| **Frontend page** | ✅ Exists (`Hbom.tsx`) | UI — shows "UNKNOWN" |
| **Data sources** | ⚠️ Partial | `hardware_live` (TPM/CPU), `payment_crypto` (HSM) |

**Gap:** Product objective lists HBOM as core; implementation is **zero**.

### 1.2 Vendor Crypto Detection — **NOT IMPLEMENTED**
| Aspect | Status | Required For |
|--------|--------|--------------|
| **Automated vendor fingerprinting** | ❌ Not implemented | Supply chain visibility |
| **Vendor crypto inventory** | ❌ Not implemented | Vendor due diligence |
| **Sub-tier vendor mapping** | ⚠️ Manual only (`graph.py:/graph/vendor-edges`) | Supply chain depth |
| **Vendor risk scoring** | ❌ Not implemented | Vendor management |

**Gap:** README claims "vendor/supply-chain" capability; only manual vendor edges exist.

### 1.3 Transitive Dependency Crypto — **PARTIAL**
| Aspect | Status | Gap |
|--------|--------|-----|
| **Language-agnostic dep graph** | ❌ | Only cascade `depends_on_systems` (declared) |
| **Lockfile parsing (all ecosystems)** | ⚠️ Partial | Python (pip), JS (npm), Java (Maven/Gradle), Go (go.mod), Rust (Cargo) — but not unified |
| **Transitive crypto propagation** | ❌ | Direct deps only; no recursive crypto analysis |
| **SBOM → crypto correlation** | ⚠️ Partial | SBOM import exists but not linked to crypto assets |

### 1.4 Runtime Crypto Correlation — **SEPARATE PIPELINE**
| Aspect | Status | Gap |
|--------|--------|-----|
| **Unified evidence chain** | ❌ | Live crypto (`crypto_live`) bypasses evidence pipeline |
| **Runtime → static correlation** | ❌ | No linking of runtime observations to source findings |
| **Live CBOM ↔ Static CBOM** | ❌ | Two separate CBOM systems |
| **Live graph ↔ Static graph** | ❌ | Live observations not in dependency graph |

---

## 2. MISSING ENTERPRISE FEATURES

### 2.1 Multi-Tenancy — **INCOMPLETE**
| Feature | Status | Gap |
|---------|--------|-----|
| **Tenant isolation in Neo4j** | ❌ | All tenants share graph |
| **Tenant-aware graph queries** | ❌ | `graph_from_db()` filters but Neo4j doesn't |
| **Cross-tenant analytics** | ❌ | Not supported |
| **Tenant quota/billing** | ⚠️ `billing` service scaffolded | Not implemented |
| **Tenant onboarding flow** | ✅ `onboarding` service + UI | Works |

### 2.2 Role-Based Access Control — **COARSE**
| Missing | Current | Needed |
|---------|---------|--------|
| **Resource-level permissions** | Domain-level only | Per-system, per-asset, per-scan |
| **Delegated administration** | No | Admin per tenant/BU |
| **Custom roles** | Fixed 3 roles | Configurable role definitions |
| **Permission inheritance** | No | BU → System → Asset |

### 2.3 Audit & Compliance — **GAPS**
| Feature | Status | Gap |
|---------|--------|-----|
| **Automated compliance reports** | ❌ | Manual template selection |
| **Regulatory mapping updates** | Manual | No feed for NIST/FIPS/PCI changes |
| **Evidence packaging for auditors** | Partial | `GET /scans/{id}/report` only |
| **Continuous compliance monitoring** | Drift only | No policy drift detection |

### 2.4 Secrets & Key Management — **NOT ENTERPRISE**
| Feature | Status | Gap |
|---------|--------|-----|
| **HSM integration (PKCS#11)** | ❌ Parser only (`cbom/hsm_pkcs11.py`) | No operational integration |
| **KMIP support** | ❌ Parser only (`cbom/kmip.py`) | No operational integration |
| **Key rotation automation** | ❌ | Manual only |
| **Key ceremony workflow** | ⚠️ `payment_crypto` only | Payment-specific |
| **Secret synchronization** | ❌ | No Vault/Secrets Manager sync |

---

## 3. MISSING DETECTION CAPABILITIES

### 3.1 Protocol Coverage
| Protocol | Status | Gap |
|----------|--------|-----|
| **QUIC/HTTP3** | ❌ | Not in `universal_crypto/protocol_engine.py` |
| **DTLS** | ❌ | Not implemented |
| **WireGuard** | ❌ | Not implemented |
| **mTLS (mutual)** | ⚠️ Partial | Cert detection yes; handshake verification no |
| **Certificate Transparency** | ❌ | Not monitored |

### 3.2 Cloud Coverage
| Provider/Service | Status | Gap |
|------------------|--------|-----|
| **AWS CloudHSM** | ❌ | Only KMS |
| **Azure Dedicated HSM** | ❌ | Only Key Vault |
| **GCP Cloud HSM** | ❌ | Only Cloud KMS |
| **Kubernetes Secrets (encrypted)** | ❌ | Only config scanning |
| **Service Mesh (Istio/Linkerd) mTLS** | ❌ | Not detected |

### 3.3 Binary/Firmware
| Capability | Status | Gap |
|------------|--------|-----|
| **Control flow analysis** | ❌ | String + disassembly only |
| **Obfuscation detection** | ❌ | Entropy only |
| **Firmware filesystem extraction** | ❌ | No UEFI/BIOS parsing |
| **RTOS crypto (FreeRTOS, Zephyr)** | ❌ | Not targeted |
| **Bootloader verification** | ❌ | Not in scope |

### 3.4 Emerging Crypto
| Algorithm/Standard | Status | Gap |
|--------------------|--------|-----|
| **ML-KEM/ML-DSA/SLH-DSA in binaries** | ❌ | Registry has names; detection untested |
| **Hybrid KEM (X25519+ML-KEM)** | ❌ | Not detected |
| **PQC TLS (draft)** | ❌ | Not in TLS parser |
| **Post-quantum SSH** | ❌ | Not in SSH parser |
| **Post-quantum IPsec** | ❌ | Not in IPsec parser |

---

## 4. MISSING OPERATIONAL FEATURES

### 4.1 Automation & Orchestration
| Feature | Status | Gap |
|---------|--------|-----|
| **Scheduled graph sync** | ❌ | Manual `POST /graph/sync` only |
| **Automated baseline creation** | ❌ | Manual baseline approval |
| **Drift auto-remediation** | ❌ | Ack/resolve/FP only |
| **Scan scheduling (cron)** | ⚠️ `monitor` daemon only | No flexible scheduler |
| **Webhook retry/dead-letter** | ❌ | No delivery guarantees |

### 4.2 Reporting & Export
| Format | Status | Gap |
|--------|--------|-----|
| **PDF report customization** | ❌ | Fixed templates only |
| **Scheduled report delivery** | ⚠️ `report_schedules` table | Not implemented |
| **Executive dashboard export** | ❌ | No PPT/PDF executive summary |
| **Compliance evidence package** | ❌ | No audit-ready bundle |

### 4.3 Integration Ecosystem
| Integration | Status | Gap |
|-------------|--------|-----|
| **SIEM (Splunk, Elastic, Sentinel)** | ⚠️ `automation` connectors scaffolded | Not implemented |
| **ITSM (ServiceNow, Jira)** | ⚠️ `automation` connectors scaffolded | Not implemented |
| **Messaging (Kafka, RabbitMQ, Pulsar)** | ⚠️ `automation` connectors scaffolded | Not implemented |
| **ChatOps (Slack, Teams)** | ⚠️ `automation` connectors scaffolded | Not implemented |
| **CMDB (ServiceNow, BMC)** | ❌ | No CMDB sync |

---

## 5. MISSING DEVELOPER EXPERIENCE

### 5.1 CI/CD Integration
| Feature | Status | Gap |
|---------|--------|-----|
| **GitHub Actions native action** | ❌ | `scripts/ci_gate.py` CLI only |
| **GitLab CI template** | ❌ | `deploy/integrations/gitlab/` exists but minimal |
| **Jenkins plugin** | ❌ | `deploy/integrations/jenkins/` exists but minimal |
| **ArgoCD integration** | ❌ | `deploy/integrations/argocd/` exists but minimal |
| **Pre-commit hook** | ❌ | `.pre-commit-config.yaml` only for lint |

### 5.2 API & SDK
| Feature | Status | Gap |
|---------|--------|-----|
| **Official Python SDK** | ❌ | `connector_sdk` is for extensions, not clients |
| **Official TypeScript SDK** | ❌ | Frontend uses internal `api/lib/api.js` |
| **OpenAPI spec per domain** | ❌ | Single monolithic spec |
| **GraphQL (full)** | ⚠️ Read-only only | No mutations |

### 5.3 Local Development
| Feature | Status | Gap |
|---------|--------|-----|
| **LocalStack full parity** | ⚠️ `.local-stack/` exists | Not documented |
| **Dev container** | ❌ | No `.devcontainer/` |
| **Tilt/Skaffold config** | ❌ | No local Kubernetes dev |

---

## 6. MISSING FEATURES — PRIORITY MATRIX

| Feature | Product Objective | Enterprise Need | Implementation Effort | Priority |
|---------|-------------------|-----------------|----------------------|----------|
| **HBOM backend** | ✅ Core | ✅ Critical | High (new service) | **P0** |
| **Vendor crypto detection** | ✅ Core | ✅ Critical | High (new service) | **P0** |
| **Neo4j tenant isolation** | ❌ Implicit | ✅ Critical | Medium (arch change) | **P0** |
| **Unified evidence pipeline** | ✅ Core | ✅ Critical | High (refactor) | **P0** |
| **Transitive dependency crypto** | ✅ Core | ✅ High | High (new analyzers) | **P1** |
| **Runtime ↔ Static correlation** | ✅ Core | ✅ High | High (refactor) | **P1** |
| **Resource-level RBAC** | ❌ Implicit | ✅ Critical | Medium | **P1** |
| **PKCS#11/KMIP operational** | ❌ Implicit | ✅ High | Medium | **P1** |
| **Scheduled graph sync** | ❌ Implicit | ✅ High | Low (cron job) | **P1** |
| **QUIC/DTLS/WireGuard** | ❌ Implicit | ✅ Medium | Medium | **P2** |
| **Cloud HSM detection** | ❌ Implicit | ✅ High | Medium | **P2** |
| **Automated compliance reports** | ❌ Implicit | ✅ High | Medium | **P2** |
| **SIEM/ITSM connectors** | ❌ Implicit | ✅ High | Medium | **P2** |
| **Official SDKs** | ❌ Implicit | ✅ Medium | High | **P3** |
| **GraphQL mutations** | ❌ Implicit | ✅ Low | High | **P3** |
| **PQC TLS/SSH/IPsec detection** | ❌ Implicit | ✅ Medium | High | **P3** |

---

## 7. FEATURES THAT EXIST BUT ARE INCOMPLETE

| Feature | What's Missing | Priority |
|---------|----------------|----------|
| **NBOM** | Passive network observation; only active probe | P1 |
| **TechBOM** | Duplicate of CBOM; should merge | P1 |
| **Remediation** | Tracking/execution; only suggestions | P2 |
| **Agility** | Roadmap execution; only scoring | P2 |
| **Quantum** | Migration execution; only analysis | P2 |
| **Digital Twin** | Scenario persistence; only simulation | P2 |
| **Payment Crypto** | HSM operational integration | P2 |
| **OT Safety** | Safety system integration; only passive scan | P3 |

---

## 8. RECOMMENDATIONS — IMPLEMENTATION ORDER

### Phase 1 (P0 — Foundation)
1. **HBOM backend** — New service using `hardware_live` + `payment_crypto` data
2. **Neo4j tenant isolation** — Separate databases or document single-tenant
3. **Unify evidence pipeline** — All discovery paths → single evidence chain

### Phase 2 (P1 — Core Capabilities)
4. **Vendor crypto detection** — Automated fingerprinting + risk scoring
5. **Transitive dependency crypto** — Unified lockfile parser + recursive analysis
6. **Runtime ↔ Static correlation** — Link live observations to source evidence
7. **Resource-level RBAC** — Per-system/asset permissions
8. **PKCS#11/KMIP operational** — HSM key detection + ceremony workflow

### Phase 3 (P2 — Enterprise Polish)
9. **Scheduled graph sync** — Background job with status API
10. **Automated compliance reports** — Template + scheduler + evidence package
11. **SIEM/ITSM connectors** — Implement scaffolded connectors
12. **QUIC/DTLS/WireGuard detection** — Protocol engine extensions

### Phase 4 (P3 — Emerging)
13. **PQC protocol detection** — TLS/SSH/IPsec post-quantum
14. **Official SDKs** — Python + TypeScript client libraries
15. **GraphQL mutations** — Full GraphQL API
## UPDATE — 2026-10-09: missing-features status after rounds 13–15

Built since this report: HBOM + vendor layers (Technology BOM, this report
§1.1/§1.2), automated drift + baseline approval (§4.1), report schedules +
signed exports + evidence packages (§4.2), remediation verification loop
(§7 "Remediation: tracking/execution"), PQC protocol detection incl. hybrid
KEM (§3.4), retired-asset registry + reintroduction detection, crypto-asset
lifecycle states (§7), conflict surfacing, evidence-chain sweep.

Still genuinely open from this report: transitive dependency crypto graph
(§1.3), QUIC/DTLS/WireGuard parsers (§3.1), cloud HSM detection (§3.2),
resource-level RBAC (§2.2 — product decision), official SDKs (§5.2).
