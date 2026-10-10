# 88_FINAL_GAP_PRIORITIZATION.md
## ZELNX CryptoScan — Final Gap Prioritization

**Generated:** 2026-09-20  
**Method:** Synthesis of all 87 audits into a prioritized gap register  
**Scope:** Complete gap register from all 87 audits with prioritization, evidence, impact, dependencies, and remediation

---

## EXECUTIVE SUMMARY

**Total Gaps Identified: 200+**  
**P0 (Critical): 10** | **P1 (High): 10** | **P2 (Medium): 10** | **P3 (Enhancement): 10**

**Overall Remediation Effort:** ~30 weeks (7-8 months) with 4-6 engineers

---

## 1. MASTER GAP REGISTER — PRIORITIZED

### P0 — CRITICAL (Must Fix Before Any Production Deployment)

| ID | Gap | Category | Evidence | Impact | Dependencies | Required Action | Acceptance Criteria | Effort | Priority |
|----|-----|----------|----------|--------|--------------|-----------------|---------------------|--------|----------|
| **GAP-001** | Zero Scanner Sandboxing | Security | `84_SCANNER_SANDBOX_AUDIT.md` | Critical — Container escape, credential theft, data exfiltration | gVisor/Kata runtime | Deploy gVisor/Kata runtime; implement per-scanner seccomp profiles; drop all capabilities; add resource limits; implement filesystem isolation; implement network isolation; implement credential injection via Vault | All scanners run in gVisor/Kata; seccomp profiles active; capabilities dropped; resource limits enforced; no host filesystem access; network namespaces isolated | 20 weeks | **P0** |
| **GAP-002** | Zero Tenant Resource Quotas | Multi-tenancy | `76_TENANT_RESOURCE_QUOTA_AUDIT.md` | Critical — One tenant can monopolize all resources | Quota service | Implement TenantQuota model; implement QuotaService; add API gateway quota enforcement; implement worker pool quotas; implement database storage quotas; implement Redis quotas | Per-tenant CPU/memory/disk/workers/API/scan quotas enforced; quota exceeded returns 429; quota dashboard shows usage vs limits | 8-12 weeks | **P0** |
| **GAP-003** | No Neo4j Tenant Isolation | Multi-tenancy | `20_MULTI_TENANCY_AUDIT.md`, `27_CRYPTO_GRAPH_FORENSIC_AUDIT.md` | Critical — Cross-tenant graph data leakage | Neo4j multi-db or Fabric | Implement separate Neo4j database per tenant OR Neo4j Fabric; update GraphEngine to use tenant-scoped driver; implement tenant-scoped Cypher queries | Each tenant has isolated Neo4j database; cross-tenant graph queries impossible; graph snapshots tenant-scoped | 8-12 weeks | **P0** |
| **GAP-004** | No Encryption at Rest | Security/Compliance | `22_SECRETS_CREDENTIALS_AUDIT.md`, `77_DATA_RETENTION_PRIVACY_AUDIT.md` | Critical — Data exposure, compliance failure | PostgreSQL TDE, LUKS, Neo4j encryption | Enable PostgreSQL TDE; enable LUKS on volumes; enable Neo4j native encryption; implement backup encryption (GPG/age); implement key management (Vault) | All data at rest encrypted; backup encrypted; keys managed in Vault; key rotation automated | 8-12 weeks | **P0** |
| **GAP-005** | No mTLS / Zero Trust | Security | `82_ZERO_TRUST_ARCHITECTURE_AUDIT.md`, `74_READ_ONLY_GUARANTEE_AUDIT.md` | Critical — Lateral movement, data interception | SPIFFE/SPIRE, mTLS, OPA | Deploy SPIFFE/SPIRE; implement mTLS for all service-to-service; deploy Calico/Cilium network policies; deploy OPA as central PDP; implement continuous verification (device health, session, behavior) | All service-to-service communication mTLS; network policies enforce least privilege; OPA central PDP; continuous verification active | 12-18 weeks | **P0** |
| **GAP-006** | No Automated Remediation Verification | Remediation | `62_REMEDIATION_VERIFICATION_AUDIT.md` | Critical — Cannot prove remediation effectiveness | Verification engine, rescan automation | Implement RemediationVerification model; implement auto-rescan on task completion; implement evidence comparison logic; implement verification result enum (VERIFIED/PARTIAL/FAILED/REGRESSION/INCONCLUSIVE); implement regression detection | Remediation tasks auto-trigger rescan; verification result recorded; regression detected and alerted; closure workflow automated | 6-8 weeks | **P0** |
| **GAP-007** | No Automated Drift Detection | Drift | `28_CRYPTO_DRIFT_FORENSIC_AUDIT.md`, `63_CONTINUOUS_CRYPTO_MONITORING_AUDIT.md` | Critical — Blind to config drift | Drift detection engine, event-driven architecture | Implement automated baseline comparison on scan completion; implement drift event emission on detection; implement real-time alerting (webhook, email, Slack); implement drift→remediation task auto-creation | Drift detected within 5 min of scan completion; drift events emitted to platform bus; alerts routed per severity; remediation tasks auto-created | 6-8 weeks | **P0** |
| **GAP-008** | No Replayability | Verification | `67_AUDIT_REPLAYABILITY_AUDIT.md`, `68_TEMPORAL_CRYPTO_INTELLIGENCE_AUDIT.md` | Critical — Cannot audit historical decisions | Version tracking, replay engine, environment capture | Implement scanner version tracking (git commit + docker digest); implement normalization rules versioning; implement policy pack versioning; implement configuration snapshotting; implement environment capture (python, OS, deps); implement ReplayEngine; implement Replay API | Any historical scan can be replayed with identical results; replay package includes all versions/env/config; replay engine provisions exact environment; replay result shows MATCH/MISMATCH + diff | 8-12 weeks | **P0** |
| **GAP-009** | No Runtime AI Boundary Enforcement | AI Safety | `81_AI_BOUNDARY_AUDIT.md`, `80_DETERMINISTIC_TRUTH_AUDIT.md` | Critical — AI could leak into deterministic path | Runtime sandboxing, eBPF monitoring | Implement runtime sandbox (seccomp, capabilities, network isolation) for deterministic services; implement eBPF-based AI call detection; implement runtime AI call blocking via seccomp; add runtime AI boundary monitoring | No AI service callable from deterministic path; any AI call from deterministic path blocked and alerted; audit trail of all AI invocations | 4-6 weeks | **P0** |
| **GAP-010** | No Continuous Monitoring | Observability | `63_CONTINUOUS_CRYPTO_MONITORING_AUDIT.md`, `64_CRYPTO_RISK_SCORING_FORENSIC_AUDIT.md` | Critical — Blind to real-time changes | Event-driven architecture, CT log streaming, CVE feeds | Implement event-driven monitoring (CloudTrail, GitHub webhooks, container registry webhooks, CT log streaming, CVE feed integration); implement event-driven re-scanning; implement real-time alerting (Alertmanager, PagerDuty, Slack); implement continuous risk recalculation; implement continuous drift detection | Real-time alerts on critical changes; event-driven re-scans within 5 min; continuous risk recalculation; automated CVE matching within 1 hour of publication | 8-12 weeks | **P0** |

---

### P1 — HIGH PRIORITY (Must Fix Before Multi-Tenant SaaS)

| ID | Gap | Category | Evidence | Impact | Dependencies | Required Action | Acceptance Criteria | Effort | Priority |
|----|-----|----------|----------|--------|--------------|-----------------|---------------------|--------|----------|
| **GAP-011** | No Automated Baseline Creation | Compliance | `28_CRYPTO_DRIFT_FORENSIC_AUDIT.md`, `31_ENTERPRISE_WORKFLOW_AUDIT.md` | High — Manual overhead, inconsistency | Baseline model, approval workflow | Implement auto-baseline on first clean scan; implement baseline approval workflow (auditor approval); implement baseline supersession logic (new baseline auto-supersedes); implement baseline archival policy | First clean scan → baseline proposed; auditor approves → baseline active; new baseline → previous superseded; baseline audit trail complete | 4-6 weeks | **P1** |
| **GAP-012** | No HBOM Implementation | BOMs | `46_CROSS_BOM_CONSISTENCY_AUDIT.md`, `26_CBOM_HBOM_CONFORMANCE_AUDIT.md` | High — Hardware visibility gap | Hardware live data, payment_crypto data | Implement HbomGenerator using hardware_live + payment_crypto data; implement HBOM API endpoints (/hbom); implement HBOM frontend integration; add HBOM to BOM query API | HBOM generator produces valid CycloneDX hardware BOM; HBOM API returns valid BOM; HBOM visible in UI; HBOM includes TPM/HSM/CPU/Cloud HSM data | 6-8 weeks | **P1** |
| **GAP-013** | No VBOM Implementation | BOMs | `46_CROSS_BOM_CONSISTENCY_AUDIT.md`, `61_PQC_MIGRATION_DEPENDENCY_AUDIT.md` | High — Supply chain blind spot | Vendor intel data, vendor_crypto model | Implement VendorCrypto fingerprinting; implement VBOM generator from vendor_intel data; implement VBOM API endpoints; implement VBOM frontend; add vendor crypto capabilities to VBOM | VBOM generator produces valid vendor BOM; VBOM includes vendor crypto capabilities, supply chain edges; VBOM queryable via API | 6-8 weeks | **P1** |
| **GAP-014** | No PQC Protocol Detection | PQC | `59_HNDL_PQC_RISK_AUDIT.md`, `52_DETECTION_ACCURACY_AUDIT.md` | High — Blind to TLS 1.3 PQC, SSH PQC, IPsec PQC | Protocol engine, quantum registry | Extend ProtocolEngine with PQC cipher suite registry (TLS 1.3 hybrid KEM, SSH PQC KEX, IPsec PQC); extend quantum registry with PQC cipher suites; extend network scanner with PQC cipher suite parsing; extend SSH/IPsec parsers with PQC algorithms | Network scanner detects TLS 1.3 hybrid KEM (X25519+ML-KEM); SSH parser detects sntrup761x25519-sha512; IPsec parser detects hybrid IKEv2; PQC cipher suites in quantum registry | 8-12 weeks | **P1** |
| **GAP-015** | No Hybrid Crypto Detection | PQC | `59_HNDL_PQC_RISK_AUDIT.md`, `52_DETECTION_ACCURACY_AUDIT.md` | High — Blind to X25519+ML-KEM, ECDHE+ML-KEM | Quantum registry, protocol engine | Extend quantum registry with hybrid KEM/signature algorithms; extend protocol engine with hybrid KEM/signature parsing; extend binary parser with PQC library detection; extend network scanner with hybrid KEX detection | Hybrid KEM (X25519+ML-KEM) detected in TLS; hybrid KEX detected in SSH; hybrid signatures detected in certificates; hybrid algorithms in quantum registry | 8-12 weeks | **P1** |
| **GAP-016** | No Migration Execution Engine | PQC Migration | `29_PQC_MIGRATION_READINESS_AUDIT.md`, `61_PQC_MIGRATION_DEPENDENCY_AUDIT.md` | High — Planning only, no execution | Graph engine, migration models, remediation engine | Implement MigrationExecutionEngine; implement code refactoring automation (AST-based); implement config migration automation; implement library upgrade orchestration; implement HSM firmware update coordination; implement certificate re-issuance automation; implement key rotation orchestration; implement testing/validation pipeline; implement rollback capability; implement canary/blue-green deployment | Migration tasks execute code refactoring; config migration automated; library upgrades orchestrated; HSM firmware updates coordinated; cert re-issuance automated; key rotation orchestrated; testing pipeline validates; rollback on failure; canary deployment supported | 12-16 weeks | **P1** |
| **GAP-017** | No Resource Quotas (CPU, Mem, Disk) | Multi-tenancy | `76_TENANT_RESOURCE_QUOTA_AUDIT.md`, `72_LARGE_ESTATE_READINESS_AUDIT.md` | High — Tenant DoS, resource exhaustion | Quota service, cgroups, K8s | Implement TenantQuota model (CPU, Mem, Disk, Workers, API, Scans, Graph, Storage); implement QuotaService with admission control; implement worker pool quotas (per-tenant cgroups); implement database storage quotas (tablespace/row counts); implement Redis quotas (per-tenant key limits); implement Neo4j quotas (per-tenant node/edge limits); implement file storage quotas (volume quotas) | Per-tenant CPU/Mem/Disk/Workers/API/Scan/Graph quotas enforced; quota exceeded → 429; quota dashboard shows usage vs limits; quota templates (S/M/L/XL) | 6-8 weeks | **P1** |
| **GAP-018** | No Credential Rotation Automation | Security | `75_CREDENTIAL_SCOPE_AUDIT.md`, `22_SECRETS_CREDENTIALS_AUDIT.md` | High — Credential sprawl, expiry risk | Vault integration, rotation scheduler | Integrate HashiCorp Vault / AWS Secrets Manager / Azure Key Vault; implement 90-day auto-rotation for all credentials; implement rotation scheduler with approval workflow; implement credential expiry dashboard with alerts (30/14/7/1 day); implement emergency rotation (immediate revocation + reissue) | All credentials auto-rotated on schedule; rotation compliance dashboard; emergency rotation < 5 min; rotation audit trail complete | 4-6 weeks | **P1** |
| **GAP-018** | No Scope Drift Detection | Security | `75_CREDENTIAL_SCOPE_AUDIT.md`, `50_CONFLICT_RESOLUTION_AUDIT.md` | High — Credential privilege escalation undetected | Credential vault, policy engine | Implement continuous scope drift detection (IAM policy diff, role assignment diff, RBAC binding diff); implement real-time drift alerts (Slack, PagerDuty, email); implement automated scope remediation (auto-revoke excess perms); implement drift audit trail with root cause analysis | Scope drift detected within 5 min; alerts routed per severity; auto-remediation for known patterns; drift audit trail with root cause | 4-6 weeks | **P1** |
| **GAP-019** | No Break-Glass Procedures | Security | `75_CREDENTIAL_SCOPE_AUDIT.md`, `78_FORENSIC_AUDIT_TRAIL_AUDIT.md` | High — Emergency access uncontrolled | Break-glass system, audit trail | Implement BreakGlassSystem with emergency credential request (1-4 hr TTL); implement multi-party approval for critical surfaces; implement auto-expiry with cleanup; implement break-glass audit trail (requester, reason, duration, approver); implement break-glass notifications (security team, CISO); implement break-glass audit report | Emergency credential issued < 5 min; multi-party approval for critical surfaces; auto-expiry enforced; full audit trail with approvals; notifications to security team | 4-6 weeks | **P1** |
| **GAP-019** | No Automated Compliance Reporting | Compliance | `66_COMPLIANCE_EVIDENCE_AUDIT.md`, `31_ENTERPRISE_WORKFLOW_AUDIT.md` | High — Manual report generation | Report templates, evidence pipeline | Implement scheduled compliance report generation (cron); implement requirement-level evidence package generation; implement gap analysis report (uncovered requirements); implement audit-ready evidence bundles (ZIP + manifest + hash); implement scheduled report delivery (email, SFTP, S3); implement compliance dashboard with requirement coverage heatmap | Scheduled reports generated automatically; requirement-level evidence bundles generated; gap analysis report with remediation; audit-ready bundles with manifest + hash; reports delivered via email/SFTP/S3 | 6-8 weeks | **P1** |
| **GAP-019** | No Continuous Monitoring | Observability | `63_CONTINUOUS_CRYPTO_MONITORING_AUDIT.md`, `64_CRYPTO_RISK_SCORING_FORENSIC_AUDIT.md` | High — Blind to real-time changes | Event-driven architecture, CT log streaming, CVE feeds | Implement event-driven monitoring (CloudTrail, GitHub webhooks, container registry webhooks, CT log streaming, CVE feed integration); implement event-driven re-scanning; implement real-time alerting (Alertmanager, PagerDuty, Slack); implement continuous risk recalculation; implement continuous drift detection | Real-time alerts on critical changes; event-driven re-scans within 5 min; continuous risk recalculation; automated CVE matching within 1 hour of publication | 8-12 weeks | **P1** |
| **GAP-020** | No Encryption at Rest | Security | `22_SECRETS_CREDENTIALS_AUDIT.md`, `77_DATA_RETENTION_PRIVACY_AUDIT.md` | High — Data exposure, compliance failure | PostgreSQL TDE, LUKS, Neo4j encryption | Enable PostgreSQL TDE (or LUKS volume encryption); enable Redis TLS + encryption; enable Neo4j native encryption; implement backup encryption (GPG/age); implement key management (Vault) | All data at rest encrypted; backup encrypted; keys managed in Vault; key rotation automated | 8-12 weeks | **P1** |

---

### P2 — MEDIUM PRIORITY

| ID | Gap | Category | Evidence | Impact | Dependencies | Required Action | Acceptance Criteria | Effort | Priority |
|----|-----|----------|----------|--------|--------------|-----------------|---------------------|--------|----------|
| **GAP-021** | No HBOM/VBOM in UI | BOMs/UI | `46_CROSS_BOM_CONSISTENCY_AUDIT.md`, `26_CBOM_HBOM_CONFORMANCE_AUDIT.md` | Medium — UI incomplete | HBOM/VBOM backend APIs | Implement HBOM/VBOM frontend components; connect to backend APIs; add HBOM/VBOM tabs in UI; add HBOM/VBOM to BOM query API | HBOM/VBOM visible in UI; BOM query API returns all 5 BOM types; HBOM/VBOM export works | 4-6 weeks | **P2** |
| **GAP-022** | No Cross-BOM Linking | BOMs | `46_CROSS_BOM_CONSISTENCY_AUDIT.md`, `47_UNIFIED_ASSET_IDENTITY_AUDIT.md` | Medium — Disconnected inventories | Unified asset identity, canonical IDs | Implement canonical asset identity service; implement cross-BOM linking via canonical IDs; add cross-BOM navigation in UI; implement cross-BOM traceability API | Single canonical ID per asset across all BOMs; cross-BOM navigation in UI; cross-BOM traceability API returns linked components | 8-12 weeks | **P2** |
| **GAP-022** | No Semantic Deduplication | Deduplication | `70_DEDUPLICATION_FORENSIC_AUDIT.md`, `71_SCAN_IDEMPOTENCY_AUDIT.md` | Medium — Duplicate assets/evidence | Canonical identity service, content hashing | Implement semantic deduplication (same logical fact, different representation); implement deduplication provenance tracking; implement deduplication metrics (rate, false positive rate); implement fuzzy deduplication (near-match with confidence) | Semantic duplicates collapsed; deduplication provenance tracked; deduplication metrics tracked; fuzzy deduplication with confidence scores | 6-8 weeks | **P2** |
| **GAP-023** | No Temporal Queries | Temporal | `68_TEMPORAL_CRYPTO_INTELLIGENCE_AUDIT.md`, `69_CRYPTO_REINTRODUCTION_AUDIT.md` | Medium — No point-in-time queries | Temporal query engine, asset timeline | Implement AssetTimeline model; implement TemporalQuery API (as-of, range, lifecycle); implement temporal aggregations (trends, rates, patterns); implement reintroduction detection; implement deprecation tracking | Point-in-time queries work; time-range change feeds work; asset timeline shows full history; temporal aggregations show trends; reintroductions detected and alerted | 6-8 weeks | **P2** |
| **GAP-023** | No Reintroduction Detection | Drift/Security | `69_CRYPTO_REINTRODUCTION_AUDIT.md`, `28_CRYPTO_DRIFT_FORENSIC_AUDIT.md` | Medium — Weak crypto reintroduced undetected | Retirement registry, reintroduction detector | Implement RetiredAssetRegistry; implement ReintroductionDetector (scan-time + monitor-time); implement severity calculation (CRITICAL/HIGH/MEDIUM/LOW); implement alerting (Critical → page, High → alert, Medium → log); implement reintroduction workflow (Detect → Alert → Investigate → Remediate → Verify → Close) | Reintroductions detected within 5 min of scan; severity calculated correctly; alerts routed per severity; workflow enforced with evidence; retirement registry updated on remediation | 6-8 weeks | **P2** |
| **GAP-024** | No Automated Evidence Packages | Compliance/Reporting | `66_COMPLIANCE_EVIDENCE_AUDIT.md`, `31_ENTERPRISE_WORKFLOW_AUDIT.md` | Medium — Manual evidence packaging | Evidence pipeline, CBOM generator | Implement automated evidence package generator (per requirement, per finding, per scan); implement evidence bundle export (ZIP + manifest + hash); implement evidence package verification (hash verification); implement evidence package API (download, verify, list) | Evidence packages generated automatically per requirement; packages include evidence, findings, CBOM, audit trail; packages verifiable via hash; packages downloadable via API | 6-8 weeks | **P2** |
| **GAP-024** | No Requirement Coverage Dashboard | Compliance | `66_COMPLIANCE_EVIDENCE_AUDIT.md`, `56_BUSINESS_IMPACT_AUDIT.md` | Medium — No coverage visibility | Requirement model, policy engine | Implement RequirementCoverage dashboard (per standard, per system, per tenant); implement coverage heatmap (covered/uncovered/gapped); implement gap analysis report (uncovered requirements + remediation); implement requirement traceability matrix (requirement → policy → evidence → finding) | Coverage dashboard shows % covered per standard; heatmap shows gaps; gap analysis report with remediation; traceability matrix exportable | 4-6 weeks | **P2** |
| **GAP-025** | No Automated Evidence Packages | Compliance/Evidence | `66_COMPLIANCE_EVIDENCE_AUDIT.md`, `25_EVIDENCE_CHAIN_FORENSIC_AUDIT.md` | Medium — Manual evidence packaging | Evidence pipeline, CBOM generator | Implement automated evidence package generator (per requirement, per finding, per scan); implement evidence bundle export (ZIP + manifest + hash); implement evidence package verification (hash verification); implement evidence package API (download, verify, list) | Evidence packages generated automatically per requirement; packages include evidence, findings, CBOM, audit trail; packages verifiable via hash; packages downloadable via API | 6-8 weeks | **P2** |
| **GAP-025** | No Cross-Framework Mapping | Compliance | `66_COMPLIANCE_EVIDENCE_AUDIT.md`, `56_BUSINESS_IMPACT_AUDIT.md` | Medium — Manual mapping effort | Requirement model, policy engine | Implement cross-framework requirement mapping (PCI-DSS ↔ NIST ↔ ISO ↔ HIPAA); implement requirement equivalence mapping; implement cross-framework gap analysis (requirement covered in one framework but not another); implement cross-framework evidence reuse | Cross-framework mapping shows equivalent requirements; gap analysis identifies framework-specific gaps; evidence reused across frameworks | 8-12 weeks | **P2** |
| **GAP-026** | No Audit Collaboration Workspace | Compliance/Audit | `78_FORENSIC_AUDIT_TRAIL_AUDIT.md`, `78_FORENSIC_AUDIT_TRAIL_AUDIT.md` | Medium — No auditor collaboration | Audit trail, evidence export | Implement auditor workspace (shared evidence review, annotations, comments); implement collaborative finding triage; implement auditor sign-off workflow; implement audit evidence packaging for external auditors; implement audit timeline with milestones | Auditor workspace supports multi-auditor review; annotations/comments on evidence; sign-off workflow with timestamps; audit packages for external auditors | 8-12 weeks | **P2** |

---

### P3 — ENHANCEMENT

| ID | Gap | Category | Evidence | Impact | Dependencies | Required Action | Acceptance Criteria | Effort | Priority |
|----|-----|----------|----------|--------|--------------|-----------------|---------------------|--------|----------|
| **GAP-026** | PQC Protocol Detection | PQC | `59_HNDL_PQC_RISK_AUDIT.md`, `52_DETECTION_ACCURACY_AUDIT.md` | Medium — Future-proofing | Protocol engine, quantum registry | Extend ProtocolEngine with PQC cipher suite registry; extend quantum registry with PQC cipher suites; extend network scanner with PQC cipher suite parsing; extend SSH/IPsec parsers with PQC algorithms | TLS 1.3 hybrid KEM detected; SSH PQC KEX detected; IPsec hybrid IKEv2 detected; PQC cipher suites in quantum registry | 8-12 weeks | **P3** |
| **GAP-027** | CT Log Verification | Certificates | `59_HNDL_PQC_RISK_AUDIT.md`, `49_EVIDENCE_QUALITY_AUDIT.md` | Medium — Trust enhancement | Certificate intel, CT log client | Implement CT log streaming client; implement SCT validation against known logs; implement CT log monitoring for domains; implement SCT verification in certificate validation | CT log streaming active; SCTs validated against known logs; CT monitoring alerts on new certificates | 4-6 weeks | **P3** |
| **GAP-027** | OCSP/CRL Validation | Certificates | `59_HNDL_PQC_RISK_AUDIT.md`, `23_CRYPTOGRAPHIC_CORRECTNESS_AUDIT.md` | Medium — Real-time revocation | Certificate intel, OCSP/CRL client | Implement OCSP stapling verification; implement CRL fetching and caching; implement real-time OCSP/CRL checking; implement revocation status in certificate validation | OCSP stapling verified; CRLs fetched and cached; real-time revocation checking; revocation status in certificate validation | 4-6 weeks | **P3** |
| **GAP-028** | Advanced Binary Analysis | Binary | `52_DETECTION_ACCURACY_AUDIT.md`, `23_CRYPTOGRAPHIC_CORRECTNESS_AUDIT.md` | Medium — Deeper analysis | angr/ghidra integration, binary engine | Integrate angr/ghidra for control flow analysis; implement deobfuscation detection; implement firmware filesystem extraction (UEFI, squashfs, jffs2); implement control flow analysis for crypto routines | Control flow analysis detects crypto routines; deobfuscation hints provided; firmware extraction works; crypto routine signatures identified | 12-16 weeks | **P3** |
| **GAP-029** | ML-Assisted Remediation | Remediation/AI | `60_CRYPTO_AGILITY_FORENSIC_AUDIT.md`, `29_PQC_MIGRATION_READINESS_AUDIT.md` | Medium — Enhanced suggestions | Remediation engine, ML pipeline | Integrate ML for remediation prioritization; implement ML for migration effort estimation; implement ML for compatibility risk prediction; implement ML for remediation code generation | ML prioritizes remediation by business impact; ML estimates migration effort; ML predicts compatibility issues; ML generates remediation code snippets | 12-16 weeks | **P3** |
| **GAP-030** | Predictive Risk Scoring | Risk/PQC | `64_CRYPTO_RISK_SCORING_FORENSIC_AUDIT.md`, `29_PQC_MIGRATION_READINESS_AUDIT.md` | Medium — Proactive risk | Risk engine, ML pipeline | Implement ML for risk trend forecasting; implement ML for exploitability prediction (EPSS + custom); implement ML for migration timeline prediction; implement ML for remediation priority optimization | Risk trends forecasted 30/60/90 days; exploitability predicted for CVEs; migration timelines predicted; remediation priorities optimized by ML | 8-12 weeks | **P3** |
| **GAP-031** | Chaos Engineering | Reliability | `82_ZERO_TRUST_ARCHITECTURE_AUDIT.md`, `32_FAILURE_RECOVERY_AUDIT.md` | Medium — Resilience validation | Chaos mesh, chaos toolkit | Implement chaos experiments (pod kill, network partition, CPU stress, disk fill, clock skew); implement chaos experiment scheduling; implement chaos experiment rollback; implement chaos experiment reporting | Chaos experiments run safely; rollback works; experiment results reported; system resilience validated | 8-12 weeks | **P3** |
| **GAP-031** | Formal Verification | Security/Correctness | `84_SCANNER_SANDBOX_AUDIT.md`, `81_AI_BOUNDARY_AUDIT.md` | Medium — Correctness proof | TLA+, seccomp proofs | Formalize seccomp profiles in TLA+; prove seccomp profile correctness; prove capability dropping correctness; prove sandbox isolation properties; verify AI boundary enforcement formally | Seccomp profiles formally verified; capability dropping proven correct; sandbox isolation proven; AI boundary enforcement formally verified | 12-16 weeks | **P3** |

---

## 2. IMPLEMENTATION ROADMAP — SYNTHESIZED

### Phase 0: SECURE THE BASE (Weeks 1-2)

| Task | Owner | Effort | Dependencies |
|------|-------|--------|--------------|
| Deploy gVisor/Kata runtime | Platform | 1 week | - |
| Create base seccomp profiles | Security | 1 week | gVisor |
| Implement capability dropping | Platform | 1 week | gVisor |
| Add resource limits to all containers | Platform | 1 week | - |
| Add missing GIN indexes | Database | 1 week | - |
| Add composite indexes on FKs | Database | 1 week | - |
| Deploy Alertmanager + Loki | Platform | 1 week | - |
| Document air-gap deployment runbook | Docs | 1 week | - |

### Phase 1: UNIFY PIPELINE (Weeks 3-6)

| Task | Owner | Effort | Dependencies |
|------|-------|--------|--------------|
| Route live crypto through evidence pipeline | Backend | 2 weeks | Evidence pipeline |
| Merge 3 CBOM generators into one | Backend | 2 weeks | CBOM generators |
| Implement HBOM generator | Backend | 1 week | Hardware data |
| Implement VBOM generator | Backend | 1 week | Vendor intel |
| Merge algorithm registries | Backend | 1 week | Registries |
| Consolidate 10 micro-services | Platform | 1 week | - |
| Implement Neo4j tenant isolation | Platform | 2 weeks | DB migration |

### Phase 1: CORE CAPABILITIES (Weeks 7-14)

| Task | Owner | Effort | Dependencies |
|------|-------|--------|--------------|
| Implement HBOM generator | Backend | 1 week | Hardware data |
| Implement VBOM generator | Backend | 1 week | Vendor intel |
| Unified lockfile parser | Backend | 2 weeks | Scanner |
| Recursive crypto analysis | Backend | 2 weeks | Dependency graph |
| Link live observations to source evidence | Backend | 2 weeks | Evidence pipeline |
| Extract Scans → Graph → Migration tasks | Backend | 2 weeks | Graph engine |
| PKCS#11/KMIP operational | Backend | 2 weeks | Hardware scanner |
| Scheduled graph sync (CDC) | Platform | 1 week | Debezium |
| CBOM portfolio streaming | Backend | 1 week | Generator |
| Incremental graph sync | Platform | 2 weeks | CDC |

### Phase 2: SCALABILITY + HA (Weeks 15-22)

| Task | Owner | Effort | Dependencies |
|------|-------|--------|--------------|
| Extract 4 domain API services | Backend | 8 weeks | API decomposition |
| PostgreSQL HA + read replicas | Platform | 4 weeks | - |
| Redis Cluster/Sentinel | Platform | 2 weeks | - |
| Neo4j Causal Cluster | Platform | 4 weeks | - |
| Incremental graph sync (CDC) | Backend | 6 weeks | Debezium |
| CBOM portfolio streaming | Backend | 2 weeks | Generator |

### Phase 3: ENTERPRISE POLISH (Weeks 15-22)

| Task | Owner | Effort | Dependencies |
|------|-------|--------|--------------|
| Resource-level RBAC | Backend | 2 weeks | Auth system |
| PKCS#11/KMIP operational | Backend | 2 weeks | HSM scanner |
| SIEM/ITSM connectors | Backend | 4 weeks | Automation |
| Python/TypeScript SDKs | SDK Team | 2 weeks | OpenAPI spec |
| Scheduled compliance reports | Backend | 2 weeks | Scheduler |
| Scheduled evidence bundles | Backend | 2 weeks | Evidence pipeline |

### Phase 5: EMERGING (Weeks 23+)

| Task | Owner | Effort | Dependencies |
|------|-------|--------|--------------|
| PQC protocol detection | Backend | 8 weeks | Protocol engine |
| Advanced binary analysis | Research | 12 weeks | angr/ghidra |
| Graph analytics | Backend | 4 weeks | NetworkX/GraphFrames |

---

## 3. RESOURCE ESTIMATION

| Phase | Duration | Engineers | Focus |
|-------|----------|-----------|-------|
| **Phase 0** | 2 weeks | 2 | Security hardening |
| **Phase 1** | 4 weeks | 4 | Pipeline unification |
| **Phase 1** | 8 weeks | 4 | Missing features |
| **Phase 2** | 8 weeks | 4 | Scalability + HA |
| **Phase 3** | 8 weeks | 4 | Enterprise polish |
| **Phase 4** | Ongoing | 2 | Emerging capabilities |
| **Total** | **~30 weeks** | **4-6 engineers** | **Full production readiness** |

---

## 4. FINAL PRIORITIZATION MATRIX

| Priority | Count | Total Effort | Key Focus |
|----------|-------|--------------|-----------|
| **P0 (Critical)** | 10 | ~90 weeks | Security, Multi-tenancy, Verification, AI Safety |
| **P1 (High)** | 10 | ~70 weeks | Missing Features, Compliance, Automation |
| **P2 (Medium)** | 10 | ~70 weeks | Integration, UX, Temporal, Deduplication |
| **P3 (Enhancement)** | 10 | ~90 weeks | Advanced Features, Formal Verification, ML |

**Total Estimated Effort: ~320 engineer-weeks (~30 weeks with 4-6 engineers)**

---

## 3. SUCCESS CRITERIA — DEFINITION OF DONE

| Milestone | Criteria |
|-----------|----------|
| **Phase 0 Complete** | All scanners sandboxed; gVisor deployed; seccomp active; capabilities dropped; resource limits set; Alertmanager+Loki deployed; air-gap runbook documented |
| **Phase 1 Complete** | Evidence pipeline unified; 3 CBOM generators merged; HBOM/VBOM generators live; algorithm registries merged; 10 micro-services consolidated; Neo4j tenant isolation active |
| **Phase 1 Complete** | HBOM/VBOM generators live; unified lockfile parser; recursive crypto analysis; live observations linked to source evidence; scans→graph→migration tasks automated; PKCS#11/KMIP operational; scheduled graph sync active; CBOM portfolio streaming; incremental graph sync active |
| **Phase 2 Complete** | 4 domain API services extracted; PostgreSQL HA + read replicas active; Redis Cluster operational; Neo4j Causal Cluster operational; incremental graph sync (CDC) operational; CBOM portfolio streaming |
| **Phase 3 Complete** | Resource-level RBAC active; PKCS#11/KMIP operational; SIEM/ITSM connectors live; Python/TS SDKs published; scheduled compliance reports running; scheduled evidence bundles running |
| **Phase 4 Complete** | PQC protocol detection operational; advanced binary analysis integrated; graph analytics (PageRank, community) operational |

---

## 4. FINAL RECOMMENDATION

**Invest 30 weeks (7-8 months) with 4-6 engineers to close P0/P1 gaps.** The resulting platform will be a **market-leading, enterprise-grade cryptographic intelligence platform** with genuine deterministic truth guarantees.

**The core intelligence model is genuinely exceptional.** The gaps are operational/infrastructural, not conceptual. With focused engineering investment, ZELNX can become the market-leading enterprise cryptographic intelligence platform.

---

**End of Final Gap Prioritization — 88 audit documents covering every dimension of ZELNX CryptoScan.**
## UPDATE — 2026-10-09: gap register status after rounds 13–15

| Gap | Status |
|---|---|
| GAP-001 sandboxing, GAP-004 encryption at rest, GAP-005 mTLS | Open — deployment/target-environment scope |
| GAP-002 tenant quotas | Largely fixed (plan quotas, 402 quota_exceeded, usage metering); CPU/memory/worker quotas are orchestrator-level |
| GAP-003 Neo4j tenant isolation | **Fixed** (tenant gate, memory-tenant-isolated backend) |
| GAP-006 remediation verification | **FIXED round 14** (see 62's update) |
| GAP-007 drift detection, GAP-010 continuous monitoring, GAP-011 baselines | **Fixed** (drift service+router, monitor daemon, webhooks, SSE, report schedules, baseline approval) |
| GAP-008 replayability | Partial by design (manifests, chain hashes, snapshots, transfer verification; full env-capture replay is target-env) |
| GAP-009 AI boundary | N/A — no AI exists in the deterministic path (report 80 proves it); runtime enforcement is deployment work |
| GAP-012/013 HBOM/VBOM | **Fixed** — Technology BOM layers (sbom/cbom/hbom/vendor/certificates) with signed exports |
| GAP-014/015 PQC + hybrid detection | **FIXED round 14** (see 52/59 updates) |
| GAP-023 reintroduction detection | **FIXED round 15, scan-time** (see 69's update); monitor-time background check remains |
| GAP-024/025 evidence packages / coverage dashboards | Evidence packs, attestations, closure register shipped; coverage heatmap + cross-framework mapping open |
| GAP-026+ P3 items | Open enhancements (CT logs, OCSP/CRL, binary analysis, ML, chaos) |

Full evidence table: `docs/AUDIT-RECONCILIATION-2026-10-09.md` and
`audit_reports/00_ROUND_STATUS.md`.


## Round 23 note (2026-10-10) — GAP-011 status update

GAP-011 (no automated baseline creation): the honest half is now BUILT.
The worker's drift stage proposes a baseline (`status=PROPOSED`) when a
system's first scan is clean — no FAIL policy evidence, no CRITICAL/HIGH
drift — and a newer clean scan supersedes an older proposal. Activation
remains an auditor decision (`POST /baselines/{id}/approve-proposed`),
per the report's own acceptance criterion "auditor approves → baseline
active". Full auto-activation is deliberately not built: a baseline is a
trust anchor. See deep/31's round-23 addendum.
