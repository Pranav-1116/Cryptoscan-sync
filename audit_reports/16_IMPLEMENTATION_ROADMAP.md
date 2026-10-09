# 16_IMPLEMENTATION_ROADMAP.md
## ZELNX CryptoScan — Implementation Roadmap

**Generated:** 2026-09-20  
**Based On:** All preceding audit reports (01-15)  
**Scope:** Prioritized, sequenced implementation plan addressing critical gaps, technical debt, and missing features

---

## 1. ROADMAP PHILOSOPHY

### 1.1 Guiding Principles
1. **Deterministic Truth First** — Evidence chain, CBOM, graph integrity before features
2. **Security by Default** — Fail-closed, encrypted, isolated
3. **Operational Simplicity** — Reduce service count, consolidate pipelines
4. **Honest Incrementalism** — Ship working slices; no vaporware

### 1.2 Sequencing Logic
```
FOUNDATION (Security + Data Integrity)
    ↓
CORE PIPELINE UNIFICATION (Evidence → CBOM → Graph)
    ↓
MULTI-TENANCY + HA (Production Prerequisites)
    ↓
SCALABILITY (API Decomposition + Read Replicas)
    ↓
MISSING FEATURES (HBOM, Vendor Crypto, Transitive Deps)
    ↓
ENTERPRISE POLISH (RBAC, Connectors, SDKs, Compliance Automation)
```

---

## 2. PHASE 0 — IMMEDIATE (Weeks 1-2) "SECURE THE BASE"

### 2.1 Security Hardening (P0)
| Task | Owner | Effort | Dependencies |
|------|-------|--------|--------------|
| **SECRETS-001** Move all secrets to Vault/Docker secrets/K8s secrets | Platform | 3 days | Vault cluster |
| **SECRETS-002** Enable PostgreSQL encryption at rest (TDE or LUKS) | Platform | 2 days | DB restart window |
| **SECRETS-003** Enable Redis TLS + ACL | Platform | 1 day | Redis restart |
| **SECRETS-004** Enable Neo4j Bolt TLS | Platform | 1 day | Neo4j restart |
| **NETWORK-001** Remove dev port mappings from production compose | Platform | 0.5 day | docker-compose.prod.yml |
| **NETWORK-002** Implement K8s NetworkPolicy (deny-all default) | Platform | 2 days | K8s CNI supporting NetworkPolicy |
| **CONTAINER-001** Add read-only rootfs to all Dockerfiles | Platform | 1 day | Test volume mounts |
| **CONTAINER-002** Scan base images for CVEs (Trivy in CI) | Platform | 1 day | CI pipeline |

### 2.2 Data Integrity (P0)
| Task | Owner | Effort | Dependencies |
|------|-------|--------|--------------|
| **EVIDENCE-001** Add automated evidence chain verification cron (hourly) | Backend | 1 day | `VerificationLog` model exists |
| **EVIDENCE-002** Add tenant_id to 4 link tables + backfill migration | Backend | 2 days | `SystemAsset`, `SystemDependency`, `CertificateUsage`, `CryptoAssetEvidence` |
| **EVIDENCE-003** Implement soft-delete for EvidenceRecord (mark deleted, preserve chain) | Backend | 3 days | Schema migration |

### 2.3 Observability (P1)
| Task | Owner | Effort | Dependencies |
|------|-------|--------|--------------|
| **OBS-001** Deploy PrometheusAlertmanager + PagerDuty/Slack routes | Platform | 2 days | Alertmanager config |
| **OBS-002** Define critical alerts: DB down, queue depth >100, scan failure rate >10% | Platform | 1 day | Prometheus rules |
| **OBS-003** Deploy Loki/Elasticsearch for log aggregation | Platform | 3 days | Logging stack |

---

## 3. PHASE 1 — FOUNDATION (Weeks 3-6) "UNIFY THE PIPELINE"

### 3.1 Pipeline Unification (P0)
| Task | Owner | Effort | Dependencies |
|------|-------|--------|--------------|
| **PIPE-001** Route live crypto events through evidence pipeline | Backend | 2 weeks | `crypto_live` → `EvidencePipeline` |
| **PIPE-002** Unify CBOM generation — single `CbomGenerator` for static + live | Backend | 2 weeks | Merge `crypto.py` live CBOM into `cbom` service |
| **PIPE-003** Deprecate `techbom` router — merge into `cbom` with type parameter | Backend | 1 week | `PIPE-002` complete |
| **PIPE-004** Merge algorithm registries — single source of truth | Backend | 1 week | `shared_models/algorithm_registry.py` + `universal_crypto/registry.py` |

### 3.2 Service Consolidation (P1)
| Task | Owner | Effort | Dependencies |
|------|-------|--------|--------------|
| **CONSOLIDATE-001** Merge 10 micro-services into libraries: `billing`, `sla`, `vaultlease`, `connector_sdk`, `keyassure`, `privacy`, `ot_safety`, `ruleset`, `universal_platform`, `universal_vendor` | Backend | 1 week | Move to `shared/` |
| **CONSOLIDATE-002** Extract shared test fixtures to `shared/test_fixtures/` | Backend | 3 days | `conftest.py` duplication |
| **CONSOLIDATE-003** Create `shared/api_client` for frontend/backend type sharing | Frontend + Backend | 1 week | OpenAPI spec generation |

### 3.3 Graph Tenant Isolation (P0)
| Task | Owner | Effort | Dependencies |
|------|-------|--------|--------------|
| **GRAPH-001** Decision: Separate Neo4j DB per tenant vs. document single-tenant | Arch + Product | 1 day | Business decision |
| **GRAPH-002** If multi-tenant: Implement Neo4j multi-database (one per tenant) | Platform | 1 week | Neo4j 5.x multi-db |
| **GRAPH-003** Update `graph_from_db()` and `Neo4jGraphStore` for tenant context | Backend | 1 week | `GRAPH-002` |

---

## 4. PHASE 2 — CORE CAPABILITIES (Weeks 7-14) "BUILD MISSING FEATURES"

### 4.1 HBOM Implementation (P0)
| Task | Owner | Effort | Dependencies |
|------|-------|--------|--------------|
| **HBOM-001** Design HBOM schema (CycloneDX hardware extensions) | Backend | 3 days | CycloneDX spec |
| **HBOM-002** Implement `HbomGenerator` using `hardware_live` + `payment_crypto` | Backend | 1 week | `PIPE-001` |
| **HBOM-003** Add HBOM database model + migrations | Backend | 3 days | |
| **HBOM-004** Implement `/hbom` API endpoints (system, portfolio, ingest) | Backend | 1 week | |
| **HBOM-005** Frontend: Connect `Hbom.tsx` to real API | Frontend | 3 days | `HBOM-004` |

### 4.2 Vendor Crypto Detection (P0)
| Task | Owner | Effort | Dependencies |
|------|-------|--------|--------------|
| **VENDOR-001** Design vendor fingerprinting (certs, library versions, config patterns) | Backend | 1 week | |
| **VENDOR-002** Implement automated vendor detection in scanner | Backend | 2 weeks | Scanner extension |
| **VENDOR-003** Vendor risk scoring model | Backend | 1 week | `vendor_intel` service |
| **VENDOR-004** Sub-tier vendor mapping (vendor-of-vendor) | Backend | 1 week | `graph.py:/graph/vendor-edges` |

### 4.3 Transitive Dependency Crypto (P1)
| Task | Owner | Effort | Dependencies |
|------|-------|--------|--------------|
| **DEP-001** Unified lockfile parser (pip, npm, Maven, Gradle, Cargo, NuGet, Go, pipenv, poetry) | Backend | 2 weeks | |
| **DEP-002** Recursive crypto analysis — propagate crypto from transitive deps | Backend | 2 weeks | `DEP-001` |
| **DEP-003** SBOM → crypto correlation — link SBOM components to crypto assets | Backend | 1 week | `DEP-001` |

### 4.4 Runtime ↔ Static Correlation (P1)
| Task | Owner | Effort | Dependencies |
|------|-------|--------|--------------|
| **CORR-001** Link live observations to source evidence (same algorithm + location) | Backend | 2 weeks | `PIPE-001` |
| **CORR-002** Unified CBOM showing both static + runtime evidence per component | Backend | 1 week | `CORR-001` |
| **CORR-003** Graph edges for runtime observations (Process → Loads → Library) | Backend | 1 week | Graph schema extension |

---

## 5. PHASE 3 — SCALABILITY + HA (Weeks 15-22) "PRODUCTION SCALE"

### 5.1 API Decomposition (P0)
| Task | Owner | Effort | Dependencies |
|------|-------|--------|--------------|
| **API-001** Extract Scans/Inventory service (scans, findings, evidence, assets, cbom) | Backend | 2 weeks | |
| **API-002** Extract Graph service (graph, blast-radius, vendor-chains, migration) | Backend | 2 weeks | `GRAPH-002` |
| **API-003** Extract Crypto service (live crypto, quantum, agility, remediation) | Backend | 2 weeks | `PIPE-002` |
| **API-004** Extract Compliance service (drift, policy, compliance, reporting) | Backend | 2 weeks | |
| **API-005** API Gateway / BFF for frontend | Platform | 1 week | Service mesh |

### 5.2 Database HA (P1)
| Task | Owner | Effort | Dependencies |
|------|-------|--------|--------------|
| **DB-001** PostgreSQL HA — Patroni or managed (RDS/Cloud SQL) | Platform | 1 week | |
| **DB-002** Read replica + routing (analytics → replica) | Backend | 1 week | `DB-001` |
| **DB-003** Redis Cluster/Sentinel for queue + rate limit HA | Platform | 1 week | |
| **DB-004** Neo4j Causal Cluster (if multi-tenant) | Platform | 1 week | `GRAPH-002` |

### 5.3 Incremental Graph Sync (P1)
| Task | Owner | Effort | Dependencies |
|------|-------|--------|--------------|
| **SYNC-001** CDC from relational → Neo4j (Debezium or custom) | Backend | 2 weeks | `DB-001` |
| **SYNC-002** Graph sync status API + progress tracking | Backend | 1 week | `SYNC-001` |
| **SYNC-003** Scheduled sync (configurable interval) | Backend | 1 week | `SYNC-001` |

### 5.4 CBOM Portfolio Streaming (P1)
| Task | Owner | Effort | Dependencies |
|------|-------|--------|--------------|
| **CBOM-001** Cursor-based streaming for `/cbom/portfolio` | Backend | 1 week | |
| **CBOM-002** Pagination for all list endpoints (already mostly done) | Backend | 3 days | |

---

## 6. PHASE 4 — ENTERPRISE POLISH (Weeks 23-30) "OPERATIONAL EXCELLENCE"

### 6.1 RBAC + ABAC (P1)
| Task | Owner | Effort | Dependencies |
|------|-------|--------|--------------|
| **RBAC-001** Resource-level permissions (per-system, per-asset, per-scan) | Backend | 2 weeks | |
| **RBAC-002** Custom role definitions (API + UI) | Backend + Frontend | 1 week | `RBAC-001` |
| **RBAC-003** Delegated administration (tenant admin, BU admin) | Backend | 1 week | `RBAC-001` |
| **ABAC-001** Enable ABAC by default (fail-closed) | Backend | 1 week | `GRAPH-002` |

### 6.2 PKCS#11/KMIP Operational (P1)
| Task | Owner | Effort | Dependencies |
|------|-------|--------|--------------|
| **HSM-001** PKCS#11 client integration (SoftHSM2 for dev, nCipher/Thales for prod) | Backend | 2 weeks | `cbom/hsm_pkcs11.py` exists |
| **HSM-002** KMIP client integration (PyKMIP) | Backend | 1 week | `cbom/kmip.py` exists |
| **HSM-003** Key ceremony workflow (dual control, M-of-N) | Backend | 1 week | `payment_crypto` service |

### 6.3 Connectors + SDKs (P2)
| Task | Owner | Effort | Dependencies |
|------|-------|--------|--------------|
| **CONN-001** Implement SIEM connectors (Splunk HEC, Elastic, Sentinel) | Backend | 2 weeks | `automation` scaffold |
| **CONN-002** Implement ITSM connectors (ServiceNow, Jira) | Backend | 1 week | `automation` scaffold |
| **CONN-003** Implement Messaging connectors (Kafka, RabbitMQ, Pulsar) | Backend | 1 week | `automation` scaffold |
| **SDK-001** Python SDK (generated from OpenAPI) | Backend | 1 week | OpenAPI spec per domain |
| **SDK-002** TypeScript SDK (generated) | Frontend | 1 week | OpenAPI spec per domain |

### 6.4 Compliance Automation (P2)
| Task | Owner | Effort | Dependencies |
|------|-------|--------|--------------|
| **COMP-001** Scheduled compliance reports (cron + evidence package) | Backend | 1 week | `report_schedules` table |
| **COMP-002** Regulatory mapping feed (NIST/FIPS/PCI updates) | Backend | 1 week | External feed |
| **COMP-003** Audit-ready evidence bundle (ZIP + manifest + chain) | Backend | 1 week | Evidence chain |

---

## 7. PHASE 5 — EMERGING CAPABILITIES (Weeks 31+) "NEXT FRONTIER"

### 7.1 PQC Protocol Detection (P3)
| Task | Owner | Effort |
|------|-------|--------|
| **PQC-001** QUIC/TLS 1.3 PQC cipher suite detection | Backend | 2 weeks |
| **PQC-002** Post-quantum SSH (hybrid KEX) detection | Backend | 1 week |
| **PQC-003** Post-quantum IPsec (hybrid IKEv2) detection | Backend | 1 week |

### 7.2 Advanced Binary Analysis (P3)
| Task | Owner | Effort |
|------|-------|--------|
| **BIN-001** Control flow analysis for crypto (angr/ghidra integration) | Backend | 4 weeks |
| **BIN-002** Obfuscation detection + deobfuscation hints | Backend | 2 weeks |
| **BIN-003** Firmware filesystem extraction (UEFI, squashfs, jffs2) | Backend | 2 weeks |

### 7.3 Graph Analytics (P3)
| Task | Owner | Effort |
|------|-------|--------|
| **GRAPH-004** PageRank/Betweenness for criticality | Backend | 1 week |
| **GRAPH-005** Community detection for segmentation | Backend | 1 week |
| **GRAPH-006** Historical graph queries (time-travel via snapshots) | Backend | 1 week |

---

## 8. RESOURCE ESTIMATION

### 8.1 Team Composition (Recommended)
| Role | Count | Focus |
|------|-------|-------|
| **Backend Engineers** | 4 | Pipeline, API, Graph, Database |
| **Platform/DevOps** | 2 | Infrastructure, Security, CI/CD |
| **Frontend Engineers** | 2 | UI, SDK, Dashboard |
| **Security Engineer** | 1 | Hardening, Crypto, Compliance |
| **QA/Automation** | 1 | Testing, E2E, Performance |
| **Technical Writer** | 0.5 | Documentation, Runbooks |
| **Product Manager** | 1 | Prioritization, Stakeholders |

### 8.2 Timeline Summary

| Phase | Duration | Key Deliverable |
|-------|----------|-----------------|
| **Phase 0** | 2 weeks | Secure baseline |
| **Phase 1** | 4 weeks | Unified pipeline, consolidated services |
| **Phase 2** | 8 weeks | HBOM, Vendor Crypto, Transitive Deps, Correlation |
| **Phase 3** | 8 weeks | API decomposition, HA, Incremental sync |
| **Phase 4** | 8 weeks | RBAC, HSM, Connectors, SDKs, Compliance |
| **Phase 5** | Ongoing | PQC protocols, Advanced binary, Graph analytics |

**Total to Production-Ready Multi-Tenant: ~30 weeks (7.5 months)**
**Total to Single-Tenant Enterprise: ~12 weeks (Phase 0 + 1 + 3 subset)**

---

## 9. RISK MITIGATION

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| **Neo4j multi-tenant complexity** | High | High | Document single-tenant as supported; multi-tenant as future |
| **API decomposition scope creep** | High | Medium | Strict domain boundaries; one service per quarter |
| **Live + Static pipeline merge conflicts** | Medium | High | Feature flag gradual migration; run in parallel |
| **Team bandwidth for 30-week plan** | Medium | High | Prioritize Phases 0-2; defer Phase 4-5 |
| **Third-party HSM availability for testing** | Medium | Medium | SoftHSM2 for CI; partner for hardware testing |
| **Frontend-backend type drift** | High | Medium | Shared types package + CI contract test |

---

## 10. SUCCESS METRICS

| Metric | Baseline | Target (Post-Phase 3) | Target (Post-Phase 4) |
|--------|----------|----------------------|----------------------|
| **API p95 latency** | Unknown | <500ms | <200ms |
| **Scan throughput** | ~4 concurrent | 20 concurrent | 50 concurrent |
| **Graph sync time (100K nodes)** | ~5 min | <30 sec (incremental) | <10 sec |
| **CBOM portfolio generation** | OOM at 100K | <5 sec (streaming) | <2 sec |
| **Tenant isolation** | Partial (Neo4j gap) | Complete | Complete |
| **Evidence chain verification** | Manual | Automated hourly | Automated continuous |
| **Backup restore tested** | Never | Monthly | Weekly |
| **MTTR (critical)** | Unknown | <1 hour | <30 min |
| **Test coverage** | Unknown | >80% | >90% |
| **Security findings (critical)** | Unknown | 0 | 0 |

---

## 11. DECISION POINTS — REQUIRED FROM LEADERSHIP

| Decision | Deadline | Options | Recommendation |
|----------|----------|---------|----------------|
| **Neo4j Multi-Tenant Strategy** | Week 2 | Separate DBs / Fabric / Single-tenant only | Separate DBs (cleanest isolation) |
| **API Decomposition Scope** | Week 3 | 4 services / 6 services / Monolith with modules | 4 domain services |
| **Managed vs Self-Hosted DB** | Week 4 | RDS/Cloud SQL / Patroni / Current | Managed (reduces ops) |
| **Service Mesh Choice** | Week 10 | Istio / Linkerd / Consul Connect / None | Linkerd (simpler) |
| **PQC Protocol Priority** | Week 20 | QUIC / SSH / IPsec / All | QUIC first (browser adoption) |
## UPDATE — round 17 build (2026-10-09)

Closed from this roadmap:

- **EVIDENCE-003 (soft-delete for EvidenceRecord, preserve chain): DONE** —
  migration 0075 + repository `include_deleted` semantics + auditor-gated
  `/findings/{id}/soft-delete` and `/findings/{id}/restore` endpoints +
  consumer filtering across listings, CBOM, conflicts, drift, remediation,
  intelligence, retirement. Chain verification and exports deliberately
  still see tombstones (see the report-15 addendum for the full contract).
- **EVIDENCE-001 (hourly chain-verification cron):** the manual sweep
  (`/ops/evidence/chain-status`, round 15) plus this round's contract
  tests cover the code path; the *schedule* is CI/CD-blocked (staged in
  `.github/workflows-pending/`).
- **EVIDENCE-002 (tenant_id on link tables):** still open, next natural
  schema round.

Also landed this round (not on this roadmap's task list): QUIC/DTLS/
WireGuard protocol analyses (report 13 §3.1), CBOM portfolio set-based
query + bounded explicit truncation (TD-007), backup encryption (report
15 §4), OpenAPI operationId contract tests, hypothesis property tests for
the hashing core, and opt-in coverage tooling (`scripts/coverage.sh`).
