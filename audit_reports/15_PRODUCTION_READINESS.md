# 15_PRODUCTION_READINESS.md
## ZELNX CryptoScan — Production Readiness Assessment

**Generated:** 2026-09-20  
**Method:** Evaluation against production deployment criteria — infrastructure, operations, security, scalability, reliability  
**Scope:** Current `docker-compose.yml` + `docker-compose.prod.yml` + `k8s/app/` + operational tooling

---

## 1. PRODUCTION READINESS SCORECARD

| Category | Score | Status | Blockers |
|----------|-------|--------|----------|
| **Infrastructure** | 7/10 | ⚠️ Ready with caveats | No HA for Neo4j/Redis/PostgreSQL |
| **Security** | 6/10 | ⚠️ Needs hardening | No mTLS, secrets in env, no DB encryption |
| **Operations** | 7/10 | ⚠️ Good tooling | No automated backup test, no DR |
| **Scalability** | 5/10 | ❌ Limited | API monolith, no read replicas, full graph sync |
| **Reliability** | 6/10 | ⚠️ Partial | No circuit breakers, no chaos testing |
| **Observability** | 7/10 | ⚠️ Good metrics | No alerting, no distributed tracing |
| **Deployment** | 8/10 | ✅ Solid | Docker + K8s manifests exist |
| **Data Integrity** | 8/10 | ✅ Strong | Evidence chain, CBOM signing, audit log |
| **Multi-tenancy** | 4/10 | ❌ Incomplete | Neo4j shared, link tables no tenant_id |
| **Compliance** | 7/10 | ⚠️ Good features | Automated reporting missing |

**Overall: 6.5/10 — "Production-Capable with Significant Caveats"**

---

## 2. INFRASTRUCTURE READINESS

### 2.1 Container Orchestration
| Component | Docker Compose | Kubernetes | Status |
|-----------|----------------|------------|--------|
| **API** | ✅ Single replica | ✅ Deployment + probes | Ready |
| **Worker** | ✅ Single replica | ✅ Deployment | Ready |
| **Monitor** | ✅ Single replica | ✅ Deployment | Ready |
| **Frontend** | ✅ Nginx static | ✅ Deployment | Ready |
| **Nginx** | ✅ TLS termination | ✅ Ingress | Ready |
| **PostgreSQL** | ✅ Single + healthcheck | ❌ No StatefulSet | **Gap** |
| **Redis** | ✅ Single + healthcheck | ❌ No StatefulSet | **Gap** |
| **Neo4j** | ✅ Single + init | ❌ No StatefulSet | **Gap** |

### 2.2 High Availability — MISSING
| Service | HA Strategy | Implemented |
|---------|-------------|-------------|
| **PostgreSQL** | Primary + replica + failover | ❌ |
| **Redis** | Sentinel or Cluster | ❌ |
| **Neo4j** | Causal cluster | ❌ |
| **API** | Multiple replicas + LB | ✅ (Docker) / ✅ (K8s HPA missing) |
| **Worker** | Multiple + queue sharding | ⚠️ Single queue |
| **Monitor** | Leader election (lease) | ✅ Implemented |

### 2.3 Resource Management
| Resource | Docker Compose | K8s | Configured |
|----------|----------------|-----|------------|
| **CPU Limits** | ❌ | ✅ | Partial |
| **Memory Limits** | ❌ | ✅ | Partial |
| **Storage** | Named volumes | ✅ PVC | Ready |
| **Network Policies** | ❌ | ❌ | **Gap** |

---

## 3. SECURITY READINESS

### 3.1 Production Hardening (main.py startup)
```python
# Fails fast in production if:
✅ SECRET_KEY >= 32 chars and not default
✅ DATABASE_URL not SQLite
✅ CORS_ORIGINS != "*"
✅ ADMIN_PASSWORD_HASH set (not plaintext)
✅ CBOM_SIGNING_SECRET set (for signing)
```

### 3.2 Security Gaps for Production
| Gap | Severity | Remediation |
|-----|----------|-------------|
| **No mTLS between services** | P1 | Service mesh (Istio/Linkerd) or manual certs |
| **Secrets in environment variables** | P1 | Docker secrets / K8s secrets / Vault |
| **No database encryption at rest** | P1 | PostgreSQL TDE / LUKS / cloud encryption |
| **No Redis encryption** | P1 | TLS + ACL |
| **No Neo4j encryption** | P1 | Bolt TLS + native encryption |
| **DB/Redis/Neo4j ports exposed in docker-compose** | P1 (dev only) | Remove port mappings in prod override |
| **No network segmentation** | P2 | K8s NetworkPolicy / Docker network isolation |
| **No WAF/DDoS protection** | P2 | Cloudflare / AWS Shield / nginx rate limit |

### 3.3 Container Security
| Hardening | Status |
|-----------|--------|
| Non-root user | ✅ All services |
| `no-new-privileges:true` | ✅ All services |
| `cap_drop: ALL` | ✅ All services |
| Read-only rootfs | ❌ |
| Distroless base | ❌ (Alpine) |
| Signed images | ❌ |
| SBOM for own images | ❌ |

---

## 4. OPERATIONAL READINESS

### 4.1 Backup & Restore
| Component | Script | Tested | Encrypted | RPO/RTO |
|-----------|--------|--------|-----------|---------|
| **PostgreSQL** | `scripts/backup_evidence.py` (includes pg_dump) | ❌ Not automated | ❌ | Undefined |
| **Evidence Chain** | `scripts/backup_evidence.py` + `restore_evidence.py` | ❌ | ❌ | Undefined |
| **Neo4j** | Not implemented | ❌ | ❌ | Undefined |
| **Redis** | Not implemented | ❌ | ❌ | Undefined |
| **Configuration** | GitOps (k8s) | ✅ | N/A | N/A |

### 4.2 Disaster Recovery
| Capability | Status |
|------------|--------|
| **RPO Defined** | ❌ |
| **RTO Defined** | ❌ |
| **Failover Procedure** | ❌ |
| **Cross-Region** | ❌ |
| **Runbooks** | ❌ |

### 4.3 Monitoring & Alerting
| Component | Implementation | Alerting |
|-----------|----------------|----------|
| **Metrics** | Prometheus `/metrics` | ❌ No Alertmanager |
| **Health Checks** | `/health`, `/ready`, `/healthz`, `/readyz` | ❌ |
| **Logs** | Structlog JSON → stdout | ❌ No aggregation |
| **Traces** | W3C trace-context → JSONL + OTLP | ❌ No backend |
| **Uptime** | Not monitored | ❌ |
| **Business Metrics** | Scan counts, findings, drift, queue | ❌ |

### 4.4 Operational Tooling
| Tool | Status | Notes |
|------|--------|-------|
| **Burn-in Harness** | `scripts/burn_in.py` | ✅ Tests external integrations |
| **Scan Estate** | `scripts/scan_estate.py` | ✅ Full estate scan + report |
| **CI Gate** | `scripts/ci_gate.py` | ✅ Policy gates for CI/CD |
| **Backup/Restore** | `scripts/backup_evidence.py` | ⚠️ Manual only |
| **Database Migration** | Alembic + `pgserver` test | ✅ Up/down tested |
| **Log Analysis** | None | ❌ |
| **Capacity Planning** | None | ❌ |

---

## 5. SCALABILITY READINESS

### 5.1 Current Limits (Estimated)
| Component | Limit | Bottleneck |
|-----------|-------|------------|
| **API Replicas** | 1 (Docker) / N (K8s) | Shared DB connections |
| **Concurrent Scans** | `MAX_CONCURRENT_JOBS` (default 4) | Worker thread pool |
| **Scan Size** | ~100K files per scan | In-memory processing |
| **Evidence Records** | 10M+ per scan | Chain verification O(N) |
| **Graph Nodes** | 100K+ | Full Neo4j rebuild on sync |
| **CBOM Portfolio** | All assets in memory | `_located_assets()` loads everything |

### 5.2 Scaling Blockers
| Blocker | Impact | Fix Effort |
|---------|--------|------------|
| **API Monolith** | Cannot scale domains independently | High |
| **Single PostgreSQL** | Read/write contention | Medium |
| **Full Graph Sync** | O(N) downtime during sync | Medium |
| **In-Memory CBOM Portfolio** | OOM at scale | Medium |
| **No Redis Cluster** | Rate limit / queue bottleneck | Low |
| **No Neo4j Cluster** | Graph HA impossible | High |

---

## 6. DATA INTEGRITY READINESS

### 6.1 Strengths (Production-Grade)
| Feature | Implementation |
|---------|----------------|
| **Evidence Chain** | SHA-256 content hash + blockchain chain hash + Merkle manifest |
| **CBOM Signing** | JWS (RS256/ES256/HS256) with key rotation support |
| **Audit Log Chain** | Hash chain with verification endpoint |
| **Graph Snapshots** | Content-addressed versions with diff |
| **Policy Pack Hash** | SHA-256 of enabled rule set |
| **Verification Log** | Periodic chain verification recorded |

### 6.2 Gaps
| Gap | Risk |
|-----|------|
| **No Automated Evidence Verification** | Corruption detected only on manual verify |
| **No Evidence Retention Policy** | Unbounded growth |
| **Chain Break on Delete** | CASCADE delete breaks chain continuity |
| **No Soft Delete for Evidence** | Cannot remove without breaking chain |

---

## 7. MULTI-TENANCY READINESS

### 7.1 Current State
| Component | Tenant Isolation | Status |
|-----------|------------------|--------|
| **Relational DB** | Row-level (`TenantScoped` + `filtered_get`) | ✅ 62% models |
| **Link Tables** | No tenant_id | ❌ |
| **Neo4j** | None — shared database | ❌ |
| **Event Stream** | In-process not scoped | ❌ |
| **Redis** | Shared queue/rate limit | ❌ |
| **File Storage** | Shared volumes | ❌ |

### 7.2 Production Blocker
**Neo4j shared database is a hard blocker for multi-tenant SaaS.** Options:
1. Separate Neo4j database per tenant (operational overhead)
2. Neo4j Fabric (multi-database queries) — complex
3. Document single-tenant only — honest limitation

---

## 8. COMPLIANCE READINESS

| Standard | Coverage | Gaps |
|----------|----------|------|
| **SOC 2 Type II** | Partial | No DR, no automated backup test, no access review automation |
| **ISO 27001** | Partial | No risk treatment automation, no asset lifecycle |
| **PCI-DSS** | Partial (payment_crypto) | No network segmentation, no ASV scan |
| **GDPR** | Partial | No data subject rights API, no retention policy |
| **NIST CSF** | Strong Identify/Protect/Detect | Respond/Recover gaps |

---

## 9. DEPLOYMENT READINESS CHECKLIST

### 8.1 Pre-Production Requirements (MUST)
- [ ] **Neo4j tenant isolation decision** — Document or implement
- [ ] **Secrets management** — Vault/Docker secrets/K8s secrets (no env vars)
- [ ] **Database encryption at rest** — PostgreSQL TDE or volume encryption
- [ ] **mTLS between services** — Service mesh or mutual TLS
- [ ] **Remove dev port mappings** — Production docker-compose override
- [ ] **Network policies** — K8s NetworkPolicy or Docker network segmentation
- [ ] **Automated backup + restore test** — Weekly restore verification
- [ ] **Alerting on metrics** — PrometheusAlertmanager with PagerDuty/Slack

### 8.2 Production-Hardening (SHOULD)
- [ ] **Read replicas** — Route analytics to replicas
- [ ] **Redis Cluster/Sentinel** — HA for queue + rate limit
- [ ] **PostgreSQL HA** — Patroni or cloud managed
- [ ] **Neo4j HA** — Causal cluster or document limitation
- [ ] **Circuit breakers** — Resilience4j/pybreaker on external calls
- [ ] **Distributed tracing** — Jaeger/Tempo + OTLP
- [ ] **Log aggregation** — Loki/Elasticsearch
- [ ] **Capacity planning** — Load test + resource quotas

### 8.3 Operational Excellence (NICE)
- [ ] **Runbooks** — Incident response procedures
- [ ] **Chaos engineering** — Regular failure injection
- [ ] **Blue/Green deployments** — Zero-downtime releases
- [ ] **Feature flags** — LaunchDarkly/Unleash
- [ ] **SBOM for own images** — Supply chain transparency

---

## 10. PRODUCTION DEPLOYMENT ARCHITECTURE — RECOMMENDED

```
┌─────────────────────────────────────────────────────────────┐
│                    EXTERNAL TRAFFIC                          │
│                    (WAF + DDoS Protection)                   │
└─────────────────────────┬───────────────────────────────────┘
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                    NGINX / INGRESS                           │
│              TLS Termination + Rate Limit                    │
└─────────────────────────┬───────────────────────────────────┘
                          ▼
        ┌─────────────────┼─────────────────┐
        ▼                 ▼                 ▼
┌───────────────┐ ┌───────────────┐ ┌───────────────┐
│   API (N)     │ │  API (N)      │ │  API (N)      │
│  Scans/Inv    │ │  Graph/Crypto │ │  Compliance   │
│  (Domain Svc) │ │  (Domain Svc) │ │  (Domain Svc) │
└───────┬───────┘ └───────┬───────┘ └───────┬───────┘
        │                 │                 │
        └─────────────────┼─────────────────┘
                          ▼
        ┌─────────────────────────────────────┐
        │      SERVICE MESH (mTLS)            │
        │  Istio / Linkerd / Consul Connect   │
        └─────────────────────────────────────┘
                          │
        ┌─────────────────┼─────────────────┐
        ▼                 ▼                 ▼
┌───────────────┐ ┌───────────────┐ ┌───────────────┐
│ PostgreSQL    │ │ Redis Cluster │ │ Neo4j Cluster │
│ Primary + Rep │ │ Sentinel/Clus │ │ Causal Cluster│
└───────────────┘ └───────────────┘ └───────────────┘
        │                 │                 │
        └─────────────────┼─────────────────┘
                          ▼
        ┌───────────────┐ ┌───────────────┐
        │ Worker (N)    │ │ Monitor (1)   │
│  (Sharded Queues)   │ │ (Leader Elect)│
└───────────────┘ └───────────────┘
```

---

## 11. GO/NO-GO DECISION

### ✅ GO FOR:
- **Single-tenant on-premise** — With manual backup, documented Neo4j limitation
- **Development/Staging** — Current docker-compose is sufficient
- **POC/PoV** — Features demonstrate well

### ❌ NO-GO FOR:
- **Multi-tenant SaaS** — Neo4j shared database, link table gaps
- **High-Availability Requirement** — No HA for DB/Redis/Neo4j
- **Regulated Environment Requiring Encryption at Rest** — Not implemented
- **Large Scale (>100K assets)** — API monolith, in-memory CBOM, full graph sync

### ⚠️ CONDITIONAL GO (with remediation):
- **Single-Tenant Enterprise** — If: secrets managed externally, backup tested, DR documented, network segmented
- **Scale < 50K Assets** — If: API replicas + read replica + incremental graph sync implemented

---

## 12. TIMELINE TO PRODUCTION READY

| Phase | Duration | Focus | Outcome |
|-------|----------|-------|---------|
| **Phase 0** | 2 weeks | Security hardening | Secrets, encryption, mTLS, network policies |
| **Phase 1** | 4 weeks | HA + Multi-tenancy | DB/Redis/Neo4j HA, tenant isolation, link tables |
| **Phase 2** | 4 weeks | Scalability | API decomposition, read replicas, incremental sync |
| **Phase 3** | 2 weeks | Operations | Backup/restore automation, alerting, runbooks |
| **Phase 4** | 2 weeks | Validation | Load test, chaos test, DR drill, penetration test |

**Total: ~14 weeks to production-ready for multi-tenant SaaS**
**Total: ~6 weeks for single-tenant enterprise (Phases 0 + 3 only)**