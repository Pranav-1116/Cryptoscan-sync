# 04_DATABASE_AUDIT.md
## ZELNX CryptoScan — Database Deep Audit

**Generated:** 2026-09-20  
**Method:** Schema inspection via migration files (71) and model definitions (52)  
**Scope:** PostgreSQL 15 (production), SQLite (test) — no modifications

---

## 1. SCHEMA INVENTORY (52 Tables)

### Core Scan & Evidence (6 tables)
| Table | Model | Purpose | Rows (est.) |
|-------|-------|---------|-------------|
| `scans` | `Scan` | Scan sessions (git, local, cloud) | 10K-100K |
| `evidence_records` | `EvidenceRecord` | Tamper-evident findings | 1M-10M |
| `verification_log` | `VerificationLog` | Chain verification audit | 10K-100K |
| `scan_jobs` | `ScanJob` | Queued/running scan jobs | 10K-100K |
| `repo_configurations` | `RepoConfiguration` | Git repo scan configs | 1K-10K |
| `baselines` | `Baseline` | Approved scan snapshots for drift | 1K-10K |

### Crypto Inventory (6 tables)
| Table | Model | Purpose |
|-------|-------|---------|
| `crypto_assets` | `CryptoAsset` | Deduplicated cryptographic assets |
| `crypto_asset_evidence` | `CryptoAssetEvidence` | Asset ↔ EvidenceRecord links |
| `crypto_library_fingerprints` | `CryptoLibraryFingerprint` | Library identity from binary/source |
| `crypto_live` | `CryptoLive` | Live crypto engine state (separate pipeline) |
| `cascade_run` | `CascadeRun` | Scanner cascade analysis runs |
| `cascade_extensions` | `CascadeExtensions` | Hardware links, vendor edges |

### Drift & Compliance (4 tables)
| Table | Model | Purpose |
|-------|-------|---------|
| `drift_events` | `DriftEvent` | Drift detections with resolution workflow |
| `gate_evaluations` | `GateEvaluation` | CI/CD policy gate results |
| `policy_exceptions` | `PolicyException` | Approved policy deviations |
| `compliance` | (router only) | No dedicated table — uses evidence_records.policy_evaluation |

### Systems & Graph (9 tables)
| Table | Model | Purpose |
|-------|-------|---------|
| `systems` | `System` | Business systems with ownership |
| `system_assets` | `SystemAsset` | System ↔ CryptoAsset links |
| `system_dependencies` | `SystemDependency` | System → System edges (CALLS, IMPORTS) |
| `system_business_process` | `SystemBusinessProcess` | System ↔ BusinessProcess links |
| `system_business_process_map` | `SystemBusinessProcessMap` | Process mapping |
| `system_agility_score` | `SystemAgilityScore` | Agility scoring history |
| `graph_snapshots` | `GraphSnapshot` | Content-addressed graph versions |
| `migration_project` | `MigrationProject` | PQC migration projects |
| `migration_task` | (in `intelligence_repository`) | Per-asset migration tasks |

### Network & Cloud (6 tables)
| Table | Model | Purpose |
|-------|-------|---------|
| `network_inventory` | `NetworkInventory` | Discovered network assets |
| `network_scan_runs` | `NetworkScanRun` | TLS probe runs with results |
| `network_scan_targets` | `NetworkScanTarget` | Configured scan targets |
| `cloud_accounts` | `CloudAccount` | Cloud credential configurations |
| `container_scans` | `ContainerScan` | Container image scan results |
| `vulnerabilities` | `Vulnerability` | CVE matches from container/cloud |

### Certificates & Hardware (5 tables)
| Table | Model | Purpose |
|-------|-------|---------|
| `certificates` | `Certificate` | X.509 certificate inventory |
| `certificate_usage` | `CertificateUsage` | Certificate ↔ System links |
| `hardware_live` | `HardwareLive` | HSM/TPM live inventory |
| `certificate_renewal` | `CertificateRenewal` | Renewal tracking |
| `transaction_volume` | `TransactionVolume` | Payment crypto volume |

### Identity & Access (7 tables)
| Table | Model | Purpose |
|-------|-------|---------|
| `users` | `User` | Platform users |
| `user_sessions` | `UserSession` | Active sessions |
| `audit_log` | `AuditLog` | Tamper-evident audit trail |
| `tenants` | `Tenant` | Tenant definitions |
| `api_keys` | `APIKey` | Service API keys |
| `access_reviews` | `AccessReview` | Access review records |
| `vendor_profiles` | `VendorProfile` | Vendor due diligence |

### Specialized (11 tables)
| Table | Model | Purpose |
|-------|-------|---------|
| `ot_devices` | `OTDevice` | OT/ICS device inventory |
| `ot_maintenance` | `OTMaintenance` | Maintenance windows |
| `payment_crypto` | `PaymentCrypto` | Payment HSM/key ceremonies |
| `credential_leases` | `CredentialLease` | Vault lease tracking |
| `technology_bom_snapshots` | `TechnologyBomSnapshot` | TechBOM versions |
| `technology_bom_exports` | `TechnologyBomExport` | Export records |
| `pentest_findings` | `PentestFinding` | Penetration test results |
| `report_snapshots` | `ReportSnapshot` | Generated report versions |
| `report_schedules` | `ReportSchedule` | Scheduled report generation |
| `monitor_targets` | `MonitorTarget` | Monitor watch-list |
| `monitor_events_realtime` | `MonitorEventRealtime` | Real-time monitor events |

---

## 2. MIGRATION HISTORY (71 Migrations)

### Key Migrations by Category

**Foundation (0001-0011):**
- 0001: `scans` table
- 0002: `evidence_records` with chain hash indexes
- 0003: `verification_log`
- 0004: `normalized_crypto` JSON column on evidence_records
- 0005: `policy_evaluation` JSON column
- 0006: `baselines`
- 0007: `drift_events`
- 0008: `scan_jobs`
- 0009: `repo_configurations`
- 0010: `crypto_assets`
- 0011: `crypto_asset_evidence`

**Systems & Graph (0012-0014, 0054, 0055, 0056, 0069, 0070, 0071):**
- 0012-0014: `systems`, `system_assets`, `system_dependencies`
- 0054: `graph_snapshots`
- 0055: `technology_bom_snapshots`
- 0056: `technology_bom_exports`
- 0069: `cascade_runs`
- 0070: `cascade_extensions`
- 0071: `scan_target_provenance` + tenant-scoped graph snapshots

**Intelligence & Maturity (0017, 0018):**
- 0017: Part 3 intelligence (vendor, sector, etc.)
- 0018: Part 4 maturity (agility, readiness, migration)

**Identity & Auth (0019, 0022, 0035, 0039, 0046, 0047, 0052, 0057, 0058):**
- 0019: `users`, `user_sessions`, `audit_log`
- 0022: MFA columns
- 0035: `api_keys`
- 0039: User soft delete
- 0046: P2 marketplace/datalake/anomaly/governance
- 0047: API key platform
- 0052: API key allowlist rotation
- 0057: SaaS tenancy core
- 0058: Access review records

**Network & Cloud (0021, 0068):**
- 0021: `network_scan_runs`
- 0068: `network_inventory_revisions`

**Containers & Binary (0015, 0016, 0063):**
- 0015: `container_scans`
- 0016: `vulnerabilities`
- 0063: `binary_scan_index`

**Payment & Crypto Live (0030, 0036, 0037, 0038, 0066, 0067):**
- 0030: Payment crypto
- 0036: Hardware live
- 0037: Crypto live
- 0038: Monitor events realtime
- 0066: Vendor due diligence profiles
- 0067: Vendor profile audit actor

**Other:**
- 0020: Runtime findings
- 0023: Gate evaluations
- 0024: Migration tracking
- 0025: Audit chain
- 0026: Query indexes
- 0027: Report schedules
- 0028: Monitor targets
- 0029: Reconcile models
- 0031: Monitor lease
- 0032: Transaction volume
- 0033: Ceremony status
- 0034: Certificate renewal
- 0040: App settings
- 0041-0042: Onboarding
- 0043: Control plane
- 0044: Enterprise
- 0045: Delivery logs
- 0048: OT maintenance
- 0049: Credential leases
- 0050: Automation
- 0051: CBOM versions
- 0053: Security posture
- 0059: Pentest findings
- 0060: UUID columns to VARCHAR(36)
- 0061-0062: Tenant scope remaining tables
- 0064: Tenant scope control plane history
- 0065: Tenant local control plane asset identity

---

## 3. INDEX ANALYSIS

### Explicit Indexes (from migrations)

**evidence_records (0002):**
- `ix_evidence_scan_chain` ON (scan_id, chain_position)
- `ix_evidence_scan_status` ON (scan_id, compliance_status)

**evidence_records (0004 - added normalized_crypto):**
- No GIN index on `normalized_crypto` JSONB — **MISSING**

**crypto_assets (0010):**
- `ix_assets_algorithm_file` ON (algorithm, file_path)

**scans (implied by FK):**
- `scan_id` FK index on evidence_records, verification_log, drift_events

**system_dependencies:**
- No explicit index on (parent_id, child_id) — **MISSING**

**graph_snapshots (0054):**
- Primary key on `version` (tenant-scoped in 0071)
- No index on `fingerprint` — **MISSING** for dedup check

**audit_log (0019):**
- No index on (actor, action, target_type, target_id) — **MISSING**

**crypto_live (0037):**
- No indexes defined in migration — **MISSING**

### Implicit Indexes (FK, PK)
All FK columns have implicit indexes via SQLAlchemy `ForeignKey(index=True)`

---

## 4. FOREIGN KEY RELATIONSHIPS

### Strong Relationships (enforced)
| Child Table | Parent Table | Column | OnDelete |
|-------------|--------------|--------|----------|
| `evidence_records` | `scans` | scan_id | CASCADE |
| `verification_log` | `scans` | scan_id | CASCADE |
| `crypto_asset_evidence` | `crypto_assets` | asset_id | CASCADE |
| `crypto_asset_evidence` | `evidence_records` | evidence_id | CASCADE |
| `system_assets` | `systems` | system_id | CASCADE |
| `system_assets` | `crypto_assets` | asset_id | CASCADE |
| `system_dependencies` | `systems` | parent_id | CASCADE |
| `system_dependencies` | `systems` | child_id | CASCADE |
| `network_scan_runs` | `network_scan_targets` | target_id | CASCADE |
| `container_scans` | `cloud_accounts` | account_id | SET NULL |

### Weak/Missing Relationships
| Relationship | Issue |
|--------------|-------|
| `system_business_process` → `systems` | No FK defined in migration 0018 |
| `system_business_process` → `business_process` | No FK; business_process table missing |
| `graph_snapshots` → `tenants` | Tenant scoping added in 0071 but no FK |
| `cascade_extensions` → `crypto_assets` | Hardware link uses asset_id but no FK |
| `cascade_extensions` → `hardware_live` | Hardware link uses hardware_asset_id but no FK |
| `vendor_dependency` → `vendors` | No FK in cascade_extensions |

---

## 5. CONSTRAINTS & UNIQUENESS

### Unique Constraints (Explicit)
| Table | Constraint | Columns |
|-------|------------|---------|
| `scans` | PK | id |
| `evidence_records` | PK | id |
| `crypto_assets` | PK | id |
| `systems` | PK | id |
| `users` | PK | id |
| `users` | UNIQUE | email (per tenant?) — **UNCLEAR** |
| `tenants` | PK | id |
| `api_keys` | UNIQUE | key_hash |
| `baselines` | UNIQUE | scan_id (one baseline per scan) |

### Missing Unique Constraints
| Table | Columns | Reason |
|-------|---------|--------|
| `crypto_assets` | (scan_id, file_path, algorithm, line_number) | Prevent duplicate assets from same scan |
| `system_dependencies` | (parent_id, child_id, relation) | Prevent duplicate edges |
| `evidence_records` | (scan_id, content_hash) | Prevent duplicate evidence — **BUT would break chain** |
| `baselines` | (system_id, scan_id) | One baseline per system per scan |
| `graph_snapshots` | fingerprint | Content-addressed uniqueness |

---

## 6. TIMESTAMPS & AUDIT FIELDS

### Standard Pattern (BaseModel)
```python
# db/models/base.py:BaseModel
id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid.uuid4)
created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
```

### Coverage
| Table | created_at | updated_at | Custom Timestamps |
|-------|------------|------------|-------------------|
| `scans` | ✅ | ✅ | scan_start, scan_end |
| `evidence_records` | ✅ | ✅ | — |
| `crypto_assets` | ✅ | ✅ | — |
| `systems` | ✅ | ✅ | — |
| `drift_events` | ✅ | ✅ | detected_at |
| `verification_log` | ✅ | ❌ | verified_at |
| `audit_log` | ✅ | ❌ | — |
| `baselines` | ✅ | ✅ | approved_at |
| `scan_jobs` | ✅ | ✅ | started_at, completed_at |

---

## 7. TENANT ISOLATION AUDIT

### Implementation
```python
# db/tenancy.py
class TenantScoped:
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)

def current_tenant() -> str:
    return getattr(_tenant_ctx.get(), "tenant_id", "default")

def filtered_get(db, model, id):
    return db.query(model).filter(model.id == id, model.tenant_id == current_tenant()).first()
```

### Models with TenantScoped (32/52 = 62%)
| Has TenantScoped | Missing TenantScoped |
|------------------|---------------------|
| Scan, EvidenceRecord, VerificationLog | CryptoAssetEvidence (link table) |
| Baseline, DriftEvent, ScanJob | SystemAsset (link table) |
| RepoConfiguration, CryptoAsset | SystemDependency |
| CryptoLibraryFingerprint, CryptoLive | CertificateUsage |
| CascadeRun, CascadeExtensions | NetworkInventory |
| System, SystemAgilityScore | Vulnerability |
| OTDevice, OTMaintenance | TechnologyBomSnapshot |
| PaymentCrypto, CredentialLease | TechnologyBomExport |
| User, UserSession, AuditLog | ReportSnapshot |
| Tenant, APIKey, AccessReview | ReportSchedule |
| VendorProfile, VendorCrypto | MonitorTarget |
| GraphSnapshot | MonitorEventRealtime |
| MigrationProject | — |

**Critical Gap:** Link tables (`SystemAsset`, `SystemDependency`, `CertificateUsage`, `CryptoAssetEvidence`) lack tenant_id — isolation relies on parent entity checks only.

---

## 8. DATA INTEGRITY RISKS

| Risk | Location | Severity | Evidence |
|------|----------|----------|----------|
| **Chain break on evidence delete** | `evidence_records` | P0 | CASCADE delete from scan breaks chain_hash continuity; no soft delete |
| **No evidence dedup constraint** | `evidence_records` | P1 | Content hash dedup in pipeline only; race condition possible |
| **Graph snapshot tenant bypass** | `graph_snapshot.py:190` | P1 | Explicit `tenant_id` filter but `graph_from_db()` doesn't filter |
| **Neo4j no tenant isolation** | Graph backend | P0 | All tenants share single Neo4j database |
| **Duplicate system edges** | `system_dependencies` | P2 | No unique constraint on (parent, child, relation) |
| **ScanJob status race** | `scan_jobs` | P2 | Worker updates status; no optimistic locking |
| **Baseline drift detection gap** | `baselines` + `scans` | P2 | No automated comparison trigger; manual API only |
| **CBOM version collision** | `technology_bom_snapshots` | P2 | Version per system but no unique constraint |

---

## 9. SCALABILITY PROBLEMS

| Problem | Table | Current Design | Risk at Scale |
|---------|-------|----------------|---------------|
| **Evidence records unbounded** | `evidence_records` | Single table, no partitioning | 10M+ rows → slow scans, chain verification |
| **No read replicas** | All | Single PostgreSQL primary | Analytics queries block writes |
| **Graph sync full reload** | `graph_snapshots` + Neo4j | `sync_graph()` loads all systems/assets/edges | O(N) per sync; blocks API |
| **CBOM portfolio in-memory** | `cbom.py:_located_assets()` | Loads ALL assets for estate CBOM | OOM at 100K+ assets |
| **Audit log no retention** | `audit_log` | No partition, no archive | Unbounded growth |
| **Verification log no partition** | `verification_log` | Single table | Chain verification scans full table |

---

## 10. RACE CONDITIONS

| Scenario | Tables | Window | Mitigation |
|----------|--------|--------|------------|
| **Concurrent scan ingest** | `scans`, `evidence_records`, `crypto_assets` | Scan finalize | `Scan.mark_completed()` not atomic with asset replace |
| **Baseline approval** | `baselines`, `scans` | Baseline creation | No lock; two approvals could create conflicting baselines |
| **Graph snapshot** | `graph_snapshots` | Snapshot creation | Fingerprint check + insert not atomic; duplicate versions possible |
| **Drift acknowledgment** | `drift_events` | Ack/resolve | `repo.acknowledge()` uses UPDATE; lost updates possible |
| **API key rotation** | `api_keys` | Rotation | `allowlist` rotation not atomic with validation |

---

## 11. RETENTION PROBLEMS

| Table | Retention Policy | Implementation |
|-------|------------------|----------------|
| `evidence_records` | None | Never deleted; chain integrity requires retention |
| `verification_log` | None | Never deleted |
| `audit_log` | None | Never deleted |
| `scan_jobs` | None | Completed/failed jobs retained forever |
| `monitor_events_realtime` | None | High-volume; no TTL |
| `graph_snapshots` | Implicit (all versions kept) | Content-addressed; no pruning |
| `technology_bom_snapshots` | None | All versions kept |
| `crypto_live` | Implicit (upsert) | Only latest state per asset |

**Missing:** `scripts/backup_evidence.py` exists but no automated retention/archival.

---

## 12. MIGRATION QUALITY

### Good Practices Observed
- ✅ `transaction_per_migration=True` in alembic env
- ✅ `compare_type=True`, `compare_server_default=True`
- ✅ `disable_existing_loggers=False` preserves app logging
- ✅ Explicit `ondelete="CASCADE"` on FKs
- ✅ UUID as VARCHAR(36) (migration 0060) — consistent

### Migration Gaps
- ❌ No data migrations for schema changes (e.g., 0004 added `normalized_crypto` but no backfill)
- ❌ No rollback testing in CI (only up migration tested)
- ❌ Migration 0060 (UUID→VARCHAR) risky — no validation of existing data
- ❌ Tenant scoping added retroactively (0061, 0062, 0064, 0065) — existing data may lack tenant_id

---

## 13. RECOMMENDATIONS

### P0 — Critical
1. **Add GIN index** on `evidence_records.normalized_crypto` for policy queries
2. **Fix link table tenant isolation** — add `tenant_id` to `SystemAsset`, `SystemDependency`, `CertificateUsage`, `CryptoAssetEvidence`
3. **Neo4j tenant isolation** — separate databases per tenant or document single-tenant limitation

### P1 — High
4. **Partition `evidence_records`** by `scan_id` or time (monthly)
5. **Add unique constraint** on `system_dependencies(parent_id, child_id, relation)`
6. **Implement optimistic locking** on `ScanJob` status updates (`version` column)
7. **Add `fingerprint` index** on `graph_snapshots`

### P2 — Medium
8. **Archive strategy** for `audit_log`, `verification_log`, `scan_jobs`
9. **Read replica routing** for analytics endpoints (`/cbom/portfolio`, `/graph/stats`, `/stats/summary`)
10. **Data migration** for tenant_id backfill on pre-0061 data
11. **CBOM portfolio streaming** — avoid loading all assets in memory

### P3 — Enhancement
12. **Materialized views** for common aggregations (coverage, algorithm counts)
13. **Soft delete** for evidence_records (mark deleted, preserve chain)
14. **Migration test suite** — up/down + data validation in CI
---

## UPDATE — round 16 verification + build (2026-10-09)

Migration 0074 (`0074_queue_lock_policy_overrides`) ships what was still
real; the rest of the report's index/migration asks were verified against
the models and found already covered:

| Ask | Verdict |
|---|---|
| unique (parent_id, child_id, relation) on system_dependencies | 🟡 Evaluated, deliberately NOT taken: the codebase dedups by pair (`SystemRepository.add_dependency` upserts on (parent, child)); a relation-level constraint would allow duplicate CALLS/IMPORTS edges per pair and double edges in the graph. Current `uq_system_dep` is the stronger, correct invariant |
| graph_snapshots fingerprint index | 🕰 Stale — `version` and `fingerprint` are both `index=True` on the model |
| audit_log (actor/action/target) index | 🕰 Stale — actor, action, target_id, chain_sequence, entry_hash all carry `index=True` |
| crypto_live indexes | 🕰 Stale — `asset_id` unique+indexed on state; `event_type`, `asset_id`, `observed_at` indexed on events |
| GIN on evidence_records.normalized_crypto | ❌ Not taken: the column is plain `JSON` (not JSONB) for SQLite parity, is a single object per row (not an array), and no query path filters on it — a GIN expression index would be speculative |
| **ScanJob optimistic locking** | 🔧 **BUILT** — `scan_jobs.version` (migration 0074) + compare-and-set `JobRepository.update_status` with a terminal-state guard: a stale worker finishing a job the reaper already failed is a detected conflict (first verdict stands); the reaper counts only races it won |
| New tables | 🔧 **BUILT** — `policy_rule_overrides` (tenant-scoped, unique per rule; see audit 05) and `remediation_tasks.source`/`source_ref` (drift auto-link provenance; see audit 03) |
| Partitioning / replicas | 🟡 Deployment-scoped, unchanged |
