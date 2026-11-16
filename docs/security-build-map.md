# Security essentials — spec row → build → verify

The CryptoScan-specific essentials table (13 rows, RBAC → security
monitoring) mapped to where each row is BUILT and how to PROVE it. Every
verify command below is a real entry point — run them from the repo root
with the suite's PYTHONPATH (`scripts/certify.sh` runs the same suites in
one command). Rows land at the build-fact bar: a row without a verify
command is a claim, not a control.

| # | Spec row | Built in | Verify with |
|---|----------|----------|-------------|
| 1 | RBAC | `api/dependencies.py` (get_current_user / require_auditor), route-level auth on all 1549 decorated routes, `config/102-authenticated-only-writes.json` (writes to ANY authenticated principal are deliberately not role-gated), frontend role checks | `pytest services/api/tests/security/test_route_auth_inventory.py`; engineering gate "X-API-Key route coverage" + "frontend direct-role authorization" |
| 2 | Tenant isolation | `db/tenancy.py` (TenantScoped/TenantOwned, `tenant_scope`, `filtered_get`, before_flush immutability guard), RLS migrations 0156/0161 (partitions included), per-tenant cache keys (`api/cache.py`) | `python3 scripts/tenant_isolation_audit.py` (gate: "tenant isolation audit"); `pytest services/api/tests/security/test_cross_tenant_adversarial.py services/api/tests/security/test_cross_tenant_scan_surface.py services/api/tests/unit/test_tenant_isolation_os_intelligence.py` |
| 3 | Secrets management | `api/security/vault.py` (vault:// file: env: resolution at boot, `ResolutionLog`, `ROTATION_POLICY` staleness windows), `GET /security/secrets/status`, durable watch (`vault_resolution_records`, migration 0163) | `pytest services/api/tests/unit/test_vault_staleness.py services/api/tests/unit/test_security_state_durable.py` |
| 4 | Encryption at rest + in transit | CAS typed `ciphertext` + `db/encryption.py` envelope encryption; mTLS at both edges (`deploy/ha/nginx.conf` `ssl_verify_client on`, `deploy/stack/envoy/envoy.yaml` `require_client_certificate: true`), TLS1.3 | `pytest services/database/tests/test_db_encryption.py services/api/tests/unit/test_backup_encryption.py services/api/tests/security/test_infrastructure_contracts.py services/api/tests/unit/test_mtls_rotation_drill.py`; `python3 scripts/mtls_rotation_drill.py` |
| 5 | Append-only audit | cryptolog hash chain (`db/models/cryptolog.py` — record_hash/prev_hash chain, corrections never overwrite), `scripts/audit_verify.py` + `cryptoscan-audit-verify.timer` (daily; FAILED unit = alert) | `pytest services/api/tests/unit/test_audit_chain.py services/database/tests/test_cryptolog_migration.py services/database/tests/test_partition_cryptolog_events.py` |
| 6 | Evidence hashing | `evidence/hashing/content_hasher.py` + `chain_hasher.py` (first link sha256(content_hash+scan_session_id), later sha256(content_hash+previous_hash)), CAS `get()` re-verifies, `GET /findings/{id}/verify` (PASS/FAIL — explicitly not a claim the observation was true) | `pytest services/api/tests/unit/test_finding_provenance_bundle.py services/api/tests/unit/test_evidence_chain_checkpoint.py` |
| 7 | Data provenance | validated sidecars (`db/loader/provenance.py` — scanner ids + fixed integrity descriptor ONLY), collector authority (`db/models/collector_authority.py` + `db/loader/collector_stamp.py` — the collection names its authority, migration 0164), `GET /api/v1/findings/{id}/provenance` (`integrity.claim=HASH_INTEGRITY_ONLY`, `truth.status=NOT_INDEPENDENTLY_VERIFIED`) | `pytest services/api/tests/unit/test_finding_provenance_bundle.py services/database/tests/test_collection_authority_stamp_0164.py services/api/tests/unit/test_collector_authority.py` |
| 8 | Idempotent processing | CAS content store, deterministic event ids (one hash per event), idempotent catalogue sync, target scan locks (migration 0159), durable queue `complete`/`fail` CAS from CLAIMED only | `pytest services/api/tests/unit/test_fault_isolation_contract.py services/api/tests/unit/test_realtime_durable_events.py services/api/tests/unit/test_queue_authority_contract.py services/worker/tests/unit/test_target_locks.py` |
| 9 | Backup + PITR | `deploy/ha/pg-primary/postgresql.conf` (wal_level=replica, archive_mode=on), `scripts/db_backup.sh` + `cryptoscan-backup.timer`, `restore-drill.sh` replays to `recovery_target_time`, `cryptoscan-restore-drill.timer` (weekly; the only backup that counts is one that has restored) | `pytest services/api/tests/unit/test_backup_encryption.py`; `python3 scripts/backup_drill.py --record-evidence` |
| 10 | Disaster recovery | `docs/runbooks/dr-recovery.md`, `deploy/ha/` (nginx pair + pg primary/replica), region drills, `docs/runbooks/operator-install-upgrade-recover.md` | `pytest services/api/tests/unit/test_ha_readiness.py services/api/tests/security/test_infrastructure_contracts.py` |
| 11 | Resource quotas | k8s namespace quota (`deploy/`), `db/models/storage_policy.py` (StorageQuota), queue backpressure + bounded monitors (auth window MAX_PER_KEY/MAX_KEYS), bounded subgraph expansion | `pytest services/api/tests/security/test_infrastructure_contracts.py services/api/tests/unit/test_resilience_storage.py services/api/tests/unit/test_auth_monitor.py` |
| 12 | Retention | storage lifecycle + enforcement (`db/models/storage_policy.py`, `services/database/tests/test_retention_enforce.py`, storage optimization migration 0160), declared-chain truncation (`truncated_before_seq` — a dropped window is declared, never mistaken for a complete chain) | `pytest services/database/tests/test_retention_enforce.py services/database/tests/test_storage_optimization.py services/api/tests/unit/test_storage_api.py` |
| 13 | Security monitoring | rate limiter (`api/middleware/rate_limit.py`, cluster-window), suspicious-access watch (`api/security/auth_monitor.py` — ≥5 failures/(user,source)/5min, bounded, durable since 0163), `GET /security/auth-monitor` + gauges, exception inventory (`config/exception-allowlist.json`) + engineering gate | `pytest services/api/tests/unit/test_auth_monitor.py services/api/tests/unit/test_rate_limit.py services/api/tests/security/test_engineering_exception_inventory.py`; `python3 scripts/engineering_gate.py` |

## The two worked examples the spec pins

* **Hash integrity is not truth** (the RSA-2048 example): proven end to
  end by `GET /api/v1/findings/{id}/provenance` + its tests — every
  question the example names is answered from build data, the claim is
  capped in the schema itself, and broken links report `CHAIN_LINK_BROKEN`.
* **Fault isolation** (the HSM-collector example): seven named tests in
  `services/api/tests/unit/test_fault_isolation_contract.py` — failed
  runs marked, evidence preserved, reasons recorded, only named
  transients retried, stale verdicts refused, others keep running,
  `PARTIAL_COVERAGE`/`DEGRADED` named.

## What this map is not

It maps controls to build and proof — it does not restate the spec, and
it is not a claim that any observation is true. Where a row's proof is a
runbook (backup, DR, mTLS rotation), the drill/verify command beside it
is the executable form.
