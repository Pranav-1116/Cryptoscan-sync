# PostgreSQL production qualification — twelve properties, graded

`cryptoscan.postgres-qualification/1` · generated 2026-11-01T02:37:28.357302+00:00 · **5 pass · 2 partial · 2 fail · 4 unproven** · 14 s · server available: no

Each row says what kind of evidence it used: **EXECUTED** (ran here), **READ** (a file or a configuration proves it), **SERVER_REQUIRED** (needs a PostgreSQL server this checkout does not have — the row is `UNPROVEN`, not passed).

| Property | Verdict | Evidence | What was found |
|---|---|---|---|
| **does the migration chain apply, round-trip and land on one head?** | **PASS** | EXECUTED | 127 revisions → ['0127'], upgrade 3.94 s, round-trip 0.15 s |
| **does a migrated database carry every index the models declare?** | **PASS** | EXECUTED | 494 indexes checked, 0 missing |
| **what does the composite-index migration cost on a populated table?** | **PASS** | EXECUTED | 200,000 rows; index build 0.1 s; read 18.7 → 0.3 ms |
| **does a failure inside a multi-step ingest leave a partial estate?** | **PASS** | EXECUTED | 50 assets offered, 0 left after the injected failure |
| **is the engine configured for a bank's connection behaviour?** | **PARTIAL** | EXECUTED | QueuePool size 10 + 20 overflow, pre-ping True |
| **are the write paths that can race protected by a lock or a version check?** | **PASS** | READ | 11 files lock rows, 32 use a version check |
| **would applying the migrations to a live bank stop writes?** | **PARTIAL** | READ | 239 indexes built non-concurrently of 127 migrations |
| **is there anything that stops the observation table growing forever?** | **FAIL** | EXECUTED | no delete path; 1000000 facts = 645.8 MB (guide 114) |
| **is the history table partitioned, or does its size bound every query?** | **FAIL** | READ | no partitioned table in the chain |
| **do two writers on the same asset produce a lost update or a deadlock?** | **UNPROVEN** | SERVER_REQUIRED | server required |
| **can the estate be restored to a point in time, and is it verified?** | **UNPROVEN** | SERVER_REQUIRED | db_backup.sh; db_restore.sh; backup_drill.py; postgres_parity.sh |
| **does the system recover from a corrupted page or a killed writer?** | **UNPROVEN** | SERVER_REQUIRED | controlled_recovery_drill.py; drill_worker_recovery.py |
| **does a standby take over, and what is the measured RPO and RTO?** | **UNPROVEN** | SERVER_REQUIRED | postgres_drill.py; postgres_dr_sandbox.sh; region_drills.py |

## Row by row

### `migration_chain` — PASS (EXECUTED)

*does the migration chain apply, round-trip and land on one head?*

- **Reading:** the chain was applied from empty to head, downgraded two revisions and reapplied — on SQLite, because this checkout has no server
- **Limit:** SQLite's DDL is far more permissive than PostgreSQL's; a chain that passes here can still fail on a server (guide 100 §5b runs it there)
- **Closes with:** ``scripts/run_migrations.sh` against a real PostgreSQL in CI`

```
{
  "revisions": 127,
  "head": [
    "0127"
  ],
  "applied": "0127",
  "after_downgrade": "0125",
  "after_upgrade": "0127",
  "tables_created": 157,
  "upgrade_seconds": 3.94,
  "roundtrip_seconds": 0.15
}
```

### `index_parity` — PASS (EXECUTED)

*does a migrated database carry every index the models declare?*

- **Reading:** a create_all deployment and a migrated one must have the same access paths; drift here is the bug class migration 0078 closed once already
- **Limit:** compared on SQLite's index catalogue, which is what the chain runs against here; expression-based indexes are skipped because SQLite reports their columns as NULL, and PostgreSQL's catalogue can differ in prefix semantics

```
{
  "indexes_checked": 494,
  "missing": [],
  "missing_count": 0,
  "expression_indexes_not_compared": [
    "uq_fact_identity"
  ],
  "tables_compared": 156
}
```

### `migration_at_scale` — PASS (EXECUTED)

*what does the composite-index migration cost on a populated table?*

- **Reading:** migration 0126 adds the index every twin read needs; the drill builds it on a populated table and measures both the build and the read it fixes
- **Limit:** SQLite builds an index in one pass with no concurrent writers; PostgreSQL will be slower and, without CONCURRENTLY, will block writes while it runs
- **Closes with:** `the same measurement on PostgreSQL, with a writer running throughout`

```
{
  "rows": 200000,
  "insert_seconds": 3.0,
  "index_build_seconds": 0.1,
  "read_without_index_ms": 18.7,
  "read_with_index_ms": 0.3,
  "speedup": 62.3
}
```

### `transaction_boundaries` — PASS (EXECUTED)

*does a failure inside a multi-step ingest leave a partial estate?*

- **Reading:** every write path is wrapped so a failure rolls the unit back and reports it in the response instead of leaving a half-materialised catalogue
- **Limit:** measured on SQLite in one session: PostgreSQL adds readers, a pool and lock waits, none of which this proves
- **Closes with:** `the same injection against a real server, with a second connection reading while the first rolls back`

```
{
  "assets_offered": 50,
  "assets_left_after_failure": 0,
  "catalog_error_reported": "RuntimeError: simulated failure inside the catalogue sync",
  "run_row_persisted": true,
  "sync_calls": 1
}
```

### `pooling` — PARTIAL (EXECUTED)

*is the engine configured for a bank's connection behaviour?*

- **Reading:** a bounded pool with overflow, pre-ping on checkout, hourly recycling, a 10 s connect timeout and a 30 s server-side statement timeout are all set on the PostgreSQL engine
- **Limit:** the engine was built from a URL, never connected — so this proves the configuration, not that the server honours it, and no metric yet reports pool saturation (see guide 117)
- **Closes with:** `a load test that saturates the pool and asserts the timeout path`

```
{
  "pool_class": "QueuePool",
  "pool_size": 10,
  "max_overflow": 20,
  "timeout_seconds": 30.0,
  "pre_ping": true,
  "recycle_seconds": 3600,
  "connect_args": {
    "host": "db.bank.example",
    "dbname": "cryptoscan",
    "user": "cryptoscan",
    "password": "secret",
    "port": 5432,
    "sslmode": "verify-full"
  },
  "url_is_normalised": "postgresql+psycopg2"
}
```

### `locking` — PASS (READ)

*are the write paths that can race protected by a lock or a version check?*

- **Reading:** SELECT … FOR UPDATE guards the approval and remediation paths, and the job row uses a version column so a stale worker cannot overwrite a newer state
- **Limit:** found by reading the code: whether these locks are taken in the right order under a real workload, and whether any path can deadlock, is not measured
- **Closes with:** `a concurrent-write drill on two sessions that asserts no deadlock and no lost update`

```
{
  "pessimistic_lock_files": [
    "services/api/api/assurance/collection.py",
    "services/api/api/assurance/host_associations.py",
    "services/api/api/assurance/oci_collection.py",
    "services/api/api/assurance/oci_truth.py",
    "services/api/api/assurance/qualification.py",
    "services/api/api/assurance/remediation.py",
    "services/api/api/assurance/resource_monitoring.py",
    "services/api/api/routers/cbom.py",
    "services/api/api/routers/cbom_legacy.py",
    "services/api/api/routers/cbom_legacy_controlled.py",
    "services/database/db/repositories/system_repository.py"
  ],
  "optimistic_version_files": [
    "services/api/api/assurance/applicability.py",
    "services/api/api/assurance/operator.py",
    "services/api/api/assurance/store.py",
    "services/api/api/estate_lifecycle.py",
    "services/api/api/routers/devsecops.py",
    "services/api/api/routers/digital_twin.py",
    "services/api/api/routers/execution_controls.py",
    "services/api/api/routers/export.py",
    "services/api/api/routers/graph.py",
    "services/api/api/routers/techbom.py",
    "services/api/api/security/network_collection.py",
    "services/api/api/security/scan_admission.py"
  ],
  "pessimistic_count": 11,
  "optimistic_count": 32
}
```

### `migration_lock_safety` — PARTIAL (READ)

*would applying the migrations to a live bank stop writes?*

- **Reading:** most indexes are created inside CREATE TABLE, which takes no lock on live rows; the ones added later to populated tables are built non-concurrently, and a plain CREATE INDEX holds a lock that blocks writes until it finishes
- **Limit:** the lock is only a problem on a populated table — for a fresh deployment every build is instant
- **Closes with:** ``postgresql_concurrently=True` on any index added to a table that is already serving traffic (0126 included, once it runs at bank scale)`

```
{
  "migrations": 127,
  "non_concurrent_index_builds": [
    {
      "revision": "0002",
      "index": "idx_evidence_scan_position"
    },
    {
      "revision": "0002",
      "index": "idx_evidence_algorithm"
    },
    {
      "revision": "0002",
      "index": "idx_evidence_hardcoded_key"
    },
    {
      "revision": "0002",
      "index": "idx_evidence_finding_data_gin"
    },
    {
      "revision": "0003",
      "index": "idx_verification_log_scan_id"
    },
    {
      "revision": "0003",
      "index": "idx_verification_log_scan_verified_at"
    },
    {
      "revision": "0003",
      "index": "idx_verification_log_result"
    },
    {
      "revision": "0004",
      "index": "idx_evidence_normalized_algorithm"
    },
    {
      "revision": "0004",
      "index": "idx_evidence_nist_designation"
    },
    {
      "revision": "0004",
      "index": "idx_evidence_normalization_status"
    },
    {
      "revision": "0004",
      "index": "idx_evidence_requires_review"
    },
    {
      "revision": "0004",
      "index": "idx_evidence_normalized_crypto_gin"
    },
    {
      "revision": "0005",
      "index": "idx_evidence_compliance_status"
    },
    {
      "revision": "0005",
      "index": "idx_evidence_policy_fail"
    },
    {
      "revision": "0005",
      "index": "idx_evidence_policy_evaluation_gin"
    }
  ],
  "non_concurrent_count": 239
}
```

### `retention` — FAIL (EXECUTED)

*is there anything that stops the observation table growing forever?*

- **Reading:** there is no retention or archival path for the twin's history: every changed fact adds a row and nothing removes one, so a bank's disk requirement is a function of how often its estate changes
- **Limit:** measured growth is a single-tenant SQLite run (guide 114); PostgreSQL page layout, TOAST and index bloat will differ
- **Closes with:** `a documented retention policy (per-table window, archive to object storage, verification that history is still answerable after pruning)`

```
{
  "delete_paths": [],
  "retention_scripts": [],
  "tables_in_scope": [
    "estate_observations",
    "estate_evidence",
    "estate_assets"
  ],
  "measured_growth": {
    "assets": 100000,
    "facts": 1000000,
    "database_mb": 645.8,
    "source": "guide 114"
  }
}
```

### `partitioning` — FAIL (READ)

*is the history table partitioned, or does its size bound every query?*

- **Reading:** 125+ migrations create no partitioned table; the twin's history is a single table with a composite tenant+asset index, which is enough for per-asset reads at 1M facts (guide 114) and not enough for pruning by age
- **Limit:** no measurement of write amplification or vacuum cost at 100M rows
- **Closes with:** `range partitioning by observed_at month, with the retention policy dropping partitions instead of deleting rows`

```
{
  "migrations_with_partitions": [],
  "tables": [
    "estate_observations",
    "estate_evidence",
    "scan_runs"
  ]
}
```

### `concurrent_writes` — UNPROVEN (SERVER_REQUIRED)

*do two writers on the same asset produce a lost update or a deadlock?*

- **Reading:** SQLite serialises writers, so a concurrency result here would say nothing about PostgreSQL. The drill that would answer it needs two sessions.
- **Limit:** unmeasured
- **Closes with:** ``DATABASE_URL=postgresql://… python scripts/load_test.py --concurrent-writers 8` with a lost-update assertion on the job version column`

```
{
  "server_available": false
}
```

### `backup_restore` — UNPROVEN (SERVER_REQUIRED)

*can the estate be restored to a point in time, and is it verified?*

- **Reading:** a dump/restore path and a parity check exist as scripts; neither was run here because there is no server to dump
- **Limit:** the scripts are unexecuted in this checkout
- **Closes with:** ``scripts/db_backup.sh && scripts/db_restore.sh && scripts/postgres_parity.sh` against the deployment database, with the row counts archived`

```
{
  "scripts_present": [
    "db_backup.sh",
    "db_restore.sh",
    "backup_drill.py",
    "postgres_parity.sh"
  ]
}
```

### `corruption_recovery` — UNPROVEN (SERVER_REQUIRED)

*does the system recover from a corrupted page or a killed writer?*

- **Reading:** recovery drills exist and require a disposable database to destroy
- **Limit:** unmeasured
- **Closes with:** ``scripts/controlled_recovery_drill.py` against a scratch server, asserting the evidence chain still verifies afterwards`

```
{
  "scripts_present": [
    "controlled_recovery_drill.py",
    "drill_worker_recovery.py"
  ]
}
```

### `ha_failover` — UNPROVEN (SERVER_REQUIRED)

*does a standby take over, and what is the measured RPO and RTO?*

- **Reading:** the failover drill requires two servers, a replication link and an operator-supplied promotion command; it refuses to run without them
- **Limit:** RPO and RTO are unmeasured here
- **Closes with:** ``scripts/postgres_drill.py --execute-promotion --acknowledge-destructive` against the bank's pair`

```
{
  "scripts_present": [
    "postgres_drill.py",
    "postgres_dr_sandbox.sh",
    "region_drills.py"
  ]
}
```

## What this does not prove

- There is no PostgreSQL server in this checkout. Four rows are therefore UNPROVEN by construction, and the executed rows ran on SQLite — same schema, same migrations, different engine.
- SQLite does not enforce the same DDL, locking or isolation rules; a PASS here is evidence the application asks for the right thing, not that the server agrees.
- No row measures write amplification, vacuum or index bloat, which are what actually decide a bank's database cost.

**The verdict this drill supports:** the migration chain, its indexes, the transaction boundaries, the pool configuration and the locking story are in place and measured. **Retention and partitioning are absent**, and four properties — concurrent writes, backup/restore, corruption recovery and HA — need a server that this checkout does not have. Those are the rows a bank should not accept as done.
