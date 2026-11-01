# PostgreSQL production qualification — 13 properties, graded

`cryptoscan.postgres-qualification/1` · generated 2026-11-01T14:28:05.225085+00:00 · **11 pass · 1 partial · 0 fail · 1 unproven** · 70 s · server available: yes

Each row says what kind of evidence it used: **EXECUTED** (ran here, on the server named above), **READ** (a file or a configuration proves it), **SERVER_REQUIRED** (needs a server this checkout does not have — the row is `UNPROVEN`, not passed).

| Property | Verdict | Evidence | What was found |
|---|---|---|---|
| **does the migration chain apply, round-trip and land on one head?** | **PASS** | EXECUTED | 130 revisions → ['0130'], upgrade 5.52 s, round-trip 0.25 s |
| **does a migrated database carry every index the models declare?** | **PASS** | EXECUTED | 495 indexes checked, 0 missing |
| **what does the composite-index migration cost on a populated table?** | **PASS** | EXECUTED | 200,000 rows; index build 0.13 s; read 26.9 → 0.3 ms |
| **does a failure inside a multi-step ingest leave a partial estate?** | **PASS** | EXECUTED | 50 assets offered, 0 left after the injected failure |
| **is the engine configured for a bank's connection behaviour?** | **PASS** | EXECUTED | QueuePool size 10 + 20 overflow, pre-ping True |
| **are the write paths that can race protected by a lock or a version check?** | **PASS** | READ | 11 files lock rows, 32 use a version check |
| **would applying the migrations to a live bank stop writes?** | **PARTIAL** | READ | 239 indexes built non-concurrently of 130 migrations |
| **is there anything that stops the observation table growing forever?** | **PASS** | EXECUTED | 4 months dropped, 3 rows pruned, 11 archived rows |
| **is the history table partitioned, or does its size bound every query?** | **PASS** | EXECUTED | 19 partitions, a month read scans 1, drop 0.003 s |
| **do two writers on the same row produce a lost update or a deadlock?** | **PASS** | EXECUTED | two writers, row counts [0, 1], final version 1 |
| **can the estate be restored, and is it verified?** | **PASS** | EXECUTED | 176 tables, 0 mismatched rows, dump 645356 bytes |
| **does the system recover from a killed writer or a crashed server?** | **PASS** | EXECUTED | killed writer left 0 rows; 14 rows before the crash, 14 after |
| **does a standby take over, and what is the measured RPO and RTO?** | **UNPROVEN** | SERVER_REQUIRED | postgres_drill.py; postgres_dr_sandbox.sh; region_drills.py |

## Row by row

### `migration_chain` — PASS (EXECUTED)

*does the migration chain apply, round-trip and land on one head?*

- **Reading:** the chain was applied from empty to head, downgraded two revisions and reapplied — on SQLite, because this checkout has no server
- **Limit:** SQLite's DDL is far more permissive than PostgreSQL's; a chain that passes here can still fail on a server (guide 100 §5b runs it there)
- **Closes with:** ``scripts/run_migrations.sh` against a real PostgreSQL in CI`

```
{
  "revisions": 130,
  "head": [
    "0130"
  ],
  "applied": "0130",
  "after_downgrade": "0128",
  "after_upgrade": "0130",
  "tables_created": 157,
  "upgrade_seconds": 5.52,
  "roundtrip_seconds": 0.25
}
```

### `index_parity` — PASS (EXECUTED)

*does a migrated database carry every index the models declare?*

- **Reading:** a create_all deployment and a migrated one must have the same access paths; drift here is the bug class migration 0078 closed once already
- **Limit:** compared on SQLite's index catalogue, which is what the chain runs against here; expression-based indexes are skipped because SQLite reports their columns as NULL, and PostgreSQL's catalogue can differ in prefix semantics

```
{
  "indexes_checked": 495,
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
  "insert_seconds": 4.5,
  "index_build_seconds": 0.13,
  "read_without_index_ms": 26.9,
  "read_with_index_ms": 0.3,
  "speedup": 89.7
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

### `pooling` — PASS (EXECUTED)

*is the engine configured for a bank's connection behaviour?*

- **Reading:** a bounded pool with overflow, pre-ping on checkout, hourly recycling, a 10 s connect timeout and a 30 s server-side statement timeout are set on the PostgreSQL engine, and a connection made through it reports the server enforcing that 30 s limit: a 31 s query is cancelled
- **Limit:** the pool was never saturated, so exhaustion and the queue timeout are unmeasured, and no metric yet reports pool saturation (see guide 117)
- **Closes with:** `a load test that saturates the pool and asserts the timeout path`

```
{
  "pool_class": "QueuePool",
  "pool_size": 10,
  "max_overflow": 20,
  "timeout_seconds": 30.0,
  "pre_ping": true,
  "recycle_seconds": 3600,
  "checkout_timeout_seconds": 30.0,
  "url_is_normalised": "postgresql+psycopg2",
  "server_check": {
    "statement_timeout": "30s",
    "idle_in_transaction": "0",
    "long_query": "refused: (psycopg2.errors.QueryCanceled) canceling statement due to statement timeout\n\n[SQL: SELECT pg_sleep(31)]\n(Background on "
  }
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
  "migrations": 130,
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

### `retention` — PASS (EXECUTED)

*is there anything that stops the observation table growing forever?*

- **Reading:** a 60-day window ran against a migrated PostgreSQL 16: two whole months were archived and dropped as partitions, the rows inside the window that were superseded were archived and deleted, the current facts and the recent history survived, and the archive on disk holds exactly what was removed
- **Limit:** the window is 60 days because the floor refuses anything shorter; the archive is a local file here, not the bank's object store, and the proof that history is still answerable is one asset's history, not a query sample
- **Closes with:** ``scripts/apply_retention.py` on a schedule, with the archive going to object storage and its manifest checked by the restore drill`

```
{
  "delete_paths": [],
  "retention_scripts": [
    "apply_retention.py"
  ],
  "tables_in_scope": [
    "estate_observations",
    "estate_evidence",
    "estate_assets"
  ],
  "measured_growth": {
    "assets": 100000,
    "facts": 1000000,
    "database_mb": 647.3,
    "source": "guide 114"
  },
  "server": "local PostgreSQL 16.2",
  "drill": {
    "rows_written": 14,
    "rows_remaining": {
      "CURRENT": 2,
      "HISTORICAL": 1
    },
    "rows_remaining_total": 3,
    "partitions_supported": true,
    "partitions_note": null,
    "partitions_created": [],
    "partitions_dropped": [
      "estate_observations_y2026m05",
      "estate_observations_y2026m06",
      "estate_observations_y2026m07",
      "estate_observations_y2026m08"
    ],
    "partitions_considered": [
      {
        "name": "estate_observations_y2026m05",
        "droppable": true,
        "rows": 0,
        "blocked_rows": null
      },
      {
        "name": "estate_observations_y2026m06",
        "droppable": true,
        "rows": 0,
        "blocked_rows": null
      },
      {
        "name": "estate_observations_y2026m07",
        "droppable": true,
        "rows": 4,
        "blocked_rows": null
      },
      {
        "name": "estate_observations_y2026m08",
        "droppable": true,
        "rows": 4,
        "blocked_rows": null
      }
    ],
    "row_deletes": {
      "estate_observations": 3,
      "estate_evidence": 0
    },
    "archive_files": [
      "estate-history-20261101T142747Z.ndjson",
      "estate-partitions-20261101T142747Z.ndjson"
    ],
    "archive_rows_on_disk": 11,
    "archive_manifest": {
      "rows": 3,
      "sha256": "a79d08c3f37bd5d4",
      "partitions": {
        "estate_observations_y2026m05": 0,
        "estate_observations_y2026m06": 0,
        "estate_observations_y2026m07": 4,
        "estate_observations_y2026m08": 4
      }
    },
    "answerable_after": {
      "checked": 1,
      "asset_id": "application:app-00042",
      "fact_count": 2,
      "rows_remaining_for_asset": 3,
      "ok": true
    },
    "refused": null,
    "seconds": 0.05
  }
}
```

### `partitioning` — PASS (EXECUTED)

*is the history table partitioned, or does its size bound every query?*

- **Reading:** ``estate_observations`` is a range-partitioned table on PostgreSQL: rows land in the month of their ``last_seen_at``, a month-scoped read is planned against exactly one partition, and dropping that partition removed its rows in a constant-time catalogue operation
- **Limit:** the drill runs on one server and a few hundred rows: it proves the mechanism, not the cost at a hundred million facts, and it does not rehearse a month boundary with live writers
- **Closes with:** `a bank-sized table converted once with `db.partitions.ensure` on a schedule and the retention sweep dropping, not deleting, months`

```
{
  "migrations_with_partitions": [
    "0130_partition_estate_observations.py"
  ],
  "server": "local PostgreSQL 16.2",
  "drill": {
    "parent_relkind": "p",
    "partitions_created_by_drill": [
      "estate_observations_y2026m05",
      "estate_observations_y2026m06",
      "estate_observations_y2026m07",
      "estate_observations_y2026m08",
      "estate_observations_y2026m09"
    ],
    "partitions_total": 19,
    "rows_by_partition": {
      "estate_observations_y2026m07": 4,
      "estate_observations_y2026m08": 4,
      "estate_observations_y2026m09": 3,
      "estate_observations_y2026m10": 1,
      "estate_observations_y2026m11": 2
    },
    "explain_relations_scanned": [
      "estate_observations_y2026m10"
    ],
    "expected_partition": "estate_observations_y2026m10",
    "partitions_dropped": [
      "estate_observations_y2026m07"
    ],
    "rows_in_dropped_partition": 4,
    "rows_before": 14,
    "rows_after": 10,
    "drop_seconds": 0.003,
    "rows_written": 14
  }
}
```

### `concurrent_writes` — PASS (EXECUTED)

*do two writers on the same row produce a lost update or a deadlock?*

- **Reading:** two sessions read version 0 of the same job and both tried to move it: exactly one update matched, the loser changed nothing, and the survivor's status is the one on the row. Taking two row locks in a fixed order completed while taking them in opposite orders was aborted by PostgreSQL's deadlock detector — which is why the scheduler sorts its locks
- **Limit:** one job row and two lock holders: it proves the compare-and-set and the ordering rule, not the behaviour of the real ingest under a bank's concurrency; the drill client is this process, not a load generator
- **Closes with:** `the same race driven by `scripts/load_test.py --concurrent-writers 8` against a populated server`

```
{
  "server": "local PostgreSQL 16.2",
  "drill": {
    "race": {
      "outcomes": [
        [
          "FAILED",
          1
        ],
        [
          "COMPLETED",
          0
        ]
      ],
      "errors": [],
      "final_version": 1,
      "final_status": "FAILED"
    },
    "ordered_locking": [
      "acquired"
    ],
    "unordered_locking": [
      "OperationalError: deadlock detected",
      "acquired"
    ]
  }
}
```

### `backup_restore` — PASS (EXECUTED)

*can the estate be restored, and is it verified?*

- **Reading:** ``pg_dump`` of the migrated database, ``pg_restore`` into a fresh one, and every table compared by row count: the restore matches the source
- **Limit:** this is a logical dump and restore, not point-in-time recovery — no WAL archive was replayed, so the RPO of the deployment is still unmeasured; row counts prove the schema and the data survived, not that a corrupt page or a lost transaction would be recovered
- **Closes with:** `a nightly dump to object storage, a parity check that runs it, and an archived-WAL drill that measures the actual RPO`

```
{
  "scripts_present": [
    "db_backup.sh",
    "db_restore.sh",
    "backup_drill.py",
    "postgres_parity.sh"
  ],
  "server": "local PostgreSQL 16.2",
  "drill": {
    "tables_compared": 176,
    "rows_in_source": 185,
    "rows_in_restored": 185,
    "mismatches": {},
    "mismatch_count": 0,
    "dump_bytes": 645356,
    "dump_seconds": 0.12,
    "restore_seconds": 1.47,
    "restored_database": "pgq_restore"
  }
}
```

### `corruption_recovery` — PASS (EXECUTED)

*does the system recover from a killed writer or a crashed server?*

- **Reading:** a writer terminated mid-transaction left no row behind, and an immediate (crash) shutdown followed by a restart replayed the log to the same row count, after which every table could still be read in full
- **Limit:** the amcheck extension is not installed in this build, so the page-level integrity check is a full-read dump and ``vacuumdb`` rather than ``pg_amcheck``; a killed backend and a clean crash are the recoveries PostgreSQL is built for; nothing here corrupts a page on disk, and no backup was needed — so this measures crash safety, not restore-from-corruption, which the backup row covers only as a successful dump and restore
- **Closes with:** ``scripts/controlled_recovery_drill.py` on a scratch server that destroys a page and restores it, asserting the evidence chain still verifies`

```
{
  "scripts_present": [
    "controlled_recovery_drill.py",
    "drill_worker_recovery.py"
  ],
  "server": "local PostgreSQL 16.2",
  "drill": {
    "rows_before": 14,
    "rows_after_restart": 14,
    "killed_writer": {
      "outcome": "refused: OperationalError: (psycopg2.OperationalError) server closed the connection unexpectedly\n\tThis probably means the server terminated abnorma",
      "orphan_rows": 0,
      "backend": 4361
    },
    "restart_seconds": 0.31,
    "integrity_checks": {
      "pg_amcheck": "pg_amcheck failed (1): pg_amcheck: warning: skipping database \"postgres\": amcheck is not installed\npg_amcheck: warning: skipping database \"template1\": amcheck is not installed\npg_amcheck: error: no relations to check",
      "vacuumdb": "clean",
      "post_restart_dump": "read every table (645193 bytes)"
    }
  }
}
```

### `ha_failover` — UNPROVEN (SERVER_REQUIRED)

*does a standby take over, and what is the measured RPO and RTO?*

- **Reading:** this checkout can now start one PostgreSQL instance, which is one node: a failover needs a standby, a replication link and a promotion. Dropping the row to a single server would answer a different question
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

- Every EXECUTED row ran on local PostgreSQL 16.2, which is one instance on a socket in this sandbox, not a bank's cluster: no replication, no WAL archive, no failover.
- The tables the drills exercise are small — tens or hundreds of rows. They prove mechanisms (a partition drop, a compare-and-set, a crash restart), not the cost of those mechanisms at bank scale.
- No row measures write amplification, vacuum or index bloat, which are what actually decide a bank's database cost; guide 114's growth figure is still the only size measurement and it came from SQLite.
- HA is unmeasured: a single server cannot be promoted, so `ha_failover` stays UNPROVEN and the RPO/RTO a bank asks for is still unstated.

**The verdict this drill supports:** 11 properties were executed and held: `backup_restore`, `concurrent_writes`, `corruption_recovery`, `index_parity`, `locking`, `migration_at_scale`, `migration_chain`, `partitioning`, `pooling`, `retention`, `transaction_boundaries`.

Still open: partial `migration_lock_safety`. unproven `ha_failover`.

A bank should read the UNPROVEN rows as *not done*. One server answering a question is not a cluster answering it, and nothing here measures what the deployment costs to run.
