# Backup & Restore Runbook (Evidence Database Helpers)

> **2026-10-23 scope correction:** use the
> [complete backup/disaster-recovery pack](../disaster-recovery/README.md) for the
> controlled PostgreSQL/TLS-Redis bank profile, architecture, every dataflow,
> consistent cohorts, isolated restore, UNKNOWN handling, cutover and failback.
> This page is a limited helper reference, not an implemented full-site plan.

The evidence database is an audit/compliance record. Preserve original ownership,
hashes, lifecycle history and tombstones. A successful dump or healthy restored
API is not proof of complete or currently eligible evidence.

## What these helpers capture

| Asset | Source-present method | Boundary |
|---|---|---|
| SQLite database, development | `scripts/backup_evidence.py`, SQLite online backup API | Database image only; no global SQL/file/queue consistency. |
| PostgreSQL logical data | Same Python helper, plain SQL `pg_dump --no-owner --no-privileges` | Not physical backup/WAL/PITR, cluster-global roles/configuration or external file backup. |
| Encrypted helper backup | `--encrypt`, CSBC1 AES-GCM/scrypt, companion JSON manifest | Separate key custody required; helper removes plaintext on successful encryption, not guaranteed secure erasure. |
| Compose PostgreSQL backup | `scripts/db_backup.sh`, custom `.dump`/age and `.sha256` | Different format/restore path; not an external-services Kubernetes adapter. |
| Raw packs, artifacts/source and file-backed stores | Site-required exact-version capture with SQL cohort | Not automatically included by dumping the database. |
| Redis roles/journals/queues | Site-approved persistence and role-specific recovery | SQL backup is not Redis backup; retain independent pre-fault ACK IDs. |
| Optional graph | Separately accepted topology and graph backup or demonstrated complete rebuild | Disabled in the controlled profile; `populate_graph.py` alone does not prove complete historical reconstruction. |
| Keys/configuration/PKI | Bank's restricted secret/trust custody and approved nonsecret release inventory | Never copy `.env`/private keys into public artifacts or general evidence manifests. |

## Safe discovery before an authorized exercise

```bash
python scripts/backup_evidence.py --help
python scripts/restore_evidence.py --help
python scripts/verify_evidence.py --help
python scripts/verify_evidence_chain.py --help
```

Use the configured repository environment. Help is not a backup/restore test.
For actual execution, use [backup policy and compatibility](../disaster-recovery/03-backup-policy-and-end-to-end-dataflow.md)
and the [authorized isolated recovery procedure](../disaster-recovery/04-disaster-recovery-runbook.md).
PostgreSQL helpers pass connection URLs to subprocess arguments: environment
injection does not hide an embedded password. Use approved password-free/libpq
credential handling or DBA-native tooling and inspect redaction boundaries.

## Correct interpretation of verification and restore

- `backup_evidence.py --verify` is a creation-time SQLite flag, not a positional
  existing-file verifier. It inspects a capped live-row listing and hash shape/
  recomputability; **it does not compare every stored content hash or verify the
  full chain**. Warnings/skips can coexist with process exit 0.
- The JSON companion manifest contains the plaintext backup digest; with `.enc`,
  decrypt before digest comparison. Compose `.sha256` instead covers the age
  ciphertext. These formats/helpers are not interchangeable.
- `restore_evidence.py --force` only bypasses a **missing manifest**. It does not
  accept a mismatched digest or make a partially corrupted backup safe. Normal
  recovery requires the intact authenticated cohort, not forced acceptance.
- SQLite restoration needs quiesced writers and reviewed WAL/SHM handling before
  a staging-file swap. A `.pre-restore.bak` is not an independent immutable backup.
- PostgreSQL Python restoration uses `psql --single-transaction` without
  `ON_ERROR_STOP`; inspect SQL errors and use the bank's reviewed stop-on-error
  restore procedure. Command success alone does not establish restored data.
- `verify_evidence.py` can return 0 for **PASS or EMPTY**. Check the verdict,
  expected target/record coverage and manifests, not just exit status. Use
  `verify_evidence_chain.py --scan-id ID --json` for the stored-chain verdict too;
  valid chain alone is not whole-site completeness or current proof eligibility.

## Schedules, retention and objectives

The earlier daily-02:30/35-day cron example is not a bank policy. No destructive
`find ... -delete` lifecycle command is recommended here: legal hold, independent
copy, key lifetime and last-known-good recoverability must be checked first.
The supplied Compose systemd timer is a different, optional host-local schedule.
Record the actual scheduler, timezone/DST, alerts and missed-run handling.

RPO is measured consistent recoverability/ACK loss, not simply cron frequency.
RTO includes dependencies, keys, reconciliation, validation and accepted cutover,
not an unmeasured fixed “minutes” promise. See
[drill measurements and acceptance](../disaster-recovery/07-drills-validation-and-acceptance.md).

## Before restarting workers or exposing the restored API

Follow the full runbook, not a liveness-only checklist. In particular:

1. Fence old SQL writers, daemon hosts and external effects; isolate restoration.
2. Verify exact schema/release/data/owner/file cohort and current identity.
3. Reconcile SQL jobs/attempts/budgets/outbox and all deployed Redis roles.
4. Preserve UNKNOWN reservations until exact-estate evidence-backed settlement;
   never reset RUNNING to QUEUED or blindly requeue historical work.
5. Reconcile post-backup revocations, expiry, tombstones and source withdrawal;
   current proofs cannot rely on historical labels alone.
6. Handle replay epoch resets/gaps through explicit fresh current-state reads.
7. Validate negative paths and measured loss/time, obtain different review and
   explicit cutover approval. Preserve every new write during later failback.

Detailed procedure: [execution/evidence reconciliation](../disaster-recovery/05-queue-execution-and-evidence-reconciliation.md).
Historical local evidence remains in [the dated SQLite drill](../backup-drill.md),
not a new bank-site qualification.
