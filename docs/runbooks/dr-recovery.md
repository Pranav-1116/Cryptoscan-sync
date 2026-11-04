# DR & Recovery Runbook — CryptoScan HA Stack

> **2026-10-23 detailed recovery plan:** start with the
> [end-to-end backup and disaster-recovery pack](../disaster-recovery/README.md).
> The older HA targets/procedures below are historical scope, not current bank acceptance. The overlay does not actually archive WAL (`archive_command=/bin/true`); its promotion helper does not prove positive old-primary fencing or enforce an acceptable lag bound.

> **2026-10-21 scope correction:** RPO/RTO values below are historical targets or
> results for the named earlier environment, not guarantees for a current release.
> Asynchronous PostgreSQL/Redis replication does not imply zero loss. The local
> TLS/Sentinel qualification in [Guide 45](../bank-environment/45-redis-tls-sentinel-qualification.md)
> is not cross-zone DR evidence. Apply the
> [execution/replay recovery procedure](execution-and-replay-upgrade.md): old
> primary-bound cursors reset; recovered RUNNING jobs are not automatically
> re-executed; legacy unpinned jobs need approved resubmission. No production
> failover/restore drill was performed by the documentation refresh.

Target service levels for the `deploy/ha` stack:

| Layer | RPO | RTO | Mechanism |
|---|---|---|---|
| Evidence DB (Postgres) | deployment-measured; async streaming can lose acknowledged writes / WAL archive target ≤ 5 min | ≤ 15 min (`promote-replica.sh`) | replication overlay: `pg_basebackup` clone + WAL streaming; nightly `pg_dump` off-host |
| Monitor continuity | 0 (no data lost) | ≤ lease TTL (default 60 s; instant on SIGTERM) | **leader lease** — run 2+ daemons, exactly one scans, standby takes over automatically (**verified live**) |
| API/dashboard | 0 | ≤ 15 min (drain via `/api/v1/readyz`) | 2+ stateless replicas behind nginx least-conn; readiness gates routing |
| Rate limits | n/a | n/a | shared Redis where configured; production fail-closed consumers must not silently substitute per-replica budgets |
| Alerting | 0 (SIEM keeps own copy) | ≤ 30 s | CEF/webhook sinks are fire-and-forget; event feed is the source of truth |

> Honest limits: **PITR and multi-*site* DR are configuration you must
> provide** (object-storage WAL archive / managed Postgres). The replication
> overlay ships the topology; `drill.sh` rehearses it and files the evidence.
> Multi-AZ monitor failover, readiness drain, and cluster rate limiting are
> implemented and were verified in this environment.

## 0. Bank-side prerequisites — fill this in before an incident, not during one

**PITR is not provided by CryptoScan.** The product ships a logical `pg_dump` path, an encrypted
archive with a signed manifest, and (from this release) a scheduled restore drill that proves
those archives come back. PostgreSQL point-in-time recovery needs a *physical* base backup plus a
continuously archived WAL stream — infrastructure the bank owns and operates. The governance
restore API refuses a requested point in time on a `pg_dump` artifact rather than silently
restoring "now" and reporting success, so nothing here should be read as a PITR capability.

A reviewer should be able to tick every line. An unticked line is a gap, not a task for the day
of the incident.

- [ ] **WAL archive destination** — an object store or host path outside the database host,
      writable by PostgreSQL, readable by the recovery host. Record its URI (not credentials).
- [ ] **`archive_mode = on` and a real `archive_command`/`archive_library`** — the shipped HA
      overlay deliberately sets `archive_command=/bin/true`, which archives nothing. Confirm the
      bank's value, and confirm `pg_stat_archiver.failed_count` is not climbing.
- [ ] **A physical base backup schedule** — `pg_basebackup` (or the bank's snapshot mechanism) at
      a cadence inside the agreed RPO, retained for at least the recovery window.
- [ ] **WAL retention covering the recovery window** — stated in hours, checked against the
      object store's lifecycle policy. Retention shorter than the window makes the window a lie.
- [ ] **A designated recovery host and database** — never the source. CryptoScan's drill refuses
      a target equal to the source for exactly this reason.
- [ ] **A rehearsed recovery command** — `recovery_target_time`, `restore_command`, and the
      promotion step, written down with the bank's own paths.
- [ ] **A measured PITR drill** — at least one restore to a chosen past timestamp, with the
      resulting row counts and the timestamp recorded. Until this exists, RPO is a target, not a
      measurement.
- [ ] **The restore drill is scheduled** — `scripts/restore_drill.py` runs weekly in
      `.github/workflows/restore-drill.yml` and files `restore-drill-history.jsonl`. In the
      bank's environment, point it at the bank's backup directory and recovery database, and
      keep the receipts with the other audit evidence.
- [ ] **Backup encryption keys are escrowed** — the archive is Fernet-encrypted and the manifest
      is HMAC-signed; a lost key means an unreadable backup. Escrow is the bank's job.

What each drill proves, stated narrowly: a passing `restore_drill.py` run proves *this archive*
restored into *this recovery database* and that the measured tables came back. It does not prove
PITR, off-site copies, or a disaster-recovery qualification. The receipt says so in its own
`claims` block.

## 1. Backups (scheduled, verified)

```bash
# nightly evidence backup + manifest (works on sqlite AND postgres backends)
python scripts/backup_evidence.py                  # -> backups/cryptoscan-<ts> + .manifest.json

# full database backup: postgres custom-format dump + sha256 manifest + retention
bash scripts/db_backup.sh                          # add --with-neo4j for a consistent graph dump
# -> backups/db/pg-<ts>.dump + pg-<ts>.sha256      (verify + restore: scripts/db_restore.sh)

# verify a backup restores and the evidence chain is intact
python scripts/backup_evidence.py --verify backups/cryptoscan-<ts>.db
bash scripts/db_restore.sh backups/db/pg-<ts>.dump   # asks for confirmation, checksum-first

# prove the archive restores, into a designated recovery database, with a receipt
export CRYPTOSCAN_RESTORE_TARGET_DB=postgresql://drill@recovery-host:5432/cryptoscan_drill
python scripts/restore_drill.py --backup-dir /var/lib/cryptoscan/backups --database-id cryptoscan \
    --out evidence/restore-drill-$(date -u +%Y%m%dT%H%M%SZ).json
```


Backups must leave the host (object storage / vault copy) — a backup that
lives on the same disk is not a backup.

## 2. Restore

**Destructive historical scratch example below:** never remove an active bank
volume. Restore a verified backup to an isolated target, preserve the original
store and approve the cutover. Substitute the exact Compose project/volume,
backup format and release revision; do not copy these example names blindly.
Reconcile current execution pins and replay epochs before enabling producers.

```bash
docker compose -f deploy/ha/docker-compose.yml down
docker volume rm ha_pgdata
docker compose up -d postgres
gunzip -c backups/pg-<date>.sql.gz | \
  docker compose exec -T postgres psql -U cryptoscan cryptoscan
python -m alembic -c services/database/migrations/alembic.ini current   # confirm the intended release revision, not a historical fixed number
docker compose up -d                                                   # migrate runs, api/worker/monitor follow
python scripts/backup_evidence.py --verify ...   # chain integrity after restore
```

## 3. Component failures

| Failure | Symptom | Action |
|---|---|---|
| One API replica | nginx 5xx briefly, then healthy | `docker compose restart api`; image/DB is shared |
| Postgres | APIs return 5xx, monitor logs `monitor_tick_failed` | loop keeps retrying (by design); restore/promote, everything self-recovers |
| Redis | Required journal/queue unavailable; readiness or publication refuses | Restore approved TLS/ACL/connectivity; reconcile persisted jobs and cursor resets before resuming |
| Monitor daemon | targets go stale (`next_scan_at` in the past) | container auto-restarts; if the host died, `docker compose up -d monitor` |
| SIEM sink down | `alert_cef_failed` in logs | alerts persist in `monitor_events`; re-dispatch via webhook replay |

## 4. Degraded-mode operation

- **No Redis in production** — required queue/journal consumers fail closed.
  Development may allow in-memory delivery, but it is not durable, cross-process
  failover or a production substitute. Inspect each consumer independently.
- **No SMTP** — report distribution returns `SKIPPED_NO_SMTP`; alerts fall
  back to CEF/webhook if configured.
- **DB read-only** — monitor logs failures and retries; no data is invented.

## 5. Failover drill (quarterly, PCI-style evidence)

Automated: `deploy/ha/drill.sh` (API replica loss, monitor leader failover,
DB outage honesty, backup verify). Manual equivalents:

1. `docker compose stop api` → verify dashboard still serves (second replica).
2. `docker compose stop postgres` → verify monitor survives + recovers.
3. Restore latest backup to a scratch instance, run `--verify`, record RTO.
4. File the drill results with the audit evidence (hash-chained in the product).
