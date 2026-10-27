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
