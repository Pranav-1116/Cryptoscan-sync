# DR & Recovery Runbook — CryptoScan HA Stack

Target service levels for the `deploy/ha` stack:

| Layer | RPO | RTO | Mechanism |
|---|---|---|---|
| Evidence DB (Postgres) | ≤ 5 min (WAL archive) | ≤ 15 min (promote replica / restore) | `pg_basebackup` + WAL shipping; nightly `pg_dump` to object storage |
| Monitor continuity | 0 (no data lost) | ≤ 30 s | `restart: unless-stopped`; the loop reschedules from `next_scan_at` |
| API/dashboard | 0 | ≤ 15 min | 2+ stateless replicas behind nginx; scale up, no session affinity needed |
| Alerting | 0 (SIEM keeps own copy) | ≤ 30 s | CEF/webhook sinks are fire-and-forget; event feed is the source of truth |

> Honest limits: **multi-AZ Postgres failover and PITR are configuration you
> must provide** (patroni / managed Postgres). This runbook covers single-host
> HA + restore; multi-site DR uses the same backup artifacts.

## 1. Backups (scheduled, verified)

```bash
# nightly evidence backup + manifest (works on sqlite AND postgres backends)
python scripts/backup_evidence.py                  # -> backups/cryptoscan-<ts> + .manifest.json

# postgres logical backup
docker compose -f deploy/ha/docker-compose.yml exec postgres \
  pg_dump -U cryptoscan cryptoscan | gzip > backups/pg-$(date +%F).sql.gz

# verify a backup restores and the evidence chain is intact
python scripts/backup_evidence.py --verify backups/cryptoscan-<ts>.db
```

Backups must leave the host (object storage / vault copy) — a backup that
lives on the same disk is not a backup.

## 2. Restore

```bash
docker compose -f deploy/ha/docker-compose.yml down
docker volume rm ha_pgdata
docker compose up -d postgres
gunzip -c backups/pg-<date>.sql.gz | \
  docker compose exec -T postgres psql -U cryptoscan cryptoscan
python -m alembic -c services/database/migrations/alembic.ini current   # confirm revision
docker compose up -d                                                   # migrate runs, api/worker/monitor follow
python scripts/backup_evidence.py --verify ...   # chain integrity after restore
```

## 3. Component failures

| Failure | Symptom | Action |
|---|---|---|
| One API replica | nginx 5xx briefly, then healthy | `docker compose restart api`; image/DB is shared |
| Postgres | APIs return 5xx, monitor logs `monitor_tick_failed` | loop keeps retrying (by design); restore/promote, everything self-recovers |
| Redis | workers log `redis_unavailable_memory_fallback` | degraded but functional (in-memory queue); restart Redis |
| Monitor daemon | targets go stale (`next_scan_at` in the past) | container auto-restarts; if the host died, `docker compose up -d monitor` |
| SIEM sink down | `alert_cef_failed` in logs | alerts persist in `monitor_events`; re-dispatch via webhook replay |

## 4. Degraded-mode operation

- **No Redis** — workers fall back to the in-memory queue; scheduled scans
  still run on whichever worker gets the job, monitor unaffected.
- **No SMTP** — report distribution returns `SKIPPED_NO_SMTP`; alerts fall
  back to CEF/webhook if configured.
- **DB read-only** — monitor logs failures and retries; no data is invented.

## 5. Failover drill (quarterly, PCI-style evidence)

1. `docker compose stop api` → verify dashboard still serves (second replica).
2. `docker compose stop postgres` → verify monitor survives + recovers.
3. Restore latest backup to a scratch instance, run `--verify`, record RTO.
4. File the drill results with the audit evidence (hash-chained in the product).
