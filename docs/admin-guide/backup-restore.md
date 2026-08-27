# Backup & Restore Runbook (Evidence Database)

The evidence database is a **compliance record** — treat it like an audit
ledger. This runbook covers scheduled backups, integrity manifests, restores,
and post-restore verification.

## What to back up

| Asset | Location | Method |
|---|---|---|
| Evidence DB (SQLite, dev) | `data/cryptoscan.db` | `scripts/backup_evidence.py` (online, WAL-safe) |
| Evidence DB (PostgreSQL, prod) | `DATABASE_URL` | `scripts/backup_evidence.py` (pg_dump) |
| Evidence packs (if exported) | `data/packs/` | copy with the DB backup |
| Neo4j graph (optional) | compose volume `neo4j_data` | `neo4j-admin database dump` — **rebuildable** from `scripts/populate_graph.py`, so a logical export is enough |
| `.env` / secrets | deployment host | your secret manager (never in the DB backup) |

## Backup

```bash
# Development (SQLite) — safe while the API is running
python scripts/backup_evidence.py --verify
# -> backups/cryptoscan-<timestamp>.db + .manifest.json

# Production (PostgreSQL)
DATABASE_URL=postgresql://... python scripts/backup_evidence.py --out /secure/backups
```

Each backup gets a `manifest.json` containing size, timestamp, and **SHA-256**
of the backup file. With `--verify` (SQLite), the evidence hash chain is
re-verified *on the backup copy* before the manifest is written.

### Schedule (cron)

```cron
# 02:30 UTC daily, keep 35 days
30 2 * * * cd /opt/cryptoscan && python scripts/backup_evidence.py --verify >> backups/backup.log 2>&1 && find backups -name 'cryptoscan-*.db*' -mtime +35 -delete
```

Restore-drill quarterly: pick a random backup, restore to staging, run
`scripts/verify_evidence.py <scan_id>` for the three most recent scans.

## Restore

```bash
# SQLite (restores via staging file; rotates current DB to *.pre-restore.bak)
python scripts/restore_evidence.py backups/cryptoscan-<ts>.db

# PostgreSQL
python scripts/restore_evidence.py backups/cryptoscan-<ts>.sql --db postgresql://...
```

The restore **refuses to proceed if the SHA-256 manifest does not match**.
Use `--force` only for forensics on partially damaged files.

## Post-restore checklist

1. Restart API and worker (`make api`, `make worker` or `docker compose up -d api worker`).
2. `curl -s localhost:8000/health` → `{"status":"healthy"}`.
3. Verify chain on recent scans: `python scripts/verify_evidence.py <scan_id>` (exit 0 = PASS).
4. Confirm drift baselines survived: `GET /api/v1/baselines` (as admin).
5. If Neo4j was restored/rebuilt: `python scripts/populate_graph.py`.
6. Record the restore in the audit log (it appears automatically as future
   admin actions are audited) and in your incident system.

## RPO / RTO guidance

- **RPO:** whatever your cron interval is (daily = up to 24h of scan loss;
  evidence is immutable per scan, so older evidence is never lost retroactively).
- **RTO:** minutes for SQLite (file swap + restart); ~15 min for Postgres
  (restore + migration check `alembic -c migrations/alembic.ini current`).
