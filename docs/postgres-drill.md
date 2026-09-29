# PostgreSQL disaster-recovery qualification

The repository's HA compose files are a topology aid, not evidence. A real
qualification uses two reachable PostgreSQL instances and
`scripts/postgres_drill.py`:

```bash
DR_PRIMARY_DSN='postgresql://...' \
DR_STANDBY_DSN='postgresql://...' \
DR_PROMOTE_COMMAND='ssh standby sudo pg_ctlcluster 16 main promote' \
DR_CLEAN_RESTORE_DSN='postgresql://clean-restore/cryptoscan' \
DR_RESTORE_COMMAND='pg_restore --clean --if-exists --dbname=postgresql://clean-restore/cryptoscan /secure/backup.dump' \
DR_API_READY_URL='https://scan.example/api/v1/readyz' \
DR_WORKER_HEALTH_COMMAND='ssh worker systemctl is-active cryptoscan-worker' \
python scripts/postgres_drill.py \
  --execute-promotion --acknowledge-destructive --require-promotion \
  --out docs/dr-evidence/postgres-drill.json
```

The promotion command is never run unless both explicit acknowledgement flags
are present. The drill records instance roles, streaming state, WAL/marker
replay, RPO, promotion command outcome, RTO, row-count continuity, clean
restore, audit-log/evidence-chain invariants, API readiness and worker
recovery. Preserve the command transcript, PostgreSQL primary/standby logs,
backup checksum, restored-database logs and release digest with the JSON and
Markdown output.

A missing DSN, promotion, restore, API or worker probe is a failed qualification
rather than an inferred pass. A preflight run is useful for diagnosis but is
not a DR result.
