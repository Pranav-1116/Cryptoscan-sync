# PostgreSQL DR qualification — 2026-09-29

`scripts/postgres_drill.py` run end to end, including the one-way standby
promotion. **Verdict: PASS, 35/35 checks.**

| Measurement | Result |
|---|---|
| **RPO** — drill marker primary → standby | **0.0 s** |
| **RTO** — promotion command → standby writable | **0.15 s** |

## What was exercised

Against a real primary/standby pair with streaming replication, built by
`scripts/postgres_dr_sandbox.sh` and carrying all 62 Alembic migrations:

- both nodes reachable, roles correct (`pg_is_in_recovery` f / t), `wal_level`
  = replica, primary reporting a `streaming` standby;
- a unique marker written to the primary and observed on the standby (RPO);
- **controlled promotion executed** — `pg_ctl promote` — and the standby
  measured becoming writable (RTO);
- the marker and every table count surviving promotion (`audit_log`,
  `evidence_records`, `scans`, `scan_jobs`);
- audit-chain continuity and evidence-record hash-field completeness verified
  on the primary **and** again on the restored copy;
- a real `pg_dump` → `pg_restore` into a third, empty container that had never
  seen the data, where the marker reappears;
- a live API (`/api/v1/readyz`) answering healthy against the promoted node,
  and a worker health probe returning clean.

## Two bugs this found

**The RPO measurement could never pass.** `wait_for_marker` polls the standby
for a row that has not replicated yet. In PostgreSQL that error aborts the
transaction, and nothing rolled back — so every later poll died with
`InFailedSqlTransaction` and the marker could not be observed however fast it
arrived. The loop burned its full timeout and reported FAIL. `wait_until_writable`
had the same shape, which would have done the same to RTO. Both now roll back
before retrying; the marker check went from FAIL at 120.103 s to PASS at
0.001 s.

**The sandbox raced the image's init server.** `pg_isready` answers "ready" on
the temporary server `initdb` runs before the real one starts, so the next
command died with *"the database system is shutting down"*. Readiness now
requires three consecutive real `SELECT 1`s.

## What this does NOT establish

- **Not the customer topology.** Two containers on one host, sharing a kernel,
  a disk and a bridge. An RPO of 0.0 s and an RTO of 0.15 s over a loopback
  bridge say nothing about a pair separated by a real network, real disks and
  real load. Re-run against the production pair before quoting any number.
- **No load during the drill.** The estate was freshly migrated and the tables
  were empty, so "counts not lost" compared 0 to 0. A qualification run should
  carry a realistic row count and concurrent writes.
- **Asynchronous replication.** `sync_state` was `async`, so a real RPO under
  load will not be zero. Synchronous commit is a deployment choice that has to
  be tested as deployed.
- **No failback.** Promotion is one-way here; returning the old primary to
  service was not exercised.
- Single run, not a schedule.

## Reproducing

```bash
bash scripts/postgres_dr_sandbox.sh up              # primary + standby
(cd services/database/migrations && alembic upgrade head)   # against the primary
bash scripts/postgres_dr_sandbox.sh restore-target  # empty third node

python scripts/postgres_drill.py --timeout 60 \
  --execute-promotion --acknowledge-destructive \
  --api-url http://127.0.0.1:8020/api/v1/readyz \
  --worker-health-command 'docker exec cryptoscan-dr-restore pg_isready -U postgres -q' \
  --restore-command 'bash scripts/postgres_dr_sandbox.sh restore-now' \
  --clean-restore-dsn 'postgresql://postgres:drill@127.0.0.1:55434/restored'

bash scripts/postgres_dr_sandbox.sh down
```

Promotion is destructive and one-way: the standby stops following. Re-run
`up` to rebuild the pair for another drill.
