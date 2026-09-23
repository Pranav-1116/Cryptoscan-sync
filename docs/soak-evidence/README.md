# Soak / burn-in evidence

One directory per run. Each contains the raw data (`cycles.jsonl`,
`summary.json`, `meta.json`, `burn_in_report.json`, `load_test_*.txt`) and a
`REPORT.md` rendered from it by `scripts/soak_report.py`. Raw files are the
evidence; the report is a reading of them.

| run | stack | duration | result |
|---|---|---|---|
| [2026-09-23-staging](2026-09-23-staging/REPORT.md) | PostgreSQL 16 + Redis 7.2, `ENVIRONMENT=production`, api/worker/monitor as separate processes | see REPORT.md (started 2026-09-23 14:21 UTC, 2-min cycles) | in progress — see below |

## How to run one

```bash
# 1. a real Postgres + Redis stack with production guards on (no Docker needed)
pip install pgserver redis            # embedded PostgreSQL 16; redis-server on PATH or $STAGE/bin
deploy/staging/staging-up.sh up       # initdb, alembic upgrade head, api :8010, worker, monitor
deploy/staging/staging-up.sh status

# 2. the soak itself (one cycle = trigger scan → wait → verify chain → read
#    every dashboard → signed TechBOM export → SSE probe → sample RSS/fds/PG/Redis)
python scripts/soak.py --hours 168 --interval 120 --out docs/soak-evidence/$(date +%F)-staging

# 3. integration burn-in and API load, into the same directory
cd docs/soak-evidence/<run>
python ../../../scripts/burn_in.py --target all --api http://127.0.0.1:8010 \
    --username admin --password "$STAGING_ADMIN_PASSWORD" --webhook-secret "$GITHUB_WEBHOOK_SECRET" \
    --host <tls host> --port 443 [--ca-file <private CA>]
python ../../../scripts/load_test.py --url http://127.0.0.1:8010 --users 20 --duration 180 \
    --username admin --password "$STAGING_ADMIN_PASSWORD" > load_test_20u_180s.txt

# 4. render
python scripts/soak_report.py docs/soak-evidence/<run> > docs/soak-evidence/<run>/REPORT.md

# redeploy code mid-soak without losing data
deploy/staging/staging-up.sh restart-apps
```

`summary.json` is rewritten after every cycle, so a run can be read (or
rendered) at any time; the soak process itself is designed to keep going when
a cycle fails and to record the failure rather than stop.

## Pass criteria for a 7-day run

- `cycles_failed` = 0, or every failure explained and fixed in a commit
- `evidence_chain.broken` = 0
- `api_reads.errors_5xx` = 0
- api / worker / monitor RSS: no monotonic growth over the last 5 days
  (the api warms to a plateau in the first hour; growth after that is a leak)
- fds flat; PostgreSQL connections bounded by the pool size; Redis queue depth returns to 0 every cycle
- workspace directory (`WORKSPACE_BASE_PATH`) not growing

## What the first run found (2026-09-23)

Running the real migration chain on a real PostgreSQL for the first time —
rather than `create_all` from the models on SQLite — found three defects that
no test had caught. All are fixed on this branch with regression tests.

1. **`alembic upgrade head` failed on a fresh PostgreSQL** at migration 0011
   (FK to a column that did not exist yet and had the wrong type). Every
   Postgres install of this product would have failed at this step.
2. **Every scan failed on PostgreSQL** at the policy stage with
   `Object of type UUID is not JSON serializable`: 15 columns were still
   `uuid` in the database while the ORM declares `String(36)`. Migration
   0060 converts them; `test_migration_chain_postgres.py` guards it.
3. **Job workspaces were never deleted** (`refusing_to_delete_workspace_outside_base`
   on every job): a relative base path was compared against a resolved one.
   One directory per job, forever — a disk leak on any long-running worker.

The load test also shows that with all virtual users sharing one identity the
production per-identity rate limit (600 req/min) is the ceiling, not capacity:
78k requests, 0 errors, 97% 429. A capacity number needs one API key per
virtual user; that is a harness limitation, recorded as such.
