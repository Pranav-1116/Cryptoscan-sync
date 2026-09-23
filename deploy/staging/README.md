# Staging without Docker

`staging-up.sh` brings up the whole platform on one host with **real**
PostgreSQL 16 and Redis 7, `ENVIRONMENT=production`, `ALLOW_SQLITE=false`,
and api / worker / monitor as separate processes — the shape production runs
in — without a container runtime. It is the target for the soak, the
PostgreSQL migration test and the burn-in.

```bash
pip install pgserver redis            # embedded PostgreSQL; redis-server on PATH or $STAGE/bin
deploy/staging/staging-up.sh up       # initdb → alembic upgrade head → api :8010 → worker → monitor
deploy/staging/staging-up.sh status
deploy/staging/staging-up.sh restart-apps   # redeploy code; data untouched
deploy/staging/staging-up.sh down
```

Everything lives under `$CRYPTOSCAN_STAGING_DIR` (default `/tmp/cryptoscan-staging`):

| path | |
|---|---|
| `staging.env` | generated once: secrets, `ADMIN_PASSWORD_HASH`, `STAGING_ADMIN_PASSWORD` (the plaintext, staging only), `DATABASE_URL`, `REDIS_URL`, `WORKSPACE_BASE_PATH` |
| `pg/`, `data/` | PostgreSQL cluster (`:55432`) and Redis AOF (`:56379`) |
| `logs/{api,worker,monitor,migrate,redis}.log` | |
| `run/*.pid` | |

The `cryptoscan` role has `CREATEDB` so `test_migration_chain_postgres.py`
can build a throwaway database next to the live one.

Related: [`scripts/soak.py`](../../scripts/soak.py),
[`docs/soak-evidence/`](../../docs/soak-evidence/README.md),
[`docs/dev/TESTING.md`](../../docs/dev/TESTING.md).
