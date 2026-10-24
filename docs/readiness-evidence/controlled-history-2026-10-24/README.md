# Replay and artifact boundaries

See [results](../controlled-history-2026-10-24.md). Private configs, passwords,
raw API keys, encrypted database snapshots and runtime data are **not** included.
JSON/XML/images are copied unchanged; text transcripts remove terminal colour
escapes/trailing whitespace only. Source/artifact hashes are in `manifest.json`.

## Python, UI and PostgreSQL

Use a reviewed constrained Python 3.11 environment and the repository dependency
locks. From repository root:

```bash
bash docs/readiness-evidence/production-data-path-2026-10-24/run-python-tests.sh \
  services/api/tests/unit/test_cbom_legacy_reconciliation.py \
  services/api/tests/unit/test_cbom_controlled_history.py \
  services/database/tests/unit/test_import_provenance.py \
  services/database/tests/unit/test_audit_chain_incremental.py \
  services/api/tests/unit/test_assurance_workflows.py \
  services/api/tests/unit/test_backup_encryption.py \
  scripts/tests/test_capacity_verdict.py --junitxml=/external/python.xml
npm --prefix frontend test -- --maxWorkers=2
npm --prefix frontend run typecheck
npm --prefix frontend run build
```

For PostgreSQL use the [existing owned fixture setup](../historical-cbom-2026-10-24/README.md),
never a deployment. Set absolute package paths plus both API/database unit-test
directories on PYTHONPATH and set `CRYPTOSCAN_PROVENANCE_TEST_DATABASE_URL` to
an owned local `cryptoscan_e2e_*` database. The controlled fixture creates/drops
its own random databases and uses real authentication/tenant middleware:

```bash
python -m pytest services/api/tests/unit/test_cbom_controlled_postgres.py \
  services/database/tests/unit/test_provenance_postgres.py -m '' -q
```

The recorded 32 checks include 15 controlled-history PG cases and 17 existing
provenance/audit cases, not a fresh full migration/whole-product PG qualification.

## Real browser and recovery

Provision the existing external synthetic-principal config (database_url,
password, package paths), owned migrated schema and approved Chromium. The
browser tool changes only the **owned synthetic** fixture principals' roles;
do not reuse customer credentials. It performs three normal logins per run.
The recorded successful rerun used an owned API restart; no limiter was disabled.
Respect the five-login/minute/IP limit when replaying.

```bash
python scripts/controlled_cbom_e2e.py --config /external/private.json \
  --chromium /approved/chromium --report /external/browser.json \
  --screenshot /external/browser.png
# Stop fixture writers first. Put compatible local pg_dump/psql on PATH.
python scripts/controlled_recovery_drill.py --config /external/private.json \
  --report /external/pg-recovery.json
```

The existing `drill_disposable_redis.py` intentionally permits only its fixed
private `/home/user/redis-8.2.4/src/redis-server` executable, port-0 Unix socket,
RDB filename and directory. Do not relax those guards to point at deployments.
Run prepare with `CRYPTOSCAN_DISPOSABLE_REDIS_OPT_IN=local-synthetic-fault`,
restart that same owned lab from RDB, then finish. Retain the loss/limitations,
not a zero-loss label. Remove owned lab artifacts after recording results.
