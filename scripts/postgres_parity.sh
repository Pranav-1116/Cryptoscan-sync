#!/usr/bin/env bash
# PostgreSQL parity gate: everything that normally runs on SQLite, on a real PostgreSQL.
#
#   scripts/postgres_parity.sh                       # embedded PostgreSQL 16 (pip install pgserver) or
#   CRYPTOSCAN_TEST_DATABASE_URL=postgresql+psycopg2://u:p@host/db scripts/postgres_parity.sh
#
# Runs: (1) the Alembic chain on a fresh database + schema == models, (2) the whole worker suite with
# CRYPTOSCAN_TEST_DB_BACKEND=postgresql, (3) the SNB / UAE estate tests (pipeline + API) on both backends.
set -euo pipefail
cd "$(dirname "$0")/.."
export PYTHONPATH="$(for d in shared/*/ services/*/; do printf '%s%s:' "$PWD/" "$d"; done)"
PY=${PYTHON:-.venv/bin/python}
$PY -c "import pgserver" 2>/dev/null || [ -n "${CRYPTOSCAN_TEST_DATABASE_URL:-}" ] || { echo "need pgserver (pip install pgserver) or CRYPTOSCAN_TEST_DATABASE_URL"; exit 2; }
echo "== 1. alembic chain on PostgreSQL"; (cd services/database && $PY -m pytest -q -p no:cacheprovider -m live tests/unit/test_migration_chain_postgres.py)
echo "== 2. worker suite on PostgreSQL"; (cd services/worker && CRYPTOSCAN_TEST_DB_BACKEND=postgresql $PY -m pytest -q -p no:cacheprovider)
echo "== 3. estate read-back through the API (sqlite + postgresql)"; (cd services/api && $PY -m pytest -q -p no:cacheprovider tests/integration/test_snb_estate_api.py)
echo "PostgreSQL parity: OK"
