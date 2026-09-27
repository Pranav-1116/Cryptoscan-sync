#!/usr/bin/env bash
# PostgreSQL parity gate: everything that normally runs on SQLite, on a real PostgreSQL.
#
#   scripts/postgres_parity.sh                       # docker, embedded pgserver, or an existing server
#   CRYPTOSCAN_TEST_DATABASE_URL=postgresql+psycopg2://u:p@host/db scripts/postgres_parity.sh
#   CRYPTOSCAN_PARITY_NO_DOCKER=1 scripts/postgres_parity.sh    # never start a container
#
# Runs: (1) the Alembic chain on a fresh database + schema == models, (2) the whole worker suite with
# CRYPTOSCAN_TEST_DB_BACKEND=postgresql, (3) the SNB / UAE estate tests (pipeline + API) on both backends.
#
# The whole ordinary suite runs on SQLite while production mandates PostgreSQL, so this gate is the
# only thing standing between the two. It used to need either `pip install pgserver` (unavailable on
# an offline box, and absent from PyPI for some interpreters) or a hand-provisioned server with
# credentials -- so in practice it was skipped, and the production database path went unexercised.
# It now falls back to a throwaway Docker container, which needs no credentials from anyone.
set -euo pipefail
cd "$(dirname "$0")/.."
export PYTHONPATH="$(for d in shared/*/ services/*/; do printf '%s%s:' "$PWD/" "$d"; done)"
# Absolute: every step below runs in a subshell that has cd'd into a service
# directory, so a relative interpreter path resolves to nothing there.
PY=${PYTHON:-$PWD/.venv/bin/python}
# Accept either a path (the local .venv) or a bare name resolved on PATH (CI).
command -v "$PY" >/dev/null 2>&1 || { echo "no interpreter '$PY' (set PYTHON=...)"; exit 2; }

PG_CONTAINER=cryptoscan-pg-parity
started_container=""

cleanup() {
  if [ -n "$started_container" ]; then
    docker rm -f "$PG_CONTAINER" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

if [ -z "${CRYPTOSCAN_TEST_DATABASE_URL:-}" ] && ! $PY -c "import pgserver" 2>/dev/null; then
  if [ -z "${CRYPTOSCAN_PARITY_NO_DOCKER:-}" ] && command -v docker >/dev/null 2>&1; then
    echo "== 0. starting throwaway PostgreSQL ($PG_CONTAINER)"
    docker rm -f "$PG_CONTAINER" >/dev/null 2>&1 || true
    docker run -d --rm --name "$PG_CONTAINER" \
      -e POSTGRES_PASSWORD=parity -e POSTGRES_USER=cryptoscan -e POSTGRES_DB=cryptoscan \
      -p 55432:5432 postgres:16-alpine >/dev/null
    started_container=1
    for _ in $(seq 1 60); do
      docker exec "$PG_CONTAINER" pg_isready -U cryptoscan >/dev/null 2>&1 && break
      sleep 1
    done
    docker exec "$PG_CONTAINER" pg_isready -U cryptoscan >/dev/null 2>&1 || {
      echo "PostgreSQL container did not become ready"; exit 2; }
    export CRYPTOSCAN_TEST_DATABASE_URL="postgresql+psycopg2://cryptoscan:parity@127.0.0.1:55432/cryptoscan"
  else
    echo "need CRYPTOSCAN_TEST_DATABASE_URL, pgserver (pip install pgserver), or docker"; exit 2
  fi
fi
echo "== 1. alembic chain on PostgreSQL"; (cd services/database && $PY -m pytest -q -p no:cacheprovider -m live tests/unit/test_migration_chain_postgres.py)
echo "== 2. worker suite on PostgreSQL"; (cd services/worker && CRYPTOSCAN_TEST_DB_BACKEND=postgresql $PY -m pytest -q -p no:cacheprovider)
echo "== 3. estate read-back through the API (sqlite + postgresql)"; (cd services/api && $PY -m pytest -q -p no:cacheprovider tests/integration/test_snb_estate_api.py)
echo "PostgreSQL parity: OK"
