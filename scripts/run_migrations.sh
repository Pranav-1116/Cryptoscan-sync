#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/services/database"
export PYTHONPATH="$ROOT/services/database${PYTHONPATH:+:$PYTHONPATH}"
if [[ -f migrations/alembic.ini && -n "${DATABASE_URL:-}" ]]; then
  alembic -c migrations/alembic.ini upgrade head
elif [[ -f migrations/alembic.ini ]]; then
  # No DATABASE_URL: default local engine (SQLite) — create via metadata
  # to avoid SQLite-incompatible Postgres DDL in historical migrations.
  python3 - <<'PY'
from db.connection.session import init_db
init_db()
print("schema created via SQLAlchemy metadata (local SQLite mode)")
PY
else
  python3 - <<'PY'
from db.connection.session import init_db
init_db()
print("schema created via SQLAlchemy metadata (no alembic.ini)")
PY
fi
