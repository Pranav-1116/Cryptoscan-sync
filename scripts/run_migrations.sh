#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/services/database"
export PYTHONPATH="$ROOT/services/database${PYTHONPATH:+:$PYTHONPATH}"
if [[ -f alembic.ini ]]; then
  alembic upgrade head
else
  python3 - <<'PY'
from db.connection.session import init_db
init_db()
print("schema created via SQLAlchemy metadata (no alembic.ini)")
PY
fi
