#!/bin/sh
# sandbox-seed container entrypoint.
# Order matters: PostgreSQL schemas must come from alembic — the API startup
# guard aborts on "applied: []" and a create_all-made table set then collides
# with the real migrations. SQLite dev databases are exempt (create_all path
# inside the seeder).
set -e
pip install -q sqlalchemy 'psycopg[binary]' pydantic alembic
# migrations/env.py imports the ORM (from db.models.base import Base) — the repo
# layout puts that package under services/database, so the container must have
# it on PYTHONPATH exactly like the API image does via its .pth file.
export PYTHONPATH="/work/services/database:/work/shared/shared_models"
cd /work
echo '[sandbox-seed] applying migrations (alembic upgrade head)'
alembic -c services/database/migrations/alembic.ini upgrade head
if [ "${SEED_MODE:-seed}" = "migrate-only" ]; then
  echo '[sandbox-seed] SEED_MODE=migrate-only — schema ready, skipping seed'
  exit 0
fi
echo '[sandbox-seed] seeding banking estate'
# shellcheck disable=SC2086
python scripts/seed_sandbox_bank.py ${SEED_ARGS:-}
