#!/usr/bin/env bash
# Production database restore from a db_backup.sh dump (pg_dump custom format).
#
# Usage:
#   bash scripts/db_restore.sh backups/db/pg-20260910T000000Z.dump            # asks for confirmation
#   bash scripts/db_restore.sh --yes backups/db/pg-20260910T000000Z.dump      # no prompt
#
# What it does:
#   1. verifies the dump against its sha256 manifest (when present)
#   2. pg_restore --clean --if-exists into the running postgres container
#   3. prints the post-restore alembic revision check to run next
#
# DANGER: --clean drops and recreates every object in the target database.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

COMPOSE_ARGS="${COMPOSE_ARGS:--f docker-compose.yml -f docker-compose.prod.yml}"
POSTGRES_USER="${POSTGRES_USER:-cryptoscan}"
POSTGRES_DB="${POSTGRES_DB:-cryptoscan}"
ASSUME_YES=0
[[ "${1:-}" == "--yes" ]] && { ASSUME_YES=1; shift; }

DUMP="${1:-}"
[[ -z "$DUMP" || ! -f "$DUMP" ]] && { echo "usage: $0 [--yes] <path-to-pg-*.dump>" >&2; exit 2; }

MANIFEST="${DUMP%.dump}.sha256"
if [[ -f "$MANIFEST" ]]; then
  echo "db_restore: verifying checksum against $(basename "$MANIFEST")"
  ( cd "$(dirname "$DUMP")" && sha256sum -c "$(basename "$MANIFEST")" | grep -q ': OK$' ) \
    || { echo "db_restore: checksum MISMATCH — refusing to restore" >&2; exit 1; }
  echo "db_restore: checksum OK"
else
  echo "db_restore: WARNING no manifest next to the dump — skipping integrity check" >&2
fi

dc() { docker compose $COMPOSE_ARGS "$@"; }
if ! dc ps --status running --services | grep -q '^postgres$'; then
  echo "db_restore: postgres service is not running — start it first (docker compose up -d postgres)" >&2
  exit 2
fi

if [[ "$ASSUME_YES" != "1" ]]; then
  echo "This DESTROYS the current contents of '$POSTGRES_DB' and restores $(basename "$DUMP")."
  read -r -p "Type the database name to confirm: " reply
  [[ "$reply" == "$POSTGRES_DB" ]] || { echo "db_restore: aborted"; exit 2; }
fi

echo "db_restore: restoring into $POSTGRES_DB"
dc exec -T postgres pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists --no-owner \
  < "$DUMP"

echo "db_restore: done. Confirm the schema revision, then start the stack:"
echo "  DATABASE_URL=\"postgresql://$POSTGRES_USER@localhost:5432/$POSTGRES_DB\" \\"
echo "    python -m alembic -c services/database/migrations/alembic.ini current"
echo "  bash scripts/deploy_prod.sh -d"
