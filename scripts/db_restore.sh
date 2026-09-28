#!/usr/bin/env bash
# Production database restore from a db_backup.sh dump (pg_dump custom format).
# Encrypted .dump.age artifacts require BACKUP_AGE_IDENTITY pointing to an age
# identity file. The checksum is verified before decryption or pg_restore.
#
# Usage:
#   BACKUP_AGE_IDENTITY=/run/secrets/backup_age_identity \
#     bash scripts/db_restore.sh backups/db/pg-20260910T000000Z.dump.age
#   bash scripts/db_restore.sh --yes backups/db/pg-20260910T000000Z.dump
#
# DANGER: --clean drops and recreates every object in the target database.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

COMPOSE_ARGS="${COMPOSE_ARGS:--f docker-compose.yml -f docker-compose.prod.yml}"
POSTGRES_USER="${POSTGRES_USER:-cryptoscan}"
POSTGRES_DB="${POSTGRES_DB:-cryptoscan}"
BACKUP_AGE_IDENTITY="${BACKUP_AGE_IDENTITY:-}"
AGE_BIN="${AGE_BIN:-age}"
ASSUME_YES=0
[[ "${1:-}" == "--yes" ]] && { ASSUME_YES=1; shift; }

DUMP="${1:-}"
[[ -z "$DUMP" || ! -f "$DUMP" ]] && { echo "usage: $0 [--yes] <path-to-pg-*.dump[.age]>" >&2; exit 2; }

if [[ "$DUMP" == *.dump.age ]]; then
  [[ -n "$BACKUP_AGE_IDENTITY" && -f "$BACKUP_AGE_IDENTITY" ]] || {
    echo "db_restore: BACKUP_AGE_IDENTITY must point to an age identity file for encrypted dumps" >&2
    exit 2
  }
  command -v "$AGE_BIN" >/dev/null 2>&1 || {
    echo "db_restore: age binary '$AGE_BIN' is required for encrypted dumps" >&2
    exit 2
  }
fi

BASE="${DUMP%.dump.age}"
BASE="${BASE%.dump}"
MANIFEST="$BASE.sha256"
if [[ -f "$MANIFEST" ]]; then
  echo "db_restore: verifying checksum against $(basename "$MANIFEST")"
  expected="$(awk -v file="$(basename "$DUMP")" '$2 == file { print $1; found=1 } END { if (!found) exit 2 }' "$MANIFEST")" || {
    echo "db_restore: manifest has no checksum for $(basename "$DUMP") — refusing to restore" >&2
    exit 1
  }
  printf '%s  %s\n' "$expected" "$DUMP" | sha256sum -c - >/dev/null || {
    echo "db_restore: checksum MISMATCH — refusing to restore" >&2
    exit 1
  }
  echo "db_restore: checksum OK"
else
  echo "db_restore: no manifest next to the dump — refusing to restore" >&2
  exit 1
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

RESTORE_DUMP="$DUMP"
TEMP_DUMP=""
cleanup() {
  [[ -n "$TEMP_DUMP" ]] && rm -f "$TEMP_DUMP"
}
trap cleanup EXIT

if [[ "$DUMP" == *.dump.age ]]; then
  TEMP_DUMP="$(mktemp "${TMPDIR:-/tmp}/cryptoscan-restore.XXXXXX.dump")"
  echo "db_restore: decrypting $(basename "$DUMP") into a temporary file"
  "$AGE_BIN" --decrypt --identity "$BACKUP_AGE_IDENTITY" < "$DUMP" > "$TEMP_DUMP"
  chmod 600 "$TEMP_DUMP"
  RESTORE_DUMP="$TEMP_DUMP"
fi

echo "db_restore: restoring into $POSTGRES_DB"
dc exec -T postgres pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists --no-owner \
  < "$RESTORE_DUMP"

echo "db_restore: done. Confirm the schema revision, then start the stack:"
echo "  DATABASE_URL=\"postgresql://$POSTGRES_USER@localhost:5432/$POSTGRES_DB\" \\"
echo "    python -m alembic -c services/database/migrations/alembic.ini current"
echo "  bash scripts/deploy_prod.sh -d"
