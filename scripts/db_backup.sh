#!/usr/bin/env bash
# Production database backup: PostgreSQL (custom format) + optional Neo4j dump.
# Every artifact is encrypted with age when BACKUP_AGE_RECIPIENT is set; in
# production encryption is required, so a missing age binary/key fails before
# any plaintext dump is written.
#
# Usage:
#   BACKUP_AGE_RECIPIENT=age1... bash scripts/db_backup.sh
#   BACKUP_AGE_RECIPIENT=age1... bash scripts/db_backup.sh --with-neo4j
#   BACKUP_DIR=/var/backups/cryptoscan KEEP=30 bash scripts/db_backup.sh
#
# Environment:
#   COMPOSE_ARGS             compose file selection
#   POSTGRES_USER            default cryptoscan
#   POSTGRES_DB              default cryptoscan
#   BACKUP_DIR               default ./backups/db
#   KEEP                     default 14
#   BACKUP_AGE_RECIPIENT     age recipient; required unless explicitly disabled
#   BACKUP_ENCRYPTION_REQUIRED 1 by default; set 0 only for local development
#   AGE_BIN                  default age
#
# A backup that stays on the same host is not a backup — copy BACKUP_DIR off
# the host (object storage / vault) after this script succeeds.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

COMPOSE_ARGS="${COMPOSE_ARGS:--f docker-compose.yml -f docker-compose.prod.yml}"
POSTGRES_USER="${POSTGRES_USER:-cryptoscan}"
POSTGRES_DB="${POSTGRES_DB:-cryptoscan}"
BACKUP_DIR="${BACKUP_DIR:-$ROOT/backups/db}"
KEEP="${KEEP:-14}"
BACKUP_AGE_RECIPIENT="${BACKUP_AGE_RECIPIENT:-}"
BACKUP_ENCRYPTION_REQUIRED="${BACKUP_ENCRYPTION_REQUIRED:-1}"
AGE_BIN="${AGE_BIN:-age}"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
WITH_NEO4J=0
[[ "${1:-}" == "--with-neo4j" ]] && WITH_NEO4J=1

mkdir -p "$BACKUP_DIR"

dc() { docker compose $COMPOSE_ARGS "$@"; }

NEO4J_STOPPED=0
PG_PLAIN=""
PG_ARTIFACT=""
NEO_PLAIN=""
NEO_ARTIFACT=""
cleanup() {
  # When encryption is required, remove plaintext even if pg_dump/age or the
  # Neo4j dump fails midway. A production backup must never leave a partial
  # unencrypted artifact behind after an interrupted command.
  if [[ "$ENCRYPT" == "1" ]]; then
    [[ -z "$PG_PLAIN" ]] || rm -f -- "$PG_PLAIN"
    [[ -z "$NEO_PLAIN" ]] || rm -f -- "$NEO_PLAIN"
  fi
  if [[ "$NEO4J_STOPPED" == "1" ]]; then
    echo "db_backup: restarting neo4j after interrupted dump" >&2
    dc start neo4j >/dev/null || true
  fi
}
trap cleanup EXIT

ENCRYPT=0
if [[ -n "$BACKUP_AGE_RECIPIENT" ]]; then
  command -v "$AGE_BIN" >/dev/null 2>&1 || {
    echo "db_backup: age binary '$AGE_BIN' is required for encrypted backups" >&2
    exit 2
  }
  ENCRYPT=1
elif [[ "$BACKUP_ENCRYPTION_REQUIRED" == "1" ]]; then
  echo "db_backup: BACKUP_AGE_RECIPIENT is required; refusing to create plaintext production backup" >&2
  echo "db_backup: set BACKUP_ENCRYPTION_REQUIRED=0 only for a local development drill" >&2
  exit 2
else
  echo "db_backup: WARNING encryption explicitly disabled (development only)" >&2
fi

# Postgres must be up to dump it.
if ! dc ps --status running --services | grep -q '^postgres$'; then
  echo "db_backup: postgres service is not running — nothing to back up" >&2
  exit 2
fi

PG_PLAIN="$BACKUP_DIR/pg-$TS.dump"
PG_ARTIFACT="$PG_PLAIN"
echo "db_backup: dumping postgres ($POSTGRES_DB) -> $PG_PLAIN"
dc exec -T postgres pg_dump -U "$POSTGRES_USER" -Fc "$POSTGRES_DB" > "$PG_PLAIN"
if [[ "$ENCRYPT" == "1" ]]; then
  PG_ARTIFACT="$PG_PLAIN.age"
  "$AGE_BIN" --encrypt --recipient "$BACKUP_AGE_RECIPIENT" < "$PG_PLAIN" > "$PG_ARTIFACT"
  rm -f "$PG_PLAIN"
  echo "db_backup: encrypted postgres -> $PG_ARTIFACT"
fi

ARTIFACTS=("$PG_ARTIFACT")

# Neo4j 5 Community can only dump an offline database. Opt in explicitly.
if [[ "$WITH_NEO4J" == "1" ]]; then
  NEO_PLAIN="$BACKUP_DIR/neo4j-$TS.dump"
  NEO_ARTIFACT="$NEO_PLAIN"
  echo "db_backup: stopping neo4j for a consistent dump"
  dc stop neo4j >/dev/null
  NEO4J_STOPPED=1
  if dc run --rm --entrypoint sh neo4j -c \
      "neo4j-admin database dump neo4j --to-stdout" > "$NEO_PLAIN"; then
    if [[ "$ENCRYPT" == "1" ]]; then
      NEO_ARTIFACT="$NEO_PLAIN.age"
      "$AGE_BIN" --encrypt --recipient "$BACKUP_AGE_RECIPIENT" < "$NEO_PLAIN" > "$NEO_ARTIFACT"
      rm -f "$NEO_PLAIN"
    fi
    ARTIFACTS+=("$NEO_ARTIFACT")
    echo "db_backup: neo4j dumped${ENCRYPT:+ and encrypted}"
  else
    echo "db_backup: WARNING neo4j dump failed (continuing; postgres backup is complete)" >&2
    rm -f "$NEO_PLAIN" "$NEO_PLAIN.age"
  fi
  dc start neo4j >/dev/null
  NEO4J_STOPPED=0
else
  echo "db_backup: skipping neo4j (use --with-neo4j for a consistent graph dump)"
fi

# sha256 manifest + provenance, so restores can be verified offline. The
# checksum covers the encrypted bytes, not an unencrypted temporary stream.
MANIFEST="$BACKUP_DIR/pg-$TS.sha256"
CHECKSUM_FILES=()
for artifact in "${ARTIFACTS[@]}"; do
  CHECKSUM_FILES+=("$(basename "$artifact")")
done
(
  cd "$BACKUP_DIR"
  sha256sum "${CHECKSUM_FILES[@]}" > "$MANIFEST"
  {
    echo "created_utc=$TS"
    echo "postgres_db=$POSTGRES_DB"
    echo "compose_args=$COMPOSE_ARGS"
    echo "encrypted=$ENCRYPT"
    echo "encryption=age"
    echo "host=$(hostname 2>/dev/null || echo unknown)"
  } >> "$MANIFEST"
)
echo "db_backup: manifest written ($MANIFEST)"

# Retention: keep the newest $KEEP postgres artifacts and their manifests.
mapfile -t OLD_ARTIFACTS < <(
  find "$BACKUP_DIR" -maxdepth 1 -type f \
    \( -name 'pg-*.dump' -o -name 'pg-*.dump.age' \) \
    -printf '%T@ %p\n' | sort -nr | tail -n +$((KEEP + 1)) | cut -d' ' -f2-
)
for old in "${OLD_ARTIFACTS[@]}"; do
  [[ -z "$old" ]] && continue
  echo "db_backup: pruning $(basename "$old")"
  rm -f "$old" "${old%.dump.age}.sha256" "${old%.dump}.sha256"
done

echo "db_backup: OK — encrypted=$ENCRYPT; now copy $BACKUP_DIR off this host (object storage / vault)."
