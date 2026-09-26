#!/usr/bin/env bash
# Production database backup: PostgreSQL (custom format) + optional Neo4j dump,
# each with a sha256 manifest and retention pruning.
#
# Usage:
#   bash scripts/db_backup.sh                    # postgres only (online, safe)
#   bash scripts/db_backup.sh --with-neo4j       # brief neo4j stop/dump/start
#   BACKUP_DIR=/var/backups/cryptoscan KEEP=30 bash scripts/db_backup.sh
#
# Environment:
#   COMPOSE_ARGS   compose file selection   (default: the production overlay)
#   POSTGRES_USER  (default cryptoscan)     POSTGRES_DB (default cryptoscan)
#   BACKUP_DIR     (default ./backups/db)   KEEP         (default 14)
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
TS="$(date -u +%Y%m%dT%H%M%SZ)"
WITH_NEO4J=0
[[ "${1:-}" == "--with-neo4j" ]] && WITH_NEO4J=1

mkdir -p "$BACKUP_DIR"

dc() { docker compose $COMPOSE_ARGS "$@"; }

# Postgres must be up to dump it.
if ! dc ps --status running --services | grep -q '^postgres$'; then
  echo "db_backup: postgres service is not running — nothing to back up" >&2
  exit 2
fi

echo "db_backup: dumping postgres ($POSTGRES_DB) -> $BACKUP_DIR/pg-$TS.dump"
dc exec -T postgres pg_dump -U "$POSTGRES_USER" -Fc "$POSTGRES_DB" \
  > "$BACKUP_DIR/pg-$TS.dump"

# Neo4j 5 Community can only dump an offline database. Opt in explicitly.
if [[ "$WITH_NEO4J" == "1" ]]; then
  echo "db_backup: stopping neo4j for a consistent dump"
  dc stop neo4j >/dev/null
  if dc run --rm --entrypoint sh neo4j -c \
      "neo4j-admin database dump neo4j --to-stdout" > "$BACKUP_DIR/neo4j-$TS.dump"; then
    echo "db_backup: neo4j dumped"
  else
    echo "db_backup: WARNING neo4j dump failed (continuing; postgres backup is complete)" >&2
  fi
  dc start neo4j >/dev/null
else
  echo "db_backup: skipping neo4j (use --with-neo4j for a consistent graph dump)"
fi

# sha256 manifest + provenance, so restores can be verified offline.
{
  cd "$BACKUP_DIR"
  sha256sum "pg-$TS.dump" $( [[ -f "neo4j-$TS.dump" ]] && echo "neo4j-$TS.dump" ) > "pg-$TS.sha256"
  cd "$ROOT"
} 
{
  echo "created_utc=$TS"
  echo "postgres_db=$POSTGRES_DB"
  echo "compose_args=$COMPOSE_ARGS"
  echo "host=$(hostname 2>/dev/null || echo unknown)"
} >> "$BACKUP_DIR/pg-$TS.sha256"
echo "db_backup: manifest written ($BACKUP_DIR/pg-$TS.sha256)"

# Retention: keep the newest $KEEP postgres dumps.
ls -1t "$BACKUP_DIR"/pg-*.dump 2>/dev/null | tail -n +$((KEEP + 1)) | while read -r old; do
  echo "db_backup: pruning $(basename "$old")"
  rm -f "$old" "${old%.dump}.sha256"
done

echo "db_backup: OK — now copy $BACKUP_DIR off this host (object storage / vault)."
