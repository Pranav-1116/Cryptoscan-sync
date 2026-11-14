#!/bin/bash
# Automated base backup with retention — the 'recover from database failure'
# capability. Nightly (cron sidecar in docker-compose.yml), writes to the
# backup volume: base backups under /pgbackup/base/, WAL under /pgbackup/archive/.
#
# Retention: BASE_BACKUP_KEEP_DAYS (default 14) base backups, WAL kept as
# long as the oldest base backup (PITR needs the chain). Deleting a backup
# is a dated-directory removal; nothing else touches the archive.
set -euo pipefail

KEEP_DAYS="${BASE_BACKUP_KEEP_DAYS:-14}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
DEST="/pgbackup/base/${STAMP}"
export PGPASSWORD="${POSTGRES_PASSWORD:?set POSTGRES_PASSWORD}"

echo "pgbackup: starting base backup ${DEST}"
mkdir -p "${DEST}"
pg_basebackup -h "${PGHOST:-postgres}" -U "${PGUSER:-cryptoscan}" \
    -D "${DEST}" -Ft -z -X stream
echo "${DEST}" > /pgbackup/base/LATEST
echo "pgbackup: complete"

echo "pgbackup: pruning base backups older than ${KEEP_DAYS} days"
find /pgbackup/base -maxdepth 1 -type d -name '20*' -mtime "+${KEEP_DAYS}" \
    -exec rm -rf {} +
echo "pgbackup: retention applied"
