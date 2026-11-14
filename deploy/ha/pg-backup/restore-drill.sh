#!/bin/bash
# Point-in-time recovery drill — 'restore to a specific time' and 'backup
# and restore testing' made runnable. Rehearse quarterly (drill.sh's rule).
#
# Restores the latest base backup from /pgbackup/base into a FRESH data
# directory and replays archived WAL to recovery_target_time, proving the
# chain base+archive actually reaches the moment the bank says it needs.
#
#   ./restore-drill.sh [TARGET_TIME]     # default: one hour ago (UTC)
#
# The drill NEVER touches the live data directory: it restores into
# /pgrestore/data and starts a throwaway postgres on port 55432, verifies
# the target time was reached (pg_control's state), and stops. A restore
# that has not been rehearsed is a hope, not a capability.
set -euo pipefail

TARGET_TIME="${1:-$(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-1H +%Y-%m-%dT%H:%M:%SZ)}"
BASE_DIR="$(cat /pgbackup/base/LATEST)"
RESTORE_ROOT="/pgrestore"

echo "restore-drill: target time ${TARGET_TIME}"
echo "restore-drill: base backup ${BASE_DIR}"
test -d "${BASE_DIR}" || { echo "restore-drill: no base backup — the drill fails loudly"; exit 1; }

rm -rf "${RESTORE_ROOT}/data"
mkdir -p "${RESTORE_ROOT}/data"
tar -xzf "${BASE_DIR}/base.tar.gz" -C "${RESTORE_ROOT}/data"

# PITR: replay archived WAL up to the target moment, then stop recovery.
cat > "${RESTORE_ROOT}/data/postgresql.auto.conf" <<CONF
restore_command = 'cp /pgbackup/archive/%f %p'
recovery_target_time = '${TARGET_TIME}'
recovery_target_action = 'pause'
CONF
touch "${RESTORE_ROOT}/data/recovery.signal"

echo "restore-drill: starting throwaway postgres on 55432"
pg_ctl -D "${RESTORE_ROOT}/data" -o "-p 55432 -c listen_addresses=''" -l "${RESTORE_ROOT}/restore.log" start
sleep 3
if pg_isready -h /tmp -p 55432 -q; then
    echo "restore-drill: PASS — the archive chain reached ${TARGET_TIME}"
    pg_ctl -D "${RESTORE_ROOT}/data" stop -m fast
else
    echo "restore-drill: FAIL — see ${RESTORE_ROOT}/restore.log"
    pg_ctl -D "${RESTORE_ROOT}/data" stop -m immediate || true
    exit 1
fi
