#!/usr/bin/env bash
# Stand up a real two-node PostgreSQL primary/standby pair with streaming
# replication, so scripts/postgres_drill.py has something genuine to qualify
# against.
#
# Why this exists: the DR drill deliberately refuses to simulate. It needs two
# reachable instances in a real primary/standby relationship, and without them
# it reports PREFLIGHT/SKIP. That is the right behaviour, but it left the drill
# unrunnable for anyone without a staging cluster, so item 2 of fix.md stayed
# open purely for want of a topology.
#
# What this is NOT: production evidence. These are two containers on one host,
# sharing a kernel, a disk and a network namespace. It proves the replication
# and promotion *path* works and that the drill measures it, not that the
# customer's cluster meets an RPO/RTO target. Re-run the drill against the
# real pair before anyone signs anything.
#
#   bash scripts/postgres_dr_sandbox.sh up      # start the pair, print DSNs
#   bash scripts/postgres_dr_sandbox.sh status  # roles + replication state
#   bash scripts/postgres_dr_sandbox.sh down    # remove containers + network
set -euo pipefail

IMAGE="${PG_IMAGE:-postgres:16-alpine}"
NET="${DR_NET:-cryptoscan-dr}"
PRIMARY="${DR_PRIMARY_NAME:-cryptoscan-dr-primary}"
STANDBY="${DR_STANDBY_NAME:-cryptoscan-dr-standby}"
PRIMARY_PORT="${DR_PRIMARY_PORT:-55432}"
STANDBY_PORT="${DR_STANDBY_PORT:-55433}"
SUPERPASS="${DR_SUPERPASS:-drill}"
REPLPASS="${DR_REPLPASS:-replicate}"
DB="${DR_DB:-cryptoscan}"

log() { printf '%s %s\n' "[dr-sandbox]" "$*" >&2; }

wait_ready() {
  # A real query, not pg_isready. The postgres image runs a temporary server
  # during initdb and then shuts it down before starting the real one, so
  # pg_isready answers "ready" on a socket that is about to disappear and the
  # next command dies with "the database system is shutting down".
  # Requiring N consecutive successful SELECTs rides out that window.
  local name=$1 tries=${2:-90} streak=0 need=3
  for _ in $(seq "$tries"); do
    if docker exec -u postgres "$name" psql -tAq -c 'SELECT 1' >/dev/null 2>&1; then
      streak=$(( streak + 1 ))
      [ "$streak" -ge "$need" ] && return 0
    else
      streak=0
    fi
    sleep 1
  done
  log "FATAL: $name did not become ready"
  docker logs --tail 40 "$name" >&2 || true
  return 1
}

up() {
  down >/dev/null 2>&1 || true
  docker network create "$NET" >/dev/null
  log "network $NET created"

  # --- primary -------------------------------------------------------------
  # wal_level=replica + wal_senders is what makes streaming possible at all;
  # hot_standby_feedback keeps the standby's queries from being cancelled.
  docker run -d --name "$PRIMARY" --network "$NET" \
    -e POSTGRES_PASSWORD="$SUPERPASS" -e POSTGRES_DB="$DB" \
    -p "127.0.0.1:${PRIMARY_PORT}:5432" "$IMAGE" \
    -c wal_level=replica -c max_wal_senders=10 -c max_replication_slots=10 \
    -c hot_standby=on -c synchronous_commit=on >/dev/null
  log "primary starting on 127.0.0.1:${PRIMARY_PORT}"
  wait_ready "$PRIMARY"

  docker exec -u postgres "$PRIMARY" psql -q -v ON_ERROR_STOP=1 -c \
    "CREATE ROLE repl WITH REPLICATION LOGIN PASSWORD '${REPLPASS}';"
  # trust replication from the container network only; the port publish is
  # bound to loopback so nothing off-host can reach either node.
  docker exec -u postgres "$PRIMARY" bash -c \
    "echo 'host replication repl all md5' >> /var/lib/postgresql/data/pg_hba.conf"
  docker exec -u postgres "$PRIMARY" psql -q -c "SELECT pg_reload_conf();" >/dev/null
  docker exec -u postgres "$PRIMARY" psql -q -v ON_ERROR_STOP=1 -c \
    "SELECT pg_create_physical_replication_slot('standby_slot');" >/dev/null
  log "replication role + slot created"

  # --- standby -------------------------------------------------------------
  # Base-backup into an empty volume, then start in recovery. Done in one
  # container so the backup and the server see the same data directory.
  # --user postgres: overriding the entrypoint bypasses the image's own
  # step-down, and postgres refuses to run as root.
  docker run -d --name "$STANDBY" --network "$NET" \
    --user postgres \
    -e PGPASSWORD="$REPLPASS" \
    -p "127.0.0.1:${STANDBY_PORT}:5432" \
    --entrypoint bash "$IMAGE" -c '
      set -e
      rm -rf /var/lib/postgresql/data/*
      until pg_isready -h '"$PRIMARY"' -U postgres -q; do sleep 1; done
      pg_basebackup -h '"$PRIMARY"' -U repl -D /var/lib/postgresql/data \
        -Fp -Xs -R -S standby_slot -c fast
      chmod 0700 /var/lib/postgresql/data
      exec postgres -c hot_standby=on
    ' >/dev/null
  log "standby starting on 127.0.0.1:${STANDBY_PORT} (base backup in progress)"
  wait_ready "$STANDBY" 120

  status
  cat <<EOF

Export these, then run the drill:

  export DR_PRIMARY_DSN='postgresql://postgres:${SUPERPASS}@127.0.0.1:${PRIMARY_PORT}/${DB}'
  export DR_STANDBY_DSN='postgresql://postgres:${SUPERPASS}@127.0.0.1:${STANDBY_PORT}/${DB}'
  export DR_PROMOTE_COMMAND='docker exec -u postgres ${STANDBY} pg_ctl promote -D /var/lib/postgresql/data'

Promotion is one-way: the standby becomes a primary and stops following.
Re-run '$0 up' to rebuild the pair for another drill.
EOF
}

status() {
  local p s
  p=$(docker exec -u postgres "$PRIMARY" psql -tAc "SELECT pg_is_in_recovery();" 2>/dev/null || echo "?")
  s=$(docker exec -u postgres "$STANDBY" psql -tAc "SELECT pg_is_in_recovery();" 2>/dev/null || echo "?")
  log "primary in_recovery=${p} (expect f)    standby in_recovery=${s} (expect t)"
  log "replication on primary:"
  docker exec -u postgres "$PRIMARY" psql -x -c \
    "SELECT client_addr, state, sync_state, sent_lsn, replay_lsn FROM pg_stat_replication;" 2>/dev/null || true
}

RESTORE="${DR_RESTORE_NAME:-cryptoscan-dr-restore}"
RESTORE_PORT="${DR_RESTORE_PORT:-55434}"
RESTORE_DB="${DR_RESTORE_DB:-restored}"

# An empty third node for the drill's --clean-restore-dsn. Separate from the
# pair because the point of a clean restore is that the target has never seen
# the data: restoring into the standby would prove nothing.
restore_target() {
  docker rm -f "$RESTORE" >/dev/null 2>&1 || true
  docker run -d --name "$RESTORE" --network "$NET" \
    -e POSTGRES_PASSWORD="$SUPERPASS" -e POSTGRES_DB="$RESTORE_DB" \
    -p "127.0.0.1:${RESTORE_PORT}:5432" "$IMAGE" >/dev/null
  wait_ready "$RESTORE"
  log "clean restore target ready on 127.0.0.1:${RESTORE_PORT}"
  echo "postgresql://postgres:${SUPERPASS}@127.0.0.1:${RESTORE_PORT}/${RESTORE_DB}"
}

# The drill's --restore-command. Lives here rather than in a scratch file so a
# qualification run is reproducible from the repository alone; an ad-hoc
# script in /tmp silently disappears and the drill then reports a restore
# failure that is really a missing file.
restore_now() {
  local dump="${DR_DUMP_PATH:-/tmp/cryptoscan-dr-dump.pgc}"
  docker exec -u postgres "$PRIMARY" pg_dump -U postgres -Fc "$DB" > "$dump"
  docker exec -u postgres -i "$RESTORE" \
    pg_restore -U postgres -d "$RESTORE_DB" --clean --if-exists < "$dump"
  log "restored $(wc -c <"$dump") bytes into ${RESTORE}/${RESTORE_DB}"
}

down() {
  docker rm -f "$PRIMARY" "$STANDBY" "$RESTORE" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  log "torn down"
}

case "${1:-up}" in
  up) up ;;
  status) status ;;
  restore-target) restore_target ;;
  restore-now) restore_now ;;
  down) down ;;
  *) echo "usage: $0 {up|status|restore-target|restore-now|down}" >&2; exit 2 ;;
esac
