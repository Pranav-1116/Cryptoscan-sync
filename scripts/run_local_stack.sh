#!/usr/bin/env bash
# Bring up the whole product locally: PostgreSQL, the API, and the console.
#
# run_stack.sh starts only the API and leaves the database and frontend to
# you. This starts all three against a real PostgreSQL (not SQLite), which is
# what production mandates, so what you look at is the shipping data path.
#
#   bash scripts/run_local_stack.sh up      # start everything, print URLs
#   bash scripts/run_local_stack.sh status  # what is listening
#   bash scripts/run_local_stack.sh logs    # tail api + frontend
#   bash scripts/run_local_stack.sh down    # stop everything
#
# The estate boots EMPTY. There is no demo data and no seeding: inventory
# appears only when a real scan runs against a target you configure. Pages
# with nothing to show render honest empty states rather than samples.
#
# Scan targets are confined to CRYPTOSCAN_SOURCE_ROOTS, which defaults to this
# repository. To scan code checked out elsewhere, widen it deliberately:
#
#   LOCAL_SOURCE_ROOTS="$PWD:/srv/checkouts" bash scripts/run_local_stack.sh up
#
# That containment is a real control -- the API refuses a path outside the
# roots -- so it is set explicitly here rather than left to a default that
# happens to be permissive.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

DB_NAME="${LOCAL_DB_NAME:-cryptoscan-local-db}"
DB_PORT="${LOCAL_DB_PORT:-55440}"
DB_USER="${LOCAL_DB_USER:-cryptoscan}"
DB_PASS="${LOCAL_DB_PASS:-cryptoscan}"
API_PORT="${LOCAL_API_PORT:-8010}"
UI_PORT="${LOCAL_UI_PORT:-3003}"   # must match frontend/vite.config.ts
PY="${PY:-$ROOT/.venv/bin/python}"
RUN="${LOCAL_RUN_DIR:-$ROOT/.local-stack}"

ADMIN_USER="${LOCAL_ADMIN_USER:-admin}"
ADMIN_PASS="${LOCAL_ADMIN_PASS:-cryptoscan}"

export DATABASE_URL="postgresql+psycopg2://${DB_USER}:${DB_PASS}@127.0.0.1:${DB_PORT}/${DB_USER}"

log() { printf '[stack] %s\n' "$*" >&2; }
pid_on() { ss -lptn "sport = :$1" 2>/dev/null | grep -oP 'pid=\K[0-9]+' | head -1; }

# Absolute, deliberately: the migration step runs alembic from
# services/database/migrations, and relative entries stop resolving the
# moment the working directory changes.
pypath() { find "$ROOT/services" "$ROOT/shared" -mindepth 1 -maxdepth 1 -type d | tr '\n' ':'; }

wait_db() {
  for _ in $(seq 90); do
    docker exec -u postgres "$DB_NAME" psql -U "$DB_USER" -tAq -c 'SELECT 1' >/dev/null 2>&1 && return 0
    sleep 1
  done
  log "FATAL: database never became ready"; docker logs --tail 30 "$DB_NAME" >&2; return 1
}

up() {
  mkdir -p "$RUN"

  # ---- database ----------------------------------------------------------
  if ! docker ps --format '{{.Names}}' | grep -qx "$DB_NAME"; then
    docker rm -f "$DB_NAME" >/dev/null 2>&1 || true
    docker run -d --name "$DB_NAME" \
      -e POSTGRES_USER="$DB_USER" -e POSTGRES_PASSWORD="$DB_PASS" -e POSTGRES_DB="$DB_USER" \
      -p "127.0.0.1:${DB_PORT}:5432" postgres:16-alpine >/dev/null
    log "postgres starting on 127.0.0.1:${DB_PORT}"
  else
    log "postgres already running"
  fi
  wait_db
  log "postgres ready"

  # ---- schema ------------------------------------------------------------
  ( cd services/database/migrations \
    && PYTHONPATH="$(pypath)" ENVIRONMENT=development \
       "$PY" -m alembic upgrade head >/dev/null )
  log "migrations applied ($(docker exec -u postgres "$DB_NAME" psql -U "$DB_USER" -tAq \
      -c "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'") tables)"

  # ---- api ---------------------------------------------------------------
  if [ -n "$(pid_on "$API_PORT")" ]; then
    log "api already listening on ${API_PORT}"
  else
    PYTHONPATH="$(pypath)" \
    ENVIRONMENT=development \
    SECRET_KEY="${LOCAL_SECRET_KEY:-local-stack-secret-key-min-32-characters}" \
    GITHUB_WEBHOOK_SECRET="${LOCAL_WEBHOOK_SECRET:-local-stack-webhook-secret-abc123}" \
    ADMIN_USERNAME="$ADMIN_USER" ADMIN_PASSWORD="$ADMIN_PASS" \
    DATABASE_URL="$DATABASE_URL" \
    CRYPTOSCAN_SNAPSHOT_DIR="$RUN/data" \
    CRYPTOSCAN_SOURCE_ROOTS="${LOCAL_SOURCE_ROOTS:-$ROOT}" \
    nohup "$PY" -m uvicorn api.main:app --host 127.0.0.1 --port "$API_PORT" \
      --log-level info > "$RUN/api.log" 2>&1 &
    log "api starting on ${API_PORT}"
  fi
  for _ in $(seq 90); do
    curl -sf --max-time 2 "http://127.0.0.1:${API_PORT}/health" >/dev/null 2>&1 && break
    sleep 1
  done

  # ---- frontend ----------------------------------------------------------
  if [ -n "$(pid_on "$UI_PORT")" ]; then
    log "frontend already listening on ${UI_PORT}"
  else
    [ -d frontend/node_modules ] || ( cd frontend && npm ci --no-audit --no-fund >/dev/null 2>&1 )
    ( cd frontend && nohup npx vite --host 127.0.0.1 > "$RUN/frontend.log" 2>&1 & )
    log "frontend starting on ${UI_PORT}"
  fi
  for _ in $(seq 90); do
    curl -sf --max-time 2 "http://127.0.0.1:${UI_PORT}/" >/dev/null 2>&1 && break
    sleep 1
  done

  status
}

status() {
  echo
  printf '  %-12s %-34s %s\n' COMPONENT URL STATE
  printf '  %-12s %-34s %s\n' "console" "http://127.0.0.1:${UI_PORT}" \
    "$(curl -sf --max-time 2 "http://127.0.0.1:${UI_PORT}/" >/dev/null 2>&1 && echo up || echo DOWN)"
  printf '  %-12s %-34s %s\n' "api" "http://127.0.0.1:${API_PORT}/health" \
    "$(curl -sf --max-time 2 "http://127.0.0.1:${API_PORT}/health" >/dev/null 2>&1 && echo up || echo DOWN)"
  printf '  %-12s %-34s %s\n' "api docs" "http://127.0.0.1:${API_PORT}/api/docs" ""
  printf '  %-12s %-34s %s\n' "postgres" "127.0.0.1:${DB_PORT}" \
    "$(docker exec -u postgres "$DB_NAME" psql -U "$DB_USER" -tAq -c 'SELECT 1' >/dev/null 2>&1 && echo up || echo DOWN)"
  echo
  echo "  sign in: ${ADMIN_USER} / ${ADMIN_PASS}   (development only; refused in production)"
  echo "  the estate boots EMPTY — run a scan to populate it"
  echo "  logs: $RUN/api.log  $RUN/frontend.log"
  echo
}

logs() { tail -n 40 -F "$RUN/api.log" "$RUN/frontend.log"; }

down() {
  for port in "$API_PORT" "$UI_PORT"; do
    p="$(pid_on "$port")"; [ -n "$p" ] && kill "$p" 2>/dev/null && log "stopped :$port"
  done
  docker rm -f "$DB_NAME" >/dev/null 2>&1 && log "database removed" || true
}

case "${1:-up}" in
  up) up ;;
  status) status ;;
  logs) logs ;;
  down) down ;;
  *) echo "usage: $0 {up|status|logs|down}" >&2; exit 2 ;;
esac
