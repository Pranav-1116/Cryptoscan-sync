#!/usr/bin/env bash
# Run the whole development stack from a checkout: API + console, one command.
#
# What this is
#   A zero-dependency launcher for a laptop or a sandbox: SQLite instead of
#   PostgreSQL, no Redis, no Docker, no worker. It is the same code path the
#   test suite uses (`ALLOW_SQLITE=1` + an unstamped dev database, which
#   `init_db()` builds from metadata).
#
# What this is NOT
#   A production or qualification deployment. There is no Redis, so realtime
#   fan-out falls back to the in-process bus and nothing consumes the scan
#   queue: a submitted scan stays QUEUED forever. There is no worker, no
#   collector and no signed install. Evidence appears only when an approved
#   collection actually runs — a fresh boot is EMPTY, and every screen is
#   supposed to say so. For the real local stack (Postgres + Redis + worker)
#   use scripts/run_local_stack.sh, which needs Docker.
#
# Usage
#   bash scripts/run_dev_stack.sh              # API + console, Ctrl-C stops both
#   bash scripts/run_dev_stack.sh api          # API only
#   bash scripts/run_dev_stack.sh console      # console only
#   bash scripts/run_dev_stack.sh status       # what is listening, and is it healthy
#   bash scripts/run_dev_stack.sh down         # stop whatever this script started
#
# Environment (all optional)
#   API_PORT          default 8010
#   CONSOLE_PORT      default 3003
#   ADMIN_USERNAME    default admin
#   ADMIN_PASSWORD    default generated once and printed; never stored
#   SECRET_KEY        default a fixed dev value (refused in production anyway)
#   VITE_DEV_HOST     default 0.0.0.0 so a proxied preview can reach the dev server
#                     (vite.config.js binds 127.0.0.1 unless this is set)
#   VITE_DEV_ALLOWED_HOSTS  default ".e2b.app" for sandbox previews; set to the
#                     comma-separated hostnames you actually serve from
#   API_RELOAD=1      uvicorn --reload (slower start, watches the tree)
#   RESET_DB=1        move the SQLite development database aside first, so the
#                     admin bootstrap runs and the printed password applies
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# shellcheck source=env.sh
source "$ROOT/scripts/env.sh"

API_PORT="${API_PORT:-8010}"
CONSOLE_PORT="${CONSOLE_PORT:-3003}"
ADMIN_USERNAME="${ADMIN_USERNAME:-admin}"
# Resolved before anything reads it: `ensure_password` probes this database to
# decide whether the bootstrap will create an admin at all.
DATABASE_URL="${DATABASE_URL:-sqlite:///./data/cryptoscan.db}"
RUN_DIR="$ROOT/data/run"
mkdir -p "$RUN_DIR"
STATE="$RUN_DIR/dev-stack.env"

#: pids THIS invocation started. Only these may be stopped by its trap: a second
#: `run_dev_stack.sh status|api` must not tear down a stack it merely found running.
OWNED_PIDS=()

PY="$ROOT/.venv/bin/python"
[ -x "$PY" ] || PY="$(command -v python3 || true)"

log() { printf '[dev-stack] %s\n' "$*"; }
die() { printf '[dev-stack] %s\n' "$*" >&2; exit 1; }

listening() { ss -lntH "sport = :$1" 2>/dev/null | grep -q .; }

http_ok() { curl -sf --max-time 2 "http://127.0.0.1:$1$2" >/dev/null 2>&1; }

wait_http() { # port path label
  local i
  for i in $(seq 60); do http_ok "$1" "$2" && return 0; sleep 1; done
  return 1
}

preflight() {
  [ -n "$PY" ] || die "no python found: create the venv first:
  python3 -m venv .venv && .venv/bin/pip install -r requirements.txt"
  "$PY" -c 'import uvicorn, fastapi' 2>/dev/null \
    || die "$PY cannot import uvicorn/fastapi — install requirements into .venv"
  [ -d "$ROOT/frontend/node_modules" ] || die "frontend/node_modules is missing: (cd frontend && npm ci)"
  command -v npm >/dev/null 2>&1 || die "npm is not on PATH"
}

api_env() {
  export ENVIRONMENT="${ENVIRONMENT:-development}"
  export ALLOW_SQLITE=1
  export DATABASE_URL
  # Empty on purpose: development allows it, and nothing here pretends to have
  # durable realtime or a queue consumer. Production refuses to boot without it.
  export REDIS_URL="${REDIS_URL:-}"
  export SECRET_KEY="${SECRET_KEY:-local-dev-secret-key-min-32-characters!}"
  export GITHUB_WEBHOOK_SECRET="${GITHUB_WEBHOOK_SECRET:-local-dev-webhook-secret-abc123}"
  export ADMIN_USERNAME="$ADMIN_USERNAME"
  export ADMIN_PASSWORD="${ADMIN_PASSWORD:-}"
  export CRYPTOSCAN_SNAPSHOT_DIR="${CRYPTOSCAN_SNAPSHOT_DIR:-./data}"
  export CRYPTOSCAN_SOURCE_ROOTS="${CRYPTOSCAN_SOURCE_ROOTS:-$ROOT}"
}

#: how the operator should read the password line in the banner
PASSWORD_STATUS=""

db_user_count() {
  # Only the SQLite dev database can be probed without a client; anything else
  # reports "unknown" and the caller stays quiet rather than guessing.
  case "$DATABASE_URL" in
    sqlite:*) ;;
    *) echo unknown; return 0 ;;
  esac
  local path
  path="${DATABASE_URL#sqlite:///}"
  path="${path#sqlite://}"
  [ -f "$path" ] || { echo 0; return 0; }
  "$PY" - "$path" <<'PYEOF' 2>/dev/null || echo unknown
import sqlite3, sys
try:
    con = sqlite3.connect(sys.argv[1])
    print(con.execute("select count(*) from users").fetchone()[0])
except Exception:
    print("unknown")
PYEOF
}

# The bootstrap only creates an admin when the users table is empty. A generated
# password therefore applies exactly once; on a database that already has users
# it would be printed and silently not work, which is worse than saying so.
ensure_password() {
  if [ -n "${ADMIN_PASSWORD:-}" ]; then
    export ADMIN_PASSWORD
    PASSWORD_STATUS="from ADMIN_PASSWORD"
    return 0
  fi
  if [ -f "$STATE" ]; then
    # shellcheck disable=SC1090
    . "$STATE"
  fi
  local users
  users="$(db_user_count)"
  if [ -n "${ADMIN_PASSWORD:-}" ]; then
    export ADMIN_PASSWORD
    PASSWORD_STATUS="reused from data/run/dev-stack.env (this database already had an admin)"
    return 0
  fi
  if [ "$users" != "0" ] && [ "$users" != "unknown" ] && [ "$users" != "" ]; then
    # Bootstrap will skip: an admin row exists, so a new password changes nothing.
    PASSWORD_STATUS="UNKNOWN — this database already has $users user(s); the bootstrap is skipped, so the password you set the first time still applies. Pass ADMIN_PASSWORD=<that one>, or RESET_DB=1 for a clean bootstrap."
    ADMIN_PASSWORD=""
    export ADMIN_PASSWORD
    return 0
  fi
  ADMIN_PASSWORD="$(head -c 18 /dev/urandom | base64 | tr -d '/+=' | cut -c1-16)"
  umask 077
  printf 'ADMIN_PASSWORD=%s\n' "$ADMIN_PASSWORD" > "$STATE"
  umask 022
  export ADMIN_PASSWORD
  PASSWORD_STATUS="generated for this first bootstrap (also in data/run/dev-stack.env)"
}

reset_db() {
  local path="$DATABASE_URL"
  path="${path#sqlite:///}"; path="${path#sqlite://}"
  if [ -f "$path" ]; then
    local backup="${path}.$(date +%Y%m%d%H%M%S).bak"
    mv "$path" "$backup"
    log "RESET_DB=1 — moved $path to $backup; a fresh schema and admin are bootstrapped"
  fi
  rm -f "$STATE"
}

start_api() {
  if listening "$API_PORT"; then
    log "port $API_PORT already listening — reusing it (not starting a second API)"
    return 0
  fi
  api_env
  local reload=()
  [ "${API_RELOAD:-0}" = "1" ] && reload=(--reload --reload-dir services/api)
  log "starting API on :$API_PORT (SQLite, no Redis, no worker) → data/run/api.log"
  (
    cd "$ROOT"
    nohup "$PY" -m uvicorn api.main:app \
      --host 0.0.0.0 --port "$API_PORT" \
      --proxy-headers --forwarded-allow-ips='*' \
      "${reload[@]}" > "$RUN_DIR/api.log" 2>&1 &
    echo $!
  ) > "$RUN_DIR/api.pid"
  OWNED_PIDS+=("$(head -1 "$RUN_DIR/api.pid")")
  if ! wait_http "$API_PORT" /ready; then
    log "API never became ready — last 25 lines of data/run/api.log:"
    tail -25 "$RUN_DIR/api.log" >&2 || true
    return 1
  fi
  log "API ready: http://127.0.0.1:$API_PORT/ready"
}

start_console() {
  if listening "$CONSOLE_PORT"; then
    log "port $CONSOLE_PORT already listening — reusing it (not starting a second console)"
    return 0
  fi
  export VITE_DEV_HOST="${VITE_DEV_HOST:-0.0.0.0}"
  export VITE_DEV_ALLOWED_HOSTS="${VITE_DEV_ALLOWED_HOSTS:-.e2b.app}"
  log "starting console on :$CONSOLE_PORT (proxy /api → 127.0.0.1:$API_PORT) → data/run/console.log"
  (
    cd "$ROOT/frontend"
    nohup npm run dev > "$RUN_DIR/console.log" 2>&1 &
    echo $!
  ) > "$RUN_DIR/console.pid"
  OWNED_PIDS+=("$(head -1 "$RUN_DIR/console.pid")")
  local i
  for i in $(seq 60); do
    http_ok "$CONSOLE_PORT" "/" && { log "console ready: http://127.0.0.1:$CONSOLE_PORT"; return 0; }
    sleep 1
  done
  log "console did not answer on :$CONSOLE_PORT — last 25 lines of data/run/console.log:"
  tail -25 "$RUN_DIR/console.log" >&2 || true
  return 1
}

# Terminate a process and everything it spawned. `npm run dev` is npm → sh →
# vite → esbuild, and killing only the first pid leaves the port held.
kill_tree() {
  local pid="$1" child
  for child in $(pgrep -P "$pid" 2>/dev/null || true); do
    kill_tree "$child"
  done
  kill -TERM "$pid" 2>/dev/null || true
}

down() {
  # Re-entry here was a real bug: the first version killed the child's process
  # *group*, which on a non-interactive shell is also this script's group, so the
  # trap re-fired on itself and printed "stopping" forever.
  trap - INT TERM
  local stopped=0 name f pid port i
  for name in console api; do
    f="$RUN_DIR/$name.pid"
    [ -f "$f" ] || continue
    pid="$(cat "$f" 2>/dev/null || true)"
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
      kill_tree "$pid"
      log "stopped $name (pid $pid)"
      stopped=1
    fi
    rm -f "$f"
  done
  [ "$stopped" = "1" ] || log "nothing recorded as running by this script"

  # Give them a moment, then confirm the ports actually came free, because a
  # "stopped" line over a port that still answers is the kind of lie this
  # repository is trying not to tell.
  for port in "$CONSOLE_PORT" "$API_PORT"; do
    for i in $(seq 10); do listening "$port" || break; sleep 0.5; done
    if listening "$port"; then
      log "port $port is still held by a process this script did not start — left alone"
    fi
  done
  return 0
}

# Stop only what this invocation started. Ctrl-C in a shell that merely reused a
# stack someone else started must leave that stack alone.
stop_owned() {
  trap - INT TERM
  local pid
  for pid in "${OWNED_PIDS[@]:-}"; do
    [ -n "$pid" ] || continue
    kill -0 "$pid" 2>/dev/null || continue
    kill_tree "$pid"
    log "stopped pid $pid (started by this invocation)"
  done
  OWNED_PIDS=()
}

status() {
  printf '%-10s %-6s %s\n' "process" "port" "state"
  if listening "$API_PORT"; then
    printf '%-10s %-6s %s\n' "api" "$API_PORT" "$(http_ok "$API_PORT" /ready && echo 'ready (GET /ready 200)' || echo 'listening but /ready is not 200 — read data/run/api.log')"
  else
    printf '%-10s %-6s %s\n' "api" "$API_PORT" "not listening"
  fi
  if listening "$CONSOLE_PORT"; then
    printf '%-10s %-6s %s\n' "console" "$CONSOLE_PORT" "$(http_ok "$CONSOLE_PORT" / && echo 'serving (GET / 200)' || echo 'listening but GET / failed')"
  else
    printf '%-10s %-6s %s\n' "console" "$CONSOLE_PORT" "not listening"
  fi
  if listening "$API_PORT" && listening "$CONSOLE_PORT"; then
    local code
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://127.0.0.1:$CONSOLE_PORT/api/v1/health" || true)"
    case "$code" in
      200) echo "proxy        /api/v1/health via console → 200 (backend reachable)" ;;
      401) echo "proxy        /api/v1/health via console → 401 (backend reachable, auth required: this is a working proxy)" ;;
      *)   echo "proxy        /api/v1/health via console → ${code:-no answer} (backend reachable but not healthy, or proxy broken)" ;;
    esac
  fi
}

banner() {
  cat <<EOF

  console   http://127.0.0.1:$CONSOLE_PORT
  api docs  http://127.0.0.1:$API_PORT/api/docs
  login     $ADMIN_USERNAME / ${ADMIN_PASSWORD:-<set ADMIN_PASSWORD>}
            password: ${PASSWORD_STATUS:-as configured}

  An empty console is an empty estate, not a broken build: nothing has been
  collected, and no screen here is allowed to make that look healthy.
  No Redis → nothing consumes the scan queue, so a submitted scan stays QUEUED.
  Ctrl-C stops both processes.

EOF
}

foreground() {
  local pids=("${OWNED_PIDS[@]:-}")
  banner
  log "following logs; press Ctrl-C to stop"
  # Tail both logs until interrupted, then stop what we started.
  trap 'echo; log "stopping"; stop_owned; exit 0' INT TERM
  tail -n 5 -F "$RUN_DIR/api.log" "$RUN_DIR/console.log" 2>/dev/null &
  local tail_pid=$!
  while :; do
    sleep 2
    local alive=0 p
    for p in "${pids[@]:-}"; do [ -n "$p" ] && kill -0 "$p" 2>/dev/null && alive=1; done
    if [ "${#pids[@]}" -gt 0 ] && [ "$alive" = "0" ]; then
      log "both processes exited — read data/run/api.log and data/run/console.log"
      kill "$tail_pid" 2>/dev/null || true
      exit 2
    fi
  done
}

case "${1:-up}" in
  up|all|"")
    preflight
    [ "${RESET_DB:-0}" = "1" ] && reset_db
    ensure_password
    start_api || exit 1
    start_console || exit 1
    foreground
    ;;
  api)
    preflight
    [ "${RESET_DB:-0}" = "1" ] && reset_db
    ensure_password
    start_api || exit 1
    banner
    trap 'log "stopping api"; stop_owned; exit 0' INT TERM
    tail -f "$RUN_DIR/api.log"
    ;;
  console|frontend)
    preflight
    [ "${RESET_DB:-0}" = "1" ] && reset_db
    ensure_password
    start_console || exit 1
    banner
    trap 'log "stopping console"; stop_owned; exit 0' INT TERM
    tail -f "$RUN_DIR/console.log"
    ;;
  status) status ;;
  down|stop) down ;;
  *)
    echo "usage: bash scripts/run_dev_stack.sh [up|api|console|status|down]" >&2
    exit 64
    ;;
esac
