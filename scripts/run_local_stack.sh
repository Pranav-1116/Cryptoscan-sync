#!/usr/bin/env bash
# Bring up the core local control plane: PostgreSQL, Redis, API, worker, console.
# Extra engines require separate staged provisioning; `tools` reports their
# observed service state without claiming that a running container is integrated.
#
# run_stack.sh starts only the API and leaves the database and frontend to
# you. This starts the local product against real PostgreSQL (not SQLite).
# Development-mode availability is not production qualification.
#
#   bash scripts/run_local_stack.sh up      # start everything, print URLs
#   bash scripts/run_local_stack.sh status  # what is listening
#   bash scripts/run_local_stack.sh logs    # tail api + frontend
#   bash scripts/run_local_stack.sh down    # stop everything, KEEP the data
#   bash scripts/run_local_stack.sh purge   # stop, then DELETE the estate
#
# A fresh estate boots EMPTY: the launcher never seeds inventory. Reused
# volumes retain their previous records and must be inspected before reuse.
# New observations require separately authorized collection.
# Privately configure LOCAL_ADMIN_PASS before the FIRST user registers if this
# estate needs an operator: bootstrap only works while the users table is empty.
# Supply LOCAL_DB_PASS_FILE and LOCAL_APP_PASS_FILE as absolute operator-owned
# secret files, plus distinct LOCAL_SECRET_KEY/LOCAL_WEBHOOK_SECRET every start.
# The application uses the separately provisioned NOBYPASSRLS PostgreSQL role.
# The launcher rejects default secrets and never places the DB password in Docker metadata.
# Existing volumes or running containers require an explicit reuse opt-in.
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
REDIS_NAME="${LOCAL_REDIS_NAME:-cryptoscan-local-redis}"
REDIS_PORT="${LOCAL_REDIS_PORT:-55441}"
DB_USER="${LOCAL_DB_USER:-cryptoscan}"
DB_PASS_FILE="${LOCAL_DB_PASS_FILE:-}"
APP_USER="${LOCAL_APP_USER:-cryptoscan_app}"
APP_PASS_FILE="${LOCAL_APP_PASS_FILE:-}"
# Named volumes, so the estate outlives the containers. Without these the
# data lived only in the container filesystem and `down` -- which does a
# `docker rm -f` -- destroyed every scan with no warning and no recovery.
DB_VOLUME="${LOCAL_DB_VOLUME:-cryptoscan-local-pgdata}"
REDIS_VOLUME="${LOCAL_REDIS_VOLUME:-cryptoscan-local-redisdata}"
API_PORT="${LOCAL_API_PORT:-8010}"
UI_PORT="${LOCAL_UI_PORT:-3003}"   # must match frontend/vite.config.js
PY="${PY:-$ROOT/.venv/bin/python}"
RUN="${LOCAL_RUN_DIR:-$ROOT/.local-stack}"

ADMIN_USER="${LOCAL_ADMIN_USER:-admin}"
# Bootstrap only with an operator-supplied private password. A known default
# would create a privileged account on every fresh local database.
ADMIN_PASS="${LOCAL_ADMIN_PASS-}"

export REDIS_URL="redis://127.0.0.1:${REDIS_PORT}/0"

log() { printf '[stack] %s\n' "$*" >&2; }
pid_on() { ss -lptn "sport = :$1" 2>/dev/null | grep -oP 'pid=\K[0-9]+' | head -1; }
owned_container() { [[ "$(docker inspect --format '{{index .Config.Labels "cryptoscan.local-stack"}}' "$1" 2>/dev/null || true)" == "1" ]]; }
owned_listener() {
  local port="$1" tag="$2" marker="$3" pid command
  pid="$(pid_on "$port")"
  [[ -n "$pid" && -f "$RUN/$tag.pid" && "$pid" == "$(<"$RUN/$tag.pid")" ]] || return 1
  command="$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || true)"
  [[ "$command" == *"$marker"* ]]
}

# Worker liveness by PID file, not by pgrep.
#
# `pgrep -f worker.main` matches any shell whose command line happens to
# contain that string -- including the very commands an operator or a drill
# runs to check on it. That false positive made this script report "worker
# already running" and skip starting a real one, leaving jobs queued in
# Redis with nothing consuming them, and made the reliability drill's
# restart check pass against a phantom.
worker_pid() {
  local f="$RUN/worker.pid"
  [ -f "$f" ] || return 1
  local p; p="$(cat "$f" 2>/dev/null)"
  [ -n "$p" ] && kill -0 "$p" 2>/dev/null &&
    tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | grep -q 'worker.main' && echo "$p"
}

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
  if [[ "${DB_PASS_FILE}" != /* || ! -f "${DB_PASS_FILE}" || -L "${DB_PASS_FILE}" || ! -r "${DB_PASS_FILE}" ]]; then
    log "FATAL: LOCAL_DB_PASS_FILE must be an existing readable absolute secret file (no default password)"
    return 2
  fi
  if [[ "${APP_PASS_FILE}" != /* || ! -f "${APP_PASS_FILE}" || -L "${APP_PASS_FILE}" || ! -r "${APP_PASS_FILE}" ]]; then
    log "FATAL: LOCAL_APP_PASS_FILE must be an existing readable absolute secret file"
    return 2
  fi
  local db_mode app_mode
  db_mode="$(stat -c %a "$DB_PASS_FILE")"
  app_mode="$(stat -c %a "$APP_PASS_FILE")"
  if (( (8#$db_mode & 0077) != 0 || (8#$app_mode & 0077) != 0 )); then
    log "FATAL: database secret files must not grant group/other access (use mode 0600)"
    return 2
  fi
  if [[ ! "$DB_USER" =~ ^[a-z_][a-z0-9_]*$ || ! "$APP_USER" =~ ^[a-z_][a-z0-9_]*$ || "$DB_USER" == "$APP_USER" ]]; then
    log "FATAL: migration and application role names must be distinct lowercase SQL identifiers"
    return 2
  fi
  local secret_key="${LOCAL_SECRET_KEY:-}" webhook_secret="${LOCAL_WEBHOOK_SECRET:-}"
  if [[ ${#secret_key} -lt 32 || ${#webhook_secret} -lt 32 ]]; then
    log "FATAL: supply distinct LOCAL_SECRET_KEY and LOCAL_WEBHOOK_SECRET (at least 32 characters each)"
    return 2
  fi
  if [[ "$secret_key" == "$webhook_secret" ]]; then
    log "FATAL: platform and webhook secrets must differ"
    return 2
  fi
  local encoded_password encoded_app_password
  encoded_password="$(python -I -c 'import sys; from urllib.parse import quote; print(quote(sys.stdin.read().rstrip("\n"), safe=""))' < "$DB_PASS_FILE")"
  encoded_app_password="$(python -I -c 'import sys; from urllib.parse import quote; print(quote(sys.stdin.read().rstrip("\n"), safe=""))' < "$APP_PASS_FILE")"
  if [[ -z "$encoded_password" || -z "$encoded_app_password" ]]; then
    log "FATAL: a local database credential file is empty"
    return 2
  fi
  export DATABASE_URL="postgresql+psycopg2://${DB_USER}:${encoded_password}@127.0.0.1:${DB_PORT}/${DB_USER}"
  local app_database_url="postgresql+psycopg2://${APP_USER}:${encoded_app_password}@127.0.0.1:${DB_PORT}/${DB_USER}"
  if [[ -n "${LOCAL_NEO4J_AUTH_FILE:-}" ]]; then
    if [[ "$LOCAL_NEO4J_AUTH_FILE" != /* || ! -f "$LOCAL_NEO4J_AUTH_FILE" ||
          -L "$LOCAL_NEO4J_AUTH_FILE" || ! -r "$LOCAL_NEO4J_AUTH_FILE" ]]; then
      log "FATAL: LOCAL_NEO4J_AUTH_FILE must name a readable absolute secret file"
      return 2
    fi
    if ! LOCAL_NEO4J_AUTH_FILE="$LOCAL_NEO4J_AUTH_FILE" "$PY" - <<'PY'
import os
from pathlib import Path
from neo4j import GraphDatabase
user, secret = Path(os.environ['LOCAL_NEO4J_AUTH_FILE']).read_text().strip().split('/', 1)
with GraphDatabase.driver('bolt://127.0.0.1:55912', auth=(user, secret), connection_timeout=3) as driver:
    driver.verify_connectivity()
PY
    then
      log "FATAL: the staged Neo4j Bolt service is unavailable or rejects its file-backed credential"
      return 2
    fi
    export NEO4J_URI=bolt://127.0.0.1:55912 NEO4J_USER=neo4j NEO4J_PASSWORD_FILE="$LOCAL_NEO4J_AUTH_FILE" NEO4J_REQUIRED=true
  fi
  if [[ "${LOCAL_EVIDENCE_REQUIRED:-1}" == "1" || -n "${SBOM_S3_ENDPOINT:-}" ]]; then
    for name in SBOM_S3_ENDPOINT SBOM_S3_BUCKET SBOM_S3_ACCESS_KEY_FILE SBOM_S3_SECRET_KEY_FILE; do
      if [[ -z "${!name:-}" ]]; then log "FATAL: $name is required for local bank-owned S3 evidence"; return 2; fi
    done
    for name in SBOM_S3_ACCESS_KEY_FILE SBOM_S3_SECRET_KEY_FILE; do
      if [[ "${!name}" != /* || ! -f "${!name}" || -L "${!name}" || ! -r "${!name}" ]]; then
        log "FATAL: $name must be an existing readable absolute credential file"
        return 2
      fi
      local s3_mode
      s3_mode="$(stat -c %a "${!name}")"
      if (( (8#$s3_mode & 0077) != 0 )); then
        log "FATAL: $name must not grant group/other access (use mode 0600)"
        return 2
      fi
    done
    if [[ "$SBOM_S3_ACCESS_KEY_FILE" == "$SBOM_S3_SECRET_KEY_FILE" ]]; then
      log "FATAL: S3 access and secret files must differ"
      return 2
    fi
    # A service identity must be provisioned separately; never mount the
    # object-store root credential as this API/worker identity.
    if ! PYTHONPATH="$(pypath)" ENVIRONMENT=development "$PY" -c \
        'import sys; from devsecops.artifact_store import storage_status; s=storage_status(); sys.exit(0 if s["mode"]=="BANK_S3_VERSIONED" and s["verdict"]!="REFUSE" else 1)' >/dev/null; then
      log "FATAL: the versioned bank-owned S3 bucket did not pass an exact-byte probe"
      return 2
    fi
    log "S3 versioning and exact-byte probe verified; backup/site qualification remains separate"
  fi
  mkdir -p "$RUN"

  # ---- database ----------------------------------------------------------
  if ! docker ps --format '{{.Names}}' | grep -qx "$DB_NAME"; then
    if docker container inspect "$DB_NAME" >/dev/null 2>&1; then
      log "FATAL: stopped container $DB_NAME exists; inspect it before restarting or removing it"
      return 2
    fi
    if docker volume inspect "$DB_VOLUME" >/dev/null 2>&1 && [[ "${LOCAL_REUSE_VOLUME:-0}" != "1" ]]; then
      log "FATAL: existing volume $DB_VOLUME may hold another estate; inspect it before LOCAL_REUSE_VOLUME=1"
      return 2
    fi
    docker run -d --name "$DB_NAME" --label cryptoscan.local-stack=1 \
      -e POSTGRES_USER="$DB_USER" -e POSTGRES_PASSWORD_FILE=/run/secrets/db-password -e POSTGRES_DB="$DB_USER" \
      -v "${DB_PASS_FILE}:/run/secrets/db-password:ro" \
      -v "${DB_VOLUME}:/var/lib/postgresql/data" \
      -p "127.0.0.1:${DB_PORT}:5432" postgres:16-alpine >/dev/null
    log "postgres starting on 127.0.0.1:${DB_PORT}"
  else
    if ! owned_container "$DB_NAME" || [[ "${LOCAL_REUSE_RUNNING:-0}" != "1" ]]; then
      log "FATAL: $DB_NAME is running; require a launcher-owned label and LOCAL_REUSE_RUNNING=1 after inspection"
      return 2
    fi
    log "postgres already running (operator-approved reuse)"
  fi
  wait_db
  log "postgres ready"

  # ---- redis -------------------------------------------------------------
  # Not optional scaffolding: without it the API falls back to an in-process
  # bus and the worker runs inline, so the queue, cross-replica fan-out and
  # Last-Event-ID replay are never exercised. Those are the parts update.md
  # section 2 asks to prove.
  if ! docker ps --format '{{.Names}}' | grep -qx "$REDIS_NAME"; then
    if docker container inspect "$REDIS_NAME" >/dev/null 2>&1; then
      log "FATAL: stopped container $REDIS_NAME exists; inspect it before restarting or removing it"
      return 2
    fi
    if docker volume inspect "$REDIS_VOLUME" >/dev/null 2>&1 && [[ "${LOCAL_REUSE_VOLUME:-0}" != "1" ]]; then
      log "FATAL: existing volume $REDIS_VOLUME may hold another estate; inspect it before LOCAL_REUSE_VOLUME=1"
      return 2
    fi
    docker run -d --name "$REDIS_NAME" --label cryptoscan.local-stack=1 \
      -v "${REDIS_VOLUME}:/data" \
      -p "127.0.0.1:${REDIS_PORT}:6379" redis:7-alpine redis-server --appendonly yes >/dev/null
    log "redis starting on 127.0.0.1:${REDIS_PORT}"
  else
    if ! owned_container "$REDIS_NAME" || [[ "${LOCAL_REUSE_RUNNING:-0}" != "1" ]]; then
      log "FATAL: $REDIS_NAME is running; require a launcher-owned label and LOCAL_REUSE_RUNNING=1 after inspection"
      return 2
    fi
    log "redis already running (operator-approved reuse)"
  fi
  for _ in $(seq 60); do
    docker exec "$REDIS_NAME" redis-cli ping 2>/dev/null | grep -q PONG && break
    sleep 1
  done
  if ! docker exec "$REDIS_NAME" redis-cli ping 2>/dev/null | grep -q PONG; then
    log "FATAL: redis never became ready"; return 1
  fi
  log "redis ready"

  # ---- schema ------------------------------------------------------------
  ( cd services/database/migrations \
    && PYTHONPATH="$(pypath)" ENVIRONMENT=development \
       "$PY" -m alembic upgrade head >/dev/null )
  log "migrations applied ($(docker exec -u postgres "$DB_NAME" psql -U "$DB_USER" -tAq \
      -c "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'") tables)"

  # Bind the runtime to a different PostgreSQL login. A migration superuser
  # bypasses tenant RLS even when every policy is enabled and FORCEd.
  LOCAL_APP_DATABASE_URL="$app_database_url" LOCAL_APP_USER="$APP_USER" \
    LOCAL_APP_PASS_FILE="$APP_PASS_FILE" PYTHONPATH="$(pypath)" "$PY" - <<'PY'
import os
from pathlib import Path
from sqlalchemy import create_engine, text
from db.rls import enforcement

role = os.environ["LOCAL_APP_USER"]  # shell validated as a lowercase SQL identifier
secret = Path(os.environ["LOCAL_APP_PASS_FILE"]).read_text().strip()
admin = create_engine(os.environ["DATABASE_URL"])
with admin.begin() as conn:
    if not conn.scalar(text("SELECT 1 FROM pg_roles WHERE rolname=:name"), {"name": role}):
        conn.execute(text('CREATE ROLE "' + role + '" LOGIN NOSUPERUSER NOBYPASSRLS '
                          'NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD :secret'),
                     {"secret": secret})
    conn.exec_driver_sql('GRANT CONNECT ON DATABASE "' + admin.url.database + '" TO "' + role + '"')
    conn.exec_driver_sql('GRANT USAGE ON SCHEMA public TO "' + role + '"')
    conn.exec_driver_sql('GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO "' + role + '"')
    conn.exec_driver_sql('GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO "' + role + '"')
    conn.exec_driver_sql('ALTER DEFAULT PRIVILEGES IN SCHEMA public '
                         'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO "' + role + '"')
    conn.exec_driver_sql('ALTER DEFAULT PRIVILEGES IN SCHEMA public '
                         'GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO "' + role + '"')
admin.dispose()
app = create_engine(os.environ["LOCAL_APP_DATABASE_URL"])
try:
    with app.connect() as conn:
        report = enforcement(conn)
        if not report["binds_this_role"] or report["superuser"] or report["bypassrls"]:
            raise RuntimeError("local application role does not bind tenant RLS")
        if report["tenant_tables"] < 100 or report["tables_with_rls_forced"] != report["tenant_tables"]:
            raise RuntimeError("local tenant tables do not all have forced RLS")
finally:
    app.dispose()
PY
  log "non-superuser runtime role and forced tenant RLS verified"
  export DATABASE_URL="$app_database_url"

  # ---- api ---------------------------------------------------------------
  if [ -n "$(pid_on "$API_PORT")" ]; then
    if ! owned_listener "$API_PORT" api 'api.main:app'; then
      log "FATAL: :$API_PORT is owned by an unrecognized process; refusing to reuse it"
      return 2
    fi
    log "launcher-owned API already listening on ${API_PORT}"
  else
    PYTHONPATH="$(pypath)" \
    ENVIRONMENT=development \
    SECRET_KEY="$secret_key" \
    GITHUB_WEBHOOK_SECRET="$webhook_secret" \
    ADMIN_USERNAME="$ADMIN_USER" ADMIN_PASSWORD="$ADMIN_PASS" \
    DATABASE_URL="$DATABASE_URL" \
    REDIS_URL="$REDIS_URL" \
    CRYPTOSCAN_SNAPSHOT_DIR="$RUN/data" \
    CRYPTOSCAN_SOURCE_ROOTS="${LOCAL_SOURCE_ROOTS:-$ROOT}" \
    nohup "$PY" -m uvicorn api.main:app --host 127.0.0.1 --port "$API_PORT" \
      --log-level info > "$RUN/api.log" 2>&1 &
    printf '%s\n' "$!" > "$RUN/api.pid"
    log "api starting on ${API_PORT}"
  fi
  for _ in $(seq 90); do
    curl -sf --max-time 2 "http://127.0.0.1:${API_PORT}/ready" >/dev/null 2>&1 && break
    sleep 1
  done
  if ! curl -sf --max-time 2 "http://127.0.0.1:${API_PORT}/ready" >/dev/null 2>&1; then
    log "FATAL: api never became ready (see $RUN/api.log)"; return 1
  fi

  # ---- worker ------------------------------------------------------------
  # With REDIS_URL set the API enqueues instead of running the pipeline
  # inline, so without this process a triggered scan sits in the queue
  # forever and the job stays QUEUED.
  if worker_pid >/dev/null; then
    log "worker already running"
  else
    PYTHONPATH="$(pypath)" \
    ENVIRONMENT=development \
    SECRET_KEY="$secret_key" \
    DATABASE_URL="$DATABASE_URL" \
    REDIS_URL="$REDIS_URL" \
    CRYPTOSCAN_SNAPSHOT_DIR="$RUN/data" \
    CRYPTOSCAN_SOURCE_ROOTS="${LOCAL_SOURCE_ROOTS:-$ROOT}" \
    nohup "$PY" -m worker.main > "$RUN/worker.log" 2>&1 &
    echo $! > "$RUN/worker.pid"
    log "worker starting (pid $(cat "$RUN/worker.pid"))"
  fi

  # ---- frontend ----------------------------------------------------------
  if [ -n "$(pid_on "$UI_PORT")" ]; then
    if ! owned_listener "$UI_PORT" frontend vite; then
      log "FATAL: :$UI_PORT is owned by an unrecognized process; refusing to reuse it"
      return 2
    fi
    log "launcher-owned frontend already listening on ${UI_PORT}"
  else
    [ -d frontend/node_modules ] || ( cd frontend && npm ci --no-audit --no-fund >/dev/null 2>&1 )
    ( cd frontend && nohup npx vite --host 127.0.0.1 > "$RUN/frontend.log" 2>&1 & )
    log "frontend starting on ${UI_PORT}"
  fi
  for _ in $(seq 90); do
    curl -sf --max-time 2 "http://127.0.0.1:${UI_PORT}/api/v1/healthz" >/dev/null 2>&1 && break
    sleep 1
  done
  if ! curl -sf --max-time 2 "http://127.0.0.1:${UI_PORT}/api/v1/healthz" >/dev/null 2>&1; then
    log "FATAL: console or API proxy never became ready (see $RUN/frontend.log)"; return 1
  fi
  printf '%s\n' "$(pid_on "$UI_PORT")" > "$RUN/frontend.pid"
  if ! worker_pid >/dev/null; then
    log "FATAL: worker exited during startup (see $RUN/worker.log)"; return 1
  fi

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
  printf '  %-12s %-34s %s\n' "redis" "127.0.0.1:${REDIS_PORT}" \
    "$(docker exec "$REDIS_NAME" redis-cli ping 2>/dev/null | grep -q PONG && echo up || echo DOWN)"
  printf '  %-12s %-34s %s\n' "worker" "(queue consumer)" \
    "$(worker_pid >/dev/null && echo up || echo DOWN)"
  echo
  if [ -n "$ADMIN_PASS" ]; then
    printf '  admin bootstrap configured for %s (only if the users table was empty at startup)\n' "$ADMIN_USER"
  else
    printf '  no bootstrap password supplied to this invocation; an existing operator may already be present\n'
    printf '  on a fresh estate, registration alone cannot authorize scans (bootstrap needs an empty users table)\n'
  fi
  echo "  launcher seeds no fixtures; inspect retained evidence before claiming collection coverage"
  echo "  logs: $RUN/api.log  $RUN/worker.log  $RUN/frontend.log"
  echo
}

container_state() {
  local name="$1" state
  state="$(docker inspect --format '{{.State.Status}}' "$name" 2>/dev/null || true)"
  if [[ -z "$state" ]]; then printf 'NOT_STARTED'; else printf '%s' "${state^^}"; fi
}

core_state() {
  local name="$1" image="$2" observed
  observed="$(docker ps --filter label=cryptoscan.local-stack=1 --filter "ancestor=$image" \
              --format '{{.Names}}' 2>/dev/null || true)"
  if [[ -n "$observed" ]]; then printf 'RUNNING'; else container_state "$name"; fi
}

tools() {
  printf '\n  %-17s %-14s %s\n' TOOL LOCAL_SERVICE PRODUCT_INTEGRATION
  printf '  %-17s %-14s %s\n' PostgreSQL "$(core_state "$DB_NAME" postgres:16-alpine)" 'canonical DB; API/worker only if ready'
  local graph_state
  graph_state="$(container_state cryptoscan-stage-neo4j)"
  if [[ "$graph_state" != RUNNING ]]; then graph_state="$(container_state cryptoscan-neo4j)"; fi
  printf '  %-17s %-14s %s\n' Neo4j "$graph_state" 'Bolt service; API projection wiring must be verified separately'
  printf '  %-17s %-14s %s\n' Redis "$(core_state "$REDIS_NAME" redis:7-alpine)" 'durable job queue/locks; local Redis is not TLS-qualified'
  printf '  %-17s %-14s %s\n' Celery NOT_CONFIGURED 'existing Redis worker + SQL outbox is not Celery'
  printf '  %-17s %-14s %s\n' Kafka NOT_CONFIGURED 'no broker or committed consumer wiring'
  printf '  %-17s %-14s %s\n' MinIO "$(container_state cryptoscan-stage-minio)" 'S3 adapter; API/worker wiring requires scoped credential files'
  printf '  %-17s %-14s %s\n' OpenSearch NOT_CONFIGURED 'no authoritative search projection wired'
  local prometheus_state
  prometheus_state="$(container_state cryptoscan-stage-prometheus)"
  if [[ "$prometheus_state" != RUNNING ]]; then prometheus_state="$(container_state cryptoscan-prometheus)"; fi
  printf '  %-17s %-14s %s\n' Prometheus "$prometheus_state" 'local API scrape or production overlay; inspect target health'
  local grafana_state
  grafana_state="$(container_state cryptoscan-stage-grafana)"
  if [[ "$grafana_state" != RUNNING ]]; then grafana_state="$(container_state cryptoscan-grafana)"; fi
  printf '  %-17s %-14s %s\n' Grafana "$grafana_state" 'local Prometheus datasource; dashboard/site qualification separate'
  printf '  %-17s %-14s %s\n' OpenTelemetry NO_COLLECTOR 'API trace export optional; receiver not verified'
  printf '  %-17s %-14s %s\n' Vault NOT_CONFIGURED 'bank secret manager required; no local Vault runtime'
  printf '  %-17s %-14s %s\n' OIDC/SAML/LDAP NOT_CONFIGURED 'local admin login is not a bank identity provider'
  local gateway_state
  gateway_state="$(container_state cryptoscan-nginx)"
  if [[ "$gateway_state" != RUNNING ]] && curl -sf --max-time 2 http://127.0.0.1:55920/api/v1/healthz >/dev/null 2>&1; then
    gateway_state=RUNNING_LOCAL
  fi
  printf '  %-17s %-14s %s\n' NGINX "$gateway_state" 'local HTTP proxy on loopback; bank TLS/mTLS separate'
  printf '  %-17s %-14s %s\n' Kubernetes NOT_DEPLOYED 'manifests are not a running cluster'
  local docker_state=UNAVAILABLE pydantic_state=UNAVAILABLE alembic_state=UNAVAILABLE
  if docker info --format '{{.ServerVersion}}' >/dev/null 2>&1; then docker_state=RUNNING; fi
  if "$PY" -c 'import pydantic' >/dev/null 2>&1; then pydantic_state=INSTALLED; fi
  if "$PY" -c 'import alembic' >/dev/null 2>&1; then alembic_state=INSTALLED; fi
  printf '  %-17s %-14s %s\n' Docker "$docker_state" 'local container daemon; image signing not qualified'
  printf '  %-17s %-14s %s\n' Pydantic "$pydantic_state" 'typed API contracts, not a running service'
  printf '  %-17s %-14s %s\n\n' Alembic "$alembic_state" 'migrations are a tool; query the live DB schema separately'
}

reload_app() {
  if ! owned_listener "$API_PORT" api 'api.main:app' || ! worker_pid >/dev/null; then
    log "FATAL: API and worker must be launcher-owned before a controlled reload"
    return 2
  fi
  local api_pid worker
  api_pid="$(pid_on "$API_PORT")"
  worker="$(worker_pid)"
  kill "$worker" "$api_pid"
  rm -f "$RUN/api.pid" "$RUN/worker.pid"
  for _ in $(seq 30); do
    if [[ -z "$(pid_on "$API_PORT")" ]]; then break; fi
    sleep 1
  done
  if [[ -n "$(pid_on "$API_PORT")" ]]; then
    log "FATAL: API did not release its loopback port; refusing an overlapping restart"
    return 2
  fi
  LOCAL_REUSE_RUNNING=1 up
}

monitoring_up() {
  local name=cryptoscan-stage-prometheus volume=cryptoscan-stage-prometheus-data
  if docker container inspect "$name" >/dev/null 2>&1; then
    if [[ "$(container_state "$name")" == RUNNING ]] &&
       [[ "$(docker inspect --format '{{index .Config.Labels "cryptoscan.stage"}}' "$name")" == 1 ]]; then
      log "launcher-owned Prometheus is already running on 127.0.0.1:55909"
      return 0
    fi
    log "FATAL: inspect existing $name before starting another monitoring service"
    return 2
  fi
  if ! curl -sf --max-time 3 "http://127.0.0.1:${API_PORT}/metrics" >/dev/null; then
    log "FATAL: API /metrics is not reachable on local loopback; no scrape target"
    return 2
  fi
  if docker volume inspect "$volume" >/dev/null 2>&1 && [[ "${LOCAL_REUSE_VOLUME:-0}" != 1 ]]; then
    log "FATAL: inspect existing $volume before LOCAL_REUSE_VOLUME=1"
    return 2
  fi
  mkdir -p "$RUN"
  if [[ -e "$RUN/prometheus.yml" ]]; then
    log "FATAL: $RUN/prometheus.yml already exists; inspect it instead of overwriting"
    return 2
  fi
  printf 'global:\n  scrape_interval: 15s\nscrape_configs:\n  - job_name: cryptoscan-local-api\n    metrics_path: /metrics\n    static_configs:\n      - targets: ["127.0.0.1:%s"]\n' "$API_PORT" > "$RUN/prometheus.yml"
  docker run -d --name "$name" --label cryptoscan.stage=1 --network host \
    --memory 256m --cpus 0.5 --cap-drop ALL --security-opt no-new-privileges:true \
    -v "$RUN/prometheus.yml:/etc/prometheus/prometheus.yml:ro" -v "$volume:/prometheus" \
    prom/prometheus@sha256:5ccad477d0057e62a7cd1981ffcc43785ac10c5a35522dc207466ff7e7ec845f \
    --config.file=/etc/prometheus/prometheus.yml --storage.tsdb.path=/prometheus \
    --storage.tsdb.retention.time=6h --web.listen-address=127.0.0.1:55909 >/dev/null
  log "Prometheus started on 127.0.0.1:55909; inspect /api/v1/targets before claiming scrape coverage"
}

gateway_up() {
  if ! command -v nginx >/dev/null 2>&1; then
    log "FATAL: local nginx binary is not installed"
    return 2
  fi
  if [[ -f "$RUN/nginx.pid" ]] && kill -0 "$(<"$RUN/nginx.pid")" 2>/dev/null; then
    if curl -sf --max-time 3 http://127.0.0.1:55920/api/v1/healthz >/dev/null; then
      log "local NGINX gateway already running on 127.0.0.1:55920"
      return 0
    fi
    log "FATAL: NGINX pid exists but gateway routing is unhealthy"
    return 2
  fi
  if [[ -n "$(pid_on 55920)" ]]; then
    log "FATAL: 127.0.0.1:55920 has an unrecognized listener"
    return 2
  fi
  if ! curl -sf --max-time 3 "http://127.0.0.1:${API_PORT}/ready" >/dev/null ||
     ! curl -sf --max-time 3 "http://127.0.0.1:${UI_PORT}/" >/dev/null; then
    log "FATAL: both local API and console must be ready before gateway startup"
    return 2
  fi
  if [[ "$RUN" != /* || ! "$RUN" =~ ^/[A-Za-z0-9._/-]+$ ]]; then
    log "FATAL: local gateway run path must be an absolute simple path"
    return 2
  fi
  mkdir -p "$RUN"
  if [[ -e "$RUN/nginx-local.conf" ]]; then
    log "FATAL: inspect existing gateway config instead of overwriting it"
    return 2
  fi
  python -I - "$ROOT/.docker/nginx/nginx.local.template.conf" "$RUN/nginx-local.conf" \
    "$RUN" "$API_PORT" "$UI_PORT" <<'PY'
import sys
from pathlib import Path
source, destination, root, api_port, ui_port = sys.argv[1:]
config = Path(source).read_text().replace('@RUN@', root).replace('@API_PORT@', api_port).replace('@UI_PORT@', ui_port)
Path(destination).write_text(config)
PY
  nginx -t -c "$RUN/nginx-local.conf" -p "$RUN/" && nginx -c "$RUN/nginx-local.conf" -p "$RUN/"
  log "NGINX bound to 127.0.0.1:55920; this local HTTP proxy is not bank TLS/mTLS"
}

graph_up() {
  local name=cryptoscan-stage-neo4j volume=cryptoscan-stage-neo4j-data
  local auth_file="${LOCAL_NEO4J_AUTH_FILE:-}" auth_line
  if docker container inspect "$name" >/dev/null 2>&1; then
    if [[ "$(container_state "$name")" == RUNNING ]] &&
       [[ "$(docker inspect --format '{{index .Config.Labels "cryptoscan.stage"}}' "$name")" == 1 ]]; then
      log "isolated Neo4j is already running on 127.0.0.1:55912 (integration is separate)"
      return 0
    fi
    log "FATAL: inspect existing $name before starting another graph"
    return 2
  fi
  if [[ "$auth_file" != /* || ! -f "$auth_file" || -L "$auth_file" || ! -r "$auth_file" ||
        "$(stat -c %a "$(dirname "$auth_file")" 2>/dev/null)" != 700 ]]; then
    log "FATAL: LOCAL_NEO4J_AUTH_FILE requires a readable file in a protected 0700 directory"
    return 2
  fi
  IFS= read -r auth_line < "$auth_file"
  if [[ ! "$auth_line" =~ ^neo4j/[A-Za-z0-9_-]{24,200}$ ]]; then
    log "FATAL: graph auth file must contain neo4j/ followed by a safe 24–200 character password (value withheld)"
    return 2
  fi
  if docker volume inspect "$volume" >/dev/null 2>&1 && [[ "${LOCAL_REUSE_VOLUME:-0}" != 1 ]]; then
    log "FATAL: inspect existing $volume before LOCAL_REUSE_VOLUME=1"
    return 2
  fi
  docker run -d --name "$name" --label cryptoscan.stage=1 --user 7474:7474 --init \
    --memory 768m --cpus 1 --security-opt no-new-privileges:true --cap-drop ALL \
    -e NEO4J_AUTH_PATH=/run/secrets/neo4j-auth \
    -e NEO4J_server_memory_heap_initial__size=128m \
    -e NEO4J_server_memory_heap_max__size=256m \
    -e NEO4J_server_memory_pagecache_size=128m \
    -v "$auth_file:/run/secrets/neo4j-auth:ro" -v "$volume:/data" \
    -p 127.0.0.1:55911:7474 -p 127.0.0.1:55912:7687 \
    neo4j@sha256:037cf5756f0135cbfd66b739b6df7c7c4bb100f9ce11602f6f9538e17e02c74d >/dev/null
  log "Neo4j started on 127.0.0.1:55912; verify authenticated Bolt before claiming graph coverage"
}

grafana_up() {
  local name=cryptoscan-stage-grafana volume=cryptoscan-stage-grafana-data
  local password_file="${LOCAL_GRAFANA_ADMIN_PASSWORD_FILE:-}"
  if docker container inspect "$name" >/dev/null 2>&1; then
    if [[ "$(container_state "$name")" == RUNNING ]] &&
       [[ "$(docker inspect --format '{{index .Config.Labels "cryptoscan.stage"}}' "$name")" == 1 ]]; then
      log "launcher-owned Grafana is already running on 127.0.0.1:55910"
      return 0
    fi
    log "FATAL: inspect existing $name before starting another Grafana"
    return 2
  fi
  if [[ "$password_file" != /* || ! -f "$password_file" || -L "$password_file" || ! -r "$password_file" ||
        "$(stat -c %a "$(dirname "$password_file")" 2>/dev/null)" != 700 ]]; then
    log "FATAL: LOCAL_GRAFANA_ADMIN_PASSWORD_FILE requires a readable file in a protected 0700 directory"
    return 2
  fi
  if ! curl -sf --max-time 3 http://127.0.0.1:55909/-/healthy >/dev/null; then
    log "FATAL: local Prometheus is not healthy; Grafana cannot have a verified datasource"
    return 2
  fi
  if docker volume inspect "$volume" >/dev/null 2>&1 && [[ "${LOCAL_REUSE_VOLUME:-0}" != 1 ]]; then
    log "FATAL: inspect existing $volume before LOCAL_REUSE_VOLUME=1"
    return 2
  fi
  mkdir -p "$RUN"
  if [[ -e "$RUN/grafana-datasource.yml" ]]; then
    log "FATAL: inspect existing $RUN/grafana-datasource.yml instead of overwriting"
    return 2
  fi
  printf 'apiVersion: 1\ndatasources:\n  - name: CryptoScan Local Prometheus\n    uid: cryptoscan-local-prometheus\n    type: prometheus\n    access: proxy\n    url: http://127.0.0.1:55909\n    isDefault: true\n    editable: false\n' > "$RUN/grafana-datasource.yml"
  docker run -d --name "$name" --label cryptoscan.stage=1 --network host \
    --memory 384m --cpus 1 --cap-drop ALL --security-opt no-new-privileges:true \
    -e GF_SERVER_HTTP_ADDR=127.0.0.1 -e GF_SERVER_HTTP_PORT=55910 \
    -e GF_SERVER_ROOT_URL=http://127.0.0.1:55910/ \
    -e GF_SECURITY_ADMIN_USER=cryptoscan_local_grafana \
    -e GF_SECURITY_ADMIN_PASSWORD__FILE=/run/secrets/grafana-admin \
    -e GF_USERS_ALLOW_SIGN_UP=false -e GF_AUTH_ANONYMOUS_ENABLED=false \
    -e GF_ANALYTICS_REPORTING_ENABLED=false -e GF_ANALYTICS_CHECK_FOR_UPDATES=false \
    -v "$password_file:/run/secrets/grafana-admin:ro" \
    -v "$RUN/grafana-datasource.yml:/etc/grafana/provisioning/datasources/cryptoscan.yml:ro" \
    -v "$volume:/var/lib/grafana" \
    grafana/grafana@sha256:f9811e4e687ffecf1a43adb9b64096c50bc0d7a782f8608530f478b6542de7d5 >/dev/null
  log "Grafana started on 127.0.0.1:55910; confirm datasource metrics before claiming monitoring"
}

logs() { tail -n 40 -F "$RUN/api.log" "$RUN/worker.log" "$RUN/frontend.log"; }

# Stop only the launcher-owned core API, worker, frontend, PostgreSQL and Redis.
# Independently staged MinIO, graph, monitoring and gateway remain running;
# inspect `tools` and stop each explicitly under its own operational approval.
# Named core volumes survive. `purge` deletes only the named core volumes.
down() {
  if owned_listener "$API_PORT" api 'api.main:app'; then
    kill "$(pid_on "$API_PORT")" && log "stopped launcher-owned API :$API_PORT"
    rm -f "$RUN/api.pid"
  fi
  if owned_listener "$UI_PORT" frontend vite; then
    kill "$(pid_on "$UI_PORT")" && log "stopped launcher-owned frontend :$UI_PORT"
    rm -f "$RUN/frontend.pid"
  fi
  p="$(worker_pid)" && kill "$p" 2>/dev/null && log "worker stopped"
  rm -f "$RUN/worker.pid"
  for name in "$DB_NAME" "$REDIS_NAME"; do
    if owned_container "$name"; then
      docker rm -f "$name" >/dev/null && log "removed launcher-owned $name"
    elif docker container inspect "$name" >/dev/null 2>&1; then
      log "left unrecognized $name untouched"
    fi
  done
  log "data kept in volumes ${DB_VOLUME} / ${REDIS_VOLUME} — inspect before LOCAL_REUSE_VOLUME=1"
  log "to delete it: $0 purge"
}

# Destroy the estate. Separate from `down`, named for what it does, and it
# asks first -- `down` used to do this silently because the containers had
# no volumes, and a restart that was only meant to reload the frontend took
# every scan with it.
purge() {
  down
  if [ "${2:-}" != "--yes" ] && [ "${FORCE_PURGE:-}" != "1" ]; then
    printf '[stack] delete volumes %s and %s? every scan in them is lost. [y/N] ' \
      "$DB_VOLUME" "$REDIS_VOLUME" >&2
    read -r reply
    case "$reply" in [yY]|[yY][eE][sS]) ;; *) log "purge cancelled"; return 0 ;; esac
  fi
  docker volume rm "$DB_VOLUME" "$REDIS_VOLUME" >/dev/null 2>&1 && log "volumes deleted" || true
}

case "${1:-up}" in
  up) up ;;
  reload) reload_app ;;
  status) status ;;
  tools) tools ;;
  monitoring-up) monitoring_up ;;
  grafana-up) grafana_up ;;
  graph-up) graph_up ;;
  gateway-up) gateway_up ;;
  logs) logs ;;
  down) down ;;
  purge) purge "$@" ;;
  *) echo "usage: $0 {up|reload|status|tools|monitoring-up|grafana-up|graph-up|gateway-up|logs|down|purge}" >&2; exit 2 ;;
esac
