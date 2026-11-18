#!/usr/bin/env bash
# One-command banking sandbox: stack up, estate up, database seeded.
#
# Notes for operators:
#  * Seeding runs inside a throwaway Python container (sandbox-seed), so the
#    host does NOT need sqlalchemy/psycopg installed.
#  * `down` only removes the SANDBOX services; the main CryptoScan stack and
#    its volumes (postgres_data, redis_data, neo4j_data) are never touched.
#    `down --all` additionally stops the main stack but STILL never deletes
#    volumes — a full destructive teardown is intentionally not offered.
set -euo pipefail
cd "$(dirname "$0")/.."

COMPOSE=(docker compose -f docker-compose.yml -f sandbox/docker-compose.sandbox.yml)
SBX_SERVICES="internet-banking mobile-api swift-gateway legacy-branch hsm-sim core-banking-db payments-bastion certgen bank-redis-seed sandbox-seed"

wait_healthy() {
  local container="$1" max="${2:-40}"
  echo "waiting for ${container} to report healthy..."
  for _ in $(seq 1 "$max"); do
    status=$(docker inspect -f '{{.State.Health.Status}}' "$container" 2>/dev/null || echo missing)
    [ "$status" = "healthy" ] && return 0
    sleep 2
  done
  echo "WARNING: $container never reported healthy (last=$status); continuing" >&2
  return 0
}

case "${1:-up}" in
  up)
    # Wave 1 — data plane only. The seed talks straight to Postgres and even
    # creates the schema itself, so a sick API can never block the sandbox.
    "${COMPOSE[@]}" up -d postgres redis
    wait_healthy cryptoscan-postgres 60
    "${COMPOSE[@]}" up -d ${SBX_SERVICES%% sandbox-seed}   # fake estate, no API dependency
    "${COMPOSE[@]}" run --rm sandbox-seed

    # Wave 2 — app plane. api/worker/frontend need each other healthy; if the
    # API is mid-migration (fresh volumes) or broken, this warns but never
    # aborts the sandbox bring-up.
    "${COMPOSE[@]}" up -d api
    if wait_healthy cryptoscan-api 90 && [ "$(docker inspect -f '{{.State.Health.Status}}' cryptoscan-api 2>/dev/null)" = "healthy" ]; then
      "${COMPOSE[@]}" up -d worker estate-daemon monitor frontend nginx 2>/dev/null || true
    else
      echo "WARNING: cryptoscan-api is not healthy — console will 502. Inspect with:" >&2
      echo "  docker logs cryptoscan-api --tail 80" >&2
    fi
    echo
    echo "sandbox ready. One-click sweep target (Scanners -> Network):"
    echo "  10.210.0.0/29      (covers .0-.7: all TLS + the database; bastion is .8)"
    echo "Live-scan targets (paste into the Network page):"
    echo "  TLS:  10.210.0.2:443  10.210.0.3:443  10.210.0.4:443"
    echo "        10.210.0.5:443 (legacy)  10.210.0.6:8443 (hsm-sim)"
    echo "  DB:   10.210.0.7:5432 (starttls=postgresql)"
    echo "  SSH:  10.210.0.8:22 (payments-bastion, legacy KEX)"
    echo "  DNS also works: internet-banking.bank.sandbox, ..."
    echo "  console: http://127.0.0.1:3003   (run '$0 targets' to reprint)"
    ;;
  seed)   "${COMPOSE[@]}" run --rm sandbox-seed ;;
  reset)  "${COMPOSE[@]}" run --rm -e SEED_ARGS="--reset" sandbox-seed ;;
  migrate)
    # Applies the DB migrations without seeding — the repair path for the
    # API's 'Database migration status is missing' startup failure.
    "${COMPOSE[@]}" run --rm -e SEED_MODE="migrate-only" sandbox-seed
    echo "schema migrated. Now: docker compose restart cryptoscan-api (or rerun: $0 up)"
    ;;
  db-rebuild)
    # Destructive but scoped: drops ONLY the CryptoScan public schema (which
    # currently holds just sandbox rows + unstamped create_all tables), then
    # re-migrates and reseeds. Needed once to repair the state left by the
    # pre-alembic seeder. Bank stack volumes are untouched.
    read -r -p "This drops the 'public' schema of the cryptoscan DB and rebuilds it. Type REBUILD to continue: " answer
    if [ "$answer" != "REBUILD" ]; then echo "aborted"; exit 1; fi
    docker exec cryptoscan-postgres psql -U "${POSTGRES_USER:-cryptoscan}" -d "${POSTGRES_DB:-cryptoscan}" \
      -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public; GRANT ALL ON SCHEMA public TO public;"
    "${COMPOSE[@]}" run --rm sandbox-seed
    echo "DB rebuilt, migrated and seeded. Restarting API..."
    docker compose -f docker-compose.yml restart api 2>/dev/null || true
    ;;
  estate) "${COMPOSE[@]}" up -d ${SBX_SERVICES%% sandbox-seed} ;;
  console)
    # Bring up the web console: api must be healthy first (frontend depends on
    # it), then frontend (:3003) and the nginx gateway (:8088).
    "${COMPOSE[@]}" up -d api
    for _ in $(seq 1 45); do
      [ "$(docker inspect -f '{{.State.Health.Status}}' cryptoscan-api 2>/dev/null)" = "healthy" ] && break
      sleep 2
    done
    "${COMPOSE[@]}" up -d frontend nginx
    echo "console:  http://127.0.0.1:${FRONTEND_PORT:-3003}"
    echo "gateway:  http://127.0.0.1:${NGINX_PORT:-8088}"
    ;;down)
    # Sandbox-only teardown: stop/remove just the fake-estate containers plus
    # the sandbox_certs volume. Never interacts with the main stack's
    # containers or named volumes.
    "${COMPOSE[@]}" stop ${SBX_SERVICES} 2>/dev/null || true
    "${COMPOSE[@]}" rm -f ${SBX_SERVICES} 2>/dev/null || true
    docker volume rm "$(basename "$PWD" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]//g')_sandbox_certs" 2>/dev/null || true
    # Detach the API (it rides this LAN for live scans), then drop the fake
    # bank LAN itself so the next `up` recreates it cleanly.
    docker network disconnect cryptoscan-sandbox-net cryptoscan-api 2>/dev/null || true
    docker network rm cryptoscan-sandbox-net 2>/dev/null || true
    echo "sandbox estate removed; main stack untouched"
    ;;
  status) "${COMPOSE[@]}" ps ;;
  agent)
    # Continuous bank-agent mode: the collector re-observes the estate every
    # COLLECT_INTERVAL_SECONDS (default 300). Needs the console credentials in
    # .env once:
    #   CRYPTOSCAN_USERNAME=admin
    #   CRYPTOSCAN_PASSWORD=...
    #   COLLECT_INTERVAL_SECONDS=300
    if ! grep -q "^COLLECT_INTERVAL_SECONDS=" .env 2>/dev/null; then
      echo "COLLECT_INTERVAL_SECONDS=300" >> .env
      echo "added COLLECT_INTERVAL_SECONDS=300 to .env"
    fi
    if ! grep -q "^CRYPTOSCAN_USERNAME=" .env 2>/dev/null; then
      echo "add CRYPTOSCAN_USERNAME + CRYPTOSCAN_PASSWORD to .env first (your console login)" >&2
      exit 1
    fi
    "${COMPOSE[@]}" up -d sandbox-collect
    echo "agent running — observations stream in on the interval; BOMs re-project from the newest"
    ;;
  collect)
    # The living-bank collector: one pass over the estate through real
    # channels, pushed to the ingestion API; every BOM re-projects from it.
    # Needs the console login once per run (prompted if not in env).
    # docker compose reads .env itself; only ask for what .env does not hold
    for key in CRYPTOSCAN_USERNAME CRYPTOSCAN_PASSWORD; do
      if [ -z "${!key:-}" ] && [ -f .env ]; then
        val="$(grep -E "^${key}=" .env | tail -1 | cut -d= -f2-)"
        [ -n "$val" ] && export "$key=$val"
      fi
    done
    if [ -z "${CRYPTOSCAN_USERNAME:-}" ]; then read -r -p "console username: " CRYPTOSCAN_USERNAME; export CRYPTOSCAN_USERNAME; fi
    if [ -z "${CRYPTOSCAN_PASSWORD:-}" ]; then read -r -s -p "console password: " CRYPTOSCAN_PASSWORD; echo; export CRYPTOSCAN_PASSWORD; fi
    "${COMPOSE[@]}" run --rm -e CRYPTOSCAN_USERNAME -e CRYPTOSCAN_PASSWORD sandbox-collect
    ;;
  agents)
    # Cryptava: the real host agent on four bank hosts (swift-gateway,
    # internet-banking, core-banking-db, payments-bastion). Each enrols itself
    # under a unique name (mrdn-sbx-dc1-...), signs its observations with its own
    # key and reports every 5 minutes. `agents stop` stops them; their enrolment
    # survives in named volumes.
    AGENTS="cryptava-swift-gateway cryptava-internet-banking cryptava-core-banking-db cryptava-payments-bastion"
    if [ "${2:-}" = "stop" ]; then "${COMPOSE[@]}" --profile agents stop $AGENTS; exit 0; fi
    if [ "${2:-}" = "status" ]; then
      for a in $AGENTS; do echo "== $a"; docker exec "cryptoscan-$a" sh -c 'PYTHONPATH=/opt/cryptava python3 -m cryptava status' 2>/dev/null | head -40 || echo "   not running"; done
      exit 0
    fi
    if [ -z "${CRYPTOSCAN_USERNAME:-}" ]; then read -r -p "console username: " CRYPTOSCAN_USERNAME; export CRYPTOSCAN_USERNAME; fi
    if [ -z "${CRYPTOSCAN_PASSWORD:-}" ]; then read -r -s -p "console password: " CRYPTOSCAN_PASSWORD; echo; export CRYPTOSCAN_PASSWORD; fi
    "${COMPOSE[@]}" --profile agents up -d $AGENTS
    echo "Cryptava agents started. Follow one:  docker logs -f cryptoscan-cryptava-swift-gateway"
    echo "Fleet view: console -> Platform -> Agent fleet.  Status:  $0 agents status"
    ;;
  targets)
    # Paste-ready target list for the console's Network page / API calls.
    cat <<'EOF'
Meridian Bank sandbox estate — live scan targets
Authorized scope (declared automatically by the seeder):  10.210.0.0/24

One-click discovery sweep (Scanners page → Network → active):
  10.210.0.0/29     covers .0–.7 — all TLS endpoints + the database
                    (never sweep the whole /24 from the UI: dead addresses
                    each cost an ARP timeout and the wizard gives up at 60s)
  10.210.0.8/32     the SSH bastion, swept as a single host

TLS endpoints (host:port, one per line):
10.210.0.2:443      internet-banking   TLS 1.2/1.3, ECDHE only (strong)
10.210.0.3:443      mobile-api         TLS 1.2/1.3 (strong)
10.210.0.4:443      swift-gateway      TLS 1.2/1.3, RSA-3072 cert
10.210.0.5:443      legacy-branch      TLS 1.0/1.1 enabled, RSA-1024, expiring (weak on purpose)
10.210.0.6:8443     hsm-sim            TLS payment-HSM simulator
10.210.0.7:5432     core-banking-db    PostgreSQL STARTTLS (set starttls=postgresql or auto)

SSH endpoint:
10.210.0.8:22       payments-bastion   legacy KEX/host-key algs (sha1, ssh-rsa, CBC)

DNS aliases (same targets, by name):
internet-banking.bank.sandbox  mobile-api.bank.sandbox  swift-gateway.bank.sandbox
legacy-branch.bank.sandbox     hsm-sim.bank.sandbox:8443  core-banking-db.bank.sandbox
payments-bastion.bank.sandbox
EOF
    ;;
  *) echo "usage: $0 [up|seed|reset|migrate|db-rebuild|estate|console|targets|collect|agent|agents|down|status]" >&2; exit 2 ;;
esac
