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
SBX_SERVICES="internet-banking mobile-api swift-gateway legacy-branch hsm-sim core-banking-db certgen bank-redis-seed sandbox-seed"

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
    echo "sandbox ready. Estate DNS (inside cryptoscan-net):"
    echo "  internet-banking.bank.sandbox  mobile-api.bank.sandbox  swift-gateway.bank.sandbox"
    echo "  legacy-branch.bank.sandbox     hsm-sim.bank.sandbox:8443  core-banking-db.bank.sandbox"
    echo "  console: http://127.0.0.1:3003"
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
  down)
    # Sandbox-only teardown: stop/remove just the fake-estate containers plus
    # the sandbox_certs volume. Never interacts with the main stack's
    # containers or named volumes.
    "${COMPOSE[@]}" stop ${SBX_SERVICES} 2>/dev/null || true
    "${COMPOSE[@]}" rm -f ${SBX_SERVICES} 2>/dev/null || true
    docker volume rm "$(basename "$PWD" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]//g')_sandbox_certs" 2>/dev/null || true
    echo "sandbox estate removed; main stack untouched"
    ;;
  status) "${COMPOSE[@]}" ps ;;
  *) echo "usage: $0 [up|seed|reset|migrate|db-rebuild|estate|down|status]" >&2; exit 2 ;;
esac
