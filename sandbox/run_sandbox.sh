#!/usr/bin/env bash
# One-command banking sandbox: stack up, estate up, database seeded.
set -euo pipefail
cd "$(dirname "$0")/.."

COMPOSE=(docker compose -f docker-compose.yml -f sandbox/docker-compose.sandbox.yml)
DB_URL="${DATABASE_URL:-postgresql://${POSTGRES_USER:-cryptoscan}:${POSTGRES_PASSWORD:-cryptoscan_secret}@127.0.0.1:${POSTGRES_PORT:-55432}/${POSTGRES_DB:-cryptoscan}}"

case "${1:-up}" in
  up)
    "${COMPOSE[@]}" up -d postgres redis api
    echo "waiting for postgres..."
    for i in $(seq 1 30); do
      docker exec cryptoscan-postgres pg_isready -U "${POSTGRES_USER:-cryptoscan}" >/dev/null 2>&1 && break
      sleep 2
    done
    "${COMPOSE[@]}" up -d
    DATABASE_URL="$DB_URL" python3 scripts/seed_sandbox_bank.py
    echo
    echo "sandbox ready. Estate DNS (inside cryptoscan-net):"
    echo "  internet-banking.bank.sandbox  mobile-api.bank.sandbox  swift-gateway.bank.sandbox"
    echo "  legacy-branch.bank.sandbox     hsm-sim.bank.sandbox:8443  core-banking-db.bank.sandbox"
    ;;
  seed)   DATABASE_URL="$DB_URL" python3 scripts/seed_sandbox_bank.py ;;
  reset)  DATABASE_URL="$DB_URL" python3 scripts/seed_sandbox_bank.py --reset ;;
  estate)
    "${COMPOSE[@]}" up -d certgen internet-banking mobile-api swift-gateway legacy-branch hsm-sim core-banking-db bank-redis-seed
    ;;
  down)   "${COMPOSE[@]}" down -v ;;
  status) "${COMPOSE[@]}" ps ;;
  *) echo "usage: $0 [up|seed|reset|estate|down|status]" >&2; exit 2 ;;
esac
