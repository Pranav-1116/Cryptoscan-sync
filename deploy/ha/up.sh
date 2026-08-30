#!/usr/bin/env bash
# Bank-grade HA stack: Postgres + Redis + 2× API behind nginx + 2× workers + monitor daemon.
# Usage: cd deploy/ha && docker compose up -d --build
# Scale workers:  docker compose up -d --scale worker=6
set -euo pipefail

# Postgres credentials come from the environment or .env next to this file.
export POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-changeme-bank-grade}"
export DATABASE_URL="${DATABASE_URL:-postgresql+psycopg2://cryptoscan:${POSTGRES_PASSWORD}@postgres:5432/cryptoscan}"
export REDIS_URL="${REDIS_URL:-redis://redis:6379/0}"

docker compose -f docker-compose.yml up -d --build "$@"
