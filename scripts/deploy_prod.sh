#!/usr/bin/env bash
# Production bring-up. Fails closed if required secrets are missing.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

missing=()
require() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    missing+=("$name")
  fi
}

require SECRET_KEY
require ADMIN_PASSWORD_HASH
require GITHUB_WEBHOOK_SECRET
require CORS_ORIGINS
require POSTGRES_PASSWORD
require CRYPTOSCAN_APP_DATABASE_URL
require REDIS_URL
require REDIS_CA_HOST_PATH
require BACKUP_STORAGE_HOST_PATH
require METRICS_TOKEN
require ALERTMANAGER_WEBHOOK_TOKEN
require TRUSTED_HOSTS
require NEO4J_PASSWORD

if [[ "${ENVIRONMENT:-}" != "production" ]]; then
  echo "ENVIRONMENT must be production (got '${ENVIRONMENT:-unset}')" >&2
  exit 2
fi
if [[ "$CORS_ORIGINS" == "*" ]]; then
  echo "CORS_ORIGINS=* is not allowed in production" >&2
  exit 2
fi
if [[ ${#missing[@]} -gt 0 ]]; then
  echo "missing required production variables: ${missing[*]}" >&2
  echo "copy .env.production.example to .env and fill secrets" >&2
  exit 2
fi
if [[ "${REDIS_URL}" != rediss://* ]]; then
  echo "REDIS_URL must use bank-owned TLS Redis (rediss://)" >&2
  exit 2
fi
if [[ ! -r "${REDIS_CA_HOST_PATH}" ]]; then
  echo "REDIS_CA_HOST_PATH must name a readable bank CA bundle" >&2
  exit 2
fi
if [[ "${BACKUP_STORAGE_HOST_PATH}" != /* || ! -d "${BACKUP_STORAGE_HOST_PATH}" ||
      -L "${BACKUP_STORAGE_HOST_PATH}" ]]; then
  echo "BACKUP_STORAGE_HOST_PATH must be an existing non-symlink absolute bank directory" >&2
  exit 2
fi

COMPOSE_FILES=(-f docker-compose.yml -f docker-compose.prod.yml)
if [[ "${1:-}" == "--tls" ]]; then
  shift
  COMPOSE_FILES+=(-f docker-compose.tls.yml)
fi

if [[ "${1:-}" == "--migrate-only" ]]; then
  shift
  if [[ $# -ne 0 ]]; then
    echo "--migrate-only takes no extra arguments" >&2
    exit 2
  fi
  exec docker compose "${COMPOSE_FILES[@]}" run --rm migrate
fi

exec docker compose "${COMPOSE_FILES[@]}" up --build "$@"
