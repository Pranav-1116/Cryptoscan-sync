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

exec docker compose -f docker-compose.yml -f docker-compose.prod.yml up --build "$@"
