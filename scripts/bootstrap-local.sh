#!/usr/bin/env bash
# Phase 0 local bootstrap. Isolated Compose ports only — never 5432/6379/80.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing prerequisite: $1" >&2; exit 1; }; }
need docker
need python3

if [[ ! -f .env ]]; then
  if [[ -f .env.example ]]; then
    cp .env.example .env
    echo "wrote .env from .env.example (edit secrets before production)"
  else
    echo "no .env.example found" >&2
    exit 1
  fi
fi

# shellcheck disable=SC1091
source "$ROOT/scripts/env.sh"
export POSTGRES_PORT="${POSTGRES_PORT:-55432}"
export REDIS_PORT="${REDIS_PORT:-56379}"
export NEO4J_HTTP_PORT="${NEO4J_HTTP_PORT:-57474}"
export NEO4J_BOLT_PORT="${NEO4J_BOLT_PORT:-57687}"
export NGINX_HTTP_PORT="${NGINX_HTTP_PORT:-8088}"

echo "starting isolated compose (host ${NGINX_HTTP_PORT})…"
docker compose up -d --build

echo "waiting for API health…"
ok=0
for _ in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:${NGINX_HTTP_PORT}/health" >/dev/null 2>&1 \
    || curl -fsS "http://127.0.0.1:${NGINX_HTTP_PORT}/api/v1/health" >/dev/null 2>&1; then
    ok=1
    break
  fi
  sleep 2
done
if [[ "$ok" -ne 1 ]]; then
  echo "API did not become healthy on :${NGINX_HTTP_PORT}" >&2
  docker compose ps
  exit 1
fi

echo "CryptoScan is up."
echo "  UI     http://127.0.0.1:${NGINX_HTTP_PORT}/"
echo "  login  admin / cryptoscan  (development only)"
echo "  verify ./scripts/zelnx verify-evidence-chain --scan-id <id>"
