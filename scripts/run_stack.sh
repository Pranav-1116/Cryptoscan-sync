#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=env.sh
source "$(cd "$(dirname "$0")" && pwd)/env.sh"
export ENVIRONMENT="${ENVIRONMENT:-development}"
if [[ ! -f "$ROOT/data/cryptoscan.db" && -z "${DATABASE_URL:-}" ]]; then
  echo "seeding local sqlite database…"
  python3 "$ROOT/scripts/seed_demo.py"
fi
exec python3 -m uvicorn api.main:app --host 0.0.0.0 --port "${API_PORT:-8000}" --proxy-headers --forwarded-allow-ips='*'
