#!/usr/bin/env bash
# CryptoScan — one-command realtime platform launcher (backend, SQLite, no Docker).
#
# Starts the API control plane with a local SQLite database, the event tailer,
# and the live-scan runner wiring. Then drive the real scanners from the UI
# (Operations → Realtime scanners) or the REST API.
#
#   ./scripts/live-platform.sh                 # API on :8010
#   ./scripts/live-platform.sh 9000            # custom port
#   PORT=8010 ./scripts/live-platform.sh
#
# Optional environment (passed through):
#   CRYPTOSCAN_LIVE_INTERVAL=<secs>           periodic scan loop interval (default off)
#   CRYPTOSCAN_LIVE_NETWORK_TARGET=host:port  include a network probe in the loop
#   CRYPTOSCAN_LIVE_CLOUD=1                   live cloud scan in the loop (needs creds)
#
# Default login: admin / cryptoscan (bootstrapped on first start).

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

PORT="${1:-${PORT:-8010}}"
PY="${PYTHON:-python3}"

# --- dependencies --------------------------------------------------------
if ! "$PY" -c "import fastapi, uvicorn, sqlalchemy" 2>/dev/null; then
  echo "ERROR: fastapi/uvicorn/sqlalchemy not found in $($PY -V 2>&1)."
  echo "Activate the project venv or install requirements, e.g.:"
  echo "  $PY -m pip install -e services/api -e services/database -e shared/shared_models 2>/dev/null || true"
  echo "  $PY -m pip install fastapi 'uvicorn[standard]' sqlalchemy pydantic pyyaml"
  exit 1
fi

# --- paths / config ------------------------------------------------------
mkdir -p "$REPO_ROOT/data"
export CRYPTOSCAN_ROOT="$REPO_ROOT"
export PYTHONPATH="$(for d in shared/*/ services/*/; do printf '%s%s:' "$REPO_ROOT/" "$d"; done)${PYTHONPATH:-}"
export ALLOW_SQLITE=true
export DATABASE_URL="${DATABASE_URL:-sqlite:///$REPO_ROOT/data/cryptoscan.db}"
# event tailer on (federates worker/monitor events) unless explicitly disabled
export EVENT_TAILER_SECONDS="${EVENT_TAILER_SECONDS:-2}"

cat <<EOF
════════════════════════════════════════════════════════════════
 CryptoScan realtime platform
   repo   : $REPO_ROOT
   db     : $DATABASE_URL
   PYTHON : $($PY -V 2>&1)
   login  : admin / cryptoscan   (bootstrapped on first run)
────────────────────────────────────────────────────────────────
   app    : http://localhost:$PORT/
   docs   : http://localhost:$PORT/api/docs
   health : http://localhost:$PORT/health
   events : http://localhost:$PORT/api/v1/events/stream   (SSE)

   Once signed in: Operations → Realtime scanners → Run scan now
   (or POST /api/v1/live-scan/run with a bearer token).
════════════════════════════════════════════════════════════════
EOF

cd services/api
exec "$PY" -m uvicorn api.main:app --host 0.0.0.0 --port "$PORT"
