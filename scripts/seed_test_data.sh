#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export CRYPTOSCAN_ROOT="$ROOT"
export PYTHONPATH="$ROOT/shared/shared_config:$ROOT/shared/shared_logging:$ROOT/shared/shared_models:$ROOT/services/api:$ROOT/services/database:$ROOT/services/scanner:$ROOT/services/evidence:$ROOT/services/normalization:$ROOT/services/policy:$ROOT/services/drift:$ROOT/services/worker:$ROOT/services/deduplication:$ROOT/services/cbom:$ROOT/services/container_scanner${PYTHONPATH:+:$PYTHONPATH}"
PYTHON="${ROOT}/.venv/bin/python"
if [[ ! -x "$PYTHON" ]]; then
  PYTHON=python3
fi
exec "$PYTHON" "$ROOT/scripts/seed_demo.py"
