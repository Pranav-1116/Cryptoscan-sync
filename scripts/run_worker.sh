#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export CRYPTOSCAN_ROOT="$ROOT"
export PYTHONPATH="$ROOT/shared/shared_config:$ROOT/shared/shared_logging:$ROOT/shared/shared_models:$ROOT/services/api:$ROOT/services/database:$ROOT/services/scanner:$ROOT/services/evidence:$ROOT/services/normalization:$ROOT/services/policy:$ROOT/services/drift:$ROOT/services/worker:$ROOT/services/deduplication:$ROOT/services/cbom:$ROOT/services/container_scanner:$ROOT/services/network_scanner:$ROOT/services/cloud_scanner:$ROOT/services/graph_engine:$ROOT/services/business_context:$ROOT/services/quantum:$ROOT/services/remediation:$ROOT/services/reporting${PYTHONPATH:+:$PYTHONPATH}"
exec python3 -m worker.main
