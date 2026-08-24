#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
python3 -m pip install -r requirements.txt
python3 -m pip install -e shared/shared_config -e shared/shared_logging -e shared/shared_models \
  -e services/database -e services/scanner -e services/evidence -e services/normalization \
  -e services/policy -e services/drift -e services/worker -e services/api
mkdir -p data/workspaces
echo "CryptoScan Python packages installed."
