#!/usr/bin/env bash
# Repository root; approved constrained Python environment. Outputs go external.
set -euo pipefail
bash docs/readiness-evidence/bank-original45-2026-10-24/run-python-tests.sh \
  services/api/tests/unit/test_cbom_production_flow.py \
  services/api/tests/unit/test_cbom_body_limit.py \
  services/api/tests/unit/test_software_supply_chain_api.py \
  services/database/tests/unit/test_asset_identity_spine.py \
  services/database/tests/unit/test_schema_ensure.py \
  services/database/tests/unit/test_schema_parity.py "$@"
