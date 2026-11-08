#!/usr/bin/env bash
# Repository root; approved Python on PATH. No CI/workflow changes or customers.
set -euo pipefail
python docs/readiness-evidence/quality-usability-release-operations-2026-10-23/run-tests.py \
  services/cbom/tests services/evidence/tests services/inventory/tests \
  shared/shared_models/tests \
  services/api/tests/unit/test_host_evidence.py \
  services/api/tests/unit/test_cbom_production_flow.py \
  services/api/tests/unit/test_cbom_body_limit.py \
  services/api/tests/unit/test_cbom_rescan_inspection.py \
  services/api/tests/unit/test_cbom_legacy_reconciliation.py \
  services/api/tests/unit/test_assurance_workflows.py \
  services/api/tests/unit/test_assurance_controlled_boundary.py \
  services/api/tests/unit/test_software_supply_chain_api.py \
  services/api/tests/unit/test_rate_limit.py \
  services/database/tests/unit/test_evidence_loader_sanitisers.py \
  services/database/tests/unit/test_evidence_repository.py \
  services/database/tests/unit/test_audit_chain_incremental.py \
  services/database/tests/unit/test_assurance_migration.py \
  -q "$@"
