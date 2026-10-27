#!/usr/bin/env bash
# Repository root, approved interpreter on PATH, disposable test backends only.
set -euo pipefail
bash docs/readiness-evidence/production-data-path-2026-10-24/run-python-tests.sh \
  services/api/tests/unit/test_cbom_legacy_reconciliation.py \
  services/api/tests/unit/test_cbom_controlled_history.py \
  services/api/tests/unit/test_cbom_rescan_inspection.py \
  services/database/tests/unit/test_import_provenance.py \
  services/database/tests/unit/test_audit_chain_incremental.py \
  services/api/tests/unit/test_assurance_workflows.py \
  services/api/tests/unit/test_backup_encryption.py services/evidence/tests \
  services/scanner/tests/unit/test_file_observation_receipts.py \
  scripts/tests/test_capacity_verdict.py \
  $(find services/worker/tests/unit -name 'test_*.py' ! -name test_quantum_stage.py | sort) \
  services/api/tests/unit/test_execution_controls.py \
  services/api/tests/unit/test_execution_recovery_integrity.py \
  services/api/tests/unit/test_execution_process_recovery.py "$@"
