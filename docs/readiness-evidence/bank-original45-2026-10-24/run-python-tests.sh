#!/usr/bin/env bash
# Run from repository root in the approved constrained Python environment.
# Pass an external --junitxml path if desired; never overwrite retained records.
set -euo pipefail
python docs/readiness-evidence/quality-usability-release-operations-2026-10-23/run-tests.py \
  services/cbom/tests \
  services/quantum/tests \
  services/api/tests/unit/test_bank_vendor_questionnaire_boundaries.py \
  services/api/tests/unit/test_bank_vendor_questionnaire_register.py \
  services/api/tests/unit/test_bank_native_cbom.py \
  services/api/tests/unit/test_banking_endpoints.py \
  services/api/tests/unit/test_banking_iso20022_kmip.py \
  services/api/tests/unit/test_bank_dependency_security.py \
  services/api/tests/unit/test_quantum_plan.py \
  services/api/tests/unit/test_agility_history_simulate_pqc.py \
  services/api/tests/unit/test_agility_roadmap_trend.py \
  services/api/tests/unit/test_cbom_enterprise_endpoints.py \
  services/api/tests/unit/test_cbom_snapshots.py \
  services/api/tests/unit/test_round22_cbom_standard_diff.py \
  services/api/tests/unit/test_cross_surface_estate_contract.py \
  services/api/tests/unit/test_six_bom_current_evidence.py \
  services/api/tests/unit/test_evidence_disposition.py \
  services/api/tests/integration/test_field_accuracy_api.py \
  services/api/tests/unit/test_crypto_live_api.py \
  services/worker/tests/unit/test_quantum_stage.py \
  shared/shared_models/tests/test_quantum_classify.py \
  shared/shared_models/tests/test_algorithm_registry.py \
  shared/shared_models/tests/test_field_accuracy.py \
  shared/shared_models/tests/test_field_accuracy_denominators.py \
  shared/shared_models/tests/test_bank_pqc_parameters.py \
  services/universal_crypto/tests/test_registry.py \
  services/universal_crypto/tests/test_accuracy.py \
  services/universal_crypto/tests/test_analysis.py \
  services/universal_crypto/tests/test_protocol_engine.py \
  -q "$@"
