#!/usr/bin/env bash
# From repository root, approved validation Python on PATH; no CI/customer work.
set -euo pipefail
bash docs/readiness-evidence/host-collection-2026-10-24/run-tests.sh \
  services/api/tests/unit/test_host_associations.py \
  services/api/tests/unit/test_ssh_receipt_contract.py "$@"
