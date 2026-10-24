#!/usr/bin/env bash
set -euo pipefail
# Approved Python on PATH, repository root. No workflow/customer changes.
bash docs/readiness-evidence/host-estate-graph-2026-10-24/run-tests.sh \
  services/api/tests/unit/test_collection_foundation.py \
  services/api/tests/unit/test_collector_identity.py "$@"
