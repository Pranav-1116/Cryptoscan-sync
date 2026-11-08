#!/usr/bin/env bash
set -euo pipefail
# Repository root; approved Python/dependencies on PATH. Never customer resources/CI.
bash docs/readiness-evidence/host-estate-graph-2026-10-24/run-tests.sh \
  services/api/tests/unit/test_collection_foundation.py "$@"
