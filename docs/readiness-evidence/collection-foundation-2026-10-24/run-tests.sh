#!/usr/bin/env bash
set -euo pipefail
# From repository root with approved Python on PATH; no CI or customer resources.
bash docs/readiness-evidence/host-estate-graph-2026-10-24/run-tests.sh \
  services/api/tests/unit/test_collection_foundation.py "$@"
