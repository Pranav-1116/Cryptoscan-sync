#!/usr/bin/env bash
# Repository root, approved Python on PATH; no workflows or customer systems.
set -euo pipefail
bash docs/readiness-evidence/collector-security-2026-10-24/run-tests.sh \
  services/api/tests/unit/test_host_worker.py "$@"
