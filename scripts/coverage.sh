#!/usr/bin/env bash
# Opt-in coverage report per service (round 17 — report 16).
#
# The gate is the suite result, never a coverage number; this script exists
# so the number is at least MEASURED honestly instead of estimated. CI
# wiring stays blocked by the standing no-workflows constraint (see
# .github/workflows-pending/).
#
# Usage: scripts/coverage.sh [service-dir ...]
#        scripts/coverage.sh services/api services/evidence
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if ! python3 -c "import pytest_cov" 2>/dev/null; then
  echo "pytest-cov not installed — run: pip3 install --break-system-packages -r requirements.txt" >&2
  exit 1
fi

SERVICES=("$@")
if [ ${#SERVICES[@]} -eq 0 ]; then
  SERVICES=(services/api services/worker services/scanner services/database \
            services/policy services/cbom services/evidence services/universal_crypto)
fi

export PP="$(for d in services/*/ shared/*/; do printf '%s%s:' "$PWD/" "$d"; done)"
FAILED=0

for svc in "${SERVICES[@]}"; do
  name="$(basename "$svc")"
  echo "=== $name ==="
  (
    cd "$svc"
    export PYTHONPATH="$PWD:$PP"
    if [ "$name" = "api" ]; then
      export ENVIRONMENT=test
      export SECRET_KEY="test-secret-key-for-sessions-min-32-chars"
      export GITHUB_WEBHOOK_SECRET="test-webhook-secret-abc123"
      export ALLOW_SQLITE=true
    fi
    python3 -m pytest tests -q --cov --cov-config="$ROOT/.coveragerc" \
      --cov-report="term-missing:skip-covered" \
      --cov-report="xml:$ROOT/coverage-$name.xml" -p no:cacheprovider
  ) || FAILED=1
  echo
done

python3 -m coverage combine --keep 2>/dev/null || true
if [ "$FAILED" -ne 0 ]; then
  echo "coverage run finished, but at least one suite FAILED — the gate is the suite result" >&2
fi
echo "per-service XML reports: coverage-<service>.xml (combined data in .coverage)"
exit $FAILED
