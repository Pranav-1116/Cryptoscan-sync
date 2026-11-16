#!/bin/sh
# One-command certification — the deterministic release-verification path.
#
#   scripts/certify.sh            full certification (serial; CI/nightly)
#   scripts/certify.sh --fast     spot certification (the surfaces a change
#                                 is most likely to break; ~8 minutes)
#
# WHY SERIAL. Six tests pass serially and flake under pytest-xdist -n 2
# (test_health_failure_privacy x4, test_ha_readiness, the realtime
# catalog-leak test): cross-file process state collides when workers
# co-schedule them. Until that root cause is closed, the certification
# path is serial on purpose — a certify command that flakes is not a
# certify command.
#
# The full run also skips services/api/tests/integration/
# test_graph_dependency_stores.py UNLESS CERTIFY_INCLUDE_HEAVY=1: that
# suite OOMs in small sandboxes (environmental). CI with headroom must
# run it with CERTIFY_INCLUDE_HEAVY=1 — the script prints a loud note
# either way so the exclusion never rots silently.
#
# Exit: first red chunk fails the run (fail-fast), summary at the end.
set -u

PY="${PYTHON:-python3}"
[ -x ".venv/bin/python" ] && PY=".venv/bin/python"

# The documented full-suite PYTHONPATH: every service package root, plus
# the api test roots and services/inventory/tests (REQUIRED — its
# conftest fixtures are imported by name from sibling suites).
ROOT=$(pwd)
PP="$ROOT/shared/shared_models:$ROOT/shared/shared_config:$ROOT/shared/shared_logging:$ROOT/shared/shared_state"
for d in services/*/; do PP="$PP:$ROOT/${d%/}"; done
PP="$PP:$ROOT/scripts:$ROOT/services/api:$ROOT/services/api/tests:$ROOT/services/api/tests/unit:$ROOT/services/inventory/tests"
export PYTHONPATH="$PP"
export ENVIRONMENT="${ENVIRONMENT:-test}"

FAST=0
[ "${1:-}" = "--fast" ] && FAST=1

fail=0
done_list=""
skipped_list=""

chunk() {
  label="$1"; shift
  echo ""
  echo "=== certify: $label ==="
  if "$PY" -m pytest "$@" -q --no-header -p no:cacheprovider; then
    done_list="$done_list $label"
  else
    echo "=== certify: $label FAILED ===" >&2
    fail=1
    done_list="$done_list $label(FAILED)"
    summary
    exit 1
  fi
}

summary() {
  echo ""
  echo "=== certify summary ==="
  echo "completed:$done_list"
  [ -n "$skipped_list" ] && echo "skipped:$skipped_list"
  [ "$fail" -eq 0 ] && echo "VERDICT: PASS" || echo "VERDICT: FAIL"
}

# 1. The constitution gate — every reviewed-boundary check the repo ships.
# The report goes to /tmp: the gate's default output path is a user-owned
# evidence directory that certification must never write into.
#
# The gate's own verdict counts SKIP as non-PASS — correct for a release
# approval (which must supply manifests, provider credentials and
# customer samples), wrong for a certify run anywhere else. Certify
# hard-fails on FAIL checks and lists every SKIP loudly as
# not-evaluable-here so nothing rots silently.
echo "=== certify: engineering gate (constitution) ==="
"$PY" scripts/engineering_gate.py --out /tmp/certify-gate.json >/tmp/certify-gate.out 2>/tmp/certify-gate.err
gate_exit=$?
if ! "$PY" - /tmp/certify-gate.json <<'PYEOF'
import json, sys
report = json.load(open(sys.argv[1]))
bad = [c for c in report["checks"] if c["status"] == "FAIL"]
skips = [c for c in report["checks"] if c["status"] == "SKIP"]
for c in bad:
    print(f"gate FAIL: {c['check']} — {str(c.get('detail'))[:200]}", file=sys.stderr)
for c in skips:
    print(f"gate SKIP (not evaluable here): {c['check']} — {str(c.get('detail'))[:160]}")
sys.exit(1 if bad else 0)
PYEOF
then
  echo "gate FAILED (exit=$gate_exit)" >&2
  fail=1
  summary
  exit 1
fi
echo "gate: PASS (evaluable checks; SKIPs listed above)"
done_list="$done_list gate"

# 2. Cross-cutting contracts.
chunk "shared-contracts" shared/shared_models/tests shared/shared_config/tests shared/shared_logging/tests

if [ "$FAST" -eq 1 ]; then
  chunk "graph-plane" services/graph_engine/tests
  chunk "security-boundaries" services/api/tests/security
  chunk "durability-and-auth" \
    services/api/tests/unit/test_auth_monitor.py \
    services/api/tests/unit/test_security_state_durable.py \
    services/api/tests/unit/test_vault_staleness.py \
    services/api/tests/unit/test_evidence_chain_checkpoint.py \
    services/api/tests/unit/test_finding_provenance_bundle.py \
    services/api/tests/unit/test_fault_isolation_contract.py \
    services/api/tests/unit/test_projection_lag.py \
    services/api/tests/unit/test_auth_hardening.py
  chunk "migration-parity" services/database/tests
  summary
  exit "$fail"
fi

# 3. The full certification set — every test directory, serial.
chunk "database" services/database/tests
chunk "graph-plane" services/graph_engine/tests
chunk "api-security" services/api/tests/security
chunk "api-unit" services/api/tests/unit
chunk "worker-and-binary" services/worker/tests services/binary_intelligence/tests

if [ "${CERTIFY_INCLUDE_HEAVY:-0}" = "1" ]; then
  chunk "api-integration" services/api/tests/integration
else
  chunk "api-integration-minus-heavy" \
    --ignore=services/api/tests/integration/test_graph_dependency_stores.py \
    services/api/tests/integration
  skipped_list="$skipped_list api-integration/test_graph_dependency_stores(needs CERTIFY_INCLUDE_HEAVY=1: OOMs in small sandboxes — CI with headroom must run it)"
fi
chunk "api-tests-root" services/api/tests

# 4. Every remaining service test directory (sorted, one chunk each).
for d in services/*/tests; do
  case "$d" in
    services/api/tests|services/database/tests|services/graph_engine/tests|services/worker/tests|services/binary_intelligence/tests) continue ;;
  esac
  name=$(echo "$d" | sed 's#services/##; s#/tests##')
  chunk "$name" "$d"
done

summary
exit "$fail"
