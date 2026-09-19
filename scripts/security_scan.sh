#!/usr/bin/env bash
# Production security scan — dependency CVEs, lint defects, secret hygiene.
#
#   bash scripts/security_scan.sh
#
# 1. pip-audit over requirements.lock.txt (the pinned set the test gate ran)
# 2. ruff defect gate (F+E9, the CI baseline)
# 3. high-signal secret pattern scan over tracked files (offline substitute for
#    gitleaks; add gitleaks in CI when workflows are activated)
#
# Exits non-zero on ANY finding — this is a release gate, not a report.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PY="${PYTHON:-.venv/bin/python}"
[ -x "$PY" ] || PY=python3
FAILED=0

echo "== 1/3 dependency audit (pip-audit) =="
if ! "$PY" -m pip_audit --version >/dev/null 2>&1; then
  echo "  installing pip-audit into the venv…"
  "$PY" -m pip install --quiet pip-audit || { echo "FAIL: pip-audit unavailable" >&2; exit 1; }
fi
LOCK="requirements.lock.txt"
if [ -f "$LOCK" ]; then
  # requirements.lock.txt uses the `name==version` requirement format directly.
  if "$PY" -m pip_audit -r "$LOCK" --progress-spinner off --no-deps; then
    echo "  ok — no known CVEs in $LOCK"
  else
    echo "FAIL: known vulnerabilities in $LOCK (upgrade + re-lock via 'make lock')" >&2
    FAILED=1
  fi
else
  echo "  WARN: $LOCK missing — run 'make lock' to pin before release" >&2
fi

echo "== 2/3 lint defect gate (ruff F+E9) =="
if "$PY" -m ruff check --select F,E9 services scripts 2>/dev/null; then
  echo "  ok — ruff defect gate clean"
else
  echo "FAIL: ruff defect findings above" >&2
  FAILED=1
fi

echo "== 3/3 secret hygiene (tracked files) =="
# High-signal patterns only; suppresses common false positives by construction
# (placeholder/example values are allow-listed below).
PATTERNS=(
  'AKIA[0-9A-Z]{16}'                                     # AWS access key id
  '-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----'      # private key material
  'xox[baprs]-[0-9A-Za-z-]{10,}'                         # Slack tokens
  'gh[pousr]_[0-9A-Za-z]{36,}'                           # GitHub tokens
  'sk-(live|test)-[0-9A-Za-z]{16,}'                      # Stripe-style keys
)
matches=$(
  { git grep -nIE "$(IFS='|'; echo "${PATTERNS[*]}")" -- . 2>/dev/null \
      | grep -vE "\.example|test|spec|fixture|\.md:|docs/" \
      | grep -vE "ci-only|placeholder|changeme|your[-_]" || true; }
)
if [ -n "$matches" ]; then
  echo "FAIL: potential secrets in tracked files:" >&2
  echo "$matches" | head -20 >&2
  FAILED=1
else
  echo "  ok — no high-signal secret patterns"
fi

if [ "$FAILED" -ne 0 ]; then
  echo "SECURITY SCAN: FAILED" >&2
  exit 1
fi
echo "SECURITY SCAN: PASS"
