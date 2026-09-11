#!/usr/bin/env bash
# Post-deploy smoke test — run against a live stack (prod or dev) and fail
# loudly if the platform is not actually serving.
#
#   BASE=http://127.0.0.1:8080 bash scripts/smoke_test.sh
#   BASE=https://cryptoscan.example.com USER=admin PASSWORD='…' bash scripts/smoke_test.sh
#
# Checks: /healthz, /readyz (DB), /metrics, authenticated login + one write-ish
# and one read surface per major layer (tech BOM, assurance, banking).
set -euo pipefail

BASE="${BASE:-http://127.0.0.1:8080}"
USER="${USER:-admin}"
PASSWORD="${PASSWORD:-cryptoscan}"
INSECURE="${INSECURE:-}"
CURL=(curl -sS -o /tmp/smoke_body -w "%{http_code}" $INSECURE)

fail() { echo "SMOKE FAIL: $1" >&2; exit 1; }
code() { "${CURL[@]}" "$1" || fail "request failed: $1"; }
code_auth() { "${CURL[@]}" -H "Authorization: Bearer ${TOKEN}" "$1" || fail "request failed: $1"; }
expect() { # expect <want> <label>
  [[ "$LAST" == "$1" ]] || fail "$2 (HTTP $LAST, want $1): $(head -c 200 /tmp/smoke_body)"
  echo "  ok ($LAST) $2"
}

echo "smoke: targeting $BASE"

LAST=$(code "$BASE/healthz");                       expect 200 "/healthz"
grep -q '"status"' /tmp/smoke_body || grep -qi ok /tmp/smoke_body || fail "/healthz body unexpected: $(head -c 120 /tmp/smoke_body)"

LAST=$(code "$BASE/readyz");                        expect 200 "/readyz (database reachable)"

LAST=$(code "$BASE/metrics");                       expect 200 "/metrics (Prometheus exposition)"
grep -q "^# " /tmp/smoke_body || fail "/metrics does not look like a Prometheus exposition"

# --- authenticated surfaces ------------------------------------------------
LAST=$(curl -sS -o /tmp/smoke_login -w "%{http_code}" -X POST "$BASE/api/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"$USER\",\"password\":\"$PASSWORD\"}")
[[ "$LAST" == "200" ]] || fail "login failed (HTTP $LAST) — set USER/PASSWORD for the deployed admin"
TOKEN=$(python3 -c 'import json;print(json.load(open("/tmp/smoke_login")).get("token",""))' 2>/dev/null || true)
[[ -n "$TOKEN" ]] || fail "login response carried no token"
echo "  ok (200) login"

LAST=$(code_auth "$BASE/api/v1/technology-bom");    expect 200 "technology BOM (unified inventory)"
LAST=$(code_auth "$BASE/api/v1/technology-bom/assurance"); expect 200 "assurance surface"
LAST=$(code_auth "$BASE/api/v1/banking/overview");  expect 200 "banking overview"
LAST=$(code_auth "$BASE/api/v1/banking/jurisdictions"); expect 200 "jurisdiction packs"
LAST=$(code_auth "$BASE/api/v1/banking/keys");      expect 200 "key lifecycle register"
LAST=$(code_auth "$BASE/api/v1/telecom/posture");   expect 200 "telecom posture (realtime scanner)"
LAST=$(code_auth "$BASE/api/v1/telecom/registry");  expect 200 "telecom registry"

echo "SMOKE OK — platform is serving on $BASE"
