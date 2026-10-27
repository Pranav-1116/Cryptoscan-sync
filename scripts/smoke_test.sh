#!/usr/bin/env bash
# Post-deploy smoke test — run against a live stack (prod or dev) and fail
# loudly if the platform is not actually serving.
#
#   BASE=http://127.0.0.1:8010 bash scripts/smoke_test.sh
#   BASE=https://cryptoscan.example.com SMOKE_USER=admin SMOKE_PASSWORD='…' bash scripts/smoke_test.sh
#
# Checks: /healthz, /readyz (DB), /metrics, authenticated login + one write-ish
# and one read surface per major layer (tech BOM, assurance, banking).
set -euo pipefail

BASE="${BASE:-http://127.0.0.1:8080}"
# USER is normally the shell account, not the API account.
SMOKE_USER="${SMOKE_USER:-admin}"
SMOKE_PASSWORD="${SMOKE_PASSWORD:-${PASSWORD:-cryptoscan}}"
INSECURE="${INSECURE:-}"
umask 077
RUN_DIR="$(mktemp -d "${TMPDIR:-/tmp}/cryptoscan-smoke.XXXXXX")"
BODY="$RUN_DIR/body"
cleanup() { rm -f -- "$BODY"; rmdir -- "$RUN_DIR"; }
trap cleanup EXIT
CURL=(curl -sS -o "$BODY" -w "%{http_code}")
if [[ -n "$INSECURE" ]]; then
  [[ "$INSECURE" == "-k" ]] || { printf 'smoke: INSECURE only accepts -k\n' >&2; exit 2; }
  CURL+=(-k)
fi

fail() { printf 'SMOKE FAIL: %s\n' "$1" >&2; exit 1; }
code() { "${CURL[@]}" "$1" || fail "request failed: $1"; }
# Headers travel on stdin, not in curl's process arguments or a token file.
code_auth() { printf 'Authorization: Bearer %s\n' "$TOKEN" | "${CURL[@]}" --header @- "$1" || fail "request failed: $1"; }
expect() { # expect <want> <label>
  [[ "$LAST" == "$1" ]] || fail "$2 (HTTP $LAST, want $1): $(head -c 200 "$BODY")"
  printf '  ok (%s) %s\n' "$LAST" "$2"
}

printf 'smoke: targeting %s\n' "$BASE"

LAST=$(code "$BASE/healthz");                       expect 200 "/healthz"
grep -q '"status"' "$BODY" || grep -qi ok "$BODY" || fail "/healthz body unexpected: $(head -c 120 "$BODY")"

LAST=$(code "$BASE/readyz");                        expect 200 "/readyz (database reachable)"

if [[ -n "${METRICS_TOKEN:-}" ]]; then
  LAST=$(printf 'Authorization: Bearer %s\n' "$METRICS_TOKEN" | "${CURL[@]}" --header @- "$BASE/metrics")
else
  LAST=$(code "$BASE/metrics")
fi
expect 200 "/metrics (Prometheus exposition)"
grep -q "^# " "$BODY" || fail "/metrics does not look like a Prometheus exposition"

# --- authenticated surfaces ------------------------------------------------
# JSON is generated from stdin so neither the password nor session token is
# exposed in a process argument, a predictable /tmp file, or shell tracing.
if ! LOGIN=$(printf '%s\0%s' "$SMOKE_USER" "$SMOKE_PASSWORD" \
  | python3 -c 'import json,sys; u,p=sys.stdin.buffer.read().split(b"\0",1); print(json.dumps({"username":u.decode(),"password":p.decode()}))' \
  | curl -fsS -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' --data-binary @-); then
  fail "login failed — set SMOKE_USER/SMOKE_PASSWORD for the deployed admin"
fi
TOKEN=$(printf '%s' "$LOGIN" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("token",""))')
unset LOGIN
[[ -n "$TOKEN" ]] || fail "login response carried no token"
[[ "$TOKEN" != *$'\n'* && "$TOKEN" != *$'\r'* ]] || fail "login token contains a newline"
printf '  ok (200) login\n'

LAST=$(code_auth "$BASE/api/v1/technology-bom");    expect 200 "technology BOM (unified inventory)"
LAST=$(code_auth "$BASE/api/v1/technology-bom/assurance"); expect 200 "assurance surface"
LAST=$(code_auth "$BASE/api/v1/banking/overview");  expect 200 "banking overview"
LAST=$(code_auth "$BASE/api/v1/banking/jurisdictions"); expect 200 "jurisdiction packs"
LAST=$(code_auth "$BASE/api/v1/banking/keys");      expect 200 "key lifecycle register"
LAST=$(code_auth "$BASE/api/v1/telecom/posture");   expect 200 "telecom posture (realtime scanner)"
LAST=$(code_auth "$BASE/api/v1/telecom/registry");  expect 200 "telecom registry"

printf 'SMOKE OK — platform is serving on %s\n' "$BASE"
