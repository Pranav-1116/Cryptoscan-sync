#!/bin/sh
# Enrol once (idempotent), then run. Configuration comes from CRYPTAVA_* variables.
#   CRYPTAVA_SERVER            console URL (required)
#   CRYPTAVA_NAME              unique agent name, e.g. mrdn-prod-dc1-$(NODE_NAME)
#   CRYPTAVA_PROVISION_KEY     admin API key (or "Bearer <token>") for one-step enrolment
#   CRYPTAVA_AGENT_ID + CRYPTAVA_ENROLLMENT_TOKEN   alternatively, a token from the console
#   CRYPTAVA_LOGIN_USER / CRYPTAVA_LOGIN_PASSWORD   sandbox only: log in to get a bearer
set -eu
if command -v cryptava >/dev/null 2>&1; then CV="cryptava"; else
  export PYTHONPATH="${PYTHONPATH:-/opt/cryptava}"; CV="python3 -m cryptava"; fi
STATE="${CRYPTAVA_STATE_DIR:-/var/lib/cryptava}"
mkdir -p "$STATE" && chmod 0700 "$STATE"

if [ ! -f "$STATE/identity.json" ]; then
  if [ -z "${CRYPTAVA_PROVISION_KEY:-}" ] && [ -n "${CRYPTAVA_LOGIN_USER:-}" ]; then
    echo "cryptava: signing in to ${CRYPTAVA_SERVER} as ${CRYPTAVA_LOGIN_USER} to enrol"
    for attempt in 1 2 3 4 5 6 7 8 9 10 11 12; do
      TOKEN="$(python3 - <<'PY' || true
import json, os, urllib.request
req = urllib.request.Request(os.environ["CRYPTAVA_SERVER"].rstrip("/") + "/api/v1/auth/login",
    data=json.dumps({"username": os.environ["CRYPTAVA_LOGIN_USER"],
                     "password": os.environ.get("CRYPTAVA_LOGIN_PASSWORD", "")}).encode(),
    headers={"Content-Type": "application/json"}, method="POST")
print(json.load(urllib.request.urlopen(req, timeout=15))["token"])
PY
)"
      [ -n "$TOKEN" ] && break
      echo "cryptava: console not ready (attempt $attempt) — retrying in 10s"; sleep 10
    done
    [ -n "$TOKEN" ] || { echo "cryptava: could not sign in" >&2; exit 3; }
    export CRYPTAVA_PROVISION_KEY="Bearer $TOKEN"
  fi
  if [ -n "${CRYPTAVA_AGENT_ID:-}" ]; then
    $CV enroll --agent-id "$CRYPTAVA_AGENT_ID"
  else
    $CV enroll --name "${CRYPTAVA_NAME:?set CRYPTAVA_NAME to a unique agent name}"
  fi
  unset CRYPTAVA_PROVISION_KEY
fi

if [ "$#" -gt 0 ]; then
  exec $CV "$@"
fi
exec $CV run
