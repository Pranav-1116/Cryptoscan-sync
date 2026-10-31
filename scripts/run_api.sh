#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=env.sh
source "$(cd "$(dirname "$0")" && pwd)/env.sh"
# The client IP is resolved ONCE, in api.security.client_ip, against
# TRUSTED_PROXY_COUNT + TRUSTED_PROXY_CIDRS. uvicorn's --proxy-headers would
# rewrite the socket peer from X-Forwarded-For for ANY caller, which is exactly
# the spoof that boundary exists to stop — so it is deliberately not passed.
# Locally the dev proxy is the only hop, and it runs on loopback.
export TRUSTED_PROXY_COUNT="${TRUSTED_PROXY_COUNT:-1}"
export TRUSTED_PROXY_CIDRS="${TRUSTED_PROXY_CIDRS:-127.0.0.1/32,::1/128}"
exec python3 -m uvicorn api.main:app --host "${API_HOST:-0.0.0.0}" --port "${API_PORT:-8010}"
