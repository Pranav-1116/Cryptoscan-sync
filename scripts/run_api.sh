#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=env.sh
source "$(cd "$(dirname "$0")" && pwd)/env.sh"
exec python3 -m uvicorn api.main:app --host 0.0.0.0 --port "${API_PORT:-8010}" --proxy-headers --forwarded-allow-ips='*'
