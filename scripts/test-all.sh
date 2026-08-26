#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
if command -v make >/dev/null 2>&1; then
  exec make test
fi
echo "make is required to run the per-service pytest suite" >&2
exit 1
