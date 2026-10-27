# Shared process environment for API, worker, and local scripts.
# shellcheck shell=bash
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export CRYPTOSCAN_ROOT="${CRYPTOSCAN_ROOT:-$ROOT}"

# Auto-discover every service + shared package instead of maintaining a
# hand-written list that rots each time a service is added (the container
# image does the same via its cryptoscan.pth file — see .docker/api/Dockerfile).
_CS_PATHS=()
for _dir in "$ROOT"/shared/*/ "$ROOT"/services/*/; do
  [ -d "$_dir" ] && _CS_PATHS+=("$_dir")
done
_JOINED="$(IFS=:; echo "${_CS_PATHS[*]}")"
export PYTHONPATH="${_JOINED}${PYTHONPATH:+:$PYTHONPATH}"
mkdir -p "$ROOT/data/workspaces"
cd "$ROOT"
