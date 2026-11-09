#!/bin/sh
# Tier-2 runtime capture driver (docs/os-kernel-intelligence/
# 01_PRODUCT_SPEC.md §3). Run ONLY on an authorised host under an
# approved runtime-tracing profile.
#
# The driver:
#   1. checks prerequisites (root, bpftrace, tracefs);
#   2. ENUMERATES available instrumentation points and records exactly
#      what it attaches to (tracepoints differ across kernels — never
#      assumed);
#   3. runs the bounded collector for N seconds;
#   4. writes EVT/META/LOST records + a session manifest with the
#      collector's own loss accounting.
#
# METADATA EVENTS ONLY — the emitted format has no field for payloads,
# keys or buffers.
set -eu
DURATION="${1:-30}"
OUT="${2:-runtime-capture-$(date +%Y%m%d-%H%M%S)}"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

[ "$(id -u)" = "0" ] || {
  echo "refused: runtime capture requires root on the authorised host"
  exit 1
}
command -v bpftrace >/dev/null 2>&1 || {
  echo "refused: bpftrace is not installed — recorded as unavailable,"
  echo "never as 'no runtime activity'"
  exit 1
}

mkdir -p "$OUT"
TRACEFS=/sys/kernel/tracing
[ -d "$TRACEFS/events" ] || TRACEFS=/sys/kernel/debug/tracing

# Enumerate what THIS kernel actually exposes — honesty first.
ATTACHED=""
if [ -d "$TRACEFS/events/crypto" ]; then
  for tp in "$TRACEFS"/events/crypto/*/; do
    [ -f "$tp/format" ] || continue
    ATTACHED="${ATTACHED}tracepoint:crypto:$(basename "$tp"),"
  done
fi

{
  echo "META|boot_id=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || echo unknown)"
  echo "META|kernel=$(uname -r)"
  echo "META|started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "META|attached_points=${ATTACHED%,}"
} > "$OUT/trace.txt"

if [ -n "$ATTACHED" ]; then
  bpftrace "$SCRIPT_DIR/crypto_trace.bt" >> "$OUT/trace.txt" 2> "$OUT/bpftrace.stderr" &
  BT_PID=$!
  sleep "$DURATION"
  kill -INT "$BT_PID" 2>/dev/null || true
  wait "$BT_PID" 2>/dev/null || true
else
  echo "META|attached_points=none" >> "$OUT/trace.txt"
  echo "no crypto tracepoints exposed by this kernel — the session is" \
       "recorded as collected-with-zero-attached-points, never as" \
       "'no crypto activity'" >> "$OUT/trace.txt"
fi

# Fold bpftrace's own dropped-record reporting into loss accounting.
LOST=$(grep -ci "lost.*event\|dropped" "$OUT/bpftrace.stderr" 2>/dev/null || echo 0)
[ "$LOST" -gt 0 ] 2>/dev/null && echo "LOST|$LOST" >> "$OUT/trace.txt"
echo "META|ended_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$OUT/trace.txt"
echo "wrote $OUT/trace.txt (metadata events only — §3)"
