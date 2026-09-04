#!/usr/bin/env bash
# CryptoScan — run every host-level, backend-only scanner in one pass and save
# a timestamped JSON result for each. No frontend, no AI, deterministic only.
#
#   ./scripts/scan-all.sh                       # runtime + hardware
#   ./scripts/scan-all.sh --host example.com:443
#   ./scripts/scan-all.sh --host example.com:443 --full
#   ./scripts/scan-all.sh --discover 10.211.3.0/24 --ports 443,8443,8000
#   ./scripts/scan-all.sh --outdir /tmp/cs-scans
#
# Results land in scan-results/<UTC-timestamp>/{hardware,runtime,network}.json
# and a one-screen verdict is printed for each scanner.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
PY="${PYTHON:-python3}"

# Make every service + shared package importable.
export PYTHONPATH="$(for d in shared/*/ services/*/; do printf '%s%s:' "$REPO_ROOT/" "$d"; done)${PYTHONPATH:-}"

TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUTDIR="$REPO_ROOT/scan-results/$TS"
NET_HOST=""; NET_FULL=""; DISCOVER=""; PORTS="443,8443,8000,8080,9000,9001"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --host)      NET_HOST="${2:?--host needs host:port}"; shift 2;;
    --full)      NET_FULL="--full"; shift;;
    --discover)  DISCOVER="${2:?--discover needs CIDR}"; shift 2;;
    --ports)     PORTS="$2"; shift 2;;
    --outdir)    OUTDIR="${2:?--outdir needs a path}"; shift 2;;
    -h|--help)   grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done
mkdir -p "$OUTDIR"

echo "═══════════════════════════════════════════════════════════════"
echo " CryptoScan all-scanner run   $(date -u +'%Y-%m-%d %H:%M:%SZ')"
echo " output: $OUTDIR"
echo "═══════════════════════════════════════════════════════════════"

# ── 1. Hardware (CPU crypto + TPM/HSM/smartcard) ─────────────────────────
echo; echo "### HARDWARE"
"$PY" services/universal_vendor/hw_scan.py -o "$OUTDIR/hardware.json"
rc_hw=$?

# ── 2. Runtime host crypto inventory ─────────────────────────────────────
echo; echo "### RUNTIME (host crypto libraries & listeners)"
( cd services/runtime && "$PY" -m runtime.main processes > "$OUTDIR/runtime.json" 2> "$OUTDIR/runtime.err.log" )
rc_rt=$?
if [[ $rc_rt -eq 0 && -s "$OUTDIR/runtime.json" ]]; then
  ( cd services/runtime && "$PY" scan_report.py < "$OUTDIR/runtime.json" )
else
  echo "  runtime scan failed (rc=$rc_rt) — first error:"
  head -3 "$OUTDIR/runtime.err.log" | sed 's/^/    /'
fi

# ── 3. Network TLS (single host OR subnet discovery) ─────────────────────
echo; echo "### NETWORK"
run_net() {  # $@ = network_scanner.main args
  ( cd services/network_scanner && "$PY" -m network_scanner.main "$@" \
      > "$OUTDIR/network.json" 2> "$OUTDIR/network.err.log" )
}
if [[ -n "$NET_HOST" ]]; then
  ARGS=("$NET_HOST" "--scan-versions" "--scan-ciphers" "--check-chain")
  [[ -n "$NET_FULL" ]] && ARGS+=("--check-renegotiation" "--live-revocation")
  run_net "${ARGS[@]}"
  if [[ -s "$OUTDIR/network.json" ]]; then
    ( cd services/network_scanner && "$PY" tls_report.py < "$OUTDIR/network.json" )
  else
    echo "  network scan of $NET_HOST produced no result:"
    head -3 "$OUTDIR/network.err.log" | sed 's/^/    /'
    echo "    (hint: 'No module named yaml' => pip install pyyaml in your venv)"
  fi
elif [[ -n "$DISCOVER" ]]; then
  run_net --discover "$DISCOVER" --ports "$PORTS" --scan
  if [[ -s "$OUTDIR/network.json" ]]; then
    ( cd services/network_scanner && "$PY" tls_report.py < "$OUTDIR/network.json" )
  else
    echo "  discovery of $DISCOVER produced no result:"
    head -3 "$OUTDIR/network.err.log" | sed 's/^/    /'
    echo "    (hint: 'No module named yaml' => pip install pyyaml in your venv)"
  fi
else
  echo "  skipped (pass --host host:port or --discover CIDR to include)"
fi

# ── Summary ──────────────────────────────────────────────────────────────
echo; echo "═══════════════════════════════════════════════════════════════"
echo " JSON artifacts:"
for f in hardware runtime network; do
  [[ -s "$OUTDIR/$f.json" ]] && printf "   %-10s %s\n" "$f.json" "$(wc -c < "$OUTDIR/$f.json") bytes"
done
echo "═══════════════════════════════════════════════════════════════"
