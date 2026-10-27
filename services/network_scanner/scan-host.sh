#!/usr/bin/env bash
# CryptoScan network TLS scan — one-screen verdict for a host (or subnet).
#
#   ./scan-host.sh host:port                 # versions + weak ciphers + chain
#   ./scan-host.sh host:port --full          # + renegotiation + live OCSP/CRL
#   ./scan-host.sh --discover CIDR [--ports 443,8443,8000]
#
# Prints a compact verdict instead of raw JSON. stdlib python only.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
PY="${PYTHON:-python3}"

if [[ "${1:-}" == "--discover" ]]; then
  CIDR="${2:?usage: scan-host.sh --discover <CIDR> [--ports 443,8443]}"
  shift 2 || true
  PORTS="443,8443"
  if [[ "${1:-}" == "--ports" ]]; then PORTS="${2:-$PORTS}"; fi
  echo "## discovering $CIDR on $PORTS ..."
  "$PY" -m network_scanner.main --discover "$CIDR" --ports "$PORTS" --scan 2>/dev/null | "$PY" tls_report.py
  exit 0
fi

TARGET="${1:?usage: scan-host.sh <host:port> [--full]}"
shift || true
ARGS=("--scan-versions" "--scan-ciphers" "--check-chain")
if [[ "${1:-}" == "--full" ]]; then
  ARGS+=("--check-renegotiation" "--live-revocation")
fi

echo "## scanning $TARGET ${ARGS[*]} ..."
"$PY" -m network_scanner.main "$TARGET" "${ARGS[@]}" 2>/dev/null | "$PY" tls_report.py
