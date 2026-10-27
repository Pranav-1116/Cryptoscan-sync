#!/usr/bin/env bash
# CryptoScan runtime scan — one-command local report (Linux).
#
# Prints, for this machine:
#   1. CONFIRMED RISKS   — EOL/weak TLS libraries with a verified version
#   2. LIBRARY INVENTORY — every TLS library, its resolved version, the OS
#      package it came from, and the verdict (ALLOWED / UNKNOWN / risk).
#      UNKNOWN = unmanaged copy (venv/pyenv/static build, browser bundle) the
#      package manager cannot version — review manually, not an auto-risk.
#   3. LISTENING PORTS   — processes with TCP listeners (TLS endpoints).
#
# Usage:
#   ./scan-laptop.sh             # report to stdout
#   ./scan-laptop.sh --submit    # also submit to CRYPTOSCAN_API_URL
#
# Requires only python3 (stdlib). For --submit set CRYPTOSCAN_API_URL and
# CRYPTOSCAN_API_TOKEN.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PY="${PYTHON:-python3}"

if [[ "${1:-}" == "--submit" ]]; then
  exec "$PY" -m runtime.main once --submit
fi

"$PY" -m runtime.main processes 2>/dev/null | "$PY" scan_report.py
