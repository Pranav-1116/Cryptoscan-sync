#!/usr/bin/env bash
# CryptoScan hardware scanner — local CPU crypto capabilities + TPM/HSM/smartcard.
# Public metadata only; never reads secret material. Stdlib python, no deps.
#
#   ./scan-hardware.sh            # one-screen verdict
#   ./scan-hardware.sh --json     # full JSON
#   ./scan-hardware.sh -o hw.json # write JSON, still print verdict

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
exec "${PYTHON:-python3}" hw_scan.py "$@"
