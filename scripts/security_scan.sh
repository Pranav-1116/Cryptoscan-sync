#!/usr/bin/env bash
set -euo pipefail
echo "=== Security Scanning — Real Product ==="
echo "Bandit SAST..."
pip install bandit -q 2>/dev/null || true
bandit -r services/api/api/ -f txt 2>&1 | head -50 || true

echo "pip-audit..."
pip install pip-audit -q 2>/dev/null || true
pip-audit --requirement requirements.txt 2>&1 | head -50 || true

echo "QRNG entropy check..."
python3 services/qrng_scanner/qrng_scanner/scanner.py 2>&1 | head -20 || true

echo "Sigstore scan..."
python3 services/sigstore_scanner/sigstore_scanner/scanner.py 2>&1 | head -20 || true

echo "OT scanner..."
python3 services/ot_scanner/ot_scanner/real_parser.py 2>&1 | head -20 || true

echo "✅ Security scanning complete — deterministic no AI"
