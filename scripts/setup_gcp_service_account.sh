#!/usr/bin/env bash
# Print GCP custom role definition used by CryptoScan. APPLY=1 creates a service account.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ROLE="$ROOT/services/cloud_scanner/iam_policies/gcp_cryptoscan_role.yaml"
echo "CryptoScan GCP role: $ROLE"
cat "$ROLE"
if [[ "${APPLY:-0}" == "1" ]]; then
  gcloud iam service-accounts create cryptoscan-readonly --display-name="CryptoScan ReadOnly"
fi
