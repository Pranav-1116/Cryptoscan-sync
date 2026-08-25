#!/usr/bin/env bash
# Print Azure custom role definition used by CryptoScan. APPLY=1 runs az ad sp create-for-rbac.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ROLE="$ROOT/services/cloud_scanner/iam_policies/azure_cryptoscan_role.json"
echo "CryptoScan Azure role: $ROLE"
cat "$ROLE"
if [[ "${APPLY:-0}" == "1" ]]; then
  az ad sp create-for-rbac --name cryptoscan-readonly --role Reader --scopes "/subscriptions/${AZURE_SUBSCRIPTION_ID:?}"
fi
