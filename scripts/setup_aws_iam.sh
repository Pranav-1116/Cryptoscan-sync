#!/usr/bin/env bash
# Print / apply the CryptoScan read-only IAM policy. Does not create live AWS resources unless APPLY=1.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
POLICY="$ROOT/services/cloud_scanner/iam_policies/aws_cryptoscan_policy.json"
echo "CryptoScan AWS IAM policy: $POLICY"
cat "$POLICY"
if [[ "${APPLY:-0}" == "1" ]]; then
  aws iam create-policy --policy-name CryptoScanReadOnly --policy-document "file://$POLICY" || true
fi
