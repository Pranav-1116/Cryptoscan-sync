# AWS IAM setup

Create role `CryptoScanReadOnly` in each scanned account. Attach `services/cloud_scanner/iam_policies/aws_cryptoscan_policy.json`. Trust the CryptoScan scanner account (or the local operator role) to call `sts:AssumeRole`.

Set `CRYPTOSCAN_CLOUD_LIVE=1` and standard AWS credentials (`AWS_PROFILE`, instance role, or access keys). Restrict `regions` on the cloud account record if you do not want every public region scanned.
