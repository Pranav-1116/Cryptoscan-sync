# ADR-013 Multi-cloud IAM strategy

## Status

Accepted.

## Decision

Cloud scanners assume a read-only role: AWS `CryptoScanReadOnly` (STS assume-role), Azure service principal with a custom Reader role, GCP service account with a custom Viewer role. Live API calls are fail-open when SDKs or credentials are missing so CI and IaC-only scans keep working.

## Consequences

- Reference policies live in `services/cloud_scanner/iam_policies/`.
- IaC parsers always run; live KMS / S3 / RDS / ELB / ACM / Azure SQL / GCP SSL scans run only when `CRYPTOSCAN_CLOUD_LIVE` is set.
