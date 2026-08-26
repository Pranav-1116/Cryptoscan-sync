# Cloud scanner design

IaC parsers (Terraform, CloudFormation, ARM, Kubernetes) always run. Live adapters for AWS (KMS, S3, RDS, ELB, ACM, CloudFront, Secrets Manager, API Gateway), Azure (Key Vault, Storage, SQL, App Gateway), and GCP (KMS, Storage, SQL, SSL policies) run only when enabled (`live=true` on the request, `CloudScanner(live=True)`, or `CRYPTOSCAN_CLOUD_LIVE`). All adapters emit the shared `cloud_finding` shape so evidence, dedup, and policy stay unchanged.

## Estate inventory

A bank estate is not a seven-file demo. `cloud_scanner.estate` maps each cryptographic resource to a system (`aws:kms:alias/payments`) with `scan_target=cloud://…`. Inventory upserts those systems and stamps `CURRENT` only after the live/IaC scan that discovered them. Coverage campaigns (`POST /estate/campaigns`, `POST /cbom/scan-uncovered`) enqueue at most 25–100 jobs and **one CLOUD job per cloud account**, never one job per resource. The worker `job_type=CLOUD` path calls `CloudScanner.scan_live` and does not clone git.
