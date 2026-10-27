# Cloud and IaC scanning

The cloud scanner reads Terraform, CloudFormation, Azure ARM, and Kubernetes
manifests in the tree. Live AWS, Azure, and GCP API calls are fail-open and
off unless `CRYPTOSCAN_CLOUD_LIVE=1` plus the matching SDK/credentials.

It flags:

- S3 / RDS resources with no encryption
- KMS key specs (AES-256, RSA-2048, …)
- Weak ELB TLS policies (`TLS-1-0`, `TLS-1-1`)
- Kubernetes TLS secrets and Ingress TLS

Live AWS API calls require `boto3` plus credentials and `CRYPTOSCAN_CLOUD_LIVE=1`. They are fail-open and off by default.

```bash
python scripts/run_cloud_scan.py demo/polyglot-app
```
