# Cloud scanner design

IaC parsers (Terraform, CloudFormation, ARM, Kubernetes) always run. Live adapters for AWS (KMS, S3, RDS, ELB, ACM, CloudFront, Secrets Manager, API Gateway), Azure (Key Vault, Storage, SQL, App Gateway), and GCP (KMS, Storage, SQL, SSL policies) run only when enabled. All adapters emit the shared `cloud_finding` shape so evidence, dedup, and policy stay unchanged.
