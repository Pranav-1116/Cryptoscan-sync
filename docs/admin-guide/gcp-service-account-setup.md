# GCP service account setup

Create a service account and bind the custom role in `services/cloud_scanner/iam_policies/gcp_cryptoscan_role.yaml`. Point `GOOGLE_APPLICATION_CREDENTIALS` at the JSON key and set `GOOGLE_CLOUD_PROJECT`. Live scans cover Cloud KMS, Cloud Storage, Cloud SQL, and compute SSL policies.
