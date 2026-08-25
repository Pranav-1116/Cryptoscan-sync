# Azure service principal setup

Register an app and grant it the custom role in `services/cloud_scanner/iam_policies/azure_cryptoscan_role.json` on the target subscription. Export `AZURE_SUBSCRIPTION_ID`, `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, and `AZURE_CLIENT_SECRET` (or use managed identity). Live scans also read Key Vault, Storage, SQL TDE, and Application Gateway TLS policy.
