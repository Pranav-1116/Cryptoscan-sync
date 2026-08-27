# CryptoScan partner deployment plumbing

One-click installations that grant the CryptoScan scanner read-only,
crypto-inventory access to a customer estate. Each template implements
least privilege: **discovery + read only** — never data-plane access to
encrypted content, never key material.

## AWS — `aws-cross-account-role.yaml` (CloudFormation)

Customer installs the CryptoScan marketplace product (or runs this
template directly) in the **management account** with:

- `CryptoScanAccountId` — the partner's AWS account ID (trusted principal)
- `ExternalId` — the shared external id issued to this customer
- `RoleName` — default `CryptoScanCrossAccountRole`

What it grants:

- `SecurityAudit` AWS-managed policy (read-only security inventory:
  KMS, S3/RDS/EBS encryption, ACM, ELB policies, Secrets Manager, …)
- an inline supplement for services SecurityAudit misses
  (`ssm:DescribeParameters`, `secretsmanager:ListSecrets`,
  `dynamodb:DescribeTable`, `sqs:GetQueueAttributes`, `sns:GetTopicAttributes`,
  `eks:DescribeCluster`, `redshift:DescribeClusters`, `opensearch:DescribeDomain`)
- `organizations:ListAccounts` **on the management account only**, so a
  single org job can enumerate every member account
- AssumeRole trust locked to `CryptoScanAccountId` + `ExternalId`
  (confused-deputy protection)

Outputs: `RoleArn` (paste into `POST /cloud/orgs/discover` as
`role_name`, or set `CRYPTOSCAN_AWS_ORG_ROLE_NAME`).

## Azure — `azure-lighthouse-registration.json` (ARM)

Azure partnerships use **Azure Lighthouse** delegation (or tenant-level
app consent for private pilots):

1. Partner publishes the CryptoScan managed application to the
   commercial marketplace; the offer's Lighthouse manifest declares the
   reading roles (`Reader`, `Security Reader`).
2. Customer purchases → picks the subscription/management group →
   delegation completes. No credentials ever change hands.
3. This template is the fallback/manual registration: deploy at
   `subscription scope` with the offer's `RegistrationDefinitionId`
   (or a programmatic `managedByTenantId` + roleDefinitionId pair).

For private pilots without Lighthouse: create a multi-tenant app
registration, admin-consent it at the tenant, and set
`AZURE_SUBSCRIPTION_ID`/credential env on the scanner host —
`enumerate_azure_subscriptions` then lists every subscription the
principal can see.

## GCP — `gcp-org-role.yaml` + commands

GCP has no assume-role; the model is an org-level IAM binding:

```bash
# 1. create the least-privilege custom role at the organization
gcloud iam roles create cryptoscan_scanner --organization=ORG_ID \
    --file=deploy/marketplace/gcp-org-role.yaml

# 2. grant it to the CryptoScan service account at the org (or a folder)
gcloud organizations add-iam-policy-binding ORG_ID \
    --member="serviceAccount:scanner@cryptoscan-partner.iam.gserviceaccount.com" \
    --role="organizations/ORG_ID/roles/cryptoscan_scanner"
```

The role grants `resourcemanager.projects.get/list` (org discovery) plus
read-only crypto inventory permissions (cloudkms, storage, sqladmin,
compute sslPolicies, container, secretmanager, pubsub).

## Scanner-side configuration

| Env | Meaning | Default |
|---|---|---|
| `CRYPTOSCAN_AWS_ORG_ROLE_NAME` | member-account role to assume | `CryptoScanCrossAccountRole` |
| `CRYPTOSCAN_CLOUD_ORG_MAX_ACCOUNTS` | discovery cap (truncation recorded) | `200` |
| `CRYPTOSCAN_CLOUD_FANOUT_WORKERS` | parallel account scans per org job | `8` |
| `CRYPTOSCAN_CLOUD_ORG_RATE` | account-scan starts per second | `4` |

## Kicking off an org scan

```
POST /api/v1/cloud/orgs/discover   {"provider":"aws","role_name":"CryptoScanCrossAccountRole"}
POST /api/v1/cloud/orgs/scan       {"provider":"aws"}          # single fan-out job
```

Targets `cloud://aws-org/<mgmt-id>`, `cloud://azure-org/<tenant>`,
`cloud://gcp-org/<folder-or-org-id>` also work anywhere cloud targets
are accepted.
