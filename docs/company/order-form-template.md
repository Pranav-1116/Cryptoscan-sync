# CryptoScan Order Form template

**Template status:** commercial/legal review required; not a quote or contract
until signed
**Order Form ID:** `[ID]`
**MSA:** `[MSA REFERENCE AND DATE]`
**Customer:** `[CUSTOMER LEGAL NAME]`
**Vendor:** `[VENDOR LEGAL NAME]`

The MSA sets the general relationship. This Order Form makes the relationship
specific enough to operate, price, measure, support, and exit.

## 1. Commercial summary

| Field | Value |
|---|---|
| Service | CryptoScan `[SERVICE/TIER]` |
| Order term | `[START]` to `[END]` |
| Renewal | `[YES/NO; NOTICE]` |
| Deployment model | `[CUSTOMER-MANAGED / DEDICATED MANAGED / PRIVATE / AIR-GAPPED]` |
| Service region | `[REGION]` |
| Customer entity | `[LEGAL ENTITY]` |
| Customer affiliates | `[LIST OR NONE]` |
| Vendor entity | `[LEGAL ENTITY]` |
| Billing currency | `[CURRENCY]` |
| Payment terms | `[TERMS]` |
| Governing law | `[LAW]` |

## 2. Business objective

```text
Primary objective: _______________________
Secondary objectives: ____________________
Decision to be made: _____________________
Customer sponsor: ________________________
Customer risk owner: _____________________
```

## 3. Scope and entitlements

| Source or capability | Included scope | Volume/frequency | Exclusions |
|---|---|---|---|
| Repositories/applications | `[SCOPE]` | `[COUNT/RATE]` | `[EXCLUSIONS]` |
| Cloud accounts/regions | `[SCOPE]` | `[COUNT/RATE]` | `[EXCLUSIONS]` |
| TLS/network targets | `[SCOPE]` | `[COUNT/RATE]` | `[EXCLUSIONS]` |
| Certificates/HSM/KMS | `[SCOPE]` | `[COUNT/RATE]` | `[EXCLUSIONS]` |
| Mainframe/payment/telecom | `[SCOPE]` | `[COUNT/RATE]` | `[EXCLUSIONS]` |
| Users/roles | `[SCOPE]` | `[COUNT]` | `[EXCLUSIONS]` |
| Reports/evidence retention | `[SCOPE]` | `[PERIOD]` | `[EXCLUSIONS]` |
| Integrations | `[SCOPE]` | `[COUNT]` | `[EXCLUSIONS]` |

The source authorization, scan mode, rate limits, data classification, and
prohibited data are defined in the [Data-Processing Terms](data-processing-terms.md)
and [Acceptable-Use Terms](acceptable-use-terms.md).

## 4. Deployment and data location

| Item | Customer-specific value |
|---|---|
| Application/API location | `[REGION/ACCOUNT]` |
| Database location | `[REGION/ACCOUNT]` |
| Evidence/object storage | `[REGION/ACCOUNT]` |
| Logs/monitoring | `[REGION/ACCOUNT]` |
| Backup/DR | `[REGION/ACCOUNT]` |
| Vendor support location | `[LOCATION]` |
| Subprocessors | `[REGISTER VERSION/URL]` |
| Transfer mechanism | `[MECHANISM]` |
| Customer-managed components | `[LIST]` |
| Vendor-managed components | `[LIST]` |

Attach the approved [Security Architecture](security-architecture.md),
[Residency Schedule](data-residency-and-transfers.md), and DPA.

## 5. Implementation milestones

| Milestone | Owner | Target | Acceptance |
|---|---|---:|---|
| Charter and access approved | Shared | `[DATE]` | Signed scope |
| Deployment ready | Vendor/customer | `[DATE]` | Health and guards pass |
| First source connected | Customer | `[DATE]` | Read-only test pass |
| Baseline scan | Vendor/customer | `[DATE]` | Coverage recorded |
| Accuracy review | Customer | `[DATE]` | Workbook reviewed |
| Operational exercise | Shared | `[DATE]` | Results retained |
| Final acceptance | Customer | `[DATE]` | Expand/remediate/stop |

## 6. Fees

| Line item | Amount | Billing trigger |
|---|---:|---|
| Pilot/evaluation | `[AMOUNT]` | `[TRIGGER]` |
| Implementation | `[AMOUNT]` | `[MILESTONES]` |
| Annual platform | `[AMOUNT]` | `[ANNUAL/QUARTERLY]` |
| Integrations | `[AMOUNT]` | `[TRIGGER]` |
| Support | `[AMOUNT]` | `[TERM]` |
| Assurance services | `[AMOUNT]` | `[TERM/MILESTONE]` |
| Taxes/expenses | `[TREATMENT]` | `[TERMS]` |

## 7. Support and service levels

Attach the approved SLA and record:

- support tier;
- coverage hours and holidays;
- support channels;
- severity definitions;
- initial response and update targets;
- availability target and exclusions;
- maintenance window;
- service credits or termination rights;
- customer dependencies; and
- incident/breach notification cross-reference.

## 8. Customer responsibilities

Customer will provide:

- source authorization and data classification;
- approved network routes and credentials;
- named users and IdP configuration;
- cloud/database/HSM/backup controls assigned to Customer;
- reference inventory and finding reviewers;
- incident and escalation contacts;
- remediation and risk-acceptance owners;
- customer/regulatory approval; and
- export, retention, and deletion instructions.

Attach the [Customer Responsibility Matrix](customer-responsibility-matrix.md).

## 9. Acceptance and limitations

Acceptance must describe:

- what was tested;
- sample size and method;
- integrations and sources;
- accuracy and performance criteria;
- unsupported formats;
- unresolved findings and risk acceptance;
- evidence delivered; and
- what acceptance does not prove.

A pilot acceptance is not production approval, certification, regulatory
approval, or evidence for systems outside the scope.

## 10. Exit

Record export format, export window, deletion trigger, backup expiry, legal
hold, transition services, and deletion confirmation. Attach
[Termination and Data Deletion](termination-and-data-deletion.md).

## 11. Signatures

```text
[VENDOR LEGAL NAME]                 [CUSTOMER LEGAL NAME]

By: __________________________      By: __________________________
Name: ________________________      Name: ________________________
Title: _______________________      Title: _______________________
Date: ________________________      Date: ________________________
```
