# Subprocessor register

**Status:** controlled template; must be populated with actual providers before
customer disclosure  
**Owner:** `[VENDOR LEGAL NAME]` privacy/security/procurement  
**Last reviewed:** `[DATE]`  
**Public register URL:** `[URL OR NOT PUBLIC]`

A subprocessor is a third party engaged by Vendor to process Customer Data for
the Services. A provider that does not process Customer Data may still appear
in a supplier or hosting register when relevant to security or procurement.

Do not list a provider based only on a logo, planned architecture, or a
provider's generic service catalogue. Confirm the actual service, region,
data categories, remote-support path, and transfer mechanism.

## 1. Active subprocessor register

| Provider | Service | Purpose | Data categories | Region(s) | Remote access | Transfer mechanism | Security evidence | Status/notice |
|---|---|---|---|---|---|---|---|---|
| `[PROVIDER]` | `[CLOUD/HOSTING/EMAIL/ANALYTICS]` | `[PURPOSE]` | `[CATEGORIES]` | `[REGION]` | `[YES/NO; WHERE FROM]` | `[SCC/ADEQUACY/OTHER]` | `[REPORT/URL/CONFIDENTIAL]` | `[ACTIVE/PROPOSED]` |
| `[PROVIDER]` | `[SERVICE]` | `[PURPOSE]` | `[CATEGORIES]` | `[REGION]` | `[YES/NO]` | `[MECHANISM]` | `[EVIDENCE]` | `[STATUS]` |

## 2. Provider categories to assess

At minimum assess:

- cloud compute, database, object storage, queue, and backup;
- identity, authentication, and support tooling;
- monitoring, logging, alerting, and incident response;
- email, ticketing, and customer communication;
- payment and billing;
- security testing and vulnerability management;
- customer support or professional services;
- HSM/KMS, signing, certificate, or key-management providers;
- disaster-recovery and regional failover providers; and
- any data-room or questionnaire platform receiving customer material.

## 3. Subprocessor due diligence

Before activation, record:

- legal entity and ownership;
- service and data flow;
- processing purpose and data categories;
- locations and support access;
- privacy and transfer terms;
- security certifications and report dates;
- vulnerability and incident obligations;
- backup and deletion practices;
- availability and continuity commitments;
- contract flow-down terms;
- audit or evidence rights;
- insurance and financial risk where material;
- customer notice and objection process; and
- owner, reviewer, approval date, and review expiry.

## 4. Customer notice and objection

The DPA or Order Form must state:

- how proposed subprocessors are announced;
- notice period, normally `[30]` days;
- information included in a notice;
- customer's reasonable objection process;
- Vendor's response, mitigation, or alternative service;
- termination or transition right if the objection cannot be resolved; and
- emergency addition process for security, continuity, or legal reasons.

## 5. Changes

Every change must include:

```text
Provider/service: _________________________
Change: new / replaced / removed / region changed
Effective date: ___________________________
Customer data affected: ___________________
Transfer impact: __________________________
Security/privacy review: __________________
Customer notice date: _____________________
Objection deadline: _______________________
Approver: _________________________________
```

## 6. Current status statement

Until this register is populated and approved, the response to a customer
question about subprocessors must be:

> The vendor is preparing a deployment-specific subprocessor register. The
> final list, locations, data categories, transfer mechanism, security evidence,
> notice period, and objection process will be supplied before Personal Data is
> processed in the contracted environment.

Do not answer `no subprocessors` unless the actual service architecture,
support, hosting, backup, email, and monitoring paths have been reviewed.
