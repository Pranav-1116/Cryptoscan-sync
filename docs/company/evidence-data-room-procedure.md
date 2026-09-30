# Security evidence and data-room procedure

**Status:** controlled assurance-operations procedure
**Owner:** `[ASSURANCE OWNER]`
**Applies to:** security reports, legal documents, architecture, customer
questionnaires, certificates, and restricted evidence

## 1. Request intake

Create an evidence request before releasing material:

```text
Request ID: _______________________________
Customer/prospect: ________________________
Legal entity/jurisdiction: _________________
Questionnaire/framework: ___________________
Due date: __________________________________
Service/deployment/release: ________________
Requested documents: _______________________
Recipient and reviewers: ___________________
Confidentiality/NDA: ______________________
```

## 2. Evidence classification

| Class | Example | Handling |
|---|---|---|
| Public | Published policies, public privacy notice | Public website or approved link |
| Customer confidential | Architecture, answer pack, pilot report | Secure portal under NDA |
| Restricted security | Pen-test report, exploit detail, key architecture | Data room, named access, no download where possible |
| Highly restricted | Credentials, private keys, raw logs, other-customer data | Do not provide; redact or refuse |

## 3. Release process

1. identify current artifact and version;
2. confirm scope, region, service, and release;
3. check owner, reviewer, expiry, and evidence tier;
4. redact secrets, Personal Data, other-customer information, exploit details,
   and provider confidential information;
5. obtain security, privacy, legal, and executive approvals as required;
6. record recipient, purpose, access duration, and download rights;
7. deliver through an approved secure channel;
8. record hash and release timestamp;
9. revoke access or close link at expiry; and
10. archive the exact package sent.

## 4. Evidence index

```text
Artifact ID | Title | Version | Scope | SHA-256 | Tier | Expires | Approved by
```

A report hash proves file integrity after release. It does not prove the report
is true, that the issuer is independent, or that the customer performed the
operation.

## 5. Response to unavailable evidence

Use a direct answer:

> The requested artifact is not currently available for the stated service and
> scope. We can provide the attached internal control description and identify
> the evidence required to close the item. These materials are not a substitute
> for the requested independent, customer, provider, or regulatory evidence.

## 6. Access review and retention

Review data-room access weekly during an active assessment and close access at
submission, expiry, or termination. Retain the request, approvals, exact
package, and access log under the records schedule. Do not retain customer
copies longer than the approved purpose.
