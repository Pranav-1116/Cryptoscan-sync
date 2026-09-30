# Data-processing terms and processing instructions

**Template status:** privacy and legal review required
**Use:** attach to the DPA and applicable Order Form
**Customer:** `[CUSTOMER LEGAL NAME]`
**Vendor:** `[VENDOR LEGAL NAME]`

These terms translate the DPA into an operational instruction set. They should
be completed before connecting Customer sources. If a question is unanswered,
the default is **do not process until the owner decides**.

## 1. Processing decision record

| Decision | Value |
|---|---|
| Controller/customer | `[ENTITY AND ROLE]` |
| Processor/vendor | `[ENTITY AND ROLE]` |
| Customer's own controller | `[IF APPLICABLE]` |
| Legal basis | `[BASIS AND JURISDICTION]` |
| Purpose | Crypto inventory, security analysis, remediation, evidence, support |
| Contract/order | `[REFERENCE]` |
| Processing start | `[DATE]` |
| Processing end | `[DATE OR EVENT]` |
| DPO/privacy owner | `[NAME AND CONTACT]` |
| Vendor privacy contact | `[NAME AND CONTACT]` |
| Security contact | `[NAME AND CONTACT]` |

## 2. Approved source register

Every source must be listed before connection.

| Source | Owner | Data class | Personal Data? | Access | Region | Retention | Approval |
|---|---|---|---|---|---|---|---|
| `[REPOSITORY]` | `[OWNER]` | `[CLASS]` | `[YES/NO]` | Read-only | `[REGION]` | `[PERIOD]` | `[DATE]` |
| `[CLOUD ACCOUNT]` | `[OWNER]` | `[CLASS]` | `[YES/NO]` | Read-only | `[REGION]` | `[PERIOD]` | `[DATE]` |
| `[CERTIFICATE EXPORT]` | `[OWNER]` | `[CLASS]` | `[YES/NO]` | Import | `[REGION]` | `[PERIOD]` | `[DATE]` |
| `[LOG OR CONFIG SOURCE]` | `[OWNER]` | `[CLASS]` | `[YES/NO]` | Import/read-only | `[REGION]` | `[PERIOD]` | `[DATE]` |

Source approval must cover the right to collect, analyze, retain, export, and
delete the data. A source with unknown authorization remains excluded.

## 3. Data minimization

The preferred order is:

1. metadata and references rather than content;
2. sanitized or masked data;
3. read-only exports with unnecessary fields removed;
4. limited source paths and time windows;
5. Personal Data only where necessary for ownership, audit, or security;
6. sensitive or special-category data only after explicit privacy approval.

Prohibited by default:

- private keys;
- passwords and authentication tokens;
- payment PINs and secret values;
- unapproved production secrets;
- unrelated employee records;
- health, biometric, or special-category data;
- content unrelated to the approved security purpose.

## 4. Processing operations

For each source, record the allowed operations:

- collection or import;
- parsing and normalization;
- asset and finding creation;
- relationship and dependency analysis;
- policy evaluation;
- report and evidence generation;
- export to Customer systems;
- support access;
- backup and restore;
- deletion and verification.

No new operation is implied by a general product feature. A new purpose or
source needs a change record and privacy/security review.

## 5. Output and decision boundaries

CryptoScan output may include findings, inventory, risk indicators, ownership,
policy states, migration relationships, evidence hashes, and report metadata.
Customer must validate material findings before regulatory, employment,
production, or legal action.

`UNKNOWN`, `NOT_EVALUATED`, `SKIPPED`, and `FAIL` must remain distinguishable
from a clean or passing result.

## 6. Access instructions

Customer must define:

- approved user groups;
- role and privilege;
- SSO/MFA requirement;
- API key scope and expiry;
- service-account owner;
- support-access approval path;
- break-glass process;
- periodic access-review cadence; and
- termination trigger.

Vendor support must use named, time-bounded, least-privilege access and must
record the reason, scope, start, end, and reviewer.

## 7. Transfer and location instructions

Record location separately for:

- primary application;
- database;
- evidence/object storage;
- logs and monitoring;
- backups;
- support access;
- subprocessors;
- disaster-recovery site; and
- export destination.

A customer-selected deployment region does not by itself prove that support,
backups, subprocessors, telemetry, or disaster recovery stay in that region.
See [data-residency-and-transfers.md](data-residency-and-transfers.md).

## 8. Retention and deletion instructions

Complete one retention row per data class in
[data-retention-schedule.md](data-retention-schedule.md). Define:

- active service retention;
- report and evidence retention;
- audit-log retention;
- support-ticket retention;
- backup retention;
- legal hold;
- export window;
- deletion trigger;
- deletion method; and
- verification recipient.

## 9. Request assistance

Vendor assistance may cover:

- locating Customer Data;
- exporting data in the agreed format;
- deleting active copies;
- identifying backup copies;
- applying restriction or preservation;
- investigating an incident; and
- answering a data-protection impact assessment.

Customer provides the identity, legal deadline, scope, and instruction needed.
Vendor may require reasonable cost approval for extensive assistance.

## 10. Change control

The following require a documented change before implementation:

- new source or data class;
- new region or subprocessor;
- new processing purpose;
- new support-access route;
- new retention period;
- new export or downstream integration;
- new active scan capability;
- change from pilot to production; and
- change in controller/processor role.

## 11. Completion record

```text
Customer privacy owner: __________________  Date: ______________
Customer security owner: _________________  Date: ______________
Vendor privacy owner: ____________________  Date: ______________
Vendor security owner: ___________________  Date: ______________
Order Form / DPA reference: ______________  Version: ____________
```
