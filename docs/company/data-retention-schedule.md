# Data-retention and deletion schedule

**Status:** proposed baseline; privacy, legal, security, and customer review
required  
**Owner:** `[PRIVACY OWNER]`  
**Effective date:** `[EFFECTIVE DATE]`

This schedule defines baseline retention for CryptoScan. The Order Form, DPA,
legal hold, customer policy, and applicable law may require different periods.
The shortest lawful period consistent with the purpose should be selected.

## 1. Retention principles

- Collect only what the approved purpose requires.
- Do not use retention to compensate for unknown ownership or scope.
- Separate active service data, reports, audit records, backups, and support
  records.
- Record the deletion trigger, not only a duration.
- Put legal holds above ordinary deletion but document the scope and owner.
- Restrict retained data during backup expiry.
- Verify deletion where the system permits verification.
- Customer-managed systems remain Customer's deletion responsibility.
- A hash or deletion log proves an action record, not that every copy in every
  external system was deleted.

## 2. Baseline schedule

| Data class | Examples | Active retention | Post-termination | Trigger/method | Owner |
|---|---|---:|---:|---|---|
| Account and identity | Name, work email, role, user ID | Contract term + 30 days | Delete or anonymize within 30 days | Account closure and access revocation | Identity owner |
| Authentication/security logs | Login, API key, role, access, admin events | 12 months | Delete at next scheduled cycle | Secure log expiry | Security operations |
| Scan job metadata | Job ID, scope, timestamps, status, errors | Contract term + 90 days | Delete within 30 days after export | Service deletion job | Operations |
| Findings and inventory | Assets, findings, owners, policy states | Contract term + customer schedule | Export then delete within 30 days | Customer-approved exit | Customer/security owner |
| Evidence and reports | CBOM, report, hash manifest, signed evidence | Customer-defined; baseline 12 months | Export then delete within 30 days | Evidence retention expiry | Evidence owner |
| Source/configuration data | Imported repository/config/log material | Minimum needed; baseline 90 days after processing | Delete with active data | Source removal or exit | Customer + Vendor |
| Support records | Tickets, correspondence, attachments | 24 months after closure | Legal/support schedule | Ticket closure | Support owner |
| Billing and contracts | Orders, invoices, tax records | Legal/tax period | As law requires | Contract and tax expiry | Finance/legal |
| Security incidents | Incident timeline, reports, evidence | 7 years or legal requirement | Legal/security review | Incident closure + retention | Security/legal |
| Backups | Encrypted database/evidence backups | 35 days baseline | Expire within 90 days after exit | Backup lifecycle | Operations |
| Marketing contacts | Consent, preferences, business contact | Until unsubscribe or 24 months inactivity | Delete/anonymize | Withdrawal or inactivity | Marketing/privacy |
| Aggregated analytics | De-identified usage metrics | 24 months | Retain only if non-identifying | Re-identification review | Product/privacy |

The periods above are proposed internal defaults. They are not regulatory
retention promises and must be reconciled with the customer's policy and legal
hold.

## 3. Customer-specific overrides

The Order Form or DPA must identify overrides:

| Data class | Customer period | Legal basis/requirement | System | Approval |
|---|---:|---|---|---|
| `[CLASS]` | `[PERIOD]` | `[REASON]` | `[LOCATION]` | `[OWNER/DATE]` |

A longer period requires a reason and a deletion date. A shorter period must be
validated against backup, audit, support, and incident obligations.

## 4. Deletion process

At the deletion trigger:

1. identify customer, environment, systems, and data classes;
2. verify export and customer acceptance where applicable;
3. suspend new collection;
4. revoke users, API keys, service accounts, webhooks, and support access;
5. delete active database, object, evidence, index, queue, cache, and temporary
   workspace copies;
6. notify or direct subprocessors to delete their copies;
7. mark encrypted backups for expiry;
8. preserve only documented legal, security, billing, or incident records;
9. verify representative systems and logs;
10. create a deletion record with operator, reviewer, timestamp, method, scope,
    digest, and exception; and
11. close the retention task.

## 5. Legal hold

A legal hold suspends ordinary deletion for the identified data and period.
The legal owner must record:

- matter/reference;
- data classes and custodians;
- systems and regions;
- start date;
- approving counsel;
- access restrictions;
- review date; and
- release date.

A legal hold must not be broader than necessary. When released, ordinary
retention resumes.

## 6. Backups and immutable evidence

Backups may not support immediate individual deletion. During the residual
period, Vendor must restrict access, prevent ordinary restoration into live
service without approval, record the expiry date, and delete or destroy the
backup at expiry.

If evidence is hash-chained or signed, the evidence record may need to remain
for audit. Delete Customer content and retain only the minimum metadata or
cryptographic verification record allowed by the DPA and law.

## 7. Retention review cadence

- quarterly: review active schedules, overrides, deletion failures, and legal
  holds;
- before every material release: check new data stores and logs;
- after an incident: review preservation and deletion impact;
- annually: approve the schedule and subprocessors;
- at contract exit: complete a customer-specific deletion certificate.

## 8. Deletion evidence record

```text
Customer/environment: ____________________
Data classes: ____________________________
Trigger: __________________________________
Export reference: _________________________
Active systems deleted: ____________________
Subprocessors notified: ____________________
Backup expiry: ____________________________
Legal hold: none / reference ______________
Verification method/result: ________________
Operator/date: ____________________________
Reviewer/date: ____________________________
Exceptions: _______________________________
```
