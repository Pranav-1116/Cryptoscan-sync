# Termination, exit, and data deletion terms

**Template status:** legal, privacy, security, and operations review required
**Applies to:** `[CUSTOMER]` and `[VENDOR]`
**Related:** MSA, DPA, Data-Processing Terms, SLA, and Order Form

Exit must be designed before production processing. A customer must know how
to retrieve its evidence, stop access, delete data, handle backups, and move
to another deployment or provider.

## 1. Termination events

An Order Form may terminate:

- at the end of its term with required notice;
- for material breach after a cure period;
- for repeated material SLA failure as agreed;
- for insolvency or cessation of business;
- for unlawful processing or unacceptable security risk;
- for regulatory or customer risk reasons where the contract permits; or
- for convenience if the Order Form includes a convenience right and fee.

The notice must identify the affected Order Form, effective date, reason where
required, access end time, export window, and contact for transition.

## 2. Suspension versus termination

Suspension is narrow and temporary. Termination ends the service order but does
not immediately erase evidence needed for export, legal hold, incident
investigation, or security review.

Vendor should avoid deleting data while a Security Incident, legal hold,
regulator request, payment dispute, or customer-approved export remains open.

## 3. Exit timeline

Recommended default timeline, subject to the Order Form:

| Exit activity | Target |
|---|---:|
| Termination confirmation | Within 2 business days |
| Access freeze or scope reduction | On the agreed effective date |
| Export request and format confirmation | Within 5 business days |
| Customer export window | 30–60 days |
| Active-copy deletion after export/trigger | Within 30 days |
| Deletion confirmation | Within 10 business days after active deletion |
| Backup expiry | Within 90 days, unless legal/technical exception is documented |
| Final exit review | Within 15 business days after deletion confirmation |

The customer may require shorter or longer periods for regulatory retention,
large evidence volumes, air-gapped exports, or migration complexity.

## 4. Export package

The export format must be listed in the Order Form. It may include:

- crypto asset inventory;
- certificates and endpoint inventory;
- findings and severity history;
- policy and exception records;
- business ownership and system mappings;
- scan metadata and job history;
- CBOM/SBOM and report files;
- evidence manifests and SHA-256 hashes;
- audit events permitted for Customer export;
- configuration and policy definitions;
- integration mappings; and
- deletion and chain-verification records.

Export must distinguish raw customer data, derived findings, system metadata,
Vendor Materials, and third-party content. Vendor may withhold another
customer's data, Vendor secrets, private keys, licensed third-party material,
and information prohibited by law.

## 5. Deletion procedure

The exit operator must record:

1. termination or deletion trigger;
2. approved scope and data categories;
3. export completed and customer acceptance;
4. active databases and evidence stores deleted;
5. object storage, indexes, queues, caches, and temporary workspaces deleted;
6. API keys, service accounts, webhooks, certificates, and support access
   revoked;
7. backups scheduled for expiry;
8. legal holds or regulatory retention exceptions;
9. subprocessor deletion confirmations where applicable;
10. verification method and result; and
11. approving owner and reviewer.

No deletion record should claim deletion of data that was not within the
operator's control.

## 6. Backup treatment

Backups may be immutable, encrypted, replicated, or technically unavailable
for immediate selective deletion. In that case:

- access to the retained copy must be restricted;
- the copy must not be used for ordinary service operation;
- the retention expiry must be recorded;
- legal hold must be documented;
- the deletion scope must include the backup schedule; and
- an expiry or destruction certificate must be produced.

The parties must agree whether backup deletion is measured from termination,
last active copy deletion, or the next backup cycle.

## 7. Customer-managed deployments

For customer-managed deployments, Customer is responsible for deletion from
Customer-controlled:

- cloud accounts;
- databases and object stores;
- backups;
- SIEM and ticketing systems;
- identity providers;
- local exports and administrator devices; and
- HSM/KMS or certificate stores.

Vendor will provide a runbook and reasonable assistance for the components it
supplied. Vendor cannot certify deletion from systems it cannot access.

## 8. Vendor-managed deployments

For vendor-managed services, Vendor will run the deletion procedure under the
DPA and Order Form. Vendor may retain a minimum archival record for legal,
security, billing, dispute, or audit purposes, with access restricted and
retention documented.

## 9. Transition assistance

Transition services may include:

- export preparation;
- data dictionary and schema explanation;
- evidence-chain verification;
- configuration handover;
- deployment and integration handover;
- migration workshops;
- successor-vendor access; and
- final security review.

Services outside the included exit window may be billed at the agreed rate.
Vendor must not withhold Customer Data as leverage for a disputed amount when
law or contract requires release, subject to reasonable security controls.

## 10. Deletion confirmation template

```text
Customer: ______________________________
Order Form: ____________________________
Deletion trigger/date: __________________
Scope: __________________________________
Export delivered:  yes / no
Export accepted:   yes / no / pending
Active systems deleted: _________________
Credentials/access revoked: _____________
Backups scheduled to expire: ____________
Legal hold or exception: _________________
Verification method: ____________________
Verification result: _____________________
Operator: _____________ Date: ____________
Reviewer: _____________ Date: ____________
```

The confirmation should state any exception rather than using an unqualified
"all data deleted" claim.
