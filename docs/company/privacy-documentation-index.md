# Privacy documentation index

**Status:** privacy package index  
**Owner:** `[PRIVACY OWNER / DPO]`  
**Rule:** documents are effective only after the legal entity, jurisdiction,
version, approval, and deployment scope are completed.

## 1. Required privacy package

| Artifact | Purpose | Owner | Status |
|---|---|---|---|
| Privacy Policy | Public notice for Vendor-controlled processing | Privacy/Legal | Template |
| Data Processing Agreement | Customer controller/processor terms | Privacy/Legal | Template |
| Data-processing terms | Operational instructions and source register | Privacy/Security | Template |
| Retention schedule | Data-class retention, deletion, backup, hold | Privacy/Operations | Proposed baseline |
| Subprocessor register | Provider, purpose, region, data, transfer | Privacy/Procurement | Must populate actual providers |
| Residency and transfer schedule | Region, support, backup, DR, mechanisms | Privacy/Legal | Customer-specific |
| DPIA/transfer assessment | Risk and safeguards for applicable processing | Privacy/Customer | Customer-specific |
| Cookie notice | Website technology and choices | Privacy/Marketing | Must match deployment |
| Data-subject request process | Access, correction, deletion, objection, export | Privacy/Support | Process template |
| Deletion confirmation | Exit and deletion record | Privacy/Operations | Controlled form |
| Breach terms | Notification and cooperation | Privacy/Legal/Security | Template |

## 2. Processing inventory

Maintain a record for each processing activity:

- business purpose;
- controller/processor role;
- data subject categories;
- Personal Data categories;
- sensitive/special-category data;
- source and collection method;
- system and region;
- recipients and subprocessors;
- transfer mechanism;
- retention and deletion trigger;
- security measures;
- rights and request path;
- risk/DPIA status;
- owner, reviewer, and next review.

## 3. Privacy response rule

For customer questionnaires:

- do not answer residency without the deployment schedule;
- do not answer no subprocessors without architecture review;
- do not answer zero retention while backups/logs remain;
- do not answer GDPR/DPDP/CCPA compliance without legal applicability review;
- do not use a generic DPA as a signed DPA;
- do not call a transfer tool or provider region a lawful transfer mechanism;
- do not treat a product report as a legal decision about an individual; and
- do not accept special-category data without explicit approval.

## 4. Customer request workflow

1. Verify requestor and customer controller.
2. Identify data, system, region, and legal deadline.
3. Search active and archived service records within scope.
4. Apply legal hold and security preservation if required.
5. Respond, export, restrict, correct, or delete as instructed.
6. Record exceptions, backup expiry, and downstream actions.
7. Obtain privacy review and close the request.

## 5. Approval record

```text
Entity: ___________________________________
Jurisdiction: ______________________________
Processing activity: _______________________
Owner: ____________________________________
Privacy reviewer: __________________________
Legal basis: _______________________________
DPIA/transfer assessment: ___________________
Effective date: ____________________________
Next review: _______________________________
```
