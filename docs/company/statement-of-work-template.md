# CryptoScan Statement of Work template

**Template status:** commercial/legal/ delivery review required
**SOW ID:** `[ID]`
**Related Order Form:** `[REFERENCE]`
**Customer:** `[CUSTOMER]`
**Vendor:** `[VENDOR]`

Use a Statement of Work for implementation, pilot delivery, custom
integration, validation, advisory, migration, or assurance services. The SOW
prevents services, deliverables, staffing, acceptance, and change control from
being confused with subscription rights.

## 1. Objective and outcome

```text
Business objective: _______________________
Technical outcome: _______________________
Decision supported: _______________________
In-scope deployment: _____________________
Out-of-scope deployment: _________________
```

## 2. Work packages

| Work package | Activities | Deliverables | Owner |
|---|---|---|---|
| Discovery | Scope, data, architecture, access, risks | Charter and design | Shared |
| Deployment | Install, configure, harden, validate | Deployment record | Vendor/customer |
| Integration | Connect approved sources/IdP/SIEM/ITSM | Integration record | Shared |
| Baseline | Collect and scan approved data | Baseline report | Vendor |
| Validation | Expert review, precision/recall, misses | Validation workbook | Customer |
| Remediation | Assign, fix, re-scan, evidence | Recheck record | Customer/vendor |
| Operations | Backup, restore, failure, support exercise | Exercise report | Shared |
| Exit | Export, deletion, final report | Exit record | Shared |

## 3. Deliverables and acceptance

For each deliverable specify:

- format;
- owner;
- due date;
- input dependency;
- acceptance reviewer;
- acceptance criteria;
- exclusions;
- confidentiality;
- evidence location; and
- correction period.

| Deliverable | Format | Due | Acceptance criteria | Reviewer |
|---|---|---:|---|---|
| `[DELIVERABLE]` | `[FORMAT]` | `[DATE]` | `[CRITERIA]` | `[NAME]` |

A deliverable is not accepted merely because it contains a PASS result. The
customer must confirm scope, methodology, limitations, and evidence.

## 4. Schedule and dependencies

| Milestone | Date | Customer dependency | Vendor dependency | Exit condition |
|---|---:|---|---|---|
| Kickoff | `[DATE]` | `[DEPENDENCY]` | `[DEPENDENCY]` | `[CONDITION]` |
| Deployment | `[DATE]` | `[DEPENDENCY]` | `[DEPENDENCY]` | `[CONDITION]` |
| Baseline | `[DATE]` | `[DEPENDENCY]` | `[DEPENDENCY]` | `[CONDITION]` |
| Validation | `[DATE]` | `[DEPENDENCY]` | `[DEPENDENCY]` | `[CONDITION]` |
| Final | `[DATE]` | `[DEPENDENCY]` | `[DEPENDENCY]` | `[CONDITION]` |

Customer delays extend the schedule when the dependency was not available and
Vendor had made reasonable preparation. The parties must document impact rather
than silently changing scope.

## 5. Staffing

| Role | Vendor/customer | Name | Effort | Responsibility |
|---|---|---|---:|---|
| Executive sponsor | Customer | `[NAME]` | `[HOURS]` | Decision and risk |
| Security owner | Customer | `[NAME]` | `[HOURS]` | Accuracy and risk |
| Platform owner | Customer | `[NAME]` | `[HOURS]` | Network and access |
| Delivery lead | Vendor | `[NAME]` | `[HOURS]` | Plan and evidence |
| Solutions engineer | Vendor | `[NAME]` | `[HOURS]` | Deployment/integration |
| Product/security lead | Vendor | `[NAME]` | `[HOURS]` | Findings and limitations |

## 6. Change control

A change request is required for:

- additional sources or volume;
- additional region or environment;
- new data category;
- new connector or custom engineering;
- additional workshops or validation waves;
- support or schedule change;
- retention or evidence change; and
- customer-specific regulatory or audit work.

A change request must state scope, price, schedule, risk, data impact, owner,
and approval.

## 7. Fees and expenses

```text
Fixed fee: _________________________________
Time-and-materials rate: ___________________
Payment milestones: ________________________
Travel/expense treatment: __________________
Third-party costs: _________________________
Tax/withholding: __________________________
```

## 8. Security and data requirements

The SOW incorporates the MSA, DPA, Security Addendum, Acceptable-Use Terms,
SLA, and customer responsibility matrix. It must record source authorization,
prohibited data, access expiry, transfer region, and deletion.

## 9. Success and decision

The final SOW result must be one of:

- **Expand** — agreed criteria met for tested scope;
- **Remediate and repeat** — useful but criteria incomplete;
- **Stop** — security, data, integrity, or material accuracy failure; or
- **No decision** — required reviewer/evidence not available.

## 10. Signatures

```text
[VENDOR LEGAL NAME]                 [CUSTOMER LEGAL NAME]

By: __________________________      By: __________________________
Name: ________________________      Name: ________________________
Title: _______________________      Title: _______________________
Date: ________________________      Date: ________________________
```
