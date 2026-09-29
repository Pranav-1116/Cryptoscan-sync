# Security, privacy, and assurance package

**Status:** evidence index and response guide  
**Audience:** CISO, third-party risk, procurement, internal audit, privacy,
architecture, and customer security reviewers

This document explains what a complete assurance package should contain and how
to answer when a prospect requests SOC 2, ISO 27001, security architecture,
data flow, encryption, policies, pen-test material, subprocessors, hosting,
backup, SLA, vulnerability disclosure, mappings, privacy documentation, and
attestations.

## 1. Evidence status language

Use one of these statuses for every requested artifact:

- **AVAILABLE — APPROVED:** current artifact exists, owner and review date are
  recorded, and it is approved for the customer and scope.
- **AVAILABLE — RESTRICTED:** artifact exists but requires NDA, data room,
  redaction, or counsel/security approval.
- **IN PREPARATION:** artifact is being created; do not use it as evidence.
- **NOT CURRENTLY AVAILABLE:** no artifact exists or it is expired.
- **NOT APPLICABLE:** reason and approving owner are recorded.
- **CUSTOMER-SPECIFIC:** vendor cannot issue it; customer must approve or
  provide it.

Never answer a missing external report with a policy draft or source-code link.

## 2. Assurance request matrix

| Prospect request | Expected artifact | Current repository support | Final answer rule |
|---|---|---|---|
| SOC 2 report | Type I/II report and bridge letter | Readiness gap analysis only | State report status; never call readiness a report |
| ISO 27001 certificate | Certificate, scope, expiry, issuing body | Control and policy material | State certificate status; no certificate without issuer |
| Security architecture | Approved deployment and trust-boundary diagram | [End-to-end architecture](../END-TO-END-ARCHITECTURE.md), service map, threat model | Supply approved version for actual deployment |
| Data-flow diagram | Data sources, stores, transfers, regions, support | [Data flow](../DATAFLOW.md) | Add customer-specific regions and subprocessors |
| Encryption architecture | In-transit, at-rest, key, HSM/KMS, signing diagram | Evidence-chain and HSM qualification docs | Confirm actual deployment and provider |
| Data-retention policy | Approved retention and deletion schedule | [Data-retention schedule](data-retention-schedule.md), draft operational policy | Use signed customer schedule |
| Access-control policy | Roles, least privilege, SSO, MFA, review, break-glass | Repository RBAC and policy docs | Include operational review record |
| Incident-response policy | Severity, contacts, response, evidence, notification | [Incident policy](../policies/incident-response-policy.md) and terms | Attach approved policy and exercise record |
| Business-continuity policy | Dependencies, decision authority, continuity plan | [BC/DR policy](../policies/bc-dr-policy.md) | Add customer-approved plan |
| Disaster-recovery policy | RPO/RTO, topology, failover, failback, tests | DR runbooks and drill artifacts | Do not treat local drill as bank guarantee |
| Vulnerability-management policy | Intake, severity, remediation, disclosure | [Vulnerability policy](../policies/vulnerability-management-policy.md) | Add operational records and approved targets |
| Secure SDLC policy | Threat model, review, scans, release, change | CI, release, engineering gates | Attach current controls and review evidence |
| Pen-test executive summary | Independent assessor summary, scope, dates, retest | Internal security tests and scope only | State independent report availability honestly |
| Subprocessor list | Provider, purpose, region, data, transfer, notice | [Subprocessor register](subprocessors.md) | Populate actual providers before submission |
| Hosting/cloud architecture | Accounts, regions, services, isolation, support | Architecture and deployment docs | Produce deployment-specific diagram |
| Backup architecture | Frequency, encryption, off-site, immutability, restore | Backup/restore docs and scripts | State customer/Vendor responsibility |
| Availability/SLA | Signed targets, measurement, exclusions, credits | [SLA template](sla-template.md) | Never infer SLA from a test result |
| Vulnerability disclosure | Security contact, intake, response, coordinated disclosure | Security docs and contact template | Publish actual contact and process |
| Security contact | monitored address, escalation, PGP if used | Placeholder only until populated | Use staffed monitored contact |
| Compliance mappings | framework, control, owner, evidence, exceptions | Control register and mapping docs | Distinguish internal mapping from certification |
| Privacy documentation | privacy policy, DPA, retention, transfers, subprocessors | This directory | Complete entity and jurisdiction fields |
| Relevant attestations | provider/customer/external issuer evidence | Readiness closure gate | Do not self-issue an attestation |

## 3. SOC 2 response

If no SOC 2 report is available, use:

> `[VENDOR LEGAL NAME]` does not currently provide a SOC 2 report for this
> service. The company maintains security policies, technical controls, tests,
> and a readiness programme. These materials are not a SOC 2 examination or
> attestation. A current independent report will be supplied only if and when
> issued by an independent CPA firm and applicable to the contracted service.

If a report exists, disclose:

- Type I or Type II;
- report period;
- system description and scope;
- service regions and subservice organizations;
- exceptions and complementary customer controls;
- bridge letter if the period ended;
- secure delivery method; and
- expiry/review date.

## 4. ISO 27001 response

If no certificate exists, use:

> `[VENDOR LEGAL NAME]` does not currently hold an ISO/IEC 27001 certificate
> applicable to this service. Internal policies, risk registers, and control
> mappings are readiness material and do not constitute certification.

If a certificate exists, provide only the issuing body's certificate, scope,
locations, expiry, certificate number, and applicable statement of
applicability through an approved secure channel.

## 5. Architecture package

A customer-facing architecture package should contain:

1. context and trust-boundary diagram;
2. deployment/topology diagram;
3. data-flow diagram;
4. identity and access-flow diagram;
5. encryption and key-boundary diagram;
6. logging and monitoring flow;
7. backup and recovery flow;
8. source-system connector matrix;
9. subprocessor and hosting map;
10. customer/Vendor responsibility matrix; and
11. limitations and assumptions.

Use the actual Order Form region and deployment. Do not send a generic diagram
as if it described the customer's topology.

## 6. Policy package

The package should include approved versions of:

- information security;
- access control and authentication/MFA;
- data classification and privacy;
- retention and deletion;
- incident response and breach notification;
- vulnerability and patch management;
- secure SDLC and change management;
- business continuity and disaster recovery;
- backup and restore;
- vendor and subprocessor management;
- acceptable use;
- confidentiality and information handling; and
- vulnerability disclosure.

Every policy should show owner, approval authority, effective date, review
cycle, scope, version, exception process, and next review date.

## 7. Penetration-test response

The executive summary should state:

- independent assessor and qualifications;
- assessment dates;
- scope and excluded systems;
- methodology and test types;
- environment and release tested;
- severity definitions;
- finding counts by severity;
- remediation status;
- retest date and result;
- residual risks and accepted exceptions; and
- report confidentiality restrictions.

Internal security tests are valuable supporting evidence but must be labelled as
internal. The repository's pen-test scope document is not an independent pen-
test report.

## 8. Availability and resilience package

Supply:

- signed SLA;
- uptime measurement method;
- support matrix;
- maintenance policy;
- dependency map;
- backup architecture;
- RPO/RTO and scope;
- last applicable DR and restore test;
- raw logs or controlled evidence;
- failover, failback, and rollback result;
- known limitations; and
- customer responsibilities.

Do not copy local test results into the SLA. Measurement and contractual target
are different artifacts.

## 9. Evidence release procedure

For each customer request:

1. open a questionnaire/evidence request ID;
2. identify customer, jurisdiction, service, release, and deployment;
3. map every question to an artifact and owner;
4. check artifact status, date, scope, and confidentiality;
5. redact secrets, private keys, other-customer data, and unnecessary detail;
6. obtain legal/privacy/security approval;
7. deliver through an approved data room or secure transfer;
8. record what was sent, to whom, when, and under what NDA;
9. record expiry, follow-up, and customer-specific commitments; and
10. archive the exact submitted pack.

## 10. Assurance boundary statement

> The evidence package distinguishes implemented controls, operational records,
> customer attestations, and independent certifications. A control description
> or test result demonstrates only what its stated evidence tier supports. It
> does not establish certification, legal compliance, customer approval,
> regulatory approval, or production operation outside the stated scope.
