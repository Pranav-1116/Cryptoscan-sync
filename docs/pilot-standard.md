# CryptoScan standard bank pilot

**Document status:** proposed operating standard  
**Audience:** product, security, solutions engineering, operations, and a
prospective bank's security, architecture, risk, and procurement teams  
**Applies to:** supervised evaluations of CryptoScan before customer-specific
production approval

This document defines what a CryptoScan pilot is, what it is intended to
prove, how it is run, and what it must not be represented as. It standardizes
the engagement so that every pilot produces comparable technical, accuracy,
operational, and commercial evidence.

A pilot is not a shortened production contract. It is a controlled evaluation
that converts product claims into customer-reviewed evidence.

## 1. Pilot definition

A CryptoScan pilot is a time-bounded deployment in an approved customer or
customer-like environment that uses a limited, documented estate to evaluate:

1. **Safety** — whether the product can be installed, accessed, and operated
   without exceeding its approved permissions or data boundary.
2. **Usefulness** — whether it discovers and explains cryptographic assets,
   controls, weaknesses, ownership, and migration impact in a way the bank can
   act on.
3. **Accuracy** — how findings compare with a trusted customer inventory and
   expert review.
4. **Integration** — whether identity, repositories, cloud accounts,
   certificates, ticketing, SIEM, export, and support workflows fit the bank's
   environment.
5. **Operability** — whether the bank can monitor, back up, recover, and
   govern the deployment.
6. **Commercial fit** — whether the scope, responsibilities, support model,
   and pricing basis are understandable to the customer.

The pilot ends with a decision: **expand**, **remediate and repeat**, or
**stop**.

## 2. What the current product is being evaluated for

The pilot should evaluate the current product as a crypto-security inventory
and decision-support platform. The standard product loop is:

```text
approved sources
    -> collection and scanning
    -> crypto asset and certificate inventory
    -> findings and policy assessment
    -> ownership, risk, and remediation workflow
    -> evidence, reports, CBOM, drift and migration views
    -> customer review and decision
```

Depending on the agreed scope, this may include:

- source-code and configuration scanning;
- certificate and TLS endpoint discovery;
- cloud configuration and key-management inventory;
- container and infrastructure-as-code analysis;
- HSM/KMS and keystore inventory imports;
- network, runtime, telecom, or payment evidence imports;
- CBOM and evidence exports;
- policy, compliance, drift, risk, and remediation views;
- API, dashboard, role-based access, audit, and report workflows.

The capability-maturity labels in the product and
[`CAPABILITY-MATURITY.md`](CAPABILITY-MATURITY.md) remain authoritative for
which surface is GA, beta, or preview. A pilot may evaluate a beta or preview
surface, but the final report must say so explicitly.

## 3. What the pilot is not

The pilot does not, by itself, establish any of the following:

- SOC 2, ISO 27001, PCI, FIPS 140-3, or other certification;
- regulator approval or legal compliance;
- customer production approval;
- perfect detection accuracy or complete coverage of every technology;
- HSM provider qualification from a local or simulated HSM;
- customer RPO, RTO, availability, or capacity guarantees;
- a contractual SLA or incident-notification commitment;
- permission to scan systems outside the approved scope;
- permission to collect private keys, plaintext secrets, or payment data;
- evidence that a synthetic or vendor-provided sample represents the bank's
  whole estate.

The current repository decision is **supervised pilot or pre-production**, not
unattended regulated production. The pilot must preserve that boundary in its
charter, reports, sales material, and customer communications.

## 4. Standard pilot objectives

Every pilot charter must select one primary objective and may select up to
three secondary objectives.

### Primary objective A — inventory and visibility

Prove that CryptoScan can create a useful inventory across the agreed source
systems:

- identify cryptographic algorithms, key sizes, protocols, certificates,
  libraries, keys, HSM/KMS references, and dependencies;
- distinguish discovered, inferred, unknown, and not-evaluated results;
- link assets to applications, owners, business processes, and environments;
- export results in a form the bank can retain and independently review.

### Primary objective B — risk and remediation

Prove that the bank can use the findings to make decisions:

- classify severity according to the bank's policy;
- assign an accountable owner;
- create a remediation or migration work item;
- record an exception with expiry and approver;
- re-scan and determine whether the issue changed state;
- demonstrate the evidence behind the conclusion.

### Primary objective C — crypto-agility and migration planning

Prove that CryptoScan helps the bank plan change rather than only detect
current weaknesses:

- identify algorithms or protocols approaching policy restrictions;
- show affected applications, libraries, certificates, vendors, or shared
  keys;
- estimate migration waves and dependencies;
- distinguish a confirmed dependency from an analyst hypothesis;
- retain the basis for the migration decision.

### Primary objective D — deployment and operational fit

Prove that the bank can operate the product inside its boundary:

- deploy the approved topology;
- integrate identity and least-privilege access;
- connect approved sources through the bank's network controls;
- monitor jobs, failures, evidence, and audit events;
- back up, restore, and verify the pilot estate;
- remove access and delete pilot data at exit.

## 5. Standard scope levels

Use one of these scope levels rather than describing a pilot as simply
"enterprise-wide."

| Level | Typical scope | Recommended use |
|---|---|---|
| **L1 — controlled proof** | 1–3 repositories, one certificate export, one user group, synthetic or sanitized data | First technical demonstration |
| **L2 — application estate** | 10–50 repositories or applications, selected cloud/configuration sources, real owners and triage | Standard first bank pilot |
| **L3 — business-unit pilot** | Multiple application teams, network/TLS targets, ticketing workflow, representative legacy or payment samples | Expansion after L2 success |
| **L4 — supervised production candidate** | Customer-approved topology, production-like volume, backup/restore, operational exercises, customer risk review | Only after L2/L3 evidence and external requirements are addressed |

L4 is still a qualification step. It is not automatically production approval.

## 6. Required pilot charter

Before any customer data or credentials are connected, the charter must record:

- customer legal entity and accountable sponsor;
- vendor legal entity and accountable delivery owner;
- pilot name, version, start date, end date, and environment identifier;
- primary and secondary objectives;
- in-scope systems, repositories, applications, accounts, endpoints, and
  artifacts;
- excluded systems and prohibited data;
- data classification and retention/deletion period;
- deployment location and network diagram;
- identities, roles, permissions, and credential owners;
- approved scan modes and rate limits;
- expected source volume and workload assumptions;
- incident contacts and stop conditions;
- success metrics and acceptance thresholds;
- customer responsibilities and vendor responsibilities;
- known product limitations and unsupported formats;
- exit date, data export method, and deletion verification method;
- signatories and approval dates.

A pilot without a signed scope is a demonstration, not a controlled pilot.

## 7. Standard deployment posture

The default posture is one dedicated deployment per customer or per pilot.
Shared SaaS tenancy should not be enabled merely because tenant filters exist
in code. A shared-tenancy model requires separate independent qualification
of API, worker, queue, cache, object storage, exports, background jobs, and
platform-scope paths.

The standard pilot posture is:

- customer-approved network boundary;
- dedicated database and evidence storage;
- separate pilot credentials;
- read-only source integrations where possible;
- no private-key ingestion;
- no destructive scan actions;
- explicit outbound network allowlist;
- audit logging enabled;
- least-privilege roles;
- documented backup and restore path;
- no use of development credentials in the customer environment.

The production configuration guard, identity configuration, deployment
hardening, and backup procedures must be exercised rather than merely linked
in documentation.

## 8. Pilot workstreams

### Workstream 1 — discovery and architecture

Confirm the customer's estate, data flows, identity provider, network routes,
source systems, expected volume, and operational owners. Produce a deployment
and data-flow diagram. Decide whether data remains in the bank's environment.

### Workstream 2 — access and integration

Create named, expiring pilot identities. Verify that each integration uses the
minimum required permission. Test both successful and denied access. Record
certificate, proxy, timeout, retry, rate-limit, and ownership details.

### Workstream 3 — baseline collection

Run the initial scan on the approved scope. Record collection completeness,
unsupported files, timeouts, skipped sources, discovered assets, and initial
findings. Do not convert an unknown result into a clean result.

### Workstream 4 — expert validation

A bank subject-matter expert reviews a representative sample of findings. The
sample must include high, medium, low, unknown, duplicate, and not-evaluated
results. Record true positives, false positives, missed findings, and reasons.

### Workstream 5 — operational exercise

Exercise access review, audit-log review, report export, backup/restore, worker
recovery, connector failure, evidence verification, and pilot data deletion.
Record raw results and deviations.

### Workstream 6 — decision and exit

Compare measured outcomes with the charter. Produce the pilot report, residual
risk register, open limitations, commercial recommendation, and next decision.
Remove access and retain or delete data according to the approved charter.

## 9. Standard metrics

The pilot must report measurements, not only opinions.

### Accuracy metrics

- reference assets in scope;
- assets discovered by CryptoScan;
- confirmed true positives;
- confirmed false positives;
- duplicates;
- missed findings or candidate misses;
- unknown/not-evaluated results;
- precision and recall where a trusted reference exists;
- validation sample size and selection method.

Do not publish a precision or recall number without the denominator,
methodology, source data classification, and reviewer names.

### Operational metrics

- deployment time;
- time to first successful scan;
- scan duration and throughput;
- API latency and error rate;
- queue age, retries, and failed jobs;
- CPU, memory, database, storage, and network consumption;
- backup and restore duration;
- access-provisioning and access-removal duration;
- report generation duration;
- incidents and manual interventions.

### Adoption metrics

- active pilot users;
- findings reviewed;
- findings assigned;
- remediation work items created;
- exceptions approved;
- repeat scans completed;
- reports accepted by intended stakeholders;
- number of unsupported sources that blocked a decision.

## 10. Proposed pilot acceptance criteria

These are proposed internal pilot thresholds, not contractual commitments.
The customer may set stricter thresholds.

A pilot is ready for an **expand** recommendation only when:

- all in-scope integrations have a recorded result;
- no unauthorized cross-scope access is observed;
- all high-severity findings have been reviewed by a named customer owner;
- the accuracy sample and candidate-miss log are complete;
- unknown and not-evaluated results are visible in the report;
- at least one finding has completed the full assign-remediate-recheck loop;
- backup/restore and evidence verification have passed in the pilot boundary;
- operational failures have produced visible failures rather than false passes;
- limitations and unsupported formats are accepted in writing;
- all pilot credentials have an owner and expiry or removal plan;
- the customer and vendor agree on the remaining risk register.

A pilot is **remediate and repeat** if the product works but an integration,
accuracy, performance, or operational criterion is not met. It is **stop** if
there is a security boundary failure, uncontrolled data access, unexplained
high-severity detection miss, evidence-integrity failure, or inability to
remove access and data.

## 11. Standard deliverables

The delivery team must produce:

1. approved pilot charter;
2. architecture and data-flow diagram;
3. access and permission matrix;
4. source and integration inventory;
5. baseline scan report;
6. finding-validation workbook;
7. accuracy and candidate-miss report;
8. operational exercise report;
9. backup/restore and evidence-verification record;
10. performance and capacity observations;
11. limitations and residual-risk register;
12. exit/deletion record;
13. final customer-reviewed pilot report; and
14. recommendation: expand, remediate, or stop.

Every evidence artifact should include UTC time, release/source commit,
environment, scope, operator, method, digest, limitations, and review status.
The repository's readiness closure gate validates this envelope but cannot
prove an external issuer's statement is true.

## 12. Roles and responsibilities

| Role | Customer responsibility | Vendor responsibility |
|---|---|---|
| Executive sponsor | Approves objectives, scope, risk acceptance, and decision | Explains product boundary and escalation path |
| Security owner | Approves data, access, findings, exceptions, and residual risk | Supplies security design, safe defaults, and remediation support |
| Application owners | Provide context, reference inventories, and finding validation | Help interpret findings without overriding customer ownership |
| Platform/operations owner | Provides network, runtime, backup, and monitoring boundary | Provides deployment and recovery runbooks |
| Identity owner | Creates, reviews, and removes pilot access | Maps roles and tests authorization behavior |
| Vendor delivery lead | Coordinates plan and evidence | Owns schedule, issue log, and final report |
| Vendor product/security lead | Responds to defects and limitations | Owns product fixes, threat boundary, and honest claims |

No vendor employee should approve the customer's residual risk on the
customer's behalf.

## 13. Pilot decision language

Use one of these standardized statements:

### Expand

> The supervised CryptoScan pilot met the agreed technical, accuracy, and
> operational criteria for the tested scope. The result supports an expanded
> qualification phase. It does not constitute production approval, regulatory
> approval, certification, or evidence for systems outside the tested scope.

### Remediate and repeat

> The pilot produced useful evidence but one or more agreed criteria were not
> met. The open items, owners, and retest conditions are recorded in the
> residual-risk register. No production approval is implied.

### Stop

> The pilot is stopped because a security, data-boundary, evidence-integrity,
> or material accuracy condition was not met. No positive production or
> capability claim may be based on this pilot.

## 14. Related standards

- [Pilot duration and phases](pilot-duration-and-phases.md)
- [Business model](business-model.md)
- [Enterprise and international-bank readiness gaps](enterprise-bank-readiness-gaps.md)
- [Production readiness](../PRODUCTION-READINESS.md)
- [Readiness evidence handling](readiness-evidence/README.md)
- [Capability maturity](CAPABILITY-MATURITY.md)
- [Operational policy](../config/operational-policy.yaml)
