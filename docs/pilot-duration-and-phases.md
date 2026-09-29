# CryptoScan pilot duration and phased plan

**Document status:** proposed delivery standard  
**Default duration:** six weeks after access and scope approval  
**Audience:** customer sponsor, security owner, platform owner, vendor delivery
lead, and commercial team

A pilot duration should be long enough to observe real workflows, repeat a
scan, validate findings, exercise recovery, and make a decision. A live demo
is not a pilot. A pilot that ends before the customer has reviewed findings is
only an installation test.

## 1. Recommended duration model

Use the duration that matches the scope rather than forcing every customer
into one calendar period.

| Model | Duration | Scope | Outcome |
|---|---:|---|---|
| **Technical proof** | 2 weeks | L1 controlled proof | Deployment and first-scan feasibility |
| **Standard pilot** | 6 weeks | L2 application estate | Accuracy, workflow, integration, and operational decision |
| **Expanded pilot** | 8–12 weeks | L3 business unit | Multiple teams, additional integrations, repeat validation |
| **Production qualification** | 12+ weeks | L4 production-like topology | Customer-specific operational and assurance evidence |

The six-week standard pilot is the recommended commercial starting point. The
clock begins only when the charter is approved, access owners are named, and
the required source data is available. Delays caused by customer approvals,
network changes, or unavailable source systems are recorded rather than hidden
inside the pilot duration.

## 2. Standard six-week schedule

### Preparation: 5–10 business days before Week 1

Preparation is a gate, not part of the six-week measurement period.

Complete:

- pilot charter and scope approval;
- data classification and retention decision;
- deployment location and network route approval;
- identity and role design;
- source-system inventory;
- read-only permission requests;
- incident contacts and stop conditions;
- success metrics and reference inventory agreement;
- commercial order or evaluation agreement;
- named customer and vendor delivery leads.

**Preparation exit criterion:** all required approvals and access requests have
an owner and due date. If the pilot starts without this, the schedule is not
controlled.

### Week 1 — kickoff, deployment, and access validation

Activities:

- hold the formal kickoff;
- confirm objectives, scope, and prohibited data;
- deploy the approved pilot topology;
- verify production guards and non-development credentials;
- configure identity and roles;
- test login, authorization, audit events, and access denial;
- connect the first low-risk source;
- record baseline environment metadata;
- confirm support and escalation contacts.

Outputs:

- signed kickoff record;
- deployment and data-flow diagram;
- access matrix;
- integration checklist;
- first operational issue log.

**Week 1 exit criterion:** the product is reachable only through the approved
boundary, pilot users have the correct permissions, and the first source can
be scanned without an unresolved security issue.

### Week 2 — baseline inventory and first findings

Activities:

- connect the remaining L2 sources;
- run the baseline scan;
- record collection completeness and skipped inputs;
- inspect assets, certificates, algorithms, policies, and findings;
- export the first CBOM/evidence/report package;
- identify a reference inventory or trusted sample;
- select the accuracy-validation sample.

Outputs:

- baseline scan report;
- source coverage matrix;
- initial finding inventory;
- unknown and not-evaluated list;
- evidence digest record.

**Week 2 exit criterion:** the customer can see what was scanned, what was not
scanned, what was discovered, and what remains unknown.

### Week 3 — expert accuracy validation

Activities:

- customer security and application experts review the sample;
- classify true positives, false positives, duplicates, and missed findings;
- compare results with the trusted reference inventory;
- test severity and ownership mapping;
- identify parser or connector limitations;
- record candidate misses rather than silently changing output;
- agree on any configuration or policy adjustments.

Outputs:

- finding-validation workbook;
- precision/recall calculation where the denominator is valid;
- candidate-miss log;
- false-positive and duplicate analysis;
- product issue list;
- customer-approved limitations list.

**Week 3 exit criterion:** the customer has independently reviewed enough of
the sample to say whether the findings are useful and which claims remain
unsupported.

### Week 4 — remediation and workflow integration

Activities:

- assign findings to actual owners;
- create tickets or approved work items;
- run exception and risk-acceptance workflow;
- apply a safe remediation or configuration change;
- re-scan the affected source;
- verify finding state and evidence changes;
- test report distribution or SIEM/ITSM integration if in scope;
- review role boundaries and audit trails.

Outputs:

- assign/remediate/recheck record;
- ticket or work-item references;
- exception records with expiry;
- integration results;
- audit-log review.

**Week 4 exit criterion:** at least one representative finding has completed
the full customer workflow from discovery through recheck.

### Week 5 — operational and recovery exercises

Activities:

- perform backup and restore within the pilot boundary;
- verify evidence integrity after restore;
- restart API and worker components;
- simulate connector timeout or permission failure;
- inspect queue, retry, and failure visibility;
- review health, audit, and security logs;
- test access removal for one pilot user;
- verify pilot data export and deletion procedure;
- record recovery times and manual steps.

Outputs:

- operational exercise report;
- backup/restore result;
- evidence-verification result;
- access-removal record;
- deletion or retention record;
- open recovery limitations.

**Week 5 exit criterion:** no recovery exercise produces a false PASS, and the
customer understands which operations require vendor assistance.

### Week 6 — repeat scan, decision, and exit

Activities:

- run a repeat scan over the agreed scope;
- compare baseline and current inventory;
- close or carry forward findings;
- review accuracy, performance, operations, and limitations;
- finalize residual-risk register;
- calculate commercial and expansion recommendation;
- remove or renew access;
- export or delete pilot data according to the charter;
- conduct the final customer review.

Outputs:

- final pilot report;
- baseline-to-repeat comparison;
- residual-risk register;
- commercial recommendation;
- exit/deletion evidence;
- expand, remediate, or stop decision.

**Week 6 exit criterion:** the customer signs the outcome and the report states
exactly what was tested, what was not tested, and what the result does not
prove.

## 3. Calendar and ownership

| Week | Customer lead | Vendor lead | Decision checkpoint |
|---|---|---|---|
| Preparation | Sponsor/security owner | Delivery lead | Scope and access approved |
| 1 | Platform/identity owner | Solutions engineer | Safe deployment |
| 2 | Application/security owners | Scanner/product engineer | Baseline accepted |
| 3 | Security subject-matter expert | Product/security lead | Accuracy accepted or remediation required |
| 4 | Application owners | Delivery/product engineer | Workflow demonstrated |
| 5 | Operations/security | SRE/support | Recovery and support reviewed |
| 6 | Sponsor/security owner | Delivery lead | Expand, remediate, or stop |

## 4. Pilot meeting cadence

### Kickoff meeting

Duration: 60–90 minutes.

Agenda:

1. objectives and decision to be made;
2. in-scope and out-of-scope systems;
3. data and access boundary;
4. deployment and network design;
5. roles and escalation;
6. metrics and acceptance thresholds;
7. schedule and dependencies;
8. stop conditions.

### Weekly working session

Duration: 45–60 minutes.

Review:

- completed activities;
- source coverage;
- findings and validation status;
- defects and decisions needed;
- access or data issues;
- upcoming exercises;
- risk and dependency changes.

### Weekly executive checkpoint

Duration: 20–30 minutes.

Review only:

- red risks;
- scope changes;
- missed milestones;
- security incidents;
- decision blockers;
- commercial or expansion implications.

### Final review

Duration: 60–90 minutes.

The final review must include the customer security owner, the sponsor, the
operations owner, and the vendor delivery and product/security leads.

## 5. Conditions that extend the pilot

Extend by two to four weeks when:

- the source data was delayed but the product boundary remained safe;
- a required integration needs a retest;
- the accuracy sample is too small or biased;
- a material parser or connector defect was fixed;
- the customer needs another remediation/recheck cycle;
- the customer wants to evaluate a second technology or business unit.

An extension requires a written reason, new end date, owner, and decision
criteria. It must not be used to hide a failed acceptance criterion.

## 6. Conditions that pause or stop the pilot

Pause immediately for:

- unauthorized data access or scope expansion;
- credential leakage or private-key exposure;
- cross-customer or cross-tenant data visibility;
- unexplained evidence-chain or report-integrity failure;
- destructive behavior outside the approved charter;
- an unbounded scanner, connector, or network request;
- inability to revoke access;
- a critical vulnerability discovered in the pilot deployment.

The customer security owner decides whether a paused pilot can resume. The
vendor must preserve the relevant evidence and provide an incident timeline.

## 7. Effort planning

These are planning estimates, not service commitments.

| Role | Standard pilot effort |
|---|---:|
| Customer sponsor | 4–8 hours |
| Customer security owner | 20–40 hours |
| Customer application owners | 20–60 hours total |
| Customer platform/identity owner | 12–30 hours |
| Customer operations owner | 12–24 hours |
| Vendor delivery lead | 30–50 hours |
| Vendor solutions engineer | 30–60 hours |
| Vendor product/security lead | 15–30 hours |
| Vendor support/SRE | 8–20 hours |

Actual effort depends on the number of source systems, network approvals,
identity-provider complexity, data handling, and the quality of the reference
inventory.

## 8. Decision matrix

| Result | Meaning | Next action |
|---|---|---|
| **Expand** | Agreed criteria met for tested scope and no unresolved blocker | Move to expanded qualification with a new scope and charter |
| **Remediate and repeat** | Product or integration is promising but a criterion is incomplete | Assign owners, fix, define retest, and extend or restart the affected phase |
| **Stop** | Security boundary, evidence integrity, material accuracy, or data-control failure | Stop access, preserve evidence, close the pilot, and document the reason |
| **No decision** | Required customer reviewers or evidence did not participate | Do not convert to a success claim; schedule a controlled completion |

## 9. Relationship to production approval

A successful six-week pilot is evidence for the next qualification phase. It is
not production approval. Before a regulated production decision, the customer
may still require:

- independent security assessment and penetration testing;
- customer-specific HSM/KMS qualification;
- topology-realistic DR and business-continuity testing;
- signed immutable release and deployment evidence;
- approved vulnerability, patch, incident, support, and access policies;
- privacy, residency, deletion, and contractual approvals;
- capacity and soak testing;
- SOC, SIEM, ITSM, identity, and mainframe/payment integration evidence;
- customer risk acceptance and applicable regulatory mapping.

See [enterprise-bank-readiness-gaps.md](enterprise-bank-readiness-gaps.md) for
the full P0/P1 closure requirements.

## 10. Pilot completion checklist

### Before start

- [ ] Charter signed
- [ ] Scope and prohibited data approved
- [ ] Deployment location approved
- [ ] Identity and permissions approved
- [ ] Data retention/deletion approved
- [ ] Support and incident contacts named
- [ ] Reference inventory agreed
- [ ] Success metrics approved

### Before expansion

- [ ] Baseline scan complete
- [ ] Source coverage recorded
- [ ] Accuracy sample reviewed
- [ ] Candidate misses recorded
- [ ] At least one remediation/recheck cycle complete
- [ ] Failure and recovery exercises complete
- [ ] Limitations and residual risks accepted

### Before close

- [ ] Repeat scan complete
- [ ] Final report reviewed
- [ ] Customer decision recorded
- [ ] Access removed or renewed explicitly
- [ ] Data exported or deleted as agreed
- [ ] Evidence digests retained
- [ ] Commercial next step agreed
