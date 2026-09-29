# CryptoScan business model

**Document status:** proposed commercial model  
**Audience:** founders, product leadership, sales, solutions engineering,
security, finance, customer success, and procurement teams

This document explains how CryptoScan can be sold and delivered without making
unsupported bank-readiness, certification, accuracy, or production claims. It
is a planning model, not a price list, legal offer, SLA, or customer contract.
Actual pricing must reflect the legal entity, country, taxes, deployment
responsibilities, support hours, data boundary, and customer procurement rules.

## 1. Product position

CryptoScan should be positioned as a **cryptographic intelligence,
crypto-agility, and evidence platform**.

It helps a customer:

- discover where cryptography is used;
- inventory algorithms, keys, certificates, protocols, libraries, HSM/KMS
  references, and dependencies;
- identify policy, configuration, lifecycle, and migration risks;
- connect assets to applications, owners, processes, and business impact;
- prioritize remediation and post-quantum migration;
- monitor drift and repeat scans;
- produce CBOM, evidence, compliance, and executive reports;
- support an auditable decision process.

It is not positioned as:

- a replacement for an HSM or KMS;
- a certificate authority;
- a general vulnerability scanner;
- an independent auditor;
- a certification body;
- a regulator-approved control;
- a guarantee that an estate is free of cryptographic risk;
- a substitute for the customer's risk owner or security governance.

The commercial value is not the number of findings. The value is reduced
uncertainty and faster, better-governed decisions about cryptographic exposure
and migration.

## 2. Ideal customer profile

The strongest initial customers have several of these characteristics:

- a large or changing cryptographic estate;
- regulatory or board visibility into resilience and cryptography;
- a post-quantum migration programme;
- many application teams and incomplete crypto inventory;
- certificate, HSM, KMS, cloud, payment, telecom, or mainframe complexity;
- a need to prove remediation and exception decisions;
- an approved private or customer-controlled deployment model;
- a security architecture or cryptography centre of excellence;
- budget for a supervised technical pilot and customer validation.

Priority sectors may include:

- banks and payment institutions;
- insurance and capital markets;
- telecom operators;
- government and critical infrastructure;
- healthcare and large regulated enterprises;
- technology providers with long-lived or embedded devices.

A customer should not be selected only because it is large. A smaller customer
with an accountable crypto owner, a trusted reference inventory, and access to
the right systems can produce better evidence and a better reference outcome.

## 3. Buyer and user map

| Stakeholder | Problem | Value they need | Buying influence |
|---|---|---|---|
| CISO | Cannot explain cryptographic exposure and remediation status | Risk view, evidence, ownership, and exceptions | Economic/security buyer |
| Chief architect | Cryptography is spread across applications and platforms | Dependency graph, standards, migration impact | Technical influencer |
| Crypto or PKI owner | Certificates, keys, HSMs, and algorithms are fragmented | Inventory, lifecycle, expiry, and policy control | Technical champion |
| Application owner | Findings are difficult to interpret and assign | Specific asset, owner, severity, and remediation guidance | User and validator |
| Cloud/platform owner | Key and crypto settings vary by account and region | Read-only discovery, drift, and control evidence | Technical approver |
| Risk/compliance team | Control answers lack evidence and history | Hash-sealed reports, review history, and exceptions | Governance buyer |
| SOC/operations | Need to detect changes and investigate events | Alerts, audit trails, integration, and runbooks | Operational approver |
| Procurement/legal | Needs clear responsibility and exit terms | Scope, data boundary, support, DPA, SLA, and deletion | Contract approver |
| CFO/finance | Needs predictable cost and measurable value | Estate-based pricing and outcome milestones | Economic approver |

The product should sell to the risk owner but be validated by the people who
will use and challenge the findings.

## 4. Commercial lifecycle

The recommended commercial lifecycle is:

```text
qualified discovery
    -> paid or approved pilot
    -> customer validation
    -> expanded qualification
    -> annual subscription or managed deployment
    -> recurring scans, evidence and advisory services
    -> renewal and expansion
```

A free demonstration may show product navigation, but it should not be called a
pilot or a customer validation. A pilot has an approved scope, evidence,
customer reviewers, and a decision.

## 5. Offer structure

### Offer A — technical proof

Purpose: determine whether CryptoScan can deploy and scan a small approved
sample.

Typical scope:

- L1 scope;
- one deployment;
- one or two source types;
- limited users;
- one baseline report;
- no production claim;
- short written technical result.

Commercial form: fixed-fee evaluation or a tightly bounded paid workshop.

Success outcome: proceed to a standard pilot, identify a product blocker, or
stop without making an accuracy claim.

### Offer B — standard bank pilot

Purpose: validate safety, accuracy, integration, workflow, and operational fit.

Typical scope:

- six weeks;
- L2 application estate;
- dedicated customer or pilot deployment;
- read-only integrations;
- customer finding-validation workbook;
- repeat scan;
- backup/restore and failure exercises;
- final customer-reviewed pilot report.

Commercial form: fixed pilot fee with explicit scope-change rules. Credit toward
the first annual subscription may be offered if the customer signs a defined
production or expanded-qualification order, subject to legal approval.

### Offer C — expanded qualification

Purpose: extend the validated scope to multiple business units, technology
families, or bank workflows.

Typical scope:

- L3 or selected L4 scope;
- more repositories, accounts, endpoints, or artifact types;
- identity, SIEM, ITSM, HSM/KMS, mainframe, payment, or telecom integrations;
- capacity and soak measurements;
- operational and security tabletop exercises;
- customer-specific risk acceptance package.

Commercial form: implementation fee plus subscription or managed-service fee.

### Offer D — annual platform subscription

Purpose: provide continuing inventory, monitoring, evidence, and migration
management after qualification.

Typical entitlements:

- agreed deployment topology;
- named users or role groups;
- source connectors;
- scan frequency and volume;
- evidence/report exports;
- support tier;
- product updates;
- customer success reviews;
- agreed retention and exit support.

Commercial form: annual subscription, paid in advance or according to the
customer's procurement schedule.

### Offer E — regulated or strategic deployment

Purpose: serve customers needing dedicated infrastructure, strict support,
regional controls, air-gap operation, or extensive integration.

Possible components:

- customer-managed deployment;
- dedicated vendor-managed deployment;
- private registry or signed offline bundle;
- customer-region operation;
- extended support coverage;
- HSM/KMS integration assistance;
- mainframe/payment/telecom onboarding;
- recurring evidence and resilience exercises;
- named technical account management.

Commercial form: negotiated enterprise agreement with separate implementation,
subscription, support, and professional-services line items.

## 6. Pricing basis

Do not price only by the number of findings. That encourages noisy detection
and makes a security product financially reward bad output.

Use a base platform fee plus transparent usage and service dimensions.

### Suggested pricing dimensions

1. **Deployment model** — pilot, customer-managed, dedicated managed, or
   strategic/air-gap.
2. **Estate size** — number of applications, repositories, cloud accounts,
   certificate domains, endpoints, or approved artifact volume.
3. **Scan frequency** — one-time, monthly, daily, continuous/drift monitoring.
4. **Connector complexity** — standard connectors versus custom mainframe,
   payment, telecom, SIEM, ITSM, or HSM qualification.
5. **User and governance scope** — named users, roles, business units, and
   approval workflows.
6. **Retention and evidence volume** — report, CBOM, audit, and evidence
   retention requirements.
7. **Support tier** — business-hours, extended-hours, or 24x7 contractual
   support where actually staffed and contractually available.
8. **Services** — deployment, training, data mapping, pilot validation,
   migration workshops, and recurring advisory work.

### Illustrative pricing formula

```text
annual price
  = platform base
  + estate band
  + connector/integration band
  + retention and monitoring band
  + support tier
  + optional professional services
  + approved regional or deployment costs
```

The proposal should show which inputs change the price. A bank should be able
to understand what happens if it adds a business unit, doubles source volume,
requests 24x7 support, or changes deployment responsibility.

## 7. Packaging principles

- Make the pilot finite and measurable.
- Put custom engineering in a separate statement of work.
- Separate subscription rights from professional services.
- Separate support commitments from best-effort product guidance.
- State whether hosting, database, storage, backup, HSM, and network costs are
  paid by the customer or vendor.
- State what happens when the source volume exceeds the contracted band.
- Do not bundle certification language into a commercial tier unless the
  certification actually exists and applies to the offered deployment.
- Do not call a feature GA merely because it is included in a price tier.
- Keep the customer's data, approvals, and residual risk under the customer's
  control.

## 8. Pilot-to-subscription conversion

A pilot should convert only when both technical and commercial conditions are
met.

### Technical conversion conditions

- pilot result is expand rather than stop;
- agreed accuracy limitations are accepted;
- security boundary has no unresolved blocker;
- customer owners accept the integration and operational model;
- production-specific evidence plan exists;
- open issues have owners and dates;
- deployment and data-retention responsibilities are understood.

### Commercial conversion conditions

- customer scope and estate band are measurable;
- subscription start date is defined;
- support hours and escalation contacts are contractually clear;
- DPA, security schedule, subprocessor, residency, and exit terms are agreed;
- implementation work is separated from recurring subscription;
- pricing assumptions and change control are recorded;
- customer procurement and risk approvals are complete.

A pilot that does not convert is still valuable if it produces honest learning,
closed issues, and a documented stop reason. Do not relabel every pilot as a
sales success.

## 9. Revenue streams

### Recurring platform subscription

The primary revenue stream. It funds product development, secure release,
maintenance, evidence tooling, and support.

### Implementation services

One-time services for deployment, source onboarding, identity mapping, policy
configuration, data classification, and initial training.

### Validation and migration services

Time-bounded services for reference-inventory construction, accuracy review,
post-quantum migration planning, remediation workshops, and executive reporting.

### Integration services

Separate work for non-standard SIEM, ITSM, mainframe, payment, telecom, HSM,
air-gap, or customer-specific connector requirements.

### Managed operations

Optional fee for vendor-operated deployment, monitoring, upgrades, evidence
collection, and support, subject to the actual staffing and contractual
boundary.

### Training and enablement

Role-specific training for security owners, application teams, PKI/HSM teams,
operations, auditors, and executives.

No revenue line should depend on inflating the number or severity of findings.

## 10. Unit economics to track

The business should measure:

- qualified opportunities to pilot conversion;
- pilot completion rate;
- pilot expand/remediate/stop distribution;
- pilot-to-subscription conversion;
- time from signature to first successful scan;
- implementation hours per deployment;
- support hours per customer;
- connector onboarding cost;
- infrastructure cost per estate band;
- evidence storage and retention cost;
- gross margin by deployment model;
- annual recurring revenue;
- expansion revenue;
- renewal rate and net revenue retention;
- customer acquisition cost and payback period;
- product defect rate and security incident cost.

Track these by deployment model. Customer-managed deployments and vendor-
managed deployments have different cost, support, and liability profiles.

## 11. Customer responsibilities

The contract and pilot charter should make these responsibilities explicit:

- provide accurate scope and reference data;
- approve network routes and source permissions;
- classify data and prohibit unsafe data collection;
- maintain customer-side identity, cloud, HSM, database, and network controls;
- review findings and own remediation decisions;
- nominate incident, support, and risk contacts;
- approve retention, deletion, and export requirements;
- perform customer-side risk acceptance and regulatory assessment;
- notify the vendor of material topology or policy changes.

CryptoScan can provide mechanisms, reports, and evidence. It cannot accept the
customer's operational or regulatory risk on the customer's behalf.

## 12. Vendor responsibilities

The vendor should commit only to responsibilities it can staff and evidence:

- provide the agreed software release and deployment material;
- maintain secure development and release controls;
- provide documentation, runbooks, and support contacts;
- protect vendor-controlled systems and credentials;
- respond to vulnerabilities and incidents according to the signed agreement;
- preserve evidence integrity and disclose limitations;
- maintain the agreed connector and report behavior;
- support backup, restore, export, and exit activities within the agreed
  boundary;
- provide release, change, and security information required by the contract.

Vendor responsibilities do not automatically include customer availability,
customer network health, customer HSM operation, or customer remediation.

## 13. Commercial risk controls

### Scope creep

Use a written change request for additional applications, connectors, regions,
source volume, retention, support hours, or validation requirements.

### Unsupported technology

Record unsupported or beta technology in the scope matrix. Price onboarding or
custom work separately. Never imply coverage because a similar format was
scanned successfully.

### Accuracy disputes

Use the agreed validation workbook and candidate-miss process. Do not promise
a universal accuracy percentage. A missed critical finding is a product and
risk issue, not a sales dispute to be hidden.

### Security incident

The incident path, notification window, contacts, evidence preservation, and
customer responsibilities must come from an approved contract and policy. A
draft repository policy is not a contractual notification commitment.

### Certification questions

Answer with the evidence tier: repository control, operational record, customer
attestation, or external certification. Do not answer that encryption code is
FIPS certified or that a pilot is regulator approved.

### Exit and deletion

The contract must state export format, retention, deletion authorization,
verification, support period, and responsibilities for customer-managed
backups and HSM/KMS keys.

## 14. Standard proposal structure

Every proposal should contain:

1. customer objective;
2. proposed scope and exclusions;
3. deployment and data-flow model;
4. integrations and permissions;
5. pilot or implementation plan;
6. duration and milestones;
7. deliverables and acceptance criteria;
8. customer responsibilities;
9. vendor responsibilities;
10. pricing basis and assumptions;
11. support and escalation model;
12. security, privacy, residency, and subprocessor references;
13. retention, export, deletion, and exit terms;
14. limitations and evidence boundary;
15. change-control process;
16. commercial validity and signature blocks.

## 15. Example first-year commercial path

This is a planning example, not a quotation.

| Stage | Customer buys | Vendor delivers | Decision |
|---|---|---|---|
| Discovery | Structured discovery workshop | Scope, data-flow, and success plan | Proceed to proof or stop |
| Technical proof | Fixed-fee L1 evaluation | Deployment and first-scan result | Feasible or blocker |
| Standard pilot | Six-week L2 pilot | Accuracy, workflow, recovery, and final report | Expand, remediate, or stop |
| Implementation | Deployment and onboarding services | Production-like configuration and integrations | Ready for qualification |
| Annual platform | Subscription and agreed support | Recurring inventory, drift, evidence, and reports | Renew or exit |
| Expansion | Additional estate/integrations | New scope with new acceptance criteria | Expand responsibly |

The commercial process should follow the evidence process. Do not sell an
unqualified production promise first and attempt to create evidence later.

## 16. Commercial language to use

Recommended:

> CryptoScan provides cryptographic inventory, assessment, migration, and
evidence workflows. The proposed engagement begins with a controlled pilot to
validate the product against the customer's approved estate. Coverage,
accuracy, integrations, operational responsibility, support, and production
approval are scoped and evidenced separately.

Avoid:

- "bank certified" without the actual issuing evidence;
- "regulator approved" without the applicable decision;
- "100% accurate" or "complete coverage";
- "zero-risk cryptography";
- "FIPS compliant" when only FIPS-validatable primitives are used;
- "production ready for every bank" based on a synthetic pilot;
- "24x7 support" unless a staffed, contractual service exists;
- "zero data retention" when backups, logs, or evidence retain data;
- "multi-tenant secure by default" until the shared-tenancy deployment has
  been independently qualified.

## 17. Relationship to the pilot standard

The business model must use the standardized pilot in
[`pilot-standard.md`](pilot-standard.md) and the timeline in
[`pilot-duration-and-phases.md`](pilot-duration-and-phases.md). The pilot
report is the input to the commercial expansion decision; it is not marketing
copy and it must retain failed, skipped, unknown, and not-evaluated results.

For production assurance boundaries, see
[`enterprise-bank-readiness-gaps.md`](enterprise-bank-readiness-gaps.md),
[`PRODUCTION-READINESS.md`](../PRODUCTION-READINESS.md), and the
[readiness evidence gate](readiness-evidence/README.md).
