# Lean hiring plan and ownership model

**Status:** proposed plan for the first 12–18 months
**Assumption:** two founders initially cover product/engineering and commercial/customer discovery. Adjust headcount only when customer evidence creates a repeatable bottleneck.

## 1. Hiring principles

1. Hire delivery capacity before a large sales team. A bad first pilot creates more
   damage than a small pipeline.
2. Keep one accountable owner for every customer promise.
3. Use short, scoped specialists for legal/privacy, local procurement, and an
   independent security review rather than pretending an early full-time hire can
   cover every jurisdiction.
4. Do not hire a "compliance officer" to imply regulatory approval. Hire someone to
   manage evidence, requirements, and customer security reviews.
5. Do not add sales development until the founders can state a narrow ICP,
   measurable pain, pilot scope, and conversion signal.
6. Never count an advisor's informal help as production delivery capacity.

## 2. Headcount by stage

| Stage | Trigger and target | Founders | New full-time hires | Fractional/contract support | Total team after hire |
|---|---|---:|---:|---|---:|
| Stage 0: prove delivery | before first live pilot; current product boundary is supervised pre-production | 2 | 0 | 0.25–0.5 FTE privacy/legal; independent security review when affordable | 2 + specialists |
| Stage 1: first design partners | one signed pilot and a second qualified pilot, or founders spend >40% of time on support | 2 | **2** | 0.25 FTE finance/procurement; local advisor only where needed | 4 + specialists |
| Stage 2: first five customers | three active pilots or two converted paid customers; delivery is the bottleneck | 2 | **3** | 0.5 FTE legal/privacy and local partner support | 7 + specialists |
| Stage 3: repeatable regional motion | five paid customers, two repeatable ICPs, and documented onboarding | 2 | **3–5** | external penetration test/assurance and jurisdictional counsel | 10–12 + specialists |

The trigger is evidence, not a calendar. If the first pilot is not repeatable, delay
Stage 2 hires and fix product scope, reporting, or trust first.

## 3. Stage 0: what the founders cover

### Founder A: product and engineering owner

- architecture and release decisions;
- code review and secure defaults;
- backend, worker, parser, database, and frontend prioritization;
- test strategy and release gates;
- incident technical lead until a reliability engineer exists;
- direct response to customer technical questions; and
- records which capabilities are implemented, proposed, or not validated.

### Founder B: customer and commercial owner

- ICP and account selection;
- problem interviews and pilot discovery;
- proposal, charter, and commercial negotiation;
- named customer sponsor and review cadence;
- partner/referral relationships;
- pilot report walkthrough and conversion decision; and
- CRM, activity metrics, and honest claims review.

### Both founders

- no real-system scan without a written authorization and scope;
- weekly risk review covering data, access, open findings, customer promises, and
  stop conditions;
- customer escalation and post-pilot retrospective; and
- hiring decisions based on documented workload and customer evidence.

### Fractional support

Use a qualified privacy/technology lawyer for data-processing language, IP,
liability, confidentiality, deletion, and local contract questions. Treat their
templates as proposed language until executed. Use a qualified security reviewer
for a scoped independent review when a customer requires it; do not call a
self-review an external audit.

## 4. Stage 1 hires: two people

### Hire 1 — Pilot Delivery and Security Engineer

**Count:** 1 FTE
**Reports to:** Founder A; day-to-day customer assignment from Founder B

**Responsibilities**

- prepare customer-specific deployment and network prerequisites;
- configure read-only source access, scope, rate limits, and workspace policy;
- operate the pilot runbook and keep a decision/evidence log;
- triage parser errors, unsupported formats, queue failures, and false-positive
  reports;
- reproduce customer issues in sanitized fixtures;
- run the validation sample and safe re-scan;
- prepare the technical appendix and coverage statement;
- execute access revocation, export, retention, and deletion checks; and
- write an internal incident note for any security or data boundary deviation.

**Why now:** founders cannot both build product and perform careful customer
operations once two pilots overlap. This role protects delivery quality and makes
one pilot look like a disciplined process rather than founder improvisation.

**Success measures:** on-time pilot gates, complete evidence/limit metadata,
closed customer blockers, no unapproved access, and a repeatable onboarding
checklist—not number of scans alone.

### Hire 2 — Product / Full-Stack Engineer (Evidence and Workflow)

**Count:** 1 FTE
**Reports to:** Founder A

**Responsibilities**

- improve API/read-model contracts and frontend evidence workflows;
- build customer-requested import/export and report improvements;
- maintain tenant-boundary tests, API-key/role tests, and regression fixtures;
- improve parser refusal/truncation explanations;
- instrument queue, artifact, and report failure modes;
- review migrations and backwards compatibility; and
- turn repeated pilot workarounds into product capabilities.

**Why now:** the first customer will reveal workflow gaps. This role converts
repeated manual work into tested product behaviour without asking the delivery
engineer to become the entire product team.

**Success measures:** reduced manual work per pilot, preserved tenant isolation,
shorter time from approved input to reviewable evidence, and fewer repeat defects.

## 5. Stage 2 hires: three people

Trigger this stage when at least three pilots overlap or two customers are paid and
the founders are the delivery bottleneck. Do not hire all three on a date if only
one bottleneck exists.

### Hire 3 — Solutions Architect / Customer Security Lead

**Count:** 1 FTE
**Reports to:** Founder B for customer plan; dotted line to Founder A for technical quality

**Responsibilities**

- run discovery with CISO/security architecture/platform stakeholders;
- translate customer source systems into a safe scope and data-flow diagram;
- answer security questionnaires using an evidence register;
- coordinate customer IAM, network, procurement, and change-management gates;
- lead pilot kickoff, weekly review, and executive readout;
- prevent overclaiming in proposals and demos; and
- identify expansion only when the first scope is validated.

**Why now:** a technical founder should not be the only person who can explain
trust boundaries and pilot limits. This is a customer-facing technical role, not a
salesperson with unsupported compliance language.

### Hire 4 — Detection / Data Engineer

**Count:** 1 FTE
**Reports to:** Founder A

**Responsibilities**

- improve algorithm/library/certificate/fingerprint evidence quality;
- maintain parser fixtures across formats and versions;
- build deduplication, provenance, vulnerability-BOM, and ownership workflows;
- measure false positives, false negatives, coverage, and unknowns on approved
  datasets;
- maintain rule/fingerprint versioning and digests; and
- document what a result can and cannot prove.

**Why now:** repeat customers will ask whether results are trustworthy, not just
whether the dashboard looks good. This role creates measurement and evidence rather
than marketing accuracy claims.

### Hire 5 — Platform / SRE Engineer

**Count:** 1 FTE
**Reports to:** Founder A

**Responsibilities**

- production-like deployment automation and configuration management;
- PostgreSQL/Redis/Neo4j operations, backups, restore tests, and capacity planning;
- secrets, KMS/object-storage integration, logging, alerting, and traces;
- worker leases, queue back-pressure, job recovery, and resource limits;
- hardened image/build/release pipeline; and
- customer-controlled/private deployment support.

**Why now:** multiple pilots expose operational risk. The SRE owns operational
repeatability; the founders should no longer be the only people who know how to
recover a worker or restore an artifact.

## 6. Stage 3 hires: three to five people

Only after five paid customers and a repeatable pilot offer:

### Hire 6 — Partnerships and Regional Business Development

One FTE, or one person per region only when regional pipeline justifies it.

- build relationships with MSSPs, cloud partners, incubators, and authorized
  resellers;
- create referral rules, partner qualification, and deal registration;
- coordinate Dubai/Saudi/India localization and procurement routing;
- never present an accelerator, regulator, or partner as an endorsement without
  written permission; and
- own partner-sourced pipeline, conversion, and partner quality.

### Hire 7 — Product Manager / Customer Operations

One FTE when more than three concurrent customers create conflicting requests.

- own roadmap from measured customer problems;
- maintain the pilot template, change log, and product-boundary register;
- schedule customer reviews and capture evidence of value;
- define release notes and deprecation policy; and
- protect engineering focus from one-off feature promises.

### Hire 8 — Security and Trust Program Manager

One FTE only when customer security reviews consume a sustained half-person or
more.

- maintain the control/evidence matrix;
- coordinate independent testing, risk register, policies, incident exercises,
  subprocessors, and data-processing answers;
- manage evidence freshness and customer questionnaire responses; and
- distinguish internal controls from certifications or independent attestations.

### Optional hires 9–10

A support engineer and a second solutions engineer are justified by ticket volume,
response-time expectations, and active deployments—not by a desire to appear large.
A sales development representative is the last of these hires, after the founders
have a proven message and qualification rubric.

## 7. Hiring sequence and ownership matrix

| Work | Stage 0 owner | Stage 1 owner | Stage 2 owner | Approval |
|---|---|---|---|---|
| architecture/release | Founder A | Founder A + product engineer | Founder A + SRE | Founder A |
| pilot scope/authorization | Founder B | Founder B + delivery engineer | Solutions architect | Founder B + customer sponsor |
| scan operation | Founder A/delivery engineer | Delivery engineer | Delivery engineer + solutions architect | Customer source owner |
| evidence quality | Founder A | Product engineer | Detection/data engineer | Founder A |
| data/privacy terms | fractional counsel + Founder B | same | trust programme manager | Founder B + counsel |
| deployment/backup | Founder A | delivery engineer | SRE | Founder A |
| report/readout | Founder B | Founder B + delivery engineer | solutions architect | Customer sponsor |
| pipeline/partners | Founder B | Founder B | partnerships lead | Founder B |
| incident decision | Founder A | Founder A + delivery engineer | SRE + security lead | Founder A/customer sponsor |

## 8. Interview exercises

### Pilot Delivery and Security Engineer

Give a fictional repository/binary sample and ask the candidate to write a
scope/authorization checklist, identify data risks, operate a bounded scan, and
explain why an unsupported or truncated parser result is not clean evidence.

### Product / Full-Stack Engineer

Ask for a small API/read-model change with a tenant-isolation test, a bounded
response, and an explicit truncation field. Evaluate reasoning and test design,
not framework trivia.

### Solutions Architect

Ask the candidate to turn a vague request—"scan our whole bank"—into a six-week
read-only pilot charter with sponsor, source owner, data boundary, success metric,
stop condition, and exit evidence.

### Detection / Data Engineer

Give a labelled fixture set and ask for a precision/recall measurement plan that
preserves unknown and unsupported states instead of forcing binary yes/no results.

### Platform / SRE Engineer

Ask for a failure drill: Redis unavailable during queueing, worker killed during
scan, artifact write failure, and deletion request. Require an observed recovery
or a clearly labelled gap.

## 9. Compensation and location approach

Use locally lawful employment terms and transparent salary bands. The first team
can be distributed across India with customer-facing regional travel or partners
in Dubai/Saudi; that does not make the company locally incorporated or a locally
approved vendor. For Saudi/UAE customer work, budget for qualified local counsel,
translation, travel, and partner support rather than assuming a remote employee
solves procurement or residency.

## 10. Stop hiring conditions

Pause hiring and revisit the offer if:

- no qualified account has a named problem owner;
- pilots are free, open-ended, or lack a written scope;
- founders cannot explain the evidence limits;
- every customer asks for a different product with no common pattern;
- support incidents or data-boundary misses are not closed; or
- headcount is being used to compensate for lack of customer learning.
