# CryptoScan detailed price model

**Document status:** proposed internal list-price model  
**Currency:** USD as the commercial reference; convert to local currency at
contract signature  
**Audience:** founders, finance, product, sales, solutions engineering,
procurement, and customer sponsors

This document is a pricing framework for planning and proposals. It is not a
quote, market survey, tax opinion, SLA, or customer contract. Actual prices
must be approved by finance and legal after confirming the deployment region,
data boundary, support obligation, source volume, implementation effort,
subprocessors, taxes, and customer procurement rules.

The most important rule is:

> **Price the estate, deployment responsibility, integrations, support, and
> evidence needs — never the number or severity of security findings.**

Pricing by findings rewards noisy detection and creates the wrong incentive for
a security product.

## 1. Commercial model at a glance

CryptoScan uses a hybrid model:

```text
first-year customer price
  = pilot or implementation fee
  + annual platform subscription
  + selected integration and professional services
  + support or deployment premium
  + customer-specific infrastructure costs
```

The customer should be able to understand which dimensions change the price:

- number and type of sources;
- scan frequency;
- number of environments or business units;
- deployment ownership;
- integration complexity;
- evidence retention;
- support hours;
- air-gap, regional, HSM, mainframe, payment, or telecom requirements;
- professional services and custom engineering.

The product should avoid a large number of small metered charges. A bank wants
predictable annual cost, clear expansion bands, and no surprise bill caused by
a scan producing more findings.

## 2. Reference currency and conversion

Use USD for the internal price book because enterprise software proposals often
cross jurisdictions. A local-currency quote should use:

```text
local-currency price = approved USD price × contract FX rate
                      + local taxes and statutory charges
```

The contract FX rate, tax treatment, withholding, invoice currency, and
payment terms must be agreed by finance. Any INR examples below are only
planning illustrations using an explicitly selected internal FX rate. They are
not a current exchange-rate claim.

## 3. Price architecture

There are four price layers.

### Layer 1 — evaluation

Short, bounded work that determines whether CryptoScan is relevant and
technically feasible.

### Layer 2 — subscription

Recurring rights to use the platform, receive updates, access agreed features,
and retain evidence according to the contracted scope.

### Layer 3 — implementation and integration

One-time services required to deploy, configure, connect, validate, and train.

### Layer 4 — assurance and support

Support coverage, recurring evidence exercises, security reviews, HSM/KMS
qualification assistance, migration advisory, and customer-specific
operational work.

Separating these layers prevents a one-time deployment effort from being hidden
inside an annual license and makes renewal economics understandable.

## 4. Proposed evaluation prices

These are internal list-price ranges for initial planning.

| Offer | Duration | Indicative price | Included purpose |
|---|---:|---:|---|
| Discovery workshop | 1–2 days | **$3,000–$8,000** | Scope, architecture, source inventory, success plan |
| Technical proof | 2 weeks | **$8,000–$15,000** | L1 deployment and first controlled scan |
| Standard pilot | 6 weeks | **$35,000–$60,000** | L2 safety, accuracy, workflow, recovery, and final report |
| Expanded pilot | 8–12 weeks | **$75,000–$150,000** | Multiple teams, integrations, and customer-specific qualification |
| Production qualification | 12+ weeks | **$150,000–$300,000+** | Production-like topology and operational evidence plan |

A pilot price must include a written scope. At minimum, it should state:

- one deployment or environment;
- number and type of source systems;
- source volume;
- number of pilot users;
- included integrations;
- scan frequency;
- customer and vendor responsibilities;
- planned workshops and review sessions;
- deliverables;
- acceptance criteria;
- change-request rates;
- travel and third-party costs;
- data retention and exit method.

### Standard pilot reference bundle

The proposed $35,000–$60,000 standard pilot range assumes:

- six weeks;
- one dedicated pilot deployment;
- up to 25 repositories or equivalent source units;
- up to 5 cloud accounts or equivalent configuration sources;
- up to 250 approved TLS/network targets;
- up to 15 named pilot users;
- one identity integration;
- one standard ticketing, SIEM, or export integration;
- one baseline scan and one repeat scan;
- one accuracy-validation workbook;
- one backup/restore exercise;
- one final customer-reviewed report;
- remote delivery during agreed working hours.

This is a planning bundle, not a contractual entitlement until placed in a
signed order.

## 5. Proposed annual subscription tiers

The following tiers are designed to make the first commercial proposal simple.
The entitlement table is more important than the tier name.

| Tier | Annual platform fee | Typical customer | Included estate band |
|---|---:|---|---|
| **Foundation** | **$60,000–$100,000/year** | Smaller regulated company or one business unit | Up to 25 repositories, 5 cloud accounts, 250 endpoints, 15 users |
| **Professional** | **$120,000–$220,000/year** | Enterprise with several application teams | Up to 100 repositories, 15 cloud accounts, 1,000 endpoints, 50 users |
| **Enterprise** | **$250,000–$450,000/year** | Large bank or multi-business-unit deployment | Up to 300 repositories, 40 cloud accounts, 5,000 endpoints, 150 users |
| **Strategic / regulated** | **$450,000–$900,000+/year** | Large bank, air-gap, regional, or highly integrated estate | Negotiated estate and support envelope |

The ranges allow for deployment and support differences. A proposal must select
one actual price inside the approved range rather than showing a range as if it
were the invoice amount.

### What the annual platform fee includes

Unless the order says otherwise, the annual fee should include:

- the agreed CryptoScan software release;
- the contracted deployment model;
- platform features within the selected maturity and entitlement scope;
- standard product documentation;
- standard security and release notices;
- ordinary bug fixes and maintenance releases;
- agreed report and evidence export capabilities;
- named customer success or technical review cadence;
- support according to the selected support tier;
- reasonable release and configuration guidance.

It should not silently include unlimited custom development, unlimited source
volume, unlimited integrations, 24x7 response, customer cloud or HSM costs,
independent certification, or customer regulatory approval.

## 6. Entitlement and usage bands

The product should use bundles rather than per-finding pricing. The following
bands provide a repeatable quote basis.

### 6.1 Repository and application sources

| Band | Included in next band | Indicative annual add-on |
|---|---:|---:|
| Small | 25 repositories/applications | Included in Foundation |
| Medium | Additional 25 | $8,000–$15,000 |
| Large | Additional 100 | $25,000–$45,000 |
| Very large | 300+ total | Negotiated Enterprise/Strategic |

A repository should mean an approved source location, not every branch or
historical commit. Historical scanning, large binary repositories, and very
frequent scans may require a separate workload assessment.

### 6.2 Cloud accounts and subscriptions

| Band | Indicative annual add-on |
|---|---:|
| Additional 5 accounts | $6,000–$12,000 |
| Additional 10 accounts | $10,000–$20,000 |
| Additional region or regulated boundary | $10,000–$30,000 |
| Custom cloud control mapping | $20,000–$60,000 services |

The price assumes read-only roles. Customer cloud charges and provider API
charges remain the customer's responsibility unless the contract says
otherwise.

### 6.3 Network, TLS, and certificate scope

| Band | Indicative annual add-on |
|---|---:|
| Additional 250 approved targets | $5,000–$12,000 |
| Additional 1,000 targets | $15,000–$30,000 |
| Certificate inventory import and mapping | $10,000–$25,000 services |
| High-volume active probing or special protocols | Custom scope |

Active network scanning must be separately approved. The customer owns network
authorization, rate limits, target accuracy, and any impact caused by the
customer's network controls.

### 6.4 Users and business units

Do not make the primary product price depend heavily on named users; governance
requires broad participation. Include a reasonable user envelope in each tier.

For expansion:

- additional 25 named users: **$5,000–$12,000/year**;
- additional business unit with separate workflows: **$15,000–$40,000/year**;
- additional dedicated environment: **$25,000–$75,000/year** depending on
  operation and support;
- external auditor or read-only evidence access: include a limited number in
  the tier, then price additional access by agreement.

## 7. Deployment model premiums

Deployment responsibility changes the vendor's cost and risk.

| Deployment model | Pricing treatment | Main cost driver |
|---|---|---|
| Customer-managed | Platform fee plus implementation | Customer operates compute, database, backup, network, and many integrations |
| Vendor-managed dedicated | Platform fee plus managed-service premium | Vendor operates agreed infrastructure, monitoring, patching, and support |
| Private region or dedicated cloud | Platform fee plus infrastructure and operations | Dedicated resources, region, backup, networking, and compliance work |
| Air-gapped or offline | Strategic subscription plus setup premium | Signed bundles, feed import, update process, support transfer, testing |
| Multi-region resilience | Enterprise/Strategic plus topology fee | Replication, failover, testing, storage, and support coverage |

Indicative one-time deployment premiums:

- customer-managed standard deployment: **$15,000–$40,000**;
- vendor-managed dedicated deployment: **$35,000–$90,000**;
- private region or air-gap setup: **$50,000–$150,000+**;
- multi-region design and initial exercise: **$75,000–$200,000+**.

These are not guarantees that the deployment is certified, resilient, or
approved. They pay for implementation and qualification work.

## 8. Professional services price book

Professional services should be quoted separately with a statement of work.

| Service | Indicative price |
|---|---:|
| Deployment and hardening | $15,000–$50,000 |
| Identity integration and role mapping | $10,000–$30,000 |
| Standard source onboarding | $5,000–$15,000 per source family |
| SIEM or ITSM integration | $15,000–$50,000 per integration |
| HSM/KMS qualification assistance | $30,000–$100,000 |
| Mainframe/payment/telecom onboarding | $40,000–$150,000+ |
| Customer accuracy-validation programme | $25,000–$100,000 |
| Post-quantum migration workshop | $20,000–$75,000 |
| Executive or auditor evidence pack | $10,000–$40,000 |
| Training and enablement | $2,000–$10,000 per course or cohort |
| Custom connector or parser engineering | $25,000–$150,000+ |
| DR/backup/restore qualification exercise | $30,000–$120,000 |

A service line must state what is delivered, what the customer must provide,
what counts as acceptance, and what is explicitly not included.

## 9. Support pricing

Support should be priced from actual staffing and response capability. Do not
sell 24x7 support until a staffed rota, escalation process, and measured
service exists.

| Support tier | Coverage | Indicative annual premium |
|---|---|---:|
| Standard | Business hours, portal/email, documented severity response | Included or $10,000–$25,000 |
| Enhanced | Extended hours, named technical contact, quarterly review | $25,000–$60,000 |
| Critical | 24x7 staffed response, formal escalation, incident coordination | +25%–40% of platform fee |
| Strategic | Custom response, regional team, exercises, named account team | Negotiated |

Support response targets must be defined in the contract and must not be
copied from the draft operational policy without approval.

## 10. Recurring assurance services

Banks often need more than software access. Optional recurring services may
include:

- quarterly access-review support;
- quarterly backup/restore exercise;
- annual DR tabletop or failover exercise;
- release evidence and supply-chain review;
- HSM/KMS key-lifecycle review;
- recurring accuracy validation;
- post-quantum migration steering;
- evidence pack preparation;
- customer security questionnaire refresh.

Indicative annual assurance packages:

| Package | Indicative annual fee |
|---|---:|
| Evidence maintenance | $20,000–$50,000 |
| Operational resilience | $50,000–$150,000 |
| Crypto-agility advisory | $50,000–$200,000 |
| Strategic assurance programme | $150,000–$400,000+ |

These services provide assistance and records; they do not replace an
independent auditor, customer approval, or regulatory decision.

## 11. Example quote scenarios

### Scenario A — focused business-unit pilot

Assumptions:

- six-week standard pilot;
- 20 repositories;
- 3 cloud accounts;
- 150 TLS targets;
- one identity integration;
- remote delivery;
- customer-managed pilot environment.

Example commercial structure:

| Line item | Example price |
|---|---:|
| Standard pilot | $45,000 |
| Additional identity integration | Included in pilot |
| Training workshop | $5,000 |
| Travel | Not included; at cost if required |
| **Pilot total** | **$50,000 plus taxes** |

This price buys a supervised evaluation, not an annual production license.

### Scenario B — mid-size regulated enterprise

Assumptions:

- Professional subscription;
- 75 repositories;
- 10 cloud accounts;
- 750 TLS targets;
- 40 users;
- two standard integrations;
- customer-managed deployment;
- business-hours support.

| Line item | Example price |
|---|---:|
| Implementation and hardening | $35,000 one time |
| Professional annual platform | $165,000/year |
| Identity and SIEM integration | $35,000 one time |
| Training | $8,000 one time |
| **First-year total** | **$243,000 plus taxes** |
| **Renewal baseline** | **$165,000/year plus approved changes** |

The final quote must confirm source volume, retention, connector complexity,
and support scope.

### Scenario C — international bank deployment

Assumptions:

- Enterprise or Strategic tier;
- several business units;
- customer-controlled region;
- HSM/KMS, SIEM, ITSM, payment, or mainframe integration;
- extended or 24x7 support;
- evidence and resilience exercises;
- customer-specific privacy and exit requirements.

Indicative structure:

| Line item | Example range |
|---|---:|
| Qualification and implementation | $150,000–$350,000 one time |
| Enterprise/Strategic subscription | $300,000–$700,000/year |
| Custom integrations | $100,000–$300,000 one time |
| Assurance and resilience services | $75,000–$200,000/year |
| Critical support premium | 25%–40% of platform fee |
| **First-year planning range** | **$625,000–$1,550,000+** |

This range is deliberately broad. It must not be presented as a bank quote
until topology, integration, support, and legal scope are known.

## 12. Pilot credit policy

A pilot credit can reduce sales friction while protecting delivery economics.

Recommended policy:

- credit up to **50% of the standard pilot fee**;
- credit only against the first annual platform subscription;
- credit available only when the annual order is signed within **60 days** of
  pilot acceptance;
- no cash refund if the customer does not convert;
- professional services, travel, third-party costs, and custom engineering
  are not creditable unless explicitly approved;
- credit requires the pilot report and acceptance record to be complete.

A discount should not pressure the customer into production before security,
legal, privacy, and operational approval.

## 13. Payment terms

Proposed defaults:

### Pilot

- 50% at signature;
- 50% at pilot kickoff or agreed midpoint;
- payment not conditional on a positive technical result;
- customer receives the agreed report regardless of expand, remediate, or stop
  outcome, subject to payment and confidentiality terms.

### Implementation services

- 40% at signature;
- 30% at deployment readiness;
- 30% at accepted implementation milestone.

### Annual subscription

- annual payment in advance for standard accounts;
- quarterly or milestone billing for strategic procurement where approved;
- renewal notice and price-adjustment terms defined in the contract;
- taxes, withholding, travel, cloud, storage, and provider charges identified
  separately.

The commercial agreement must define whether a customer can suspend scans while
subscription, support, or implementation disputes are investigated.

## 14. Discount governance

Discounts require a business reason and an expiry, not an arbitrary reduction.

Suggested approval limits:

| Discount | Approval |
|---|---|
| Up to 10% | Account owner and finance |
| 10%–20% | Sales lead and finance |
| 20%–30% | Executive sponsor and finance |
| Above 30% | Founder/board-level approval with written strategic rationale |

Do not discount the pilot to zero merely to create an unsupported reference.
If a customer supplies unusually valuable validation, record the mutual value
and approvals rather than hiding it as free work.

## 15. Cost and margin model

Finance should estimate fully loaded cost before publishing list price.

```text
gross margin
  = (revenue - hosting - storage - support labor - delivery labor
     - third-party provider costs) / revenue
```

Track cost separately for:

- customer-managed deployment;
- vendor-managed dedicated deployment;
- air-gapped operation;
- custom connectors;
- high-volume scanning;
- 24x7 support;
- recurring assurance services.

Initial planning targets may be:

- software subscription gross margin: **70%–85%**;
- standard implementation gross margin: **35%–55%**;
- custom engineering priced to at least cover fully loaded cost;
- managed operations priced with a visible support and infrastructure margin.

These are internal targets, not customer promises. A high-security customer
may have lower first-year margin and still be attractive if the deployment is
repeatable and renewal economics are strong.

## 16. Expansion and renewal rules

Expansion may be triggered by:

- more repositories or applications;
- more cloud accounts or regions;
- more network/certificate scope;
- additional business units;
- higher scan frequency;
- new source families;
- longer evidence retention;
- additional integrations;
- higher support coverage;
- additional environments or resilience requirements.

Renewal review should occur 90–120 days before expiry and cover:

- actual source and user usage;
- findings reviewed and remediation workflow adoption;
- unresolved limitations;
- support incidents and response performance;
- evidence and report value;
- security or legal changes;
- proposed scope and price changes;
- exit obligations if the customer does not renew.

Do not make renewal depend on an arbitrary finding count. Use adoption,
coverage, workflow completion, evidence usefulness, and customer outcomes.

## 17. What is included versus excluded

### Included when explicitly contracted

- agreed software release;
- agreed deployment and source bands;
- standard documentation;
- standard support tier;
- standard reports and evidence exports;
- ordinary maintenance updates;
- defined onboarding and training;
- defined product issue response.

### Usually excluded or separately priced

- customer cloud, database, HSM, storage, network, or SIEM fees;
- private-key recovery or handling;
- custom parser or connector development;
- independent penetration testing;
- certification audits;
- legal, regulatory, or privacy advice;
- customer remediation work;
- 24x7 support without a signed staffed service;
- unlimited source volume or scan frequency;
- unlimited retention or historical reprocessing;
- customer-specific DR topology operation;
- travel and on-site expenses;
- third-party licence fees.

## 18. Commercial guardrails

The following statements must not appear in a proposal unless the relevant
evidence exists and the statement is approved:

- "bank certified";
- "regulator approved";
- "FIPS certified" based only on cryptographic primitives;
- "SOC 2 compliant" without an applicable report;
- "100% accurate";
- "complete coverage of all bank systems";
- "zero risk";
- "24x7 support" without staffed and contractual service;
- "zero data retention" when backups, logs, or evidence remain;
- "production ready for every international bank";
- "HSM qualified" based only on local SoftHSM or adapter code.

Use the evidence tiers defined by the control register and the pilot decision
language in [`pilot-standard.md`](pilot-standard.md).

## 19. Quote approval checklist

Before sending a quote, confirm:

- [ ] Customer legal entity and deployment region are known
- [ ] Pilot or subscription scope is measurable
- [ ] Source and usage bands are recorded
- [ ] Deployment responsibility is explicit
- [ ] Customer and vendor infrastructure costs are separated
- [ ] Integrations are listed as standard or custom
- [ ] Support hours and response commitments are approved
- [ ] Data retention, residency, export, and deletion terms are included
- [ ] Pilot acceptance and change-control terms are included
- [ ] No unsupported certification or production claim appears
- [ ] Discounts have an owner and expiry
- [ ] Taxes, FX, withholding, and invoice currency are clear
- [ ] Finance approved margin and payment terms
- [ ] Legal approved liability, confidentiality, DPA, and exit terms
- [ ] Security approved the evidence and readiness wording

## 20. Recommended starting price card

For the first standard proposals, use this simplified card and move to the
full model only when the customer scope is known:

| Item | Starting reference |
|---|---:|
| Discovery workshop | $5,000 |
| Two-week technical proof | $12,000 |
| Six-week standard pilot | $45,000 |
| Foundation subscription | $80,000/year |
| Professional subscription | $165,000/year |
| Enterprise subscription | $325,000/year |
| Standard implementation | $35,000 |
| Standard integration | $25,000 each |
| Enhanced support | $40,000/year |
| Critical support | +30% of platform fee |

These starting references are internal planning numbers. Finance, sales, and
legal must approve the actual price before a customer receives a proposal.

## 21. Relationship to the other commercial documents

- [Standard bank pilot](pilot-standard.md) defines what the pilot delivers.
- [Pilot duration and phases](pilot-duration-and-phases.md) defines the
  schedule and exit criteria.
- [Enterprise readiness gaps](enterprise-bank-readiness-gaps.md) defines what
  still requires customer, provider, auditor, legal, or production evidence.
- [Readiness evidence gate](readiness-evidence/README.md) defines how evidence
  is retained and checked.
- [Production readiness](../PRODUCTION-READINESS.md) defines the current
  decision boundary.

The sales process should follow the evidence process: price a controlled pilot,
measure it honestly, and expand only after the customer understands the result
and the remaining risk.
