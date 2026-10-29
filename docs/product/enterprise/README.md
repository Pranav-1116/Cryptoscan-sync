# CryptoScan Enterprise Documentation Center

> **Reviewed 2026-10-22 (`698beb38`):** begin with
> [current implementation status](../../CURRENT-IMPLEMENTATION-STATUS.md),
> [CI/product-build plan](../../CI-WORKFLOW-AND-PRODUCT-BUILD-PLAN.md) and
> [launch handoff](../../runbooks/launch-assurance-handoff.md).
> Current schema head is **0105**; the generated inventory has **77** surfaces
> (33 GA / 32 Beta / 12 Preview). Development collection examples are not a
> production allowlist, and the user's remaining CI failure is not waived.

**Purpose:** provide an enterprise documentation experience with the breadth and
navigation discipline expected from large platform vendors. This is a
repository-backed product manual for CryptoScan; it is not a claim of IBM,
Google, or any other vendor's certification, scale, SLA, or feature parity.

**Documentation status:** implementation-aligned drafting set
**Audience:** evaluators, security architects, platform administrators,
operators, developers, auditors, and customer success teams
**Product boundary:** cryptographic discovery, inventory, posture assessment,
remediation planning, evidence, and automation. It does not replace a secrets
manager, certificate authority, WAF, SIEM, HSM, cloud provider, or legal,
regulatory, or audit authority.

## Start here

| Goal | Read |
|---|---|
| Understand the product in ten minutes | [Product overview and positioning](01-product-overview-and-positioning.md) |
| See every capability and its maturity | [Capability catalog](02-capability-catalog.md) |
| Install a local or production-like deployment | [Deployment and installation](03-deployment-and-installation.md) |
| Run the first safe scan | [First scan and operating loop](04-first-scan-and-operating-loop.md) |
| Review the architecture | [Architecture and runtime](05-architecture-and-runtime.md) |
| Understand data, evidence, and BOMs | [Data model, evidence, and data flow](06-data-model-evidence-and-dataflow.md) |
| Configure users and security | [Identity, access, tenancy, and privacy](07-identity-access-tenancy-and-privacy.md) |
| Understand what each collector does | [Scanners and collection](08-scanners-and-collection.md) |
| Create policy and compliance decisions | [Policy, compliance, and risk](09-policy-compliance-and-risk.md) |
| Automate through APIs and integrations | [APIs, automation, and DevSecOps](10-api-automation-and-devsecops.md) |
| Operate the service safely | [Operations, reliability, backup, and DR](11-operations-reliability-backup-and-dr.md) |
| Run support and incident response | [Monitoring, alerting, and support](12-monitoring-alerting-and-support.md) |
| Extend the platform | [Developer and extension guide](13-developer-and-extension-guide.md) |
| Upgrade and troubleshoot | [Lifecycle, troubleshooting, and FAQ](14-lifecycle-troubleshooting-and-faq.md) |
| Plan a customer pilot or rollout | [Adoption, pilot, and acceptance](15-adoption-pilot-and-acceptance.md) |
| Decide what can be claimed | [Boundaries, maturity, and readiness](16-boundaries-maturity-and-readiness.md) |

## Documentation map

The enterprise center is the narrative layer. The existing specialized manuals
remain the implementation authority for detailed procedures. The current
console map is maintained separately so product navigation does not drift from
code:

- [Navigation & Feature Reference](../../NAVIGATION-FEATURE-REFERENCE.md) — five sidebar sections and their groups, primary/deep-linked routes, role guards and feature ownership.
- [Product narrative](../README.md) — nine deep chapters and diagrams.
- [User guide](../../user-guide/) — operator and analyst workflows.
- [Admin guide](../../admin-guide/) — installation, configuration, identity,
  policies, integrations, and backups.
- [Architecture decisions](../../decisions/) — durable design decisions.
- [API reference](../../api-reference/rest-api.md) — generated REST surface.
- [Runbooks](../../runbooks/) and [operations](../../ops/) — recovery and
  production procedures.
- [Security documentation](../../security/) — threat model, hardening,
  network controls, and testing scope.
- [Company assurance pack](../../company/README.md) — legal, privacy,
  procurement, assurance, and questionnaire materials.
- [Production readiness gate](../../../PRODUCTION-READINESS.md) — the current
  PASS/FAIL/SKIP evidence boundary.
- [Backend/database gaps](../../../BACKEND-DATABASE-GAPS.md) — audit findings
  that override optimistic or historical documentation.

## How to read status labels

This documentation uses four different dimensions, because a feature can be
implemented but not operationally qualified:

| Label | Meaning |
|---|---|
| **Implemented** | Code, configuration, or a documented workflow exists in this repository. |
| **Tested** | A repeatable repository test or local harness covers the behavior. |
| **Environment-dependent** | The feature needs real cloud, identity, database, HSM, network, or connector credentials. |
| **Externally assured** | A customer, provider, auditor, regulator, or certification body supplied evidence. |

Implemented or tested does not mean externally assured. A page, endpoint,
mock, synthetic scan, or policy file cannot be represented as a customer
validation, independent penetration test, SOC 2 report, ISO certificate, or
regulatory approval.

## Standard product lifecycle

Every capability should be documented through the same lifecycle:

1. **Discover** — identify the source, owner, authorization, data class, and
   expected outcome.
2. **Connect** — configure a least-privilege connector or a safe upload path.
3. **Collect** — scan read-only and record what was reached, skipped, or
   blocked.
4. **Normalize** — map observations to canonical algorithms, assets, systems,
   and identities.
5. **Assess** — evaluate deterministic policy, risk, drift, PQC exposure,
   agility, and business impact.
6. **Act** — open a remediation item, CI gate, alert, exception, or change
   request; do not silently change evidence.
7. **Prove** — preserve hashes, manifests, reports, approvals, and verification
   results for the intended audience.
8. **Review** — refresh credentials, scope, policies, baselines, evidence, and
   documentation after material change.

## Version and ownership

Each page should be reviewed when its referenced code, endpoint, migration,
configuration variable, deployment model, or security boundary changes. When a
page conflicts with the running product, use this order of authority:

1. executable code and its tests;
2. the current generated API schema and migration state;
3. the current production-readiness evidence;
4. the relevant runbook or admin guide;
5. narrative and historical documents.

This order prevents an attractive documentation portal from becoming a source
of unsupported commitments.

## Latest execution/replay operating contract

The enterprise pages now incorporate the 2026-10-21 queue/SSH/Redis increment.
Use the [API contract companion](../../api-reference/execution-and-replay.md)
for exact-estate replay and receipt semantics, and the
[upgrade runbook](../../runbooks/execution-and-replay-upgrade.md) for coordinated
rollout, legacy jobs and explicit failover cursor resets. The
[documentation coverage map](../../DOCUMENTATION-STATUS.md) separates refreshed
instructions, regenerated schema and historical evidence; it is not a new
production qualification or company assurance attestation.
