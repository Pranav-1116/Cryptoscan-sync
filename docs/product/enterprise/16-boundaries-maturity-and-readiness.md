# Boundaries, maturity, and readiness

## 1. The evidence boundary

CryptoScan documentation must distinguish four things:

1. **Product behavior** — what code and configuration do.
2. **Repository verification** — what tests and local harnesses prove.
3. **Operational evidence** — what a real deployment did at a recorded time.
4. **External assurance** — what a provider, customer, auditor, or regulator
   accepted or issued.

Only the highest supported level may be used in a customer answer. A code path
can be implemented while its production configuration is unknown. A test can
pass while a cloud credential, firewall, or support rota is absent.

## 2. Readiness decision

Use the root [production-readiness gate](../../../PRODUCTION-READINESS.md) and
its generated evidence. It separates PASS, FAIL, and SKIP categories for
engineering, database/DR, HSM, integrations, compliance, load/soak,
documentation, policy, closure, and external attestations.

The decision rule is:

- a required category with FAIL blocks approval;
- a required category with SKIP means evidence is incomplete;
- local or synthetic evidence cannot satisfy external/customer categories;
- a readiness percentage cannot override a failed critical boundary; and
- pilot/pre-production suitability is not unattended regulated production
  approval.

## 3. Known claim restrictions

Do not claim without the actual artifact and scope:

- SOC 2, ISO 27001, PCI, FIPS, or regulator approval;
- independent penetration testing or "no findings";
- customer validation, production topology, or residency;
- 24x7 support, RPO/RTO, uptime, or response targets;
- complete discovery or 100% accuracy;
- no subprocessors or no international transfer;
- immediate deletion from all backups and immutable storage;
- production HSM/KMS qualification from a simulator;
- tenant isolation from a diagram alone; or
- insurance, legal entity, or financial viability from a template.

## 4. Maturity record

For each capability retain:

```text
Capability: ________________________________
Version/release: ___________________________
Deployment model: _________________________
Customer/scope/region: _____________________
Status: implemented / tested / beta / preview
Operational evidence: _______________________
External dependency: _______________________
Known limitations: _________________________
Owner/reviewer: ____________________________
Review/expiry date: ________________________
Decision: expand / remediate / stop / no decision
```

## 5. Documentation quality gate

Before publishing or sending a page:

- every command is safe and uses placeholders for secrets;
- paths and endpoints exist in the current repository or are labeled planned;
- screenshots and metrics have version/date/scope;
- examples identify synthetic data;
- failure and unknown behavior is documented;
- security/privacy claims cite evidence tier;
- contract language is reviewed by legal;
- customer-specific values are not hard-coded;
- link validation and formatting checks pass; and
- the page names the authoritative source and owner.

## 6. Honest enterprise positioning

The documentation breadth now covers product, user, administrator, developer,
security, privacy, operations, API, integration, support, adoption, and
assurance concerns in one navigable center. That makes the product easier to
evaluate and operate; it does not create the external evidence that a large
cloud vendor may possess.

The correct customer statement is:

> CryptoScan provides an enterprise-oriented cryptographic discovery,
> inventory, assessment, evidence, and migration workflow. The supported
> deployment, operational commitments, external assurance, and customer
> approvals are specific to the contracted version, topology, scope, and
> evidence package.

## Latest engineering delta and evidence scope

Implementation `e9bfbef7` adds persisted/fresh queued execution authority, durable
SSH receipts and verified realtime/current-run Redis TLS/ACL/Sentinel behavior.
Recorded local runs: 1315 passes/4 skips broad, then 205 focused passes after the
final provenance increment, plus 28 TLS/Sentinel/unit passes. Counts overlap;
this documentation refresh does not rerun them or amend external attestations.
Remaining positive/regional grants, distributed budgets, all-consumer HA and
production CA/partition/load/restore acceptance must not be marked closed.
[Guides 44–45](../../bank-environment/44-queued-authority-and-durable-ssh.md) and
[upgrade/recovery](../../runbooks/execution-and-replay-upgrade.md) define the
implemented scope, compatibility changes and outstanding work.
