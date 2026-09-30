# Adoption, pilot, and acceptance

## 1. Adoption principles

An enterprise rollout should begin with evidence and ownership, not a promise
of universal discovery. Start with a representative but bounded scope, prove
the operating loop, then expand domains and volume.

A good rollout has:

- an executive sponsor;
- security/crypto owner;
- platform and network owner;
- application and developer representatives;
- privacy/legal reviewer;
- business risk owner;
- operations/support owner; and
- customer-approved success criteria.

## 2. Pilot phases

### Phase 0 — charter and safety

Define entity, systems, sources, data classes, prohibited inputs, credentials,
regions, support, retention, policy packs, and stop criteria. Sign or approve
scope documents before connecting production sources.

### Phase 1 — technical connection

Connect one or two low-risk representative sources. Validate identity,
network, source authorization, worker path, evidence redaction, and report
export. Do not treat this as estate coverage.

### Phase 2 — representative inventory

Add varied source types: source code, dependency, binary/container, endpoint,
cloud metadata, or approved export. Compare results with customer owners and
record false positives, false negatives, unsupported cases, and missing
permissions.

### Phase 3 — policy and workflow

Select baseline/framework scope, approve a test baseline, route findings to
owners, test CI or ticket integration, record exceptions, and verify one
remediation from changed source to cleared finding.

### Phase 4 — evidence and operating exercise

Run backup/restore, evidence verification, support escalation, connector retry,
access review, and report delivery. Confirm what an auditor can verify and what
still requires external evidence.

### Phase 5 — decision

Choose **Expand**, **Remediate and repeat**, **Stop**, or **No decision**. The
result must state tested scope, coverage, limitations, unresolved risks, and
approval authority.

## 3. Acceptance criteria

| Area | Evidence of acceptance |
|---|---|
| Scope | Signed/approved target list and authorization |
| Installation | Health, readiness, TLS, secrets, and configuration guard results |
| Identity | User/API key access, role boundaries, rotation/revocation test |
| Collection | Expected fixtures and representative source results |
| Coverage | Reached, skipped, blocked, unsupported, and partial counts reviewed |
| Integrity | Evidence chain and export verification pass |
| Policy | Selected rules, versions, and expected verdicts reviewed |
| Workflow | Finding assignment, exception, remediation, and rescan completed |
| Integration | Preview, delivery, retry, idempotency, and failure path tested |
| Operations | Backup, restore, health, alert, escalation, and support exercise |
| Privacy | Data map, redaction, retention, deletion, and transfer review |
| Business | Owner, criticality, blast radius, and risk decision recorded |

## 4. Pilot boundaries

A pilot acceptance is not:

- production approval for unattended regulated processing;
- a certification or regulatory approval;
- proof of every source in the customer's estate;
- proof that external connectors are staffed or available 24x7;
- proof that a customer has accepted all residual risk; or
- a substitute for penetration testing, insurance, DPA, SLA, or independent
  assurance.

Use the [pilot standard](../../pilot-standard.md), [duration and phases](../../pilot-duration-and-phases.md),
and company Order Form/SOW templates for commercial execution.

## 5. Expansion gates

Expand only when the previous phase has:

- no unresolved critical integrity or scope issue;
- named owner for every high-risk gap;
- documented compensating control or stop decision;
- tested evidence and deletion path;
- support and incident route;
- acceptable performance for the next source volume; and
- customer approval of the next scope.

## 6. Post-pilot handoff

Deliver:

- final tested-scope report;
- coverage and limitation statement;
- findings and prioritized remediation plan;
- evidence index and verification result;
- architecture/residency and responsibility matrix;
- operating/support handbook and contacts;
- backup/restore and access-review record;
- open risks and expiries; and
- expand/remediate/stop/no-decision record.
