# Capability catalog and maturity model

This page is the enterprise catalogue: it explains what each product family is
for, what it consumes, what it produces, and what must be configured before an
operator can claim it is working. It complements the measured [capability
maturity report](../../CAPABILITY-MATURITY.md) and the detailed [feature
chapter](../02-features.md).

## 1. Capability families

| Family | What it provides | Primary output | Main implementation areas |
|---|---|---|---|
| Source discovery | Finds cryptographic use in repositories, files, dependencies, and configuration | Evidence records and crypto assets | `services/scanner`, `services/worker` |
| Binary and firmware discovery | Reads supported binary, archive, package, and firmware structures and reports hardening or crypto facts | Parsed observations, warnings, and findings | `services/scanner`, binary scanners |
| Network and TLS discovery | Inspects configured endpoints and certificate/TLS behavior | Endpoint, certificate, chain, and protocol observations | `services/network_scanner`, `services/keyassure` |
| Cloud inventory | Reads configured AWS, Azure, and GCP accounts and key/certificate metadata | Cloud asset records and reconciliation data | `services/cloud_scanner`, cloud setup guides |
| Container and SBOM discovery | Reads images, manifests, lockfiles, licenses, vulnerabilities, and component relationships | SBOM/CBOM evidence and release changes | `services/container_scanner`, `services/devsecops`, `services/cbom` |
| OT/ICS and telecom | Applies domain-specific passive or operator-supplied analysis | Domain findings, guardrails, and readiness views | `services/ot_scanner`, `services/telecom_scanner`, `services/ot_safety` |
| Payment and HSM metadata | Ingests approved metadata and assesses key lifecycle or HSM posture | Key inventory, HSM, payment, and migration findings | `services/payment_crypto`, banking routes |
| Normalization and deduplication | Maps aliases and merges observations without losing provenance | Canonical asset and evidence links | `services/normalization`, `services/deduplication` |
| Policy and compliance | Evaluates versioned deterministic rules in scope | PASS/WARN/FAIL/unknown results and mappings | `services/policy`, `services/compliance`, `services/ruleset` |
| Drift and baselines | Compares current state with an approved state | Added, removed, changed, and unapproved findings | `services/drift`, baseline routes |
| PQC and crypto agility | Estimates migration urgency and replacement planning | Buckets, HNDL indicators, waves, scores, and roadmaps | `services/quantum`, `services/agility` |
| Risk and business context | Connects technical findings to systems, owners, revenue, and dependencies | Priority, blast radius, and business impact | `services/business_context`, `services/graph_engine`, `services/correlation` |
| Remediation and workflow | Turns findings into templates, work items, exceptions, and SLA states | Remediation records, status, deadlines, and audit actions | `services/remediation`, `services/sla`, `services/governance` |
| BOM and reporting | Materializes inventory and exports evidence | Shared SBOM, CBOM, HBOM, VBOM plus binary static NBOM, vulnerability BOM, correlated snapshots, reports, packs, and manifests | `services/cbom`, `services/devsecops/devsecops/binary_boms.py`, `services/reporting`, `services/evidence` |
| Automation and integrations | Delivers events and actions to configured systems | Webhooks, tickets, SIEM events, API results, and schedules | `services/automation`, `services/connector_sdk`, `services/eventstream` |
| Platform administration | Provides identity, tenancy boundary, plans, health, billing, and configuration | Sessions, audit, API keys, metrics, and lifecycle records | `services/api`, `services/identity`, `services/control_plane` |

## 2. Maturity labels

Use all four labels when describing a capability:

- **GA surface:** exposed and intended for normal use in the supported
  deployment, subject to the readiness gate.
- **Beta surface:** implemented but needs customer validation, broader test
  evidence, or operational hardening before a universal commitment.
- **Preview surface:** available for evaluation and feedback; contracts,
  support, or backward compatibility are not implied.
- **External dependency:** the repository provides the adapter or workflow, but
  a real provider, credential, endpoint, network, or assessor is required.

A capability can be GA in the interface but external-dependency in operation.
For example, a ServiceNow payload mapper may be tested while delivery still
requires a customer ServiceNow tenant and approved credentials.

## 3. Per-capability documentation contract

Every capability page should document:

1. **Purpose** — the operational problem solved.
2. **Inputs** — source, credential, format, scope, and required permissions.
3. **Collection behavior** — read/write actions, network behavior, and limits.
4. **Data contract** — records created, identifiers, provenance, and retention.
5. **Decision logic** — policy, parser, scoring, or matching algorithm.
6. **Outputs** — UI pages, endpoints, exports, events, and alerts.
7. **Failure behavior** — blocked, skipped, unknown, retry, or hard failure.
8. **Security boundary** — secrets, tenancy, redaction, and audit behavior.
9. **Operations** — schedule, capacity, health, backup, and recovery.
10. **Maturity** — tests, environment dependencies, and unsupported claims.

## 4. Capability selection by outcome

### Build-time prevention

Use source scans, dependency and container scans, policy packs, SARIF, CI
profiles, and SBOM/CBOM diffs. The authoritative result is the gate exit
code and stored evidence, not a PR comment alone.

### Estate inventory

Use repository, binary, cloud, network, certificate, HSM, payment, OT, and
telecom collectors. Start with a declared inventory scope and reconcile data
sources before drawing conclusions about coverage.

### Migration programme

Use normalized assets, ownership, dependency graph, business context, quantum
classification, agility scores, remediation work items, and roadmap exports.
A migration wave is a plan; it becomes evidence only after the source system
is changed and rescanned.

### Audit and procurement

Use verification endpoints, evidence packs, audit exports, compliance mappings,
access review records, manifests, and the company assurance package. Mark
unavailable external reports as unavailable instead of attaching internal
readiness material as a substitute.

## 5. Capability acceptance checklist

Before moving a capability from evaluation to contracted scope, record:

- supported version and deployment model;
- target customer environment;
- required credentials and least-privilege policy;
- test scope and observed result;
- known unsupported formats and conditions;
- performance and rate limits;
- data retention and deletion path;
- owner, support path, and escalation;
- evidence artifact and expiry; and
- customer acceptance or risk exception.
