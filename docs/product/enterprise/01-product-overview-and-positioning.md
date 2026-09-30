# Product overview and positioning

## 1. The problem

Organizations use cryptography in applications, libraries, containers,
firmware, network endpoints, cloud key services, certificates, payment
systems, telecom infrastructure, and operational technology. Ownership is
usually split across security, development, infrastructure, cloud, network,
application, and compliance teams. The result is not simply "weak crypto";
it is incomplete knowledge:

- an algorithm is present but its owner is unknown;
- a certificate is expiring but no service map exists;
- a dependency introduces a primitive that is not visible in a source scan;
- a policy applies to one system but not another;
- an HSM or KMS export contains metadata that is not reconciled with code;
- a migration plan lacks business criticality and blast radius; or
- a report cannot demonstrate which observations were actually verified.

CryptoScan is designed to turn that fragmented problem into a repeatable,
reviewable operating loop.

## 2. What CryptoScan is

CryptoScan is a cryptographic discovery, inventory, posture, and evidence
platform. It collects authorized observations, protects their integrity,
normalizes them into a common asset model, evaluates deterministic policy, and
produces actionable and auditable outputs.

The platform's core output is not a dashboard score. It is a chain of linked
artifacts:

```text
Authorized source
  -> observation
  -> evidence record
  -> normalized crypto asset
  -> system / owner / business context
  -> policy and risk result
  -> remediation, gate, alert, or exception
  -> BOM, report, export, and verification record
```

Each stage has a different purpose. A finding is not automatically a risk
acceptance; a policy result is not a certificate; a planned migration is not a
completed remediation; and a report is not proof unless its underlying evidence
can be verified.

## 3. The product loop

| Stage | Product responsibility | Customer/operator responsibility |
|---|---|---|
| Scope | Enforce configured target and safety boundaries | Authorize sources, targets, accounts, and data classes |
| Collect | Read configured sources and report reachability | Provide least-privilege credentials and network paths |
| Integrity | Hash and chain evidence; preserve provenance | Retain keys, manifests, and approved storage according to policy |
| Normalize | Canonicalize algorithms, modes, key sizes, assets, and identities | Correct ownership and source metadata when the product cannot infer it |
| Assess | Apply policy, drift, risk, PQC, and agility logic | Select applicable frameworks and approve baselines |
| Act | Produce gates, work items, alerts, templates, and exports | Remediate systems, approve exceptions, and verify changes |
| Prove | Provide verification endpoints, reports, manifests, and packs | Decide what evidence is acceptable for the customer, auditor, or regulator |

## 4. Correlated technology-BOM output

The shared Technology BOM model exposes SBOM, CBOM, HBOM, and VBOM views over
bounded, provenance-linked evidence. A binary or firmware scan adds a correlated
bundle containing:

- **SBOM** components and dependencies;
- **CBOM** cryptographic assets and algorithm evidence;
- **HBOM** hardware and firmware context when the artifact provides it;
- **static NBOM** capability candidates from imports, exports, and strings;
- **VBOM** vendor/product evidence when supplied or inferred from bounded
  metadata;
- a separate **vulnerability BOM** for weak/deprecated algorithms, hardening
  failures, malformed/truncated/refused artifacts, and supplied advisory or
  package matches; and
- a deterministic technology-BOM snapshot with tenant-scoped storage,
  stable references, confidence/unknown states, provenance, and per-layer
  bundle diffs.

Binary-derived NBOM records are marked `observed: false`; imports of socket or
TLS APIs are not live network observations. An authorized network scan must
supply corroborating evidence before a candidate is described as an exposed
listener or endpoint. Parsers are bounded and static-only: they do not execute
or compile modules, mount firmware filesystems, decrypt private material, or
prove signatures, malware absence, provenance, or complete reverse engineering.

## 5. Who uses it

### Security and cryptography teams

They use the inventory, evidence chain, finding detail, policy results, PQC
readiness, agility score, and remediation queue to answer:

- What cryptography exists?
- Which uses are weak, unsupported, or unowned?
- Which systems are affected by a provider, library, certificate, or key?
- What must change first, and why?
- Can the result be rechecked after the fix?

### Developers and platform engineers

They use repository scans, CI gates, SARIF, SBOM/CBOM changes, remediation
templates, and API automation. The intended workflow is fast feedback at pull
request time, followed by a deeper scheduled or release scan.

### CISO and risk owners

They use system ownership, business criticality, unified risk, compliance
reports, drift, migration waves, PQC/HNDL analysis, and board-ready exports.
The score is a prioritization aid, not a substitute for a risk decision.

### Auditors and assessors

They use read-only access, evidence verification, audit exports, manifests,
compliance mappings, and versioned reports. The auditor should be able to
recompute or challenge the result without trusting a screenshot.

### Operators

They install the stack, configure databases and queues, maintain credentials,
monitor health, run backups and restore drills, rotate keys, and manage
upgrades.

## 6. Positioning relative to large enterprise platforms

Large vendors often publish separate product, administrator, developer,
security, compliance, API, operations, and support manuals. CryptoScan follows
the same documentation pattern here, but the product is not represented as an
IBM or Google service. Specifically:

- the deployment model is determined by this repository and the customer's
  chosen infrastructure;
- service availability, support coverage, and data residency are not implied
  by the existence of a container compose file;
- cloud inventory is limited to the accounts and permissions actually supplied;
- integrations need real endpoints and credentials before they become
  operational evidence; and
- the current production decision is the readiness gate, not marketing prose.

## 7. What it does not do

CryptoScan does not:

- retrieve private keys, secret values, passwords, or key material as part of
  normal discovery;
- modify scanned repositories, hosts, cloud resources, HSMs, or OT networks;
- send active packets into OT/ICS networks where the configured collector is
  passive;
- make an unreviewed human decision using an automated score;
- allow AI or generated text to decide a policy verdict;
- guarantee complete discovery where credentials, source, network, or format
  access is missing;
- replace certificate lifecycle management, secrets management, PKI, SIEM,
  EDR, CSPM, WAF, HSM, or an auditor; or
- convert a repository control into an external certification.

## 7. Success definition

A successful deployment can answer, for a declared scope and time period:

1. which sources were authorized and scanned;
2. what was observed and what was not reachable;
3. how observations became assets and findings;
4. which policy version produced each result;
5. who owns the affected system and risk;
6. which changes are open, accepted, or verified;
7. which evidence pack was delivered; and
8. how another reviewer can verify the result.

If any of those questions cannot be answered, the correct product state is an
explicit unknown, blocked, skipped, or not-evaluated state—not a guessed PASS.
