# CryptoScan — bank questions and answers

**Reviewed:** 2026-10-25 UTC · **implementation reference:** `e4afd4a3406219758f4aae9c5f53e7b4398f8409`.

Practical answers for bank sponsors, application owners, SOC, network, platform, audit and implementation teams. This pack contains **100 questions with answers**, including what is present and absent, how collection works, all six BOMs, firewall/IDS coordination, on-premises installation and pre-discovery.

This is an explanation of existing implementation and its limits—not a new feature, deployment approval, penetration-test authorization, signed release or service-level agreement. Older documents retain their dated scope. The dated Windows guides linked below describe later increments than the historical summary tables.

## Start with these five answers

1. **CryptoScan does not automatically scan the whole bank.** The bank approves exact systems, inputs, operations, windows and limits first.
2. **Collectors discover facts; BOMs project stored evidence.** One approved session can support several BOMs, but unsupported BOMs must remain partial/unknown.
3. **Current production support is narrower than repository capability.** The controlled reference profile is `kubernetes-external-services/local-source-v1`; it is a site-qualification baseline, not blanket clearance for live host/network/cloud acquisition.
4. **CryptoScan is not a firewall, IDS/IPS, EDR or SIEM replacement.** Bank security teams control network access and monitoring; the scanner must cooperate with them, not bypass them.
5. **Evidence has limits.** A package is not an invocation, a registered function is not tested capability, a TLS session is not universal protocol coverage, and a hash is not authenticity.

## Question index

| File | Questions | Who should read it |
|---|---|---|
| [01 — Present, partial and absent scope](01-scope-and-capabilities.md) | Q001–Q012 | Sponsor, architecture, procurement, security |
| [02 — Bank scanning and pre-discovery](02-bank-scan-and-pre-discovery.md) | Q013–Q024 | Application owners, discovery team, operators |
| [03 — Firewall, IDS, rate limits and scan safety](03-firewall-ids-and-scan-safety.md) | Q025–Q036 | SOC, network, security engineering |
| [04 — How all six BOMs work](04-six-boms-and-evidence.md) | Q037–Q048 | Crypto, software inventory, architecture, audit |
| [05 — On-premises deployment](05-on-prem-deployment.md) | Q049–Q060 | Kubernetes, infrastructure, DBA, PKI |
| [06 — Access, evidence and governance](06-access-evidence-and-governance.md) | Q061–Q070 | IAM, CISO, compliance, reviewers |
| [07 — Operations, recovery and acceptance](07-operations-recovery-and-acceptance.md) | Q071–Q080 | Operators, support, service owners |
| [08 — Worked bank example and meeting checklist](08-bank-example-and-meeting-checklist.md) | Q081–Q090 | Joint bank/CryptoScan implementation team |
| [09 — Integration, accuracy and PQC follow-up](09-integration-accuracy-and-pqc.md) | Q091–Q100 | IAM, integration, risk and procurement teams |

## Status vocabulary used throughout

| Label | Meaning |
|---|---|
| **Implemented — scoped** | Code and bounded evidence path exist. Availability still depends on the selected deployment profile, permissions and qualification. |
| **Partial** | A narrower subset is implemented; do not generalize it to the whole system or estate. |
| **Candidate** | Engineering implementation exists, but native/site/production admission is not complete. |
| **Blocked / not admitted** | The relevant controlled/universal execution path refuses it; a UI page or legacy module does not override that boundary. |
| **Planned / separate qualification** | Requires more implementation or a separately approved and demonstrated adapter/deployment. |
| **Bank responsibility** | Must be supplied, operated or approved by the bank or its explicitly appointed provider. |

**Two independent questions must always be answered:** “Does code exist?” and “May this exact deployment execute it?” A positive answer to the first does not answer the second.

## Authoritative follow-up reading

- [Current on-premises support boundary](../BANK-ON-PREMISES-DEPLOYMENT.md) and [operator install/upgrade/recovery runbook](../runbooks/operator-install-upgrade-recover.md).
- [Controlled API surface enforcement](../../services/api/api/middleware/controlled_surface.py).
- [Universal foundation](../bank-environment/62-universal-collection-foundation.md), [phase order/coverage](../bank-environment/69-phasewise-universal-collection-build.md), [Linux inputs](../bank-environment/63-linux-collection-phase-two.md), [Linux relationships/validated SBOM](../bank-environment/71-linux-relationships-and-validated-sbom.md).
- Windows candidates: [public certificates](../bank-environment/72-phase-three-windows-public-certificate-candidate.md), [process/modules](../bank-environment/73-phase-three-windows-process-module-candidate.md), [CNG registration](../bank-environment/74-phase-three-windows-cng-registration-candidate.md).
- [Six-BOM evidence paths](../bank-environment/49-six-bom-evidence-paths.md), [supplier quarantine](../bank-environment/52-qualified-adapters-and-supplier-quarantine.md), [operating/support model](../BANK-24X7-OPERATIONS-AND-WEEKLY-SUPPORT.md).

Do not send credentials or private keys in chat, questionnaires or public evidence. Use bank-approved secret custody and sanitized examples.
