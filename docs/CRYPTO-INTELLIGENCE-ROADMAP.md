# Cryptographic Intelligence Platform — Strategic Roadmap

> **Document class: plan, not status.** This is the build plan for the next product
> phase. Nothing here is claimed as built; current state is
> [docs/CURRENT-STATE.md](CURRENT-STATE.md) (generated from the tree), and every
> capability ships with a test that proves it or an explicit reason it is listed
> without one.

Priorities are as marked: **1 (highest strategic) → 2 (very high) → 3 (major
differentiator)**, then 4–11. Implementation order below follows those priorities:
the shared evidence and identity foundations (items 1–3, 6) are built first because
items 4, 7, 8 and the workflows in 9 all read from them.

---

## 1. Digital Twin — make it the central intelligence engine

**Highest strategic priority.**

You already have a Digital Twin architecture. The next improvement is to make it
the actual central operating model rather than a separate graph visualization.

Improvements:

- Stable identity resolution across all six BOMs.
- Connect application → service → host → library → algorithm → HSM/KMS →
  certificate → network endpoint.
- Track ownership and business-system mapping.
- Preserve conflicting observations instead of overwriting them.
- Show first-seen, last-seen and historical changes.
- Show which relationships are proven, inferred or unknown.
- Calculate impact when an asset, certificate, algorithm or vendor changes.

**Important: every graph relationship should have evidence behind it.**

Example:

`Payments API → Load Balancer → TLS Certificate → RSA-2048 → CA`

CryptoScan should explain exactly which evidence establishes each relationship.

## 2. Cryptographic usage verification

**Very high priority** — one of the most important differentiators for CryptoScan.

A library supporting AES-256 does not prove that the application uses AES-256.

Build a verification model that separates:

| Evidence level | What it proves |
|---|---|
| Capability | A library supports an algorithm |
| Static reference | Code references an algorithm |
| Configuration | An algorithm is configured |
| Runtime observed | An operation was observed at runtime |
| Network negotiated | A protocol actually negotiated an algorithm |

Improvements:

- Runtime cryptographic operation observation.
- TLS handshake and cipher-suite verification.
- HSM/KMS operation correlation.
- Certificate and key metadata correlation.
- Application-to-algorithm usage mapping.
- Evidence freshness and confidence tracking.

**Goal: CryptoScan should tell the bank what cryptography is available, configured
and actually observed — not confuse these categories.**

## 3. PQC readiness and migration intelligence

**Major product differentiator.**

Move beyond simply identifying RSA, ECC and other quantum-vulnerable cryptography.
Build a complete PQC decision engine.

| Capability | Improvement |
|---|---|
| Discovery | Identify affected cryptographic assets |
| Classification | Classify quantum-vulnerable and quantum-resistant algorithms |
| Prioritization | Rank systems using risk and business criticality |
| Dependency analysis | Identify migration blockers |
| Compatibility | Check application, protocol, HSM and vendor support |
| Simulation | Model algorithm replacement and dependencies |
| Cost estimation | Estimate engineering, infrastructure and licensing costs |
| Migration planning | Create phased migration waves |
| Validation | Verify migration evidence after implementation |

Include support for relevant standards and algorithms: ML-KEM, ML-DSA, SLH-DSA,
hybrid key establishment, TLS post-quantum negotiation, crypto-agility assessment.

Also add separate fields for:

- PQC support available
- PQC configured
- PQC runtime observed
- PQC network negotiated
- PQC migration validated

**Do not automatically mark an organization PQC-ready just because a library
supports ML-KEM.**

## 4. Cryptographic Threat Intelligence Engine

Where CryptoScan becomes more than an inventory tool. Build a deterministic threat
correlation engine.

| Threat intelligence capability | Example |
|---|---|
| Cryptographic regression | TLS 1.3 changes to TLS 1.2 |
| Weak algorithm exposure | New MD5 usage detected |
| Certificate risk | Unexpected certificate replacement |
| Trust-path mutation | Unexpected CA or trust-chain change |
| HSM dependency risk | Critical application loses HSM connectivity |
| Crypto library risk | Vulnerable cryptographic dependency introduced |
| Vendor risk | Supplier changes cryptographic implementation |
| Collection blind spot | Previously visible critical asset becomes unobservable |
| PQC regression | PQC configuration disappears after deployment |

For every finding, show:

1. What changed?
2. Which asset is affected?
3. Why does it matter?
4. What evidence supports it?
5. What is not yet proven?
6. What should the security team investigate?

Keep detection deterministic. AI can explain and summarize the finding, but must
not invent evidence or independently declare a compromise.

## 5. Enterprise asset discovery expansion

Prioritize these integrations:

| Area | Improvements |
|---|---|
| Linux | Complete production qualification |
| Windows | CAPI, CNG, Schannel and certificate qualification |
| HSM | Thales, Entrust, Utimaco and other supported devices |
| Cloud KMS | AWS, Azure and GCP key metadata |
| Databases | Oracle, PostgreSQL, SQL Server and MySQL crypto configuration |
| Network | Firewalls, load balancers, VPN and TLS endpoints |
| Containers | Kubernetes, OCI and image provenance |
| CI/CD | GitHub, GitLab, Jenkins and ArgoCD |
| PKI | CA, certificate issuance, renewal and trust relationships |
| Vendors | Product version, firmware, crypto declarations and deployment matching |

**Don't claim support simply because an integration has a fixture or a connector
definition. Track its actual qualification status.**

## 6. Evidence coverage and discovery completeness

A critical enterprise requirement: a bank must know not only what CryptoScan
discovered, but also what it could not inspect. Build an Estate Coverage
Intelligence module.

Illustrative estate coverage dashboard (figures illustrative only, not actual
CryptoScan measurements):

| | |
|---|---|
| 92% | Authorized targets collected |
| 8% | Collection incomplete |
| 14 | Unknown assets or relationships |
| 7 | Collectors requiring attention |

Coverage by collection plane (illustrative): source repositories 98%, network 95%,
hardware 72%, cloud 90%, HSM 65%.

Include:

- Authorized target count.
- Discovered target count.
- Successful and failed collectors.
- Partial observations.
- Unknown assets.
- Stale evidence.
- Unsupported device types.
- Access-denied targets.
- Unverified relationships.
- Collection freshness.

**A missing asset must never silently become a clean security result.**

## 7. Enterprise risk and prioritization engine

Banks don't want hundreds of disconnected findings. They want to know what matters
most. Create a risk engine using:

- Algorithm strength.
- Key size and cryptographic parameters.
- Exposure and network reachability.
- Business criticality.
- Data sensitivity and retention lifetime.
- Dependency centrality.
- Evidence quality and freshness.
- Vendor support and lifecycle.
- PQC migration difficulty.
- Operational impact.

Provide separate risk dimensions rather than hiding everything in one score:

- Cryptographic risk.
- Quantum migration urgency.
- Operational dependency risk.
- Evidence confidence.
- Vendor and supply-chain risk.

**Every score should be explainable and reproducible.**

## 8. Digital Twin simulation — complete the scenario engine

Make the simulation concepts fully executable against a selected, versioned
snapshot. Scenarios:

1. RSA-2048 → ML-DSA migration.
2. RSA/ECDSA → hybrid post-quantum key establishment.
3. HSM failure.
4. KMS outage.
5. Certificate expiry.
6. TLS downgrade.
7. Cryptographic library vulnerability.
8. Vendor product retirement.
9. CA compromise.
10. Trust-path modification.
11. Crypto provider replacement.
12. Network segmentation change.

For every simulation, calculate: affected assets, affected applications, dependency
chain, migration blockers, compatibility failures, estimated cost, required
approvals, rollback considerations.

**A simulation must distinguish a proven dependency from an assumed dependency.
Never represent a hypothetical result as a real production change.**

## 9. Enterprise workflows and governance

A bank needs to act on findings, not merely view them. Add: finding assignment,
asset ownership, remediation tickets, risk acceptance, exception expiry, approval
workflows, change management integration, evidence attachment, auditor sign-off,
remediation verification, immutable audit history.

Suggested roles:

| Role | Permissions |
|---|---|
| Platform admin | Platform configuration |
| Security architect | Risk and migration decisions |
| Crypto engineer | Technical investigation |
| Infrastructure engineer | Infrastructure remediation |
| Auditor | Read-only evidence and reports |
| Executive | Portfolio-level visibility |

## 10. Enterprise-grade deployment and operations

For bank customers, this is a product feature — not just DevOps. Prioritize:
on-premises deployment, air-gapped deployment qualification if offered, high
availability, database backup and tested restoration, disaster recovery, tenant
isolation, bank IAM integration, mTLS machine identity, key rotation, signed
software releases, software bill of materials for CryptoScan itself, upgrade and
rollback procedures, database migration validation, monitoring and alerting,
resource limits and collector isolation.

**Your on-premises bank deployment should keep the bank in control of its own
database, evidence and cryptographic metadata.**

## 11. UI improvements — Cryptography Threat Intelligence

Design principles:

- Dark navy or charcoal enterprise interface.
- Dense but readable technical tables.
- Evidence-linked findings.
- Search and filters.
- Graph-based investigations.
- Timeline and drift views.
- No excessive gradients, glowing AI effects or unnecessary chatbot panels.

---

## Build order (this plan's own sequencing)

| Wave | Items | Why first |
|---|---|---|
| A | 2 (usage-verification levels), 1 (evidence-backed graph edges), 6 (coverage intelligence) | The shared evidence/identity/coverage foundations everything else reads |
| B | 3 (PQC fields + readiness), 7 (risk dimensions) | Projections over the wave-A evidence model |
| C | 4 (threat intel), 8 (scenario engine) | Deterministic consumers of waves A–B |
| D | 5 (discovery qualification), 9 (governance), 10 (deployment), 11 (UI) | Per-integration and per-surface work; qualification tracked honestly per item 5's rule |

Each shipped piece lands with tests that prove its acceptance rows. Fixtures and
connector definitions never count as qualification.
