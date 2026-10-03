# Cryptography Threat Intelligence: product vision and end-to-end roadmap

**Document status:** product strategy and future-update plan
**Date:** 2026-10-02
**Audience:** product, engineering, security operations, cryptography owners, enterprise buyers, and partners

### How to read status

- **Current / shipped foundation** means the repository contains a capability or
  workflow, but its maturity, coverage, deployment prerequisites, and production
  qualification still come from the capability and readiness evidence. It is not
  a claim that every connector or deployment is generally available.
- **Planned** means a product direction that requires implementation,
  integration, telemetry, testing, and customer qualification before it can be
  represented as delivered.
- **Research / future direction** means an exploration or longer-term hypothesis;
  there is no delivery commitment or production claim.

For current maturity, read [Capability Maturity](../CAPABILITY-MATURITY.md),
[Product capabilities, end to end](../PRODUCT-CAPABILITIES-END-TO-END.md), and
the [production-readiness gate](../../PRODUCTION-READINESS.md). This roadmap does
not override those evidence documents.

## 1. Product thesis

CryptoScan's long-term category is **Cryptography Threat Intelligence**.

CBOM and PQC are important capabilities, but they are not the whole plan:

- **CBOM** tells the organization what cryptography is present and how the
  components relate.
- **PQC** tells the organization which public-key uses may require quantum-safe
  migration and how to plan the transition.
- **Cryptography Threat Intelligence** explains what the cryptography means in
  the current threat, technology, supplier, policy, and business context.
- **Cryptographic attack detection** identifies suspicious or unsafe activity
  involving cryptographic controls and assets.
- **Cryptographic defence** helps the responsible team contain, remediate,
  migrate, verify, and produce evidence safely.

The product must grow from an inventory tool into an evidence-led decision and
response system without pretending that a scanner can see every secret, infer
every control, or replace a security operations team.

```text
cryptographic observations
        + vendor and system context
        + standards and vulnerability intelligence
        + change and runtime telemetry
        + customer policy and business criticality
        ↓
cryptography threat intelligence
        ↓
prioritized decision, detection, response, migration, and evidence
```

## 2. Current foundation

The current product direction provides the foundation for this category:

- cryptographic discovery and asset inventory;
- CBOM and related evidence outputs;
- algorithms, protocols, certificates, keys, libraries, and dependency context;
- network and vendor cryptography surfaces;
- PQC classification and crypto-agility planning;
- policy evaluation, drift, findings, remediation, and evidence history;
- vendor due diligence and supplier cryptography context;
- explicit unknown, incomplete, unverified, and unavailable states;
- tenant-scoped persistence and request-isolation controls where implemented
  and qualified;
- customer-controlled deployment and read-only integration patterns where
  supported by the deployment.

These capabilities are not a blanket production or compliance approval. Each
scanner, connector, detection, and integration must retain its own evidence
status, coverage limitations, and qualification state.

The repository's code-mapped [Security Intelligence
Roadmap](../architecture/SECURITY-INTELLIGENCE-ROADMAP.md) records the current
identity, confidence, verification-state, correlation, scheduling, and
integration work separately from this category roadmap. Some of that work is
partial, needs wiring, or is preview maturity; it should not be read as a
finished threat-feed, attack-detection, or autonomous-defence capability.

## 3. The end-to-end operating loop

### Stage 1 — Discover

Collect cryptographic observations from approved sources:

- source code, packages, binaries, firmware, containers, and configuration;
- certificates, TLS endpoints, protocols, and network services;
- cloud, KMS, HSM, keystore, payment, telecom, and platform inventories;
- vendor responses, contracts, assessments, CBOMs, and public evidence;
- approved runtime and security telemetry;
- change records, deployment metadata, and service ownership.

Every observation should carry provenance, timestamp, source, confidence, and
limitations. A missing connector is a coverage gap, not an empty or healthy
result.

### Stage 2 — Normalize

Convert observations into stable cryptographic entities and relationships:

- algorithm and parameter set;
- protocol, mode, key type, and key size;
- certificate, issuer, subject, validity, and usage;
- library, package, component, binary, device, or service;
- provider, consumer, owner, business process, and dependency;
- evidence reference, content hash, and review state.

Normalization must distinguish a direct observation from an inference or a
vendor assertion.

### Stage 3 — Produce CBOM and evidence

Generate a machine-readable CBOM plus human-readable views. CBOM is the
interchange and inventory layer, not a final risk decision. The output should
make it possible to answer:

- what was found;
- where it was found;
- which component provides or consumes it;
- how complete the source coverage is;
- what is unknown;
- what evidence supports the record;
- when it should be rechecked.

OWASP CycloneDX identifies CBOM as one of the BOM types in the ECMA-424
standard family. CryptoScan should interoperate with that ecosystem instead of
claiming ownership of the standard.

Source: [OWASP CycloneDX / ECMA-424](https://owasp.org/projects/cyclonedx)

### Stage 4 — Assess risk and migration exposure

Combine the normalized record with:

- policy and approved algorithm catalogues;
- vulnerability and advisory intelligence;
- known exploitation or abuse context;
- data confidentiality lifetime;
- certificate and key lifecycle;
- system criticality and business impact;
- vendor and product support status;
- dependency and replacement complexity;
- PQC readiness and crypto-agility evidence;
- customer-specific risk acceptance rules.

The result must be a structured explanation, not a mysterious score:

```text
observation
  → evidence and confidence
  → affected service and owner
  → threat or policy context
  → impact and dependency path
  → recommended action
  → acceptance, migration, or response evidence
```

### Stage 5 — Detect change and threat

The future detection layer should compare new observations with baselines and
threat intelligence. It should identify signals such as:

- unexpected downgrade to a weaker protocol or cipher suite;
- new use of a deprecated or disallowed algorithm;
- certificate replacement outside an approved change window;
- suspicious key, certificate, or signing activity;
- unexpected trust-store or root-certificate change;
- a cryptographic library or provider change in a critical application;
- a vendor or component advisory affecting an observed cryptographic asset;
- a new public-key dependency in a long-lived or high-confidentiality service;
- a mismatch between declared PQC capability and observed behavior;
- unusual failed verification, handshake, signature, or key-access patterns;
- cryptographic configuration drift on a network, cloud, device, or workload.

These are detection hypotheses and candidate signals. A production detector must
be tested against customer-approved telemetry, benign change, negative cases,
latency, false positives, false negatives, and response safety.

### Stage 6 — Defend and migrate

Defence should be a controlled workflow, not an unreviewed destructive action:

1. alert with evidence and confidence;
2. correlate with change, asset, owner, and business context;
3. assign an accountable responder;
4. validate the signal and determine blast radius;
5. select a safe action: configuration change, policy block, certificate or key
   workflow, patch, rollback, segmentation, vendor escalation, or PQC migration;
6. require approval for high-impact actions;
7. execute through the customer's approved control plane;
8. re-scan and verify the result;
9. record residual unknowns, exceptions, and rollback evidence.

CryptoScan should not revoke certificates, rotate keys, disable production
protocols, or change live infrastructure without explicit customer authority,
change control, and a tested rollback path.

## 4. Roadmap beyond CBOM and PQC

### Phase A — Cryptographic intelligence foundation

**Status:** current capability and continuing hardening

- multi-source cryptographic inventory;
- CBOM and evidence export;
- certificate, key, protocol, library, and dependency context;
- vendor profile and supplier evidence;
- policy, drift, and remediation workflow;
- explicit completeness and provenance states;
- customer and tenant isolation;
- repeat scans and historical comparison.

**Exit evidence:** customer-reviewed inventory, source coverage report, false-
positive and false-negative review, evidence pack, and repeat-scan comparison.

### Phase B — Cryptography threat intelligence feeds

**Status:** planned

Create a governed intelligence layer for:

- algorithm deprecation and standards changes;
- CVE, vendor advisory, and product-version relationships;
- exploitation and abuse patterns involving cryptographic controls;
- certificate authority, trust-store, and protocol ecosystem events;
- hardware, HSM, KMS, firmware, and library advisories;
- PQC implementation and migration support signals;
- sector-specific intelligence for banking, payments, telecom, healthcare,
  government, and critical infrastructure;
- threat-actor techniques that target authentication, signing, key material,
  trust anchors, or cryptographic configuration.

Every feed item needs source, publication time, collection time, confidence,
expiry, licensing, deduplication, and a clear mapping to affected assets. A
feed must not automatically declare a customer's asset vulnerable merely because
an algorithm family appears in a report.

### Phase C — Cryptographic exposure correlation

**Status:** planned

Correlate intelligence with the customer's estate:

- match algorithm, library, product, firmware, certificate, and provider
  identifiers;
- map the finding to a system, owner, vendor, service, and business process;
- calculate observed blast radius through the dependency graph;
- distinguish exposed, reachable, configured, loaded, and merely present;
- prioritize by exploitability, confidentiality lifetime, business criticality,
  migration effort, and evidence confidence;
- generate a reasoned decision record rather than a generic severity label.

### Phase D — Detection engineering

**Status:** planned and subject to customer telemetry qualification

Possible detection families:

| Detection family | Example signal | Required qualification |
|---|---|---|
| Protocol downgrade | TLS or SSH negotiation moves below the approved baseline | Packet, endpoint, or telemetry source; approved baseline; benign-change tests |
| Trust-store change | New or removed root/intermediate certificate | Managed trust-store inventory and authorized change feed |
| Certificate anomaly | Unexpected issuer, SAN, validity, key size, or renewal path | Certificate observations and change ownership |
| Key-access anomaly | Unusual key use, signing volume, caller, location, or time | HSM/KMS/keystore audit data and customer-specific baselines |
| Algorithm drift | New disallowed or quantum-vulnerable algorithm in a critical path | Repeat inventory and source/version correlation |
| Signature or verification abuse | Repeated invalid verification or unexpected signer | Application or gateway telemetry; abuse-case testing |
| Library/provider change | Cryptographic provider or library changes in a deployment | Build, package, artifact, and deployment evidence |
| Vendor exposure | Advisory affects a product or supplier observed in the estate | Vendor/product identity resolution and advisory provenance |

CryptoScan should begin with alerting and evidence. Blocking and automated
containment must require stronger qualification and customer approval.

### Phase E — Defensive orchestration

**Status:** planned; no autonomous production mutation is implied

Potential controls include:

- policy-as-code checks at build and deployment gates;
- proposed certificate replacement workflows;
- key-rotation and revocation runbooks with approvals;
- safe protocol and cipher configuration proposals;
- compensating controls when migration cannot happen immediately;
- vendor escalation packages with exact affected assets;
- SIEM, SOAR, ITSM, CI/CD, PKI, HSM, and KMS integrations;
- pre-change impact simulation and rollback plan;
- post-change re-scan and evidence closure.

The product may orchestrate approved actions through customer systems, but the
customer remains the authority for production changes.

### Phase F — Cryptographic defence intelligence

**Status:** research / future direction

Longer-term capabilities may include:

- cryptography-specific attack-path graphs;
- simulation of downgrade, trust-anchor, key misuse, or signing compromise
  scenarios;
- crypto-agility digital twins for migration sequence testing;
- privacy-preserving cross-customer indicators without exposing customer data;
- federated supplier and sector intelligence with provenance controls;
- adaptive policy based on observed threat, asset criticality, and change risk;
- cryptographic deception and canary signals where safe and authorized;
- a continuous cryptographic defence loop that re-evaluates exposure, controls,
  telemetry, and recovery evidence as the estate changes;
- continuous control validation for cryptographic defence assumptions;
- machine-readable evidence for insurers, auditors, procurement, and regulators.

These are research directions, not delivered capabilities or guaranteed roadmap
dates.

## 5. Product modules and buyer value

| Module | Primary question | Buyer value |
|---|---|---|
| CBOM and inventory | What cryptography exists? | Visibility and a common machine-readable record |
| Crypto-agility and PQC | What must migrate and in what order? | Migration planning and dependency awareness |
| Vendor cryptography intelligence | What do suppliers claim, and what is observed? | Comparable evidence and third-party risk decisions |
| Threat intelligence | Why does an observed asset matter now? | Prioritization grounded in current context |
| Detection | What changed or looks suspicious? | Earlier investigation and controlled response |
| Defence orchestration | What can the customer safely do? | Repeatable remediation and change evidence |
| Evidence and governance | How can the decision be defended later? | Auditability, accountability, and review history |

The product becomes more valuable as these modules share the same provenance,
identity, dependency, tenant, and evidence model. A collection of disconnected
features is not the same as an end-to-end platform.

## 6. Data and trust requirements

A cryptography-threat-intelligence system must protect the intelligence itself.
It should enforce:

- source provenance and licensing records;
- evidence hashes and immutable audit history where required;
- tenant isolation at request, ORM, storage, export, and event boundaries;
- no secrets, private keys, passwords, raw credentials, or key material in
  profiles, CBOMs, logs, or evidence artifacts;
- explicit confidence and uncertainty;
- clock, freshness, and expiry handling for intelligence;
- source conflict resolution without silently choosing a preferred fact;
- analyst review for high-impact detections and response actions;
- customer-controlled retention and deletion policies;
- least-privilege connector and telemetry access;
- deterministic re-evaluation when policy, standards, or threat context changes.

## 7. What is not promised

The roadmap does not promise that CryptoScan will:

- detect every attack or cryptographic misuse;
- observe private keys or encrypted content that the customer does not expose;
- replace a SIEM, SOC, HSM, KMS, PKI, EDR, SOAR, auditor, or regulator;
- determine legal compliance automatically;
- certify a product, algorithm, vendor, or customer estate;
- block a production action without customer control and authorization;
- infer PQC support from a vendor logo, marketing statement, or algorithm name;
- convert a CBOM into an automatic migration without engineering validation;
- make an unconfigured or unavailable source appear healthy.

## 8. Success measures for future releases

Each future capability should ship with measurable acceptance evidence:

### Intelligence quality

- source coverage and freshness;
- provenance completeness;
- duplicate and conflict handling;
- analyst agreement on relevance;
- false-positive and false-negative review;
- expiry and revocation of stale intelligence.

### Detection quality

- precision and recall on approved test cases;
- time to detect and time to triage;
- benign-change suppression;
- detection confidence calibration;
- performance and telemetry loss behavior;
- customer-approved severity and escalation mapping.

### Defence quality

- approval and authorization coverage;
- rollback success;
- change blast-radius validation;
- post-change verification;
- evidence completeness;
- no-secret and no-unauthorized-mutation tests.

### Commercial quality

- pilot acceptance rate;
- time from first scan to customer-approved finding;
- renewal and expansion;
- measurable analyst time saved;
- number of verified migration decisions;
- referenceability in the target sector.

A roadmap item is not complete because code exists. It is complete when the
capability has evidence, safety boundaries, customer validation, and a clear
operational owner.

## 9. External foundations

- [NIST approved FIPS 203, FIPS 204, and FIPS 205](https://www.nist.gov/news-events/news/2024/08/announcing-approval-three-federal-information-processing-standards-fips)
- [NIST PQC publications and status](https://csrc.nist.gov/Projects/post-quantum-cryptography/publications)
- [CISA quantum-readiness migration resource](https://www.cisa.gov/resources-tools/resources/quantum-readiness-migration-post-quantum-cryptography)
- [CISA automated cryptographic discovery and inventory strategy](https://www.cisa.gov/resources-tools/resources/strategy-migrating-automated-post-quantum-cryptography-discovery-and-inventory-tools)
- [NIST Cybersecurity Framework 2.0](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf)
- [OWASP CycloneDX / ECMA-424](https://owasp.org/projects/cyclonedx)
- [MarketsandMarkets threat-intelligence market estimate](https://www.prnewswire.com/news-releases/threat-intelligence-market-worth-22-97-billion-by-2030--marketsandmarkets-302540891.html)
