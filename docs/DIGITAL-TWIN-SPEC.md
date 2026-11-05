# The Digital Twin — product specification, and how this build measures against it

**Status:** specification, stored verbatim in structure and intent from the product brief.
**Conformance:** machine-readable at `shared_models/twin_spec.py`, served at
`GET /api/v1/estate/evidence/twin/spec-conformance`, asserted by
`shared/shared_models/tests/test_twin_spec.py`.
**Operational companion:** [guide 94 — CryptoScan Digital Twin](bank-environment/94-cryptoscan-digital-twin.md).

Every claim in §1–§12 has a row in §13 with a status (`SUPPORTED` / `PARTIAL` / `ABSENT`), the
file, symbol or route that proves it, and — where the build falls short — the gap in plain
words. A row may not be promoted without changing the code: the register is data, the test
resolves every proof, and editing a status alone fails the suite.

---

## 1. What is a Digital Twin?

In CryptoScan, a Digital Twin is an evidence-backed digital representation of a bank's entire
authorized technology and cryptographic estate.

It represents the real infrastructure in a connected digital model.

It is not just a dashboard, a graph visualization, a database or another Bill of Materials.

It is the central intelligence layer that understands:

- What assets exist.
- Where each asset exists.
- What software runs on each asset.
- Which applications depend on other applications.
- Which cryptographic algorithms and libraries are present.
- Which hardware supports cryptographic operations.
- Which network devices protect or connect systems.
- Which vendors supply products and services.
- Which certificates and keys are associated with assets.
- What evidence proves each fact and relationship.
- What changed over time.
- What will be affected if something changes.

The main purpose is to understand the entire estate, not just list its components.

## 2. Why does CryptoScan need a Digital Twin?

Imagine a bank has:

- 1000 applications.
- 500 servers.
- 100 databases.
- 20 HSMs.
- 50 load balancers.
- 200 network appliances.
- Thousands of certificates.
- Hundreds of software libraries.
- Multiple vendors.

The bank may have separate tools for software inventory, network monitoring, hardware
inventory, certificate management and security events.

But those tools do not necessarily understand how everything is connected.

For example: the bank knows it has an HSM called `HSM-01`, and it knows it has a Payment API.
But does it know:

- Does Payment API actually depend on HSM-01?
- Which application connects to it?
- Which cryptographic operation does it perform?
- Which vendor supplies the HSM?
- Which firmware version is installed?
- Which certificates or key references are associated with it?
- Which business systems will be affected if it becomes unavailable?
- Does its firmware support the bank's PQC migration requirements?

A conventional inventory might list these assets separately. The Digital Twin connects them
using evidence-backed relationships.

## 3. How the Digital Twin works

```
             REAL BANK INFRASTRUCTURE
                        |
       +----------------+----------------+
       |                |                |
    SOFTWARE         HARDWARE          NETWORK
       |                |                |
       +----------------+----------------+
                        |
                DISCOVERY COLLECTORS
                        |
                        v
                RAW OBSERVATIONS
                        |
                        v
                EVIDENCE VALIDATION
                        |
                        v
                   NORMALIZATION
                        |
                        v
               CANONICAL IDENTITY
                        |
                        v
                 RELATIONSHIP
                  CORRELATION
                        |
                        v
                 DIGITAL TWIN
                        |
       +----------------+----------------+
       |                |                |
     ASSETS        RELATIONSHIPS       HISTORY
       |                |                |
       +----------------+----------------+
                        |
              INTELLIGENCE ENGINE
                        |
       +----------------+----------------+
       |                |                |
      BOMs          PQC ANALYSIS       THREAT
                                      INTELLIGENCE
```

The Digital Twin is built from collected observations. It must not invent missing
relationships.

## 4. What does the Digital Twin contain?

Eight layers.

### Layer 1 — Estate model

The organisation and its infrastructure hierarchy:

```
BANK
 |
 +-- Region: UAE
 |     |
 |     +-- Data Center 01
 |     |      |
 |     |      +-- Production
 |     |      +-- UAT
 |     |      +-- DR
 |     |
 |     +-- Data Center 02
 |
 +-- Cloud Environment
        |
        +-- AWS
        +-- Azure
        +-- GCP
```

It must support organisations, regions, data centres, cloud environments, production/UAT/
development/DR, business systems, departments and owners.

Purpose: understand where assets belong and which organisational environment they belong to.

### Layer 2 — Asset model

| Category     | Asset examples                         |
| ------------ | -------------------------------------- |
| Software     | Packages, libraries, binaries          |
| Application  | Payment API, authentication service    |
| Compute      | Servers, VMs, containers               |
| Database     | PostgreSQL, Oracle, SQL Server         |
| Network      | Firewall, WAF, router, switch          |
| Cryptography | RSA, AES, certificates, keys metadata  |
| Hardware     | HSM, TPM, storage, security appliances |
| Cloud        | KMS, cloud instances, managed services |
| Container    | Images, pods, Kubernetes workloads     |
| Vendor       | Vendor, product, version, firmware     |
| PKI          | Root CA, intermediate CA, certificates |

Every asset needs a stable canonical identity:

```
ASSET-000192

Name: PAYMENT-API
Type: APPLICATION
Environment: PRODUCTION
Owner: Payments Team
System: Payments
Status: ACTIVE
First Seen: 2026-11-01
Last Seen: 2026-11-04
```

A stable ID matters because names can change, aliases can differ, and several assets can share
similar names.

### Layer 3 — Relationship model

A list of assets is not enough. The Digital Twin must understand how assets are connected.

```
PAYMENTS SYSTEM
      |
      v
PAYMENT API
      |
      +------ RUNS_ON ------> SERVER-01
      |
      +------ USES ---------> OPENSSL
      |
      +------ USES ---------> CERTIFICATE-01
      |
      +------ USES_HSM -----> HSM-01
      |
      +------ CONNECTS_TO --> DATABASE-01
```

| Relationship          | Meaning                                  |
| --------------------- | ---------------------------------------- |
| `CONTAINS`            | Contains another asset                   |
| `RUNS_ON`             | Application or process runs on a host    |
| `DEPENDS_ON`          | Depends on another asset                 |
| `USES_CRYPTO_LIBRARY` | Uses a cryptographic library             |
| `USES_ALGORITHM`      | Uses an algorithm                        |
| `USES_CERTIFICATE`    | Associated with a certificate            |
| `USES_HSM`            | Uses an HSM                              |
| `USES_KMS`            | Uses a KMS                               |
| `CONNECTS_TO`         | Communicates with another asset          |
| `ROUTES_TO`           | Network route to another asset           |
| `TERMINATES_TLS`      | Terminates a TLS connection              |
| `RE_ENCRYPTS`         | Establishes another encrypted connection |
| `HOSTED_ON`           | Hosted on an infrastructure asset        |
| `DEPLOYED_AS`         | Deployed as a specific artifact          |
| `PROVIDED_BY`         | Supplied by a vendor                     |
| `OWNED_BY`            | Has an identified owner                  |
| `SIGNED_BY`           | Signed by a certificate or key           |
| `BACKED_BY`           | Backed by another infrastructure asset   |

Every important relationship must carry:

```
relationship_id
source_asset_id
relationship_type
target_asset_id
evidence_id
evidence_type
collector
observed_at
confidence
first_seen
last_seen
status
```

Example:

```
PAYMENT-API
    |
    +-- USES_HSM --> HSM-01

Evidence:  EVID-9182
Source:    Approved application configuration
Status:    CONFIGURED
Confidence: Based on the available evidence
```

Important distinction: a configuration reference can prove that an HSM is configured, but it
does not necessarily prove that a cryptographic operation was executed against it.

### Layer 4 — Cryptographic graph

```
PAYMENT-API -> OPENSSL -> AES-256-GCM -> RUNTIME OBSERVATION
```

A separate network observation might establish:

```
LOAD-BALANCER -> TLS 1.3 -> AES-256-GCM -> X25519
```

The graph must preserve the distinction between: library capability, source-code reference,
configuration, actual runtime usage, and network-negotiated cryptography. An installed library
supporting an algorithm does not prove that the application uses it.

### Layer 5 — Evidence graph

```
PAYMENT-API
     |
     | USES_HSM
     |
    HSM-01
     |
     v
  EVIDENCE
     |
     +-- Evidence ID
     +-- Collector
     +-- Collector version
     +-- Timestamp
     +-- Source
     +-- Evidence type
     +-- Hash
     +-- Raw evidence reference
```

Evidence categories: `OBSERVED`, `STATIC_OBSERVED`, `RUNTIME_OBSERVED`, `NETWORK_OBSERVED`,
`CONFIGURED`, `IMPORTED`, `VENDOR_DECLARED`, `INFERRED`, `UNKNOWN`.

If evidence conflicts, the Digital Twin retains both facts and marks the conflict:

```
SBOM:      OpenSSL 3.0.13
Runtime:   OpenSSL 3.0.11
Container: OpenSSL 3.0.13
Twin status: VERSION_CONFLICT
```

It must not silently choose one version.

### Layer 6 — Time and historical twin

```
1 November  TLS 1.3 · AES-256-GCM · Certificate A      (previous state)
3 November  Certificate A replaced by Certificate B    (certificate changed)
4 November  TLS 1.2 · AES-128-GCM observed             (cryptographic regression candidate)
```

The twin retains previous state, current state, observation times, evidence references and the
reason for the change. Historical capabilities: first/last seen, relationship history,
certificate rotation history, software version changes, hardware and firmware changes,
algorithm changes, network configuration changes, vendor product revisions, collector coverage
changes, snapshot comparison and drift investigation.

A critical rule: an asset disappearing from an observation must not automatically be marked
physically removed. It may simply be unobservable because of a failed collector or changed
access.

### Layer 7 — Simulation twin

A simulation uses a copy of a known estate snapshot, applies hypothetical changes and
calculates the potential impact.

```
BASE SNAPSHOT -> Clone Digital Twin -> Apply hypothetical change -> RSA → ML-DSA
             -> Recalculate dependencies -> Find compatibility blockers -> Impact report
```

Possible results (illustrative, not measurements):

```
Affected applications: 18
Affected certificates: 42
Affected HSMs: 3
Affected load balancers: 5
Affected vendors: 4

Blockers:
- HSM firmware compatibility unknown
- Load balancer support not established
- Legacy application requires investigation
- Vendor migration timeline not confirmed
```

Other scenarios: HSM failure, KMS failure, certificate compromise, TLS downgrade,
cryptographic library vulnerability, vendor product compromise, network segmentation changes,
trust-path compromise, custom cryptographic changes.

The simulation must never modify the real bank environment.

### Layer 8 — Intelligence and impact layer

- Which applications depend on a vulnerable library?
- Which systems use a particular certificate?
- Which business systems depend on HSM-01?
- Which endpoints use deprecated TLS?
- Which assets may be affected by a vendor firmware issue?
- Which applications have unknown cryptographic usage?
- What changed before a suspicious network event?
- Which migration blockers affect critical systems?
- What is the potential blast radius of an asset change?

This is where Digital Twin information supports PQC analysis, cryptographic threat
intelligence, drift detection and future attack-pattern correlation.

## 5. How the six BOMs connect to the Digital Twin

The Digital Twin is the shared estate model. The six BOMs are projections of that model, not
six independent versions of reality.

```
                 EVIDENCE STORE
                       |
                       v
              CANONICAL ESTATE MODEL
                       |
                       v
                  DIGITAL TWIN
                       |
       +---------------+----------------+
       |               |                |
     SBOM            CBOM             HBOM
       +---------------+----------------+
       |               |                |
     NBOM            VBOM             TechBOM
                       |
                       v
              INTELLIGENCE SERVICES
                       |
        +--------------+---------------+
        |              |               |
       PQC           THREAT           DRIFT
       ANALYSIS      INTELLIGENCE     ANALYSIS
```

### Example: certificate changes

Suppose Certificate A is replaced with Certificate B. CryptoScan should:

1. Receive the new certificate observation.
2. Validate its evidence.
3. Resolve its identity.
4. Find the related endpoint and load balancer.
5. Update the Digital Twin's certificate relationship.
6. Preserve the previous relationship in history.
7. Update the affected CBOM and NBOM projections.
8. Evaluate relevant certificate policies.
9. Identify dependent applications.
10. Generate a change or drift event.

It should not rescan the entire bank or regenerate every unrelated BOM.

## 6. A complete real-world example: Payment API

```
BANK
 |
 +-- Payments System
       |
       +-- Payment API
       |     |
       |     +-- Java Application
       |     +-- OpenSSL / JCE
       |     +-- AES-256-GCM observation
       |     +-- Certificate A
       |
       +-- Server-01
       +-- Load Balancer-01  (TLS 1.3)
       +-- Database-01
       +-- HSM-01
       +-- Vendor-X
```

| Question                 | Digital Twin answer                                  |
| ------------------------ | ---------------------------------------------------- |
| Which business system?   | Payments                                             |
| Which application?       | Payment API                                          |
| Which software?          | Java and identified crypto libraries                 |
| Which cryptography?      | Only the algorithms established by evidence          |
| Which network endpoint?  | Observed payment endpoint                            |
| Which certificate?       | Certificate A                                        |
| Which hardware?          | Server-01 and HSM-01, if discovered                  |
| Which vendor?            | Vendor-X, if matched to evidence                     |
| Which owner?             | Payments Team, if registered or verified             |
| Which evidence?          | Evidence IDs linked to each fact                     |
| What changed?            | Historical comparison                                |
| What is the PQC blocker? | Any compatibility issue established or still unknown |

Four questions:

- **A: HSM-01 fails** — traverse the established dependencies to find affected applications and
  systems.
- **B: the payment certificate changes** — identify the endpoint, load balancer, associated
  applications and certificate relationships.
- **C: OpenSSL has a vulnerability** — find software and deployment dependencies, then affected
  processes and business systems where those links are established.
- **D: can this environment migrate to PQC?** — connect software support, cryptographic usage,
  hardware capability, network compatibility and vendor upgrade evidence to identify blockers.

## 7. How should we implement the Digital Twin technically?

Hybrid architecture:

- **PostgreSQL** — authoritative records: canonical assets, evidence metadata, observations,
  policies, snapshots, drift events, ownership, audit history.
- **Neo4j** — relationship graph: graph projections of assets, dependencies, network paths,
  cryptographic relationships and vendor relationships for traversal and impact analysis.
- **MinIO** — evidence objects: protected evidence artifacts, configuration exports and
  reports; PostgreSQL stores identifiers, hashes and metadata.
- **Redis** — caching, short-lived state, locks, coordination. Never permanent twin truth.

### Suggested Neo4j graph model

Nodes: `Organization`, `Region`, `DataCenter`, `Environment`, `BusinessSystem`, `Application`,
`Service`, `Host`, `Container`, `Package`, `Library`, `CryptoAsset`, `Certificate`, `HSM`,
`KMS`, `Hardware`, `NetworkDevice`, `NetworkEndpoint`, `Vendor`, `Product`, `Firmware`,
`Evidence`.

```
(:BusinessSystem)-[:CONTAINS]->(:Application)
(:Application)-[:RUNS_ON]->(:Host)
(:Application)-[:USES_CRYPTO_LIBRARY]->(:Library)
(:Library)-[:SUPPORTS]->(:CryptoAsset)
(:Application)-[:USES_CERTIFICATE]->(:Certificate)
(:Application)-[:USES_HSM]->(:HSM)
(:Application)-[:CONNECTS_TO]->(:NetworkEndpoint)
(:HSM)-[:PROVIDED_BY]->(:Vendor)
(:HSM)-[:RUNS_FIRMWARE]->(:Firmware)
(:Evidence)-[:SUPPORTS]->(:Relationship)
```

Only relationships supported by the controlled relationship vocabulary and evidence should be
created.

### Suggested PostgreSQL tables

```
assets                asset_aliases        asset_identifiers
relationships         evidence             observations
crypto_assets         certificates         snapshots
snapshot_assets       snapshot_relationships
drift_events          coverage_records     identity_resolutions
relationship_conflicts                     simulation_runs
simulation_results
```

**Critical architecture rule:** PostgreSQL and the evidence store remain authoritative. Neo4j
is a rebuildable graph projection; if the graph becomes inconsistent it must be reconstructible
from validated canonical records.

## 8. How the Digital Twin updates itself

1. **DISCOVER** — identify authorized targets and collect observations.
2. **VALIDATE** — check evidence integrity, scope and provenance.
3. **NORMALIZE** — convert observations into standard asset and fact representations.
4. **IDENTIFY** — resolve canonical asset identities and aliases.
5. **CORRELATE** — establish evidence-backed relationships.
6. **UPDATE** — apply valid changes to the canonical estate model.
7. **PROJECT** — update the graph and affected BOMs.
8. **SNAPSHOT** — preserve historical state.
9. **MONITOR** — compare future observations with the known state.
10. **ANALYZE** — evaluate drift, dependencies, PQC blockers and threat patterns.
11. **SIMULATE** — test hypothetical changes against a cloned snapshot.

### Asset lifecycle

```
FIRST_SEEN
    |
    v
ACTIVE
    |
    +----> CHANGED
    |         |
    |         v
    |      SUPERSEDED
    |
    +----> REMOVED
    |
    +----> UNKNOWN
```

`UNKNOWN` is particularly important: it means the platform cannot establish the current state.
It must not be treated as proof that the asset has disappeared.

## 9. Digital Twin UI — what should users see?

An enterprise cryptography intelligence investigation console, not an AI chatbot.

| Screen              | Purpose                                                   |
| ------------------- | --------------------------------------------------------- |
| Twin Overview       | Overall estate and coverage                               |
| Asset Explorer      | Search all discovered assets                              |
| Relationship Graph  | Explore dependencies                                      |
| Cryptographic Graph | Investigate algorithms, certificates and crypto providers |
| Network Topology    | View endpoints, paths and network relationships           |
| Hardware & HSM      | Investigate hardware and firmware                         |
| Vendor Dependencies | Connect vendors to products and deployments               |
| Evidence Explorer   | Understand why a fact or relationship exists              |
| Historical Twin     | Compare previous snapshots                                |
| Drift Analysis      | Investigate changes                                       |
| Blast Radius        | Identify affected systems                                 |
| Simulation Lab      | Test hypothetical changes                                 |
| PQC Impact          | Identify quantum migration blockers                       |

An asset investigation page displays: asset identity, owner, business system, environment,
host/container, software dependencies, cryptographic assets, certificates, network endpoints,
HSM/KMS dependencies, vendor dependencies, historical changes, evidence records, collection
coverage, PQC migration impact.

The most important UI action is: **"Why does CryptoScan believe this relationship exists?"** —
select an edge in the graph and open the underlying evidence.

## 10. What the Digital Twin cannot guarantee

It cannot:

- Automatically discover assets outside its authorized visibility.
- Guarantee every relationship is known.
- Prove an application uses an algorithm merely because a library supports it.
- Know an HSM's internal operations without suitable evidence.
- Inspect every IoT sensor or proprietary device.
- Reconstruct encrypted payloads it cannot legitimately observe.
- Guarantee an attack is detected just because the estate is modeled.
- Guarantee PQC compatibility based only on algorithm inventory.

It must expose: asset coverage, relationship coverage, evidence coverage, runtime visibility,
network visibility, hardware visibility, unknown relationships, unresolved conflicts and
collection failures.

Do not confuse Digital Twin completeness with PQC readiness or security posture.

## 11. Implementation priorities

| Priority | Work                                | Objective                                       |
| -------- | ----------------------------------- | ----------------------------------------------- |
| P0       | Canonical asset identity            | Prevent duplicate and incorrectly merged assets |
| P0       | Evidence-backed relationship model  | Prevent guessed dependencies                    |
| P0       | PostgreSQL canonical model          | Establish authoritative records                 |
| P0       | Graph projection                    | Enable relationship traversal                   |
| P0       | Coverage and UNKNOWN semantics      | Prevent false completeness                      |
| P1       | Cross-BOM correlation               | Connect all six BOMs                            |
| P1       | Historical snapshots and drift      | Track estate changes                            |
| P1       | Evidence explorer                   | Make every important claim auditable            |
| P1       | Blast-radius analysis               | Identify affected systems                       |
| P2       | PQC impact analysis                 | Find migration blockers                         |
| P2       | Threat-pattern correlation          | Add cryptography-aware threat intelligence      |
| P2       | Simulation engine                   | Evaluate hypothetical changes                   |
| P3       | Scale and performance qualification | Support large enterprise estates                |

## 12. The most important design decision

Do not make the Digital Twin another scanner or another independent database.

```
REAL BANK ESTATE -> COLLECTORS -> OBSERVATIONS -> VALIDATED EVIDENCE
   -> CANONICAL ASSET IDENTITY -> DIGITAL TWIN
        +-> RELATIONSHIPS / HISTORY / CRYPTO GRAPH
                +-> BOMs / PQC ANALYSIS / THREAT INTELLIGENCE
                        +-> SIMULATION & IMPACT ANALYSIS
```

---

## 13. Conformance in this build

Generated from `shared_models/twin_spec.py`; `GET /api/v1/estate/evidence/twin/spec-conformance`
returns the same rows. Statuses: **SUPPORTED** (implemented, proof in the tree),
**PARTIAL** (core exists, stated gap is real), **ABSENT** (not implemented, listed so a pilot
does not find it first).

### 13.1 The twelve sections

| § | Section | Status | Proof | Gap |
|---|---|---|---|---|
| 1 | What the twin is | SUPPORTED | `estate_twin.TWIN_SCHEMA`, `GET …/twin` | — |
| 2 | Why the estate needs one | SUPPORTED | `estate_graph.RELATIONSHIP_PREDICATES` | — |
| 3 | Observation → twin → intelligence | SUPPORTED | `estate_graph.build_graph`, `estate_twin.snapshot` | — |
| 4 | The eight layers | PARTIAL | `estate_twin.placement_model` | layer 7's expression language is bounded: no arithmetic, joins or temporal operators |
| 5 | Six BOMs are projections | SUPPORTED | `estate_graph.BOM_KINDS`, `…/boms/{kind}/export` | — |
| 6 | Payment-API walkthrough | SUPPORTED | `bank-environment/05-practical-bank-walkthrough.md`, `GET …/twin/why` | — |
| 7 | Hybrid storage | PARTIAL | `EstateAssetRecord`, `estate_twin.graph_export` / `SPEC_GRAPH_LABELS`, `services/api/api/estate_graph_loader.py` | all 22 specification labels are emitted (asset types, evidence types, four placement levels); the legacy `cypher_writes.py` projection is a narrower eight-label schema; evidence objects stay in PostgreSQL, no MinIO tier, no Redis dependency |
| 8 | Update lifecycle and asset states | SUPPORTED | `cbom_dependency.LIFECYCLE_STATES`, `transition_asset_lifecycle` | — |
| 9 | Thirteen screens | PARTIAL | `DigitalTwin.tsx`, `EstateTwin.tsx` | all thirteen investigations exist, but not as thirteen routes; an edge answers "why" from the asset investigation, not from the drawn graph |
| 10 | What the twin cannot guarantee | SUPPORTED | `GET …/twin/completeness`, `GET …/twin/why` | — |
| 11 | P0–P3 priorities | SUPPORTED | guide 94, "Status in this repository" | — |
| 12 | Not another scanner or database | SUPPORTED | `estate_twin.graph_from_snapshot` | — |

### 13.2 The eight layers

| Layer | Status | Where it lives | Note |
|---|---|---|---|
| 1 Estate model | SUPPORTED | `ESTATE_LEVELS`, `GET …/twin/placement` | BANK → ORGANIZATION → DEPARTMENT → REGION → DATA_CENTER → CLOUD_ENVIRONMENT → ENVIRONMENT → BUSINESS_SYSTEM, each from an asserted attribute only |
| 2 Asset model | SUPPORTED | `ASSET_TYPES` (32), `EstateAssetRecord` | includes root/intermediate CA, HSM, KMS key, firmware, product; canonical id with aliases |
| 3 Relationship model | SUPPORTED | `RELATIONSHIP_PREDICATES` (32), `RELATIONSHIP_BASES` | the specification's 18 names all map (see 13.3); every edge carries basis, evidence type, `observed_at`, confidence, lifecycle |
| 4 Cryptographic graph | SUPPORTED | `GET …/twin/crypto-graph`, `cbom.facts` | capability / source / configuration / runtime / network-negotiated are distinct fact classes |
| 5 Evidence graph | SUPPORTED | `GET …/twin/why`, `EstateRelationshipRecord` | contradiction stored as conflict, both sides kept |
| 6 Time | SUPPORTED | `GET …/twin/snapshots`, `…/twin/compare` | snapshot, replay, compare, journal; a vanished asset is a coverage event before a removal |
| 7 Simulation | PARTIAL | `SIMULATION_KINDS`, `POST …/twin/simulate` | 8 fact scenarios (incl. CUSTOM, a validated expression) + 3 cascades on a copy; no arithmetic/joins, no segmentation model |
| 8 Intelligence & impact | SUPPORTED | `POST …/twin/impact`, `attack_patterns.correlate` | blast radius, blockers, correlation that refuses to declare an incident |

### 13.3 Relationship vocabulary

All eighteen specification names resolve to a build predicate — `CONTAINS`→`contains`,
`RUNS_ON`→`runs_on`, `DEPENDS_ON`→`depends_on`, `USES_CRYPTO_LIBRARY`→`uses_crypto_library`,
`USES_ALGORITHM`→`uses_algorithm`, `USES_CERTIFICATE`→`uses_certificate`, `USES_HSM`→`uses_hsm`,
`USES_KMS`→`uses_kms`, `CONNECTS_TO`→`connects_to`, `ROUTES_TO`→`routes_to`,
`TERMINATES_TLS`→`terminates_tls_for`, `RE_ENCRYPTS`→`re_encrypts`, `HOSTED_ON`→`hosted_on`,
`DEPLOYED_AS`→`deployed_as`, `PROVIDED_BY`→`provided_by`, `OWNED_BY`→`owned_by`,
`SIGNED_BY`→`signed_by`, `BACKED_BY`→`backs_with`. The build adds fourteen more
(`issued_by`, `verified_by`, `protected_by`, `exposes`, `encrypts_with`, `signs_with`,
`authenticates_with`, `passthrough`, `managed_by`, `manages`, `uses`, `uses_key`, `part_of`,
`built_from`) because the certificates, KMS and TLS paths need them.

### 13.4 The thirteen screens

| Screen | Route | Component |
|---|---|---|
| Twin Overview | `/digital-twin` | `DigitalTwin.tsx` |
| Asset Explorer | `/assets` | `Assets.tsx` |
| Relationship Graph | `/graph` | `Graph.tsx` |
| Cryptographic Graph | `/crypto` | `Crypto.tsx` |
| Network Topology | `/network` | `Network.tsx` |
| Hardware & HSM | `/hardware` | `Hardware.tsx` |
| Vendor Dependencies | `/vendor` | `Vendor.tsx` |
| Evidence Explorer | `/evidence` | `Evidence.tsx` |
| Historical Twin | `/estate-twin` | `EstateTwin.tsx` |
| Drift Analysis | `/drift` | `Drift.tsx` |
| Blast Radius | `/what-if` | `WhatIf.tsx` |
| Simulation Lab | `/simulation` | `Simulation.tsx` |
| PQC Impact | `/pqc` | `Pqc.tsx` |

## 14. What was missing, and what this change built

The audit produced four gaps (§13, rows marked PARTIAL). Three are deliberate boundaries with
a stated cost; one was a genuine omission and is now built.

**Built — Layer 1, the organisation chart.** The twin placed assets under region, data centre,
cloud account, environment and business system, but had no ORGANIZATION or DEPARTMENT level, so
a bank with several legal entities could not see "this asset belongs to Bank UAE PJSC, Payments
department, owned by Payments Team" in the placement model. Both levels now exist
(`ESTATE_LEVELS`), are derived only from asserted attributes, and are reported the same way as
every other level: an asset whose evidence asserts no organisation is counted under
`unassigned.ORGANIZATION` **with the reason** ("the bank is not read downward into its
subsidiaries"), never attached to a guessed parent. `GET …/twin/placement` now returns
`organizations[]` (with departments and environments) and `departments[]` (with organisation,
owners, environments and asset counts), and the placement model version moved to
`cryptoscan.estate-placement/3`.

**Built — Layer 7, the custom scenario (`CUSTOM`).** The seven built-in kinds answer the seven
questions the product anticipated; a bank always has an eighth. A scenario can now be
*operator-authored as data*:

```json
{"when": {"all": [{"fact": "algorithm", "op": "eq", "value": "RSA"},
                  {"fact": "usage_state", "op": "ne", "value": "SUPPORTED"}]},
 "then": {"set": {"algorithm": "ML-DSA-65", "key_size": 3300}}}
```

Six operators (`eq`, `ne`, `in`, `contains`, `present`, `absent`), three combinators (`all`,
`any`, `not`), eight conditions, eight assignments, depth three — and three refusals that are
the point of the feature:

* **provenance is not writable.** `evidence_id`, `source`, `collector`, `evidence_type`,
  `observed_at` and the hash are refused with `REFUSED_PROVENANCE_WRITE`: a simulation may
  change what the estate *says*, never who said it.
* **nothing is computed.** No arithmetic, aggregation, cross-record join or clock. A scenario
  that needs one is refused rather than answered with a number no collector produced.
* **a no-op is not an effect.** An assignment whose value is already there does not count as a
  change, so a "before/after" contains only real differences.

It runs on the same copy as every other scenario (the live projection id is asserted
unchanged), and the enterprise assessment moved `CUSTOM_SCENARIO` from `ABSENT` to `PARTIAL`
with its remaining limits stated.

**Built — §7's graph labels, all 22 of them.** The twin's export emitted asset nodes and
evidence nodes, and kept the organisation chart on asset properties. §7 asks for `Organization`,
`Region`, `DataCenter` and `Environment` as *nodes* — a data centre is a thing a bank's graph asks
about ("what runs in UAE DC1"), and a string property answers it one asset at a time. All four are
now nodes in the export, joined to their assets with `CONTAINS` and to each other with `PART_OF`,
and derived from asserted attributes only: a level nothing asserts has **no node**, so an empty
chart reads as a collection gap rather than as a flat bank.

The mapping is data, not prose — `SPEC_GRAPH_LABELS` maps each of the specification's 22 names to
the label(s) this build emits, and `graph_label_coverage()` is served in every export and pinned by
a test. Where the names differ, the mapping says so instead of emitting a second spelling:
`BusinessSystem` is the `SYSTEM` asset type, `KMS` is `KMS_KEY`, `NetworkDevice` is
`FIREWALL`/`LOAD_BALANCER`/`VPN`. The loader writes each family under its own label
(`EstatePlacement` for the chart, alongside `EstateAsset` and `EstateEvidence`) with the kind label
validated against the vocabulary, so a placement node can never arrive as an untyped asset.

**Built — `COMPOSITE`, an ordered sequence of changes (`COMPOSITE`).** A migration is rarely one
edit: "retire TLS 1.0, then replace RSA on what is left, then resize the surviving keys" is three
scenarios, and running them separately leaves the operator reconciling three BOM diffs computed
against three different estates. `COMPOSITE` takes up to five primitive scenarios, applies them to
**one** copy in the order given, and reports the BOM diff of the whole sequence:

```json
{"kind": "COMPOSITE", "steps": [
  {"kind": "DISABLE_PROTOCOL", "from": "TLSv1.0"},
  {"kind": "MIGRATE_QUANTUM_VULNERABLE", "to": "ML-KEM-768", "key_size": 1184}]}
```

Each step is reported with the evidence it matched, and every effect carries its step number, so a
reviewer can see *when* a record changed rather than only that it did. A step that matches nothing
is reported and does not abort the sequence — that is a fact about the estate, not an error — while
a sequence in which no step matches anything is `NO_MATCH`, never "no impact".

Four refusals keep this from becoming a scripting language: an empty sequence, more than five
steps, a cascade or another `COMPOSITE` as a step, and a step that is not one of the primitive
kinds. Branching, loops and a clock are absent by design; a sequence with a condition between its
steps is refused rather than approximated. The preview is honest about its own limit — steps are
previewed independently against the evidence as it stands, so the run can match more than the
preview counted, and the payload says so in the answer rather than in a footnote.

**Built — the trust-path cascade (`CASCADE_TRUST_COMPROMISE`).** `TRUST_COMPROMISE` was the last
scenario with no model at all. The reason given for that was partly wrong: the twin does not
hold trust-store membership, but it does hold *vouching* edges — `issued_by`, `signed_by`,
`verified_by`, `uses_certificate`, `terminates_tls_for` — and those are enough to walk what an
issuer vouches for. The fourth cascade carries a compromise over exactly that carrier set:

```
Bank Root CA  --issued_by-->  Bank Issuing CA  --issued_by-->  payments.bank:443
                                                                     |
                                                      uses_certificate
                                                                     v
                                                                Payment API
```

A sibling application on the same host is **not** reached, because `runs_on` is not a vouching
edge — which is the whole difference between this cascade and `CASCADE_CRYPTO_COMPROMISE`, whose
carrier set is the crypto and containment edges. The answer states four blind spots rather than
assuming them away: trust-store membership (a host trusting a root the twin never collected is
invisible, so where the walk stops is a collection gap), cross-signing and alternate chains,
revocation (CRL/OCSP publication, propagation delay, soft-fail), and name constraints or
pinning — which is why the radius is published as a *superset* of a correct PKI walk, never as
one. `TRUST_COMPROMISE` moves from `ABSENT` to `PARTIAL`; all ten registered scenarios now have
a model, nine of them partial.

**Built — §9's most important action, for an edge.** The asset investigation lists each edge as
a button: selecting one asks `GET …/twin/why` about *that* subject/predicate/object and renders
the answer inline — evidence type, collector, source, timestamp and hash — or the reason the
edge was refused. Previously "why" was reachable per asset and as a route, but no edge could be
selected.

**Not built, and why.** (1) A MinIO evidence tier and a Redis dependency — evidence objects are
content-addressed rows in PostgreSQL; adding two stateful services to a bank deployment to hold
what is already hash-chained is a decision for the deployment, not a gap in the model.
(2) Re-pointing the legacy `cypher_writes` projection at the new export — it is a separate,
narrower schema used by the older dashboards; the twin's loader is the supported path and the
legacy builder is left alone rather than half-migrated. (3) Cross-record expressions and time-ordered migration windows — an expression reads one
record's facts, and a `COMPOSITE` sequence has an order but no clock; a scheduler and a query
engine would each let a scenario produce a value no evidence holds.

## Sources

The brief that became this document carried decorative marketplace/blog illustrations
(Linkurious, WanAware, Neo4j/SAP, yFiles, AWS Marketplace, BISO, Frenos, MinIO, Redis,
PostgreSQL and TOPpng logos). They are referenced, not embedded: none of them is a contract,
and a stale image URL in a specification is worse than a citation. The substantive sources for
the architecture are the ones this repository already keeps: guide 94 (the operational twin),
`docs/architecture/graph-data-model.md` (the graph model), and
`docs/bank-environment/04-six-boms.md` (the BOM projections).
