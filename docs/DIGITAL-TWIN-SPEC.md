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
  reports; PostgreSQL stores identifiers, hashes and metadata. Built as a sink rather than a
  dependency: `services/api/api/estate_evidence_objects.py` writes a record to a filesystem
  directory or to an S3-compatible bucket (MinIO included) under its content address.
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
| 7 | Hybrid storage | PARTIAL | `EstateAssetRecord`, `estate_twin.graph_export` / `SPEC_GRAPH_LABELS`, `services/api/api/estate_graph_loader.py`, `services/api/api/estate_evidence_objects.py` | all 22 specification labels are emitted (asset types, evidence types, four placement levels); evidence objects have a content-addressed filesystem/S3 (MinIO) tier behind `GET/POST …/twin/artifacts`; the legacy `cypher_writes.py` projection is a narrower eight-label schema, the sink is off until `EVIDENCE_OBJECT_DIR` or `EVIDENCE_OBJECT_S3_BUCKET` names a store, and there is no Redis dependency |
| 8 | Update lifecycle and asset states | SUPPORTED | `cbom_dependency.LIFECYCLE_STATES`, `transition_asset_lifecycle` | — |
| 9 | Thirteen screens | SUPPORTED | `TwinWalkthrough.tsx` / `/twin-walkthrough`, `TwinGraphCanvas.tsx`, `TwinEdgeExplorer.tsx`, `DigitalTwin.tsx` | in the specification's order as thirteen routes **and** as one walkthrough canvas that carries a single asset through all thirteen; the "why" action exists per step, per edge in the list, and on a **drawn canvas of the twin's own export** where a line is selectable. `/graph` still draws the legacy eight-label projection for the older dashboards |
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

The thirteen also run as **one walkthrough** at `/twin-walkthrough` (`TwinWalkthrough.tsx`): pick an
asset, then step through all thirteen investigations in the order above. Each step reads the same
twin endpoints the full screen reads and prints what it could not read as a failed read — a panel of
zeros over an unread twin is a claim about an estate nobody looked at. It summarises; it does not
replace the screens, and every step links to its own.

Step 3 carries **a drawn canvas of the twin's own graph** (`TwinGraphCanvas.tsx`): the export's nodes
in the specification's layers (organisation → region → data centre → environment → assets →
evidence), each line a relationship the twin holds, and selecting one asks `GET …/twin/why` about
that subject/predicate/object — the evidence, or the refusal. The layout is deterministic, so the
same projection draws the same picture twice; refused candidates are counted rather than drawn; and
the node cap is stated on the canvas, because a drawing that silently drops nodes reads as a
complete estate.

## 14. What was missing, and what this change built

The audit produced four gaps (§13, rows marked PARTIAL). Three are deliberate boundaries with
a stated cost; one was a genuine omission and is now built. Each gap has since been closed where it
was closeable — the register is the record, not this paragraph.

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

**Built — §9's edge-first explorer, on the canvas.** The Relationship Graph now carries an
*edge-first* panel over the twin's own export: the edge list is the twin's relationships (canonical
asset ids, the twin's predicate vocabulary), and selecting one asks `GET …/twin/why` about exactly
that subject/predicate/object. The answer is the evidence — type, collector, source, timestamp and
hash, per record — or the refusal, and the two are never blended: "nothing was returned" is printed
as *that is not "no evidence exists"*. Refused candidates are counted where they are not drawn, and
a failed read of the export says the export is unavailable rather than rendering an empty graph.

It reads the twin's export rather than the legacy `/api/v1/graph` projection on purpose: that graph
is a separate, narrower schema, and asking the twin about its ids would answer `UNKNOWN_ASSET` for
every edge a reader clicked — a refusal that looks like a finding.

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

**Built — §7's object store, as a tier with an honest "off".** Evidence objects were content
hashes in PostgreSQL and nothing else, which made §7's MinIO line a deployment intention. There is
now a real object tier: `canonical_bytes` and `content_address` key a record by the sha256 of what
it *asserts*, `store` writes it once under `ab/cd/<digest>.json` to either a filesystem directory or
an S3-compatible bucket (MinIO's API is S3), and `fetch` re-hashes what comes back and refuses an
address whose content changed. Two properties are deliberate. The address excludes `observed_at`
when it is the build clock — the same exclusion `EstateGraph.fingerprint` already documents,
because hashing the clock would give the same stored discovery a new address on every read; the
value is still archived inside the object and the wrapper names the exclusion. And a write never
overwrites: filesystem uses `O_EXCL`, S3 is signed with `If-None-Match: *`, so the second store of
the same record reports `already_stored` and leaves the first object alone.

The sink is configured, not assumed: `EVIDENCE_OBJECT_DIR`, else `EVIDENCE_OBJECT_S3_*` (reusing
`ANCHOR_EXPORT_S3_*` when those are the ones set). With neither, `GET …/twin/artifacts` says the
tier is unconfigured and `POST` refuses with 409 — because "no artefact exists" and "no tier is
configured" are different answers and only one of them is about the evidence. Reads of an address
nothing stored return 404 `not_stored` with the same wording. `POST` archives the record the twin
already holds, named by `evidence_id`, never a body the caller supplies: an archive that stores
whatever it is sent is an upload endpoint with an evidence endpoint's name.

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

**Built — the thirteen-screen walkthrough, on one canvas.** Thirteen screens existed and no
walkthrough did: an investigator who wanted an asset's history, its drift, its blast radius and its
PQC exposure read three screens and remembered the id. `/twin-walkthrough` is the specification's
canvas — one selected asset, thirteen steps in the specification's order, each step answered from
the twin's own endpoints (asset view, overview and coverage, the change feed, crypto intel) and each
step linking to the full screen it summarises.

The honesty rules are the substance. A failed read prints the failure (`that is not 'the estate
holds nothing'`), never a zero. A relationship family with no members prints a gap in the *twin's
evidence* — "the twin records no HSM relationship" — not a property of the estate, because an
application can use crypto without a key store the estate can see. A truncated blast radius says it
was truncated. And nothing on the canvas writes: the simulation step shows the facts a scenario
would read and hands the run to `/simulation`, where the copy-and-project contract lives, because a
walkthrough that quietly ran a scenario against the live twin would be the one thing §7 forbids.

**Built — §9's most important action, for an edge.** The asset investigation lists each edge as
a button: selecting one asks `GET …/twin/why` about *that* subject/predicate/object and renders
the answer inline — evidence type, collector, source, timestamp and hash — or the reason the
edge was refused. Previously "why" was reachable per asset and as a route, but no edge could be
selected.

**Built — a coverage denominator the bank declares, and the disagreement it exposes.** Every
coverage number this platform could print before answered a *different* question: attempted against
planned, **per collector**. "NETWORK 12/12 COMPLETE" says nothing about whether the bank's 120 servers
were found, and §4's own table — *Servers 118/120, HSMs 7/8* — cannot be computed from a collector run
at all. The denominator is the bank's, so it is declared, and `POST …/twin/ground-truth` measures the
estate against it. Nothing is stored: a stored declaration that later drifted would read as the
platform's own baseline, and it is the bank's claim, not ours.

Three refusals shape the output. A class with no declared count prints **no percentage** — 0% and
100% would both be invented. Finding nine HSMs against eight declared is `OVER_DECLARED`, a
disagreement to resolve (a stale declaration, or identity resolution splitting one asset into two),
never "112% coverage". And a declared class the estate cannot see is `EMPTY` — a collection gap, not
an empty estate.

The same route answers §11's second half: accuracy **per claim type** rather than one score.
`ASSET_PRESENCE`, `RELATIONSHIP`, `ALGORITHM_USE`, `KEY_SIZE`, `CERTIFICATE` and `OWNERSHIP` are
checked separately, each claim landing as `MATCHED`, `CONTRADICTED` (the estate holds the thing and
disagrees about the value), `MISSING_FROM_ESTATE` (the estate does not hold it — a collection gap or
a stale declaration, and this cannot tell which) or `NOT_CHECKABLE` (the estate cannot answer the
question, which is reported rather than skipped). A capability list never satisfies a claim about use;
a key size nobody recorded is `NOT_CHECKABLE`, not a pass; and a relationship the graph *refused* is
`CONTRADICTED` with the refusal reason, because the reason is the finding.

What it will not report is precision. Precision would need to know whether the estate's **undeclared**
findings are wrong, and a bank not having declared an asset is not evidence that the asset does not
exist — an estate finding something the declaration never mentioned is usually the platform working.
Only agreement over the declared sample is computable, and that is what it computes, labelled
`DECLARED_SAMPLE_ONLY`.

**Built — the protocol floor, answered from observed handshakes.** §9's Network Topology screen
lists endpoints and paths; it could not answer the question the list exists for: "if we only accepted
TLS 1.2 from Friday, what is already below it?" `GET …/twin/protocol-floor?floor=` ranks every
negotiated protocol the estate has observed against a requested floor and publishes four separate
buckets — below the floor, at the floor, above it, and **unrecognised** (a protocol value this build
cannot place on the ladder, which is reported as such and never as compliance). Assets with no
handshake evidence are counted in their own bucket too, because an asset nobody probed is not a
compliant one.

It is a `GET`, a check and not a scenario: no copy is made, no BOM is re-projected, nothing is
stored, and `live_state_modified` is false by construction. The check sits on step 5 of the
walkthrough, under the endpoints it is about.

The second half is **declared**, and it is deliberately a separate object with its own basis label.
A TLS configuration file says what a service *may* negotiate; a handshake says what it *did*. The
host collector has read `ssl_protocols` / `ssl_ciphers` for some time and filed the result as a
`TLS_CONFIGURATION` fact with `local_basis="DECLARED"` — but that fact never left the host BOM, so
"which declarations still permit TLS 1.0?" was unanswerable in the negative and silently answerable
in the positive. A twelfth discovery plane (`HOST`) now joins stored host snapshot imports into the
estate as `CONFIGURED` evidence, and the floor check reports, beside the observed bucket:

- **declares below floor** — a configuration that still lists a protocol weaker than the floor;
- **declared ceiling below floor** — an asset that cannot reach the floor at all, listed with the
  edges it would strand. `edges: []` prints as *"nothing recorded on either side of it"*, never as
  "nothing would break", because an absence of records is not an absence of risk;
- **declared without a rankable floor** — a declared protocol this build cannot rank, which is a
  finding, not a pass;
- **partly parsed** — a configuration with directives the collector could not follow. That fact was
  being dropped at the finding boundary (`configured_directives_unparsed` is now carried), and a
  half-read config that reads as complete is the same error as a zero that means "failed".

**Built — the client side of the handshake: what clients actually offer.** The blind spot this
section led with was runtime client acceptance — a declaration says what a config allows, but what a
client puts on the wire was not evidence this estate collected. It now is. A bounded inbound probe
binds one approved numeric endpoint and records the ClientHellos that arrive (`NETWORK_TLS_CLIENT_OFFER`,
sealed like every other probe fact, with `handshake_completed` a sealed `False` — the probe sends no
ServerHello), and sensors can submit the same observations through
`POST /network/crypto-client-offers` under the passive path's fail-closed rule: anything that looks
like captured content refuses the whole batch.

Three rules keep the axis honest. **An offer is never a negotiation** — the records carry
`handshake_role: CLIENT_HELLO_OFFER` and no `tls_version`, so they cannot satisfy a floor's measured
bucket; the client axis reports them under `basis: OBSERVED` and the status names the basis
(`BELOW_FLOOR_OFFERED`). **A value the parser cannot name is echoed as its codepoint**, GREASE decoys
(RFC 8701) are dropped with a count rather than treated as offers, and an offer whose versions are
all GREASE is refused, not filed. **A client the estate knows exists and has never been seen
offering anything is published as unseen** — it holds a client-predicate edge (`connects_to`,
`routes_to`, `depends_on`) and no offer record — and unseen is printed as unseen, never as compliant.

The estate keys a client by its address, not its ephemeral port: two connections from one client are
one asset with two offer records, never two assets.

**Built — the negotiated field, read where collectors actually put it.** Real network evidence
records the negotiated version in `tls_version` beside a family-level `protocol: "TLS"`; ranking only
`protocol` read that shape as an unrankable spelling and reported a TLSv1.0 endpoint as *at or above
the floor* — the exact "I do not know this value" ≠ "this is fine" failure. The floor now ranks the
version-bearing field (and records which field it read on each entry), and a record that states two
different negotiated versions is published under `conflicts` with both values, neither ranked. A
status was added for the case the old ladder misread outright: when protocol evidence exists but
nothing in it can be ranked, the status is `UNRANKED_EVIDENCE_ONLY`, never `AT_OR_ABOVE_FLOOR`.

`blind_spots` now leads with what is *still* unseen: clients that never connect to an approved offer
probe, and an estate that cannot enumerate its client population cannot list what it has never seen.

**Built — a migration ordered across time, from stored evidence.** A migration is not only a
sequence, it is a sequence spread over readings: "retire TLS 1.0 on what the estate showed in Q2,
then replace RSA on what survives". `COMPOSITE` now lets a step name a stored twin snapshot with
`as_of`. The step is *matched* against the evidence that snapshot recorded — the facts the plan was
written against — and the change is applied to the copy of the estate as it stands now, so a record
that has since left the estate is counted as `not_in_current_estate` and is never resurrected into
the copy. Each step reports `evaluated_against_snapshot`, `evidence_in_snapshot` and
`not_in_current_estate`, and a step that matches only records the estate has since dropped says
exactly that: the plan still describes the snapshot, it no longer describes today.

There is still no clock, and the refusal is the point. `as_of` takes a *stored snapshot id*; a
date, an integer, or an id this tenant never captured is refused (`UNKNOWN_SNAPSHOT`) rather than
quietly evaluated against today — a run that silently ignored an unresolvable `as_of` would answer a
different question than the one that was asked, which is the most expensive way to be wrong. The API
resolves the snapshots (the engine never learns about the database), the preview counts each step
against the evidence it reads, and the workspace lists the ids this tenant actually holds so a step
can name one instead of guessing.

**Not built, and why.** (1) A Redis dependency, and switching the object tier on — the MinIO/S3 tier itself
now exists (`estate_evidence_objects`, served at `…/twin/artifacts`), but no environment in this
repository names a bucket or a directory for it, so it reports itself unconfigured rather than
pretending to store; Redis stays a deployment decision, since nothing in the twin needs a cache it
can rebuild.
(2) Re-pointing the legacy `cypher_writes` projection at the new export: `/graph` still draws the
separate narrower eight-label schema used by the older dashboards, so a line there opens the legacy
view. The twin now has a drawn canvas of its own (`TwinGraphCanvas`, step 3 of the walkthrough) whose
lines ask the twin, which is why the legacy builder is left alone rather than half-migrated — two
drawn graphs is a migration decision, not a missing capability.
(3) Cross-record expressions — an expression reads one record's facts, so it cannot compute a value
from another asset, another record or the clock. Time *is* modelled, but as evidence rather than as
a clock: a `COMPOSITE` step may carry `as_of` with a **stored snapshot** id, and the step is then
matched against the evidence that snapshot recorded while its change lands on the estate as it stands
(see §14's paragraph). A date is refused, because a date is not evidence.

## Sources

The brief that became this document carried decorative marketplace/blog illustrations
(Linkurious, WanAware, Neo4j/SAP, yFiles, AWS Marketplace, BISO, Frenos, MinIO, Redis,
PostgreSQL and TOPpng logos). They are referenced, not embedded: none of them is a contract,
and a stale image URL in a specification is worse than a citation. The substantive sources for
the architecture are the ones this repository already keeps: guide 94 (the operational twin),
`docs/architecture/graph-data-model.md` (the graph model), and
`docs/bank-environment/04-six-boms.md` (the BOM projections).
