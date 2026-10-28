# 94 — CryptoScan Digital Twin

Status: **specification, in progress**. Supersedes nothing; extends
[93](93-estate-evidence-graph-and-six-bom-projections.md). The six BOMs remain
projections — the Digital Twin is the correlated model they are projected from.

> **What a Digital Twin is here:** not a 3D visualisation. It is a
> machine-readable model of the bank's technology estate — assets,
> cryptographic assets, infrastructure, network paths, software dependencies,
> hardware, vendors, certificates, HSM/KMS relationships, ownership,
> configuration, runtime observations and historical change — where **every
> important fact traces back to evidence**.

The pipeline it completes:

```
Real Bank Estate → Collectors → Evidence → Canonical Estate Graph → Digital Twin
      → Six BOMs + Crypto Intelligence + PQC + Drift + Simulation
```

The twin represents:

```
Bank
 ├── Business/System
 ├── Applications
 ├── Software
 ├── Dependencies
 ├── Hosts
 ├── Containers
 ├── Kubernetes
 ├── Network
 ├── Load Balancers
 ├── API Gateways
 ├── Databases
 ├── HSMs
 ├── KMS
 ├── PKI
 ├── Certificates
 ├── Hardware
 ├── Vendors
 ├── Crypto algorithms
 ├── Keys/key metadata
 └── Crypto relationships
```

But unlike a normal CMDB:

```
CMDB:          "Server-123 exists."

CryptoScan:    Server-123
                 ├── runs Payment API
                 ├── runs OpenSSL 3.x
                 ├── connects to LB-07
                 ├── negotiates TLS 1.3
                 ├── uses certificate CERT-982
                 ├── references HSM-03
                 ├── depends on PostgreSQL
                 ├── belongs to Payment System
                 ├── owned by Payments Platform
                 └── has evidence EVID-1234...
```

---

## 1. Architecture

```
                         BANK ENVIRONMENT
                              │
         ┌────────────────────┼─────────────────────┐
         │                    │                     │
       Static              Runtime               Network
      Discovery            Discovery             Discovery
         │                    │                     │
         ├────────────────────┼─────────────────────┤
         │                    │                     │
      Hardware             Cloud/K8s             HSM/KMS
      Discovery             Discovery             Discovery
         │                    │                     │
         └────────────────────┼─────────────────────┘
                              │
                              ▼
                    ┌──────────────────┐
                    │ Evidence Layer   │
                    │  observations    │
                    │  provenance      │
                    │  timestamps      │
                    │  hashes          │
                    │  collector       │
                    └────────┬─────────┘
                             ▼
                    ┌──────────────────┐
                    │ Normalization    │
                    └────────┬─────────┘
                             ▼
                    ┌──────────────────┐
                    │ Identity Engine  │
                    └────────┬─────────┘
                             ▼
                  ┌────────────────────────┐
                  │ CRYPTOSCAN ESTATE      │
                  │ GRAPH / DIGITAL TWIN   │
                  └────────────┬───────────┘
                               │
         ┌─────────────────────┼──────────────────────┐
         ▼                     ▼                      ▼
    Technology             Crypto                 Network
      Graph                 Graph                  Graph
         │                     │                      │
         └─────────────────────┼──────────────────────┘
                               ▼
                       ┌──────────────┐
                       │ Six BOMs     │
                       └──────┬───────┘
        ┌────────┬────────┬────┴────┬────────┬────────┐
        ▼        ▼        ▼         ▼        ▼        ▼
      SBOM     CBOM     HBOM      NBOM     VBOM    TechBOM
```

## 2. The seven layers

| Layer | Name | Question it answers |
|---|---|---|
| 1 | Estate | Where does everything belong? |
| 2 | Assets | What exists? |
| 3 | Relationships | What is connected to what, on what basis? |
| 4 | Crypto | What cryptography runs where, and at what usage state? |
| 5 | Evidence | Why do we believe any of it? |
| 6 | Time | What changed, and when? |
| 7 | Simulation | What would happen if we changed it? |

---

## Layer 1 — Estate model

```
Bank
├── Region
├── Data Center
├── Cloud Environment
├── Environment
│   ├── Production
│   ├── UAT
│   ├── DR
│   └── Development
└── Business Systems
```

Example:

```
Synthetic Bank
├── UAE Data Center
├── Dubai DR
├── AWS Environment
└── Production
```

The twin knows where everything belongs. An asset that cannot be placed is
reported as unplaced — never silently attached to the estate root.

## Layer 2 — Asset model

Every discovered object becomes an asset. Asset types:

```
SYSTEM, APPLICATION, SERVICE, HOST, VM, CONTAINER, IMAGE, PACKAGE, LIBRARY,
PROCESS, DATABASE, NETWORK_ENDPOINT, LOAD_BALANCER, API_GATEWAY, FIREWALL, VPN,
KUBERNETES_CLUSTER, KUBERNETES_NAMESPACE, HSM, KMS, CERTIFICATE, CA, HARDWARE,
FIRMWARE, VENDOR, PRODUCT, CRYPTO_ASSET, KEY_METADATA
```

Stable id per asset:

```json
{
  "asset_id": "asset:host:7f82...",
  "asset_type": "HOST",
  "name": "payment-prod-01",
  "environment": "production",
  "owner": "payments-platform",
  "status": "ACTIVE"
}
```

## Layer 3 — Relationship model

Assets are not enough; store relationships:

```
Payment System
      ├── contains → Payment API
      ├── depends_on → PostgreSQL
      ├── protected_by → WAF
      └── owned_by → Payments Team

Payment API
      ├── runs_on → Kubernetes Pod
      ├── uses → OpenSSL
      ├── connects_to → Load Balancer
      ├── uses_certificate → CERT-001
      └── uses_hsm → HSM-001
```

### Controlled vocabulary

```
CONTAINS, RUNS_ON, DEPENDS_ON, CONNECTS_TO, EXPOSES, PROTECTED_BY, TERMINATES_TLS,
RE_ENCRYPTS, PASSTHROUGH, USES_CERTIFICATE, SIGNED_BY, ISSUED_BY, USES_HSM,
USES_KMS, USES_CRYPTO_LIBRARY, USES_ALGORITHM, USES_KEY, HOSTED_ON, DEPLOYED_AS,
BUILT_FROM, PART_OF, OWNED_BY, MANAGED_BY, PROVIDED_BY, BACKED_BY, ROUTES_TO,
AUTHENTICATES_WITH, ENCRYPTS_WITH, SIGNS_WITH, VERIFIED_BY
```

Each relationship carries its own evidence.

### Relationships are not foreign keys

Not this:

```
payment_api.hsm_id = HSM-01
```

This:

```
Relationship
 ├── source      = Payment API
 ├── relation    = USES_HSM
 ├── target      = HSM-01
 ├── evidence    = EVID-9182
 ├── confidence  = HIGH
 ├── source_type = CONFIGURED
 └── observed_at = ...
```

Now the twin is auditable.

## Layer 4 — Crypto graph

A dedicated graph inside the twin. Three planes may say three different things,
and the twin keeps all three:

```
Payment API ──uses──▶ OpenSSL ──crypto capability──▶ AES-256-GCM
Payment API ──RUNTIME_OBSERVED──▶ AES-256-GCM
External LB ──NETWORK_OBSERVED──▶ TLS 1.3 / AES-256-GCM / X25519
```

This is the CBOM conflict the twin exists to solve:

```
SBOM says OpenSSL        → capability
CBOM says AES-128        → declared default
Runtime says AES-256-GCM → what ran
Network says TLS 1.3     → what the peer saw
```

A normal scanner merges those into a contradiction. The twin represents:

```
OpenSSL
 ├── CAPABILITY        { AES-128, AES-256, RSA }
 └── RUNTIME_OBSERVED   { AES-256-GCM }

Load Balancer
 └── NETWORK_OBSERVED   { TLS 1.3 → AES-256-GCM }
```

OpenSSL *supports* AES-128. The application *used* AES-256-GCM. Those are not
contradictory.

## Layer 5 — Evidence graph

Every important twin fact points at evidence:

```
Payment API ──USES_HSM──▶ HSM-01 ──▶ Evidence
                                        ├── config file
                                        ├── collector
                                        ├── timestamp
                                        └── hash
```

```json
{
  "evidence_id": "evid:93f...",
  "collector": "linux-static",
  "collector_version": "1.4.0",
  "target_id": "target:payment-01",
  "observed_at": "2026-10-27T10:20:00Z",
  "evidence_type": "CONFIGURED",
  "source": "/etc/payment/pkcs11.conf",
  "hash": "sha256:...",
  "fact": { "hsm_reference": "HSM-01" }
}
```

### Evidence strength

```
OBSERVED, STATIC_OBSERVED, RUNTIME_OBSERVED, NETWORK_OBSERVED, CONFIGURED,
IMPORTED, VENDOR_DECLARED, INFERRED, UNKNOWN
```

The UI shows the strength, not just the value:

```
AES-256-GCM     ✓ Runtime Observed  ✓ Network Observed  ✓ Configured    HIGH
AES-128         ℹ Library Capability  Source: OpenSSL  CAPABILITY ONLY
```

## Layer 6 — Time

The twin is versioned: `T0, T1, T2, T3`.

```
Monday   Payment API   TLS 1.3 / AES-256-GCM
Friday   Payment API   TLS 1.2 / AES-128-GCM
```

```
DRIFT DETECTED
  Previous: TLS 1.3 / AES-256-GCM
  Current:  TLS 1.2 / AES-128-GCM
  Changed:  Load Balancer LB-07
  Affected: Payment API, Payment System
  Evidence: EVID-18291
```

### Snapshots

Every scan creates a twin snapshot — assets, relationships, crypto, evidence
references, configuration state, network state, certificates, dependencies —
identified as `SNAPSHOT-2026-10-27-001`. Snapshot A → diff engine → snapshot B
produces drift.

## Layer 7 — Simulation

With the twin, the product can answer "what happens if we change this
cryptographic asset?":

```
Replace RSA-2048 → ML-DSA
  Affected systems / applications / certificates / vendors / HSMs /
  load balancers / APIs / dependencies / network paths
```

PQC migration simulation is the natural extension:

```
RSA-2048
   ├── Certificate CERT-001
   ├── Payment API
   ├── LB-07
   ├── HSM-02
   └── Vendor Product X

Impact:
  4 applications | 2 load balancers | 1 HSM | 7 certificates | 2 vendors | 3 network paths
Blockers:
  HSM does not support required algorithm
  LB firmware outdated
  Certificate lifecycle incompatible
Unknown:
  1 legacy application
```

### Simulation never touches production

```
Production Twin ──▶ Clone ──▶ Simulation
                                 ├── change crypto algorithm
                                 ├── change certificate
                                 ├── disable TLS 1.2
                                 ├── upgrade HSM
                                 └── replace library
```

The live twin is read-only to the simulation, by construction: the simulation
operates on a snapshot copy, and the live projection id must be unchanged
afterwards.

## Digital Twin and the six BOMs

```
DIGITAL TWIN
   Estate Graph
        │
  ┌─────┼──────────┐
Assets Relations Evidence
  └─────┼──────────┘
   BOM Projection
  ┌─────┬────┬─────┬─────┬─────┬────────┐
 SBOM  CBOM HBOM  NBOM  VBOM  TechBOM
```

The six BOMs are not six databases. One canonical model, six projections.

## Data model

Minimum tables:

| table | columns |
|---|---|
| `assets` | asset_id, asset_type, name, environment, owner, location, status, first_seen, last_seen |
| `relationships` | relationship_id, source_asset, relationship_type, target_asset, confidence, evidence_id, first_seen, last_seen |
| `crypto_assets` | crypto_id, algorithm, key_size, curve, mode, purpose, provider, status |
| `evidence` | evidence_id, target_id, collector_id, collector_version, evidence_type, timestamp, source, raw_reference, normalized_fact, hash |
| `observations` | observation_id, asset_id, fact_type, value, evidence_id, timestamp |
| `snapshots` | snapshot_id, scan_id, created_at, scope, policy_version, collector_versions |
| `drift_events` | drift_id, asset_id, previous_state, current_state, detected_at, evidence_before, evidence_after, severity |
| `simulation_runs` | simulation_id, base_snapshot, scenario, changes, impact, blockers, results |

## Storage: hybrid, with evidence as truth

**PostgreSQL** — users, organisations, jobs, targets, authorisation, evidence
metadata, policies, scan records, audit, BOM metadata, reports.

**Graph database** — asset relationships, dependencies, network topology,
crypto relationships, system/hardware/vendor relationships, impact analysis, PQC
dependency traversal, simulation.

But:

```
Evidence Store → Canonical relational records → Graph projection
```

**not**

```
Graph = truth
```

The philosophy holds: *evidence is truth. The Digital Twin is the correlated
model. BOMs are projections.*

## Ingestion pipeline

```
Collector → Raw observation → Evidence envelope → Validation → Normalization
   → Identity resolution → Relationship resolution → Conflict detection
   → Canonical estate model → Digital Twin graph → BOM projections
```

## Conflict handling

```
SBOM:      OpenSSL 3.0.13
Runtime:   OpenSSL 3.0.11
Container: OpenSSL 3.0.13
Vendor:    OpenSSL 3.0.13
```

Do not pick one silently:

```
OpenSSL
 ├── SBOM      → 3.0.13
 ├── Container → 3.0.13
 ├── Runtime   → 3.0.11
 └── Vendor    → 3.0.13

CONFLICT DETECTED — investigate.
```

Likely explanation: the container library is not the dynamically loaded host
library. That is intelligence, not noise.

## UI

One of the main CryptoScan screens. Not an AI-looking dashboard.

```
CRYPTOGRAPHIC ESTATE

Overview
Estate          Systems, Applications, Hosts, Containers, Kubernetes, Cloud
Cryptography    Algorithms, Keys, Certificates, HSM, KMS, Crypto Providers
Network         Endpoints, TLS, Load Balancers, API Gateways, VPN, Trust Paths
Supply Chain    SBOM, Vendors, Dependencies
BOM             CBOM, HBOM, NBOM, VBOM, TechBOM
Intelligence    Weak Crypto, Unknown Crypto, Drift, PQC Readiness, Impact Analysis
Digital Twin    Live Estate, Historical Snapshots, Graph, Compare, Simulation
```

### The most important screen: asset investigation

```
PAYMENT API
────────────────────────────────
System        Payment Processing
Environment   Production
Owner         Payments Platform
Runtime       Java 21
Container     sha256:...
Host          K8S-NODE-14
────────────────────────────────
CRYPTOGRAPHY
TLS           TLS 1.3
Cipher        AES-256-GCM
Key Exchange  X25519
Certificate   CERT-8821
HSM           HSM-03
────────────────────────────────
DEPENDENCIES
OpenSSL, Bouncy Castle, PostgreSQL
────────────────────────────────
NETWORK
External LB → API Gateway → Payment API → PostgreSQL
────────────────────────────────
EVIDENCE
Runtime Observed / Network Observed / Static Observed / Configured
```

That is a crypto threat-intelligence interface.

## Search

```
Search: RSA-2048
  ├── 48 certificates
  ├── 13 applications
  ├── 7 HSM references
  ├── 5 load balancers
  ├── 3 vendors
  ├── 2 legacy systems
  └── 1 critical payment system

Search: AES-128
  ├── 21 applications
  ├── 4 network paths
  ├── 2 databases
  ├── 1 HSM
  └── 3 legacy systems
```

## Blast radius

```
Click RSA-2048 → IMPACT ANALYSIS
  Direct:        48 certificates
  Applications:  13
  Systems:        7
  Network paths: 11
  Hardware:       3 HSMs
  Vendors:        5
  Critical:       2
  PQC blockers:   4
```

## "Why?"

```
Payment API → uses HSM-03

WHY IS THIS RELATIONSHIP PRESENT?
  Evidence:        EVID-9281
  Source:          /etc/payment/pkcs11.conf
  Observation:     slot = HSM-03
  Collector:       linux-static 1.4.0
  Observed:        2026-10-27 10:22:31 UTC
  Evidence hash:   sha256:...
```

This is what bank auditors ask for.

## Twin completeness

The twin has a health score — but it is **not** "crypto readiness":

```
DIGITAL TWIN QUALITY
  Asset coverage            98.2%
  Relationship coverage     94.7%
  Evidence coverage         97.1%
  Network visibility        96.4%
  Runtime visibility        83.2%
  HSM visibility            91.0%
  ──────────────────────────────
  Overall Twin Completeness 94.8%

Why not 100%?
  12 hosts unavailable
  2 HSM APIs unavailable
  41 proprietary applications
  19 unknown crypto paths
```

That is far more trustworthy than a single confident number.

## Lifecycle

```
DISCOVER → IDENTIFY → EVIDENCE → NORMALIZE → CORRELATE → MODEL → SNAPSHOT
  → MONITOR → DRIFT → SIMULATE → REMEDIATE → RE-DISCOVER
```

The twin is not a one-time scan. It is the living cryptographic model of the
bank.

---

## Status in this repository

| Spec area | State | Where |
|---|---|---|
| §1 evidence-first pipeline | **shipped** (spec 93) | `api/estate_discovery.py`, `shared_models/estate_graph.py` |
| Layer 2 assets + stable identity | **shipped**; type list extended to §5 (VM, FIREWALL, VPN, PRODUCT, CRYPTO_ASSET, KEY_METADATA) | `estate_graph.ASSET_TYPES` |
| Layer 3 relationships with basis + evidence | **shipped** | `EstateGraph.assert_relationship` |
| Layer 3 vocabulary | **shipped at full §7 width** (32 predicates); every `uses*`/`encrypts_with`/`signs_with` edge needs a usage basis | `estate_graph.RELATIONSHIP_PREDICATES`, `USE_PREDICATES` |
| Layer 4 crypto graph, capability ≠ usage | **shipped** | `estate_graph.crypto_artifacts`, `USAGE_STATES` |
| Layer 5 evidence strength + provenance | **shipped** | `EVIDENCE_TYPES`, `EVIDENCE_CONFIDENCE` |
| Conflict detection (§23) | **shipped** | `EstateGraph.conflicts()` |
| Layer 6 drift between stored runs | **shipped** (spec 93 §18) | `api/estate_drift.py` |
| Layer 4 crypto graph (§9, §10) | **shipped** — four planes (capability / configured / runtime / wire), provider→algorithm edges, capability-vs-use coexistence explained, conflicts split into *real* (same plane) and *explained* (across planes) | `estate_twin.crypto_graph()` |
| Compare two twins (§13, §24 "Compare") | **shipped** — assets/relationships/crypto-usage/coverage/evidence/unknown delta, verdict worst-first (`COVERAGE_DEGRADED` > `CRYPTO_CHANGED` > `ESTATE_CHANGED` > `NO_CHANGE`) | `estate_twin.compare()` |
| Durable catalogue (§19, §22 "canonical estate model") | **shipped** — `estate_assets`, `estate_relationships`, `estate_crypto_assets` (migration 0113). Materialised from every observation, kept across them: `first_seen_at` / `last_seen_at` / `observation_count`, evidence ids on every row, and a lifecycle of `ACTIVE` → `STALE` (absent from the latest observation) with **no delete path**. Unresolved candidates stored as `UNRESOLVED` with their refusal reason. `GET /estate/evidence/catalog{,/assets,/assets/{id},/relationships,/crypto}`, `cryptoscan twin assets\|asset\|algorithms` | `api/estate_catalog.py` |
| Snapshots as stored objects (§19) | **shipped** — `estate_twin_snapshots` (migration 0110), keyed by `(tenant, projection_id)`: identical evidence advances an observation counter instead of inventing a new snapshot | `api/estate_twin_store.py` |
| Graph projection (§20) | **shipped** — deterministic typed nodes/edges, evidence ids on every edge, unresolved edges shipped separately, `not_source_of_truth` in the payload | `estate_twin.graph_export()` |
| Graph store load (§20–§21) | **shipped** — `POST /twin/graph/load` and `cryptoscan twin graph-load` plan by default and write only on an explicit ask; MERGE by deterministic id (a re-load converges), labels/types validated against the graph vocabulary before they reach Cypher, whole-export refusal, opt-in `prune_missing`, and **read-back verification** (`VERIFIED` / `MISMATCH` / `NOT_CONNECTED` rather than "loaded") | `api/estate_graph_loader.py` |
| Simulation history (§17, §19) | **shipped, quarantined** — `estate_simulation_runs` (migration 0111). A stored simulation is a *question asked of a copy*: `quarantined=true`, `is_estate_state=false`, refused at write time unless the engine reports the live state untouched, incremented (not duplicated) when the same question is asked again, and marked `superseded` once the estate moves. Reachable as `POST /twin/simulate {persist:true}`, `GET /twin/simulations`, `cryptoscan twin simulate --save` | `api/estate_simulation_store.py` |
| Layer 1 estate placement | **shipped** | `estate_twin.placement_model()` |
| Twin completeness (§29) | **shipped** — description quality, never a posture score | `estate_twin.completeness()` |
| Asset investigation (§25) | **shipped** | `estate_twin.investigate()` |
| "Why?" (§28) | **shipped** — answers with collector/source/time/hash, refuses for a non-edge | `estate_twin.why()` |
| Search (§26) | **shipped** | `estate_twin.search()` |
| Blast radius (§27) | **shipped** — established edges only, blind spots listed | `estate_twin.impact()` |
| Layer 7 simulation (§15–§17) | **shipped** — runs on a snapshot copy, live projection id checked unchanged | `estate_twin.simulate()` |
| Live change detection (§17–§18, §23) | **shipped** — every stored observation is compared with the one before it and produces *named claims*, not a drift flag: `CRYPTO_DEMOTED Payment API AES-256-GCM: OBSERVED → SUPPORTED`, `COVERAGE_DEGRADED HSM: COMPLETE → FAILED`, `ASSET_ADDED HSM-04 (HSM, production)`. Append-only `estate_change_events` (migration 0112); identical observations store nothing; a replayed detection increments an observation counter; acknowledgement moves and nothing else does. `GET /estate/evidence/changes`, `POST /changes/detect`, `POST /changes/{id}/acknowledge`, `cryptoscan twin changes\|detect\|ack` | `api/estate_change_feed.py` |
| Twin snapshots as a first-class object (§14) | **shipped** — content-addressed by projection id | `estate_twin.snapshot()` / `graph_from_snapshot()` |
| API surface | **shipped** | `/estate/evidence/twin{,/completeness,/snapshot,/snapshots,/search,/assets/{ref},/why,/crypto-graph,/graph,/simulations}`, `POST /twin/impact`, `POST /twin/simulate`, `POST /twin/graph/load`, `GET /estate/evidence/changes{,/{id}}`, `POST /changes/detect`, `POST /changes/{id}/acknowledge` |
| UI (§24, §25) | **shipped as six views**: *Live estate* (placement, completeness with reasons, search with click-through to an asset view, blast radius with paths and blind spots, simulation with BOM diff and a "live twin unchanged" badge); *Crypto graph* (four planes with their meanings on screen); *Catalogue* (asset records with lifecycle, a type filter, per-asset crypto + edges + refused candidates, and the algorithm registry); *Changes* (the change feed — severity, the named claims with before → after and what each does *not* prove, a *detect now* action, and acknowledge); *History & compare* (capture, persisted-vs-derived, worst-first verdict, and stored simulations listed as **quarantined** with `CURRENT`/`STALE` and an "asked N×" counter); *Graph export* (counts, unresolved separate, not-source-of-truth, and a *plan the graph-store load* action that sends `dry_run: true` — the console can never write to a graph store) | `frontend/src/components/DigitalTwinPanel.tsx` |
| Historical snapshots (§14) | **shipped** — persisted (`POST/GET /twin/snapshots`); falls back to run-derived snapshots with `persisted: false` and says so | `estate_twin_store.py` |
| Traversal in a graph store | *not built* — the twin traverses **in-process** over the canonical graph. The store now receives a verified copy (§20–§21), but no query path reads traversals back from it: until BOM/drift/impact can be recomputed from the store and proven equal to the in-process answer, the store stays a copy for external consumers, never an authority | — |

### What "simulation" means here, precisely

`POST /estate/evidence/twin/simulate` applies the scenario to the **snapshot
payload** (the evidence records), rebuilds a graph from it, re-projects all six
BOMs from that copy, and diffs them component-by-component against the live
projection. It reports:

* `matched_evidence` — how many observations actually changed (0 ⇒ `NO_MATCH`,
  never "no impact");
* `bom_diff` — added/removed/changed per BOM, so the consequence is expressible in
  the same artefacts the bank already exports;
* `blockers` — `CAPABILITY_NOT_EVIDENCED` where a component in the radius declares
  supported algorithms that do not include the new one, and
  `UNRESOLVED_RELATIONSHIP` where an assumed edge could hide a larger radius;
* `live_projection_unchanged` — computed by fingerprinting the live graph before
  and after, so "production was not touched" is a check rather than a promise.

### What a snapshot identifies, precisely

The snapshot id covers assets, relationships, evidence **content** and collector
outcomes. Coverage was added after a defect was found by writing the compare test:
with only facts in the hash, a run where a plane `FAILED` fingerprinted identically
to one where it succeeded over the same (smaller) set of facts — so "we stopped
looking" was indistinguishable from "nothing changed". That is the single most
dangerous comparison this product can get wrong, and it is now a regression test.

### What the catalogue remembers, precisely

The twin used to be **reconstructed**: every request re-read the newest stored
discovery payload and rebuilt a graph from it. That answers "what is there now" and
cannot answer the questions a twin exists for — when did this appear, is it missing or
retired, which evidence establishes this edge, and who actually *uses* RSA-2048 as
opposed to merely supporting it. Migration 0113 adds the memory:

| record | keyed by | what it carries |
|---|---|---|
| `estate_assets` | the graph's stable `asset_id` | type, name, environment, owner, location, identity, attributes, evidence ids, `first_seen_at`, `last_seen_at`, `observation_count`, lifecycle |
| `estate_relationships` | `sha256(subject\|predicate\|object\|basis)` | basis, confidence, evidence ids, and `status` ∈ `ESTABLISHED` / `UNRESOLVED` with the refusal reason |
| `estate_crypto_assets` | the graph's `artifact_id` | algorithm / protocol / curve / key size / mode / layer, `usage_state`, evidence type + ids, lifecycle |

Four rules, each with a test behind it:

* **Derived, never typed.** Every row is materialised from a graph that came from
  evidence; every row keeps the evidence ids. There is no "create asset" function, and
  a test asserts one is not exported.
* **Absence is not deletion.** A row absent from the latest observation becomes
  `STALE` with `last_seen_at` intact. A host that stopped answering, a plane that
  failed and a decommissioned server are indistinguishable in a diff — so the catalogue
  refuses to turn that ambiguity into a deletion, and re-observation returns the row to
  `ACTIVE`. Nothing removes rows automatically.
* **Capability and use never merge.** Crypto rows are keyed per artefact *per plane*,
  so `SUPPORTED AES-128` on a library and `OBSERVED AES-256-GCM` on an application are
  two rows. The registry reports each algorithm *per* `usage_state`, and
  `OBSERVED` / `NEGOTIATED` / `CONFIGURED` / `SUPPORTED` are never summed into one
  "uses" number. A test stores a `SUPPORTED` and an `OBSERVED` artefact and asserts the
  counts stay apart.
* **An unresolved candidate is stored, and is not a relationship.** The graph refused
  to establish it for want of a basis or evidence; the catalogue keeps it with
  `status='UNRESOLVED'` and the reason (it is what a bank most wants to chase), and
  every read path that answers "what depends on what" filters on `ESTABLISHED`.

Evidence itself is not duplicated here. It remains the record of facts, the catalogue
stores references to it, and `?why=` still resolves a claim back to collector, source,
time and hash.

### What the catalogue still cannot say

* **No region / cloud-account hierarchy.** The twin knows environment, location and
  business system (spec §4's last three levels) but not a region → data-centre →
  cloud-subscription tree: nothing in the evidence asserts one, and inferring a region
  from a free-text `location` would be a guess dressed as structure.
* **No per-fact observation history.** `observation_count` says how often a row was
  seen; it does not keep every value that fact ever took. The evidence records in the
  run history hold that, and change events name the transitions — the catalogue keeps
  the current value, not a time series.
* **A stale row cannot distinguish "gone" from "not looked at".** That distinction
  lives in the coverage rows of the same run: a `STALE` asset on a `FAILED` plane is a
  collection gap, not a decommission, and the twin reports them side by side rather
  than merging them.

### What "change detected" means, precisely

Change detection is **a consequence of observing**, not an endpoint an operator has to
remember to call: the collector path (`/estate/evidence/scan`, the scheduler, the
daemon) and the ingest path (`/estate/evidence/discover`) both compare the run with
the observation before it, and both go through the same detector, so the two ways an
observation enters the product cannot drift into different answers.

The unit is a **claim**, not a flag. "WARNING: drift detected" is not an answer to
"what changed"; each event carries a list of them:

| kind | subject | what it says |
|---|---|---|
| `COVERAGE_DEGRADED` | plane | `HSM: COMPLETE → FAILED — API unavailable`, and that the estate under it is UNKNOWN, not absent |
| `EVIDENCE_LOST` | estate | stronger evidence fell by N while N′ was gained — a weaker audit position even when nothing appears to move |
| `CRYPTO_DEMOTED` / `_PROMOTED` | asset | `AES-256-GCM on Payment API: OBSERVED → CONFIGURED` — proof lost, not necessarily the cryptography |
| `CRYPTO_ADDED` / `_REMOVED` | asset | a new artefact is evidenced, with its `usage_state` so `SUPPORTED` cannot be read as deployed |
| `ASSET_ADDED` / `_REMOVED` / `_CHANGED` | asset | the asset and its type, and for a change, the fields that moved with before → after |
| `RELATIONSHIP_ESTABLISHED` / `_LOST` | edge | `Payment API —uses_hsm→ HSM-03 (PKCS11_REFERENCE)` |
| `UNKNOWN_GAINED` / `_REDUCED` | inventory | open work grew: those assets are uncharacterised, **not** crypto-free |
| `UNRESOLVED_GAINED` | candidates | an edge nobody established; it widens where a real path could hide, and is never counted as an edge |

Severity is a **consequence** order, not a confidence order:
`CRITICAL` (a plane stopped answering, or stronger evidence was lost) outranks
`WARNING` (crypto, assets or relationships moved) outranks `INFO` (metadata moved, or
the digests differ with no compared surface changing — which is *unexplained*, not
clean). One test exists only to hold that ordering: a run that loses a plane *and*
changes a cipher must be `CRITICAL`, because the crypto movement may be an artefact of
the plane going dark.

What the feed refuses:

* **No row for a quiet scan.** Identical evidence returns `NONE` and stores nothing.
  The discovery run is already the record that someone looked; a row per quiet scan
  would bury the afternoon something moved, and would let a scheduler's health be
  inferred from a table that does not measure it.
* **No duplicate for a replayed transition.** The event id is
  `sha256(baseline|current|verdict)`, so a restart, a retry or a re-derivation appends
  an observation counter instead of a second "the estate changed".
* **No re-collection to confirm a change.** A claim is derived from two stored
  observations; re-reading the estate would produce a *third* observation, not
  evidence about the first two.
* **No editing.** Only `acknowledged_at/by/note` are mutable. A feed whose findings can
  be edited is not an audit trail.
* **No simulations.** Nothing in the detector reads `estate_simulation_runs`; a test
  stores a simulation and asserts the feed's contents are unchanged.
* **No "the estate is fine".** `NONE` means the two observations match. An empty feed
  means nothing moved while the collectors ran — it cannot tell a stable estate from a
  scheduler that stopped running, and the response says that in `limits`.

### What a stored simulation is, precisely

Simulation runs **are** persisted (migration 0111), because the audit question "what
did we consider before we migrated?" is real. What keeps that safe is not the
docstring but the shape of the row:

* the table stores the **answer** (scenario, base projection id, matched evidence,
  impact, blockers, BOM diff) and no estate facts — nothing in it can be merged back
  into an `EstateGraph`, a snapshot, a drift comparison or a BOM projection;
* `live_state_modified` is asserted at write time: a result the engine says touched
  the live graph is refused rather than stored;
* a `NO_MATCH` scenario is refused at write time too, because "we found nothing to
  simulate" stored as a run reads like a finding;
* asking the same question against the same evidence increments `observations`
  instead of inserting a second row, which would read like the estate had moved;
* every API row carries `quarantined`, `is_estate_state`, `computed_against` and
  `freshness`; once the live projection id differs the answer is `STALE` and names
  `superseded_by`, because an impact figure computed against a different estate is
  history, not a forecast.

The tests close each route a simulation could take into the estate: the twin
overview, its summary and completeness are byte-identical before and after a stored
run; no snapshot id equals a simulation id; the graph export's counts and projection
id are unchanged; and a stored answer goes `STALE` the moment discovery moves the
estate.

### What a graph-store load is, precisely

`POST /twin/graph/load` (and `cryptoscan twin graph-load`) writes the export into the
configured Neo4j store, `dry_run` **default**. Its honesty lives in four refusals:

* an unknown `schema`, a missing `projection_id`, a duplicate node id, a dangling
  endpoint, or an `UNRESOLVED_CANDIDATE` shipped as a relationship rejects the
  **whole document** before a single statement is built — a partial import is worse
  than none;
* labels and relationship types are checked against the graph's own vocabulary
  (`ASSET_TYPES`, `EVIDENCE_TYPES`, `RELATIONSHIP_PREDICATES`) *and* a plain-token
  pattern, because Cypher cannot parameterise them — this is the one place an
  unvalidated interpolation would be arbitrary Cypher;
* every write is `MERGE` on the deterministic id, so loading the same snapshot twice
  converges instead of doubling the store;
* after writing, the loader reads the counts back. `MISMATCH` is a failure ("the copy
  is not a copy"), and with no driver configured the answer is `NOT_CONNECTED` — not
  "the graph is up to date". Pruning is opt-in, scoped to one estate, and runs only
  once the load verified.

### What the twin still cannot say

* A capability declaration never becomes usage: `supported_algorithms` on a
  library produces capability blockers, not an observed cipher.
* Completeness cannot exceed collector coverage. `PLANE_COVERAGE` counts planes
  that ran at all against planes expected, so 100% target coverage inside one
  plane cannot read as a complete twin; a `FAILED` plane appears in `why_not_100`
  and the dimension it fed stays `n/a`. `weakest_dimension` ships beside
  `overall_percent`, because an average hides its worst term.
* A file path is not a site. `location` on a static-scan hit is provenance
  (`/srv/app/Crypto.java`), so such an asset is `UNPLACED` rather than assigned to
  a data centre that it may never have run in.
* Simulation changes *evidence facts in a copy*, not a real configuration. It can
  tell you that a BOM would change; it cannot tell you that a vendor's firmware
  would accept it — that stays a human finding.
