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
├── Organization          (legal entity / group; asserted, never inferred)
│   └── Department        (business unit / cost centre, with its owners)
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

`ESTATE_LEVELS` carries all eight levels. The two organisation levels were added after
the specification audit (`docs/DIGITAL-TWIN-SPEC.md` §13): a multi-entity bank could
not previously ask "which legal entity and which department owns this asset?" in the
placement model. Both are derived from an asserted attribute only — an asset with an
owner name but no department is counted under `unassigned.DEPARTMENT` with the reason,
rather than having a cost centre invented for it.

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

### What a conflict is, now that it has a list

`GET /twin/conflicts` (and `cryptoscan twin conflicts`) gathers every disagreement the
twin is holding — from the current observation *and* from the durable fact record — and
classifies it, because "two values disagree" is not one thing:

| classification | meaning | what it means to do |
|---|---|---|
| `REAL` | two sources on the **same plane** disagree | one is wrong; fix the source and re-collect |
| `EXPLAINED` | the values come from **different planes** | both can be true (capability vs use); nothing needs fixing |
| `UNKNOWN` | no plane was recorded | treat it as real until a collector states its plane |

Three rules, and the third is the one that keeps the list read:

* **nothing is resolved.** There is no merge, no "newest wins", no way to choose in the
  API. A conflict closes when a human corrects the source and a new observation proves it;
* **a disagreement seen twice is one problem.** The same fact can be disputed by the
  current observation and by the recorded history, so entries merge on
  `(asset, field)` and name both sources in `seen_by`;
* **an unstated plane is not a different plane.** Counting a missing attribution as a
  second plane would turn every record with an attribution gap into an "explained"
  conflict, and a conflict list that explains everything stops being read. The recorded
  fact history cites the evidence behind its *asset*, not per value, so it reports those
  disputes as `UNKNOWN` and lets an observation upgrade the classification — that limit
  is why the two sides are merged rather than ranked.

Only the fields the twin treats as conflict-bearing (`algorithm`, `key_size`, `protocol`,
`version`, `firmware`, …) are compared. Two artefacts of one asset with different
`usage_state` is normal and is **not** a conflict — treating it as one is how a list fills
with noise.

### Who is told, and how

A detected change that only appears when someone opens the console is a report someone
has to remember to read. Every observation now **announces** what moved on the platform
journal — the same rows the notification feed, the SIEM drain and the dispatch registry
read — under two event types, because they are two different things to act on:

| event type | notification class | raised when |
|---|---|---|
| `estate.change.detected` | `estate_change` (WARNING) | claims were detected: an asset appeared, a usage state moved, a relationship was lost, evidence weakened |
| `estate.coverage.lost` | `estate_coverage_lost` (CRITICAL) | a plane stopped answering — everything under it is UNKNOWN, not absent |

Both classes are in the routing catalog with every channel on by default, so a bank can
route "coverage lost" to a SIEM and "asset added" to the in-app feed and nothing else.
Three rules hold here:

* **the announcement names the claims.** Its payload carries the first ten
  `{kind, severity, subject, detail}` claims, not the phrase "drift detected" — a
  notification an operator cannot act on is noise with a severity label;
* **announcing is best-effort and reported.** A journal or bus failure is recorded in
  `announced.error` and never raised: the observation already happened, and losing a
  notification is not a reason to lose a scan;
* **a quiet observation announces nothing.** Identical evidence produces no event and no
  notification, because the run itself is the record that someone looked.

`POST /changes/detect` and the collector path share one entry point
(`estate_change_feed.observe`), so an operator triggering detection by hand and the
scheduled run cannot drift into two different answers.

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

"Where is RSA-2048?" is four questions in one sentence — which assets, which artefacts,
which edges, and which evidence says so — and an operator who has to guess which of five
endpoints to call is navigating, not searching. `GET /estate/evidence/search?q=…` (and
`cryptoscan twin search`) answers across everything the twin has recorded, grouped by
kind and never merged into one list:

| group | what it reaches | why it is separate |
|---|---|---|
| `ASSETS` | name, id, owner, environment, type | a hit is an asset, not a claim about it |
| `CRYPTO` | algorithm, protocol, curve, and the artefacts behind them | grouped per `usage_state`, so a `SUPPORTED` library row can never be read as a deployed cipher |
| `RELATIONSHIPS` | subject, object, predicate — established **and** refused candidates | a candidate is labelled `UNRESOLVED` with its refusal reason |
| `EVIDENCE` | collector, source, type, target, **and the recorded facts** | "who observed this" and "which record mentions this" are different searches |
| `FACTS` | recorded fact values (`attribute:region = me-central-1`) | "what is in me-central-1" is a fact query, not an asset query |
| `CHANGES` | detected change headlines and the claims inside them | a demotion nobody can find is a demotion nobody acts on |

Three rules:

* **search is not discovery.** It searches what has been observed and recorded, and the
  response says so: an empty result means *nothing matching has been recorded*, never
  that the bank has none of it. A search box that returns zero rows reads as a negative
  finding to everyone who did not build it.
* **capability is not use, in search too.** Algorithm hits carry `usage_states` and are
  never summed into one "assets using" number.
* **a result is a shortlist.** Each kind is capped (25 in the API, `--limit` in the CLI),
  says when it was truncated, and carries ids a caller can act on. Matching is
  case-insensitive substring and deliberately not fuzzy: a near-miss presented as a hit
  is how a search becomes a rumour.

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

This is what bank auditors ask for. The shipped answer is
`GET /estate/evidence/why/{asset}?fact_type=…` and `cryptoscan twin why`; it returns the
evidence records behind the asset (collector, source, type, confidence, `observed_at`,
`first_seen_at`/`last_seen_at`) plus every window the fact's values held, and names the
attribution limit instead of implying per-attribute provenance.

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

A loop drawn like that invites a reader to assume it closes. This implementation answers
the question per phase instead, and says which hand-off is missing:

| phase | status | what is actually behind it |
|---|---|---|
| `DISCOVER` | `CONNECTED` when facts were recorded | evidence collection writes a record per fact, so a run that collected nothing leaves no rows |
| `IDENTIFY` | `CONNECTED` when assets exist | derived ids survive re-observation: a second run updates a record instead of creating a second one |
| `EVIDENCE` | `CONNECTED` when records exist | stored once, keyed by content; every claim cites one |
| `NORMALIZE` / `CORRELATE` / `MODEL` | `CONNECTED` when the graph exists | typed assets, edges with a basis, one canonical graph the six BOMs project from |
| `SNAPSHOT` | `CONNECTED` when snapshots exist | content-addressed by projection id |
| `MONITOR` | `NOT_CONNECTED` with no enabled schedule, `PARTIAL` before its first run | nothing here creates a schedule, and a schedule that has never run is configured, not proven |
| `DRIFT` | `CONNECTED` when change events exist | named claims, not a flag |
| `SIMULATE` | `CONNECTED` when a simulation is stored | a question asked of a copy, quarantined |
| `REMEDIATE` | `NOT_STARTED` with nothing to do, `PARTIAL` while work is open, `CONNECTED` once a cited observation closed one | the twin opens work from a REAL conflict, a coverage loss and a simulation blocker, and writes the proof it would take to close each item **when the item opens**. A `HUMAN`-proof item is never auto-closed; a fact that stops being asserted is `PROOF_UNAVAILABLE`, not fixed |
| `RE_DISCOVER` | `CONNECTED` once a work item was closed by a cited observation, otherwise `PARTIAL` | a new observation re-walks the pipeline, is compared with the previous one, and closes the work item that predicted it — the change is attributed to a named fix instead of to nothing |

`loop_closed` is **computed** — every phase `CONNECTED` — and `first_break` names the
earliest phase that is not, so the field flips by itself the day the last hand-off is
built. The distinction that keeps this honest is `NOT_STARTED` versus `NOT_CONNECTED`: an
estate nothing has observed yet has an **unwalked** loop, not a broken one, and every
count behind every phase is in the payload so the two cannot be confused. Read it with
`GET /estate/evidence/twin/lifecycle`, `cryptoscan twin lifecycle`, or the *Loop* view in
the console.

---

## Status in this repository

| Spec area | State | Where |
|---|---|---|
| §1 evidence-first pipeline | **shipped** (spec 93) | `api/estate_discovery.py`, `shared_models/estate_graph.py` |
| Layer 2 assets + stable identity | **shipped**; type list extended to §5 (VM, FIREWALL, VPN, PRODUCT, CRYPTO_ASSET, KEY_METADATA) | `estate_graph.ASSET_TYPES` |
| Layer 3 relationships with basis + evidence | **shipped** — and §8's provenance is on the edge itself: `basis`, `confidence`, `evidence_type` (the *strongest* record behind the edge, so a config citation cannot downgrade a runtime observation) and `observed_at`, with `null` — never a guess — when the cited evidence is not reachable | `EstateGraph.assert_relationship`, `EstateRelationshipRecord.evidence_type` (migration 0115) |
| Layer 3 vocabulary | **shipped at full §7 width** (32 predicates); every `uses*`/`encrypts_with`/`signs_with` edge needs a usage basis | `estate_graph.RELATIONSHIP_PREDICATES`, `USE_PREDICATES` |
| Layer 4 crypto graph, capability ≠ usage | **shipped** | `estate_graph.crypto_artifacts`, `USAGE_STATES` |
| Layer 5 evidence strength + provenance | **shipped** | `EVIDENCE_TYPES`, `EVIDENCE_CONFIDENCE` |
| Conflict detection (§23) | **shipped** | `EstateGraph.conflicts()` |
| Layer 6 drift between stored runs | **shipped** (spec 93 §18) | `api/estate_drift.py` |
| Layer 4 crypto graph (§9, §10) | **shipped** — four planes (capability / configured / runtime / wire), provider→algorithm edges, capability-vs-use coexistence explained, conflicts split into *real* (same plane) and *explained* (across planes) | `estate_twin.crypto_graph()` |
| Compare two twins (§13, §24 "Compare") | **shipped** — assets/relationships/crypto-usage/coverage/evidence/unknown delta, verdict worst-first (`COVERAGE_DEGRADED` > `CRYPTO_CHANGED` > `ESTATE_CHANGED` > `NO_CHANGE`) | `estate_twin.compare()` |
| Durable catalogue (§19, §22 "canonical estate model") | **shipped** — `estate_assets`, `estate_relationships`, `estate_crypto_assets` (migration 0113). Materialised from every observation, kept across them: `first_seen_at` / `last_seen_at` / `observation_count`, evidence ids on every row, and a lifecycle of `ACTIVE` → `STALE` (absent from the latest observation) with **no delete path**. Unresolved candidates stored as `UNRESOLVED` with their refusal reason. `GET /estate/evidence/catalog{,/assets,/assets/{id},/relationships,/crypto}`, `cryptoscan twin assets\|asset\|algorithms` | `api/estate_catalog.py` |
| Snapshots as stored objects (§19) | **shipped** — `estate_twin_snapshots` (migrations 0110, 0117), keyed by `(tenant, projection_id)`: identical evidence advances an observation counter instead of inventing a new snapshot. Each snapshot also records **`policy_version`** — the version of the rules (confidence table, identity keys, conflict fields) that read the evidence — and **`collector_versions`** as `collector@version`, so "the same evidence read by newer rules" and "a probe was upgraded" are distinguishable from "the estate changed". Neither is part of the projection id: the id identifies the evidence, these identify the reading of it | `api/estate_twin_store.py`, `estate_graph.POLICY_VERSION` |
| Graph projection (§20) | **shipped** — deterministic typed nodes/edges, evidence ids on every edge, unresolved edges shipped separately, `not_source_of_truth` in the payload | `estate_twin.graph_export()` |
| Graph store load (§20–§21) | **shipped** — `POST /twin/graph/load` and `cryptoscan twin graph-load` plan by default and write only on an explicit ask; MERGE by deterministic id (a re-load converges), labels/types validated against the graph vocabulary before they reach Cypher, whole-export refusal, opt-in `prune_missing`, and **read-back verification** (`VERIFIED` / `MISMATCH` / `NOT_CONNECTED` rather than "loaded") | `api/estate_graph_loader.py` |
| Simulation history (§17, §19) | **shipped, quarantined** — `estate_simulation_runs` (migration 0111). A stored simulation is a *question asked of a copy*: `quarantined=true`, `is_estate_state=false`, refused at write time unless the engine reports the live state untouched, incremented (not duplicated) when the same question is asked again, and marked `superseded` once the estate moves. Reachable as `POST /twin/simulate {persist:true}`, `GET /twin/simulations`, `cryptoscan twin simulate --save` | `api/estate_simulation_store.py` |
| Crypto intelligence (§12, §24) | **shipped** — `GET /twin/intel`, `cryptoscan twin intel`, and an *Intelligence* view. Three readings of the same artefacts: **weak** (`DISALLOWED`/`DEPRECATED` from `algorithm_registry`), **unidentified** (split into *unrecognised* and *a version string in an algorithm fact*), and **post-quantum** (Shor-vulnerable, with the vendor-bound blockers separated from what a config change can fix). Capability is counted apart from use everywhere — a library that supports DES has not used DES — and every verdict names `algorithm_registry` as its source so it is never read as evidence | `estate_crypto_intel.py` |
| Trust paths (§24 *Network → Trust Paths*) | **shipped** — `GET /twin/trust-paths` and `cryptoscan twin trust-paths` walk every certificate up its `issued_by`/`signed_by` edges and report where the walk stops: `ROOTED` (a CA the estate collected that claims no issuer), `SELF_SIGNED`, `BROKEN` (the edge was refused, or the named issuer is an asset that cannot vouch for a certificate), `CYCLE`, `UNKNOWN_ISSUER` (no edge, so nothing can be judged). No signature, expiry or revocation is checked, and the payload says so; a missing authority is never reported as an untrusted certificate | `estate_trust.py` |
| One algorithm, asked about (§26–§27) | **shipped** — `GET /twin/algorithm/{name}` and `cryptoscan twin algorithm <name>`: artefacts, in-use vs capability-only, counts by asset type / usage state / layer, and the assets themselves. A query with no match says "no observation asserts it", which is not "the estate does not use it" | `estate_crypto_intel.algorithm()` |
| Lifecycle reported (§2) | **shipped** — `GET /twin/lifecycle`, `cryptoscan twin lifecycle`, and a *Loop* view. Per phase: `CONNECTED` / `PARTIAL` / `NOT_CONNECTED` / `NOT_STARTED` from the table the phase writes, with the count behind it, the question it answers and the module that does it. `REMEDIATE` reports `NOT_CONNECTED` in as many words, `loop_closed` is computed from the phases, and `first_break` names the hand-off to build next | `estate_lifecycle.py` |
| Conflicts surfaced (§23) | **shipped** — `GET /twin/conflicts`, `cryptoscan twin conflicts`, and a conflicts block in the live twin view. Every disagreement is classified `REAL` / `EXPLAINED` / `UNKNOWN` from the planes behind its values, merged across the observation and the fact record, and carries `next_action`. Nothing in the module can resolve one | `estate_conflicts.py` |
| Estate search (§26) | **shipped** — one query across assets, artefacts, relationships (including refused candidates), evidence, recorded facts and detected changes; grouped by kind, bounded per kind with truncation stated, and `usage_states` kept apart so capability cannot be read as use | `estate_search.py`, `GET /search`, `cryptoscan twin search`, search panel in the twin view |
| Change announcement (§17–§18, §23) | **shipped** — detected changes are stored *and* published to the platform journal as `estate.change.detected` / `estate.coverage.lost`, with the claims in the payload and both classes routable in the notification matrix | `estate_change_feed.announce()`, `notification_routing.CATALOG` |
| Remediation the twin opens (§23) | **shipped** — `estate_remediation_work` (migration 0118). Work opens from a REAL/UNKNOWN conflict, a collector plane that did not complete, and a simulation blocker. The proof is recorded at open time (`COVERAGE_DISPUTE`, `COLLECTOR_STATUS`, `HUMAN`), `claim_key` is content-derived so re-proposing refreshes one item instead of filing a second ticket, and `POST /twin/remediation/reconcile` moves an item to `PROVEN` only with a cited observation row and evidence id. Proposing is a dry run unless `persist: true` | `api/estate_remediation.py`, `GET /twin/remediation`, `POST /twin/remediate`, `POST /twin/remediation/reconcile`, `cryptoscan twin remediate\|remediation\|reconcile` |
| Layer 5 evidence records + per-fact history (§11, §19, §28) | **shipped** — and each record keeps **`collector_version`** and **`raw_reference`** (migration 0116) beside the collector and source, because "linux-static" does not identify a build and a path alone cannot be re-read. The discovery path stamps every record with `estate-collectors/1` (a collector that knows its own build keeps it) and then, once the run exists, points each record at `run:<id>` — where the raw collector output actually is. Re-observing the same fact under a newer probe keeps ONE row and corrects its provenance rather than inventing a second sighting. Evidence stored as content-addressed records; every fact kept as a value *with a window*, and "why" answered from the evidence behind the asset | `estate_observations.py`, migration 0114, `GET /evidence/records`, `GET /history/summary`, `GET /history/assets/{id}`, `GET /why/{id}`, `cryptoscan twin history|why|evidence` |
| Layer 1 estate placement (§4) | **shipped at all six levels** — `BANK → REGION → DATA_CENTER → CLOUD_ENVIRONMENT → ENVIRONMENT → BUSINESS_SYSTEM`. The upper three appear **only where a collector asserted them** (`attributes.region`, `attributes.data_center`, `attributes.provider/cloud_account`); an asset no evidence places is counted under `unassigned` with the reason, and a level with no data is named in `levels_unobserved` rather than drawn as an empty box | `estate_twin.placement_model()`, `GET /twin/placement`, `cryptoscan twin placement` |
| Twin completeness (§29) | **shipped** — description quality, never a posture score | `estate_twin.completeness()` |
| Asset investigation (§25) | **shipped** | `estate_twin.investigate()` |
| "Why?" (§28) | **shipped** — answers with collector/source/time/hash, refuses for a non-edge | `estate_twin.why()` |
| Search (§26) | **shipped** | `estate_twin.search()` |
| Blast radius (§27) | **shipped** — established edges only, blind spots listed | `estate_twin.impact()` |
| Layer 7 simulation (§15–§17) | **shipped** — ten questions in two families. Seven scenarios run on a snapshot copy with the live projection id checked unchanged; `estate_twin.preview()` answers *would this match* without projecting the six BOMs. Three cascades (`cascade()`, `cascade_preview()`) propagate a failure over declared predicates in declared directions, report wave-by-wave routes, count refused edges in the radius as blind spots, and carry no BOM diff because they change nothing. The console's Simulation workspace is built from catalog → plan → run → history, with presets derived from the estate's own values and topology | `estate_twin.simulate()`, `estate_twin.preview()`, `estate_twin.cascade()`, `estate_twin.cascade_preview()`, `estate_twin.CASCADE_RULES`, `api/estate_simulation.py` |
| Live change detection (§17–§18, §23) | **shipped** — every stored observation is compared with the one before it and produces *named claims*, not a drift flag: `CRYPTO_DEMOTED Payment API AES-256-GCM: OBSERVED → SUPPORTED`, `COVERAGE_DEGRADED HSM: COMPLETE → FAILED`, `ASSET_ADDED HSM-04 (HSM, production)`. Append-only `estate_change_events` (migration 0112); identical observations store nothing; a replayed detection increments an observation counter; acknowledgement moves and nothing else does. `GET /estate/evidence/changes`, `POST /changes/detect`, `POST /changes/{id}/acknowledge`, `cryptoscan twin changes\|detect\|ack` | `api/estate_change_feed.py` |
| Twin snapshots as a first-class object (§14) | **shipped** — content-addressed by projection id | `estate_twin.snapshot()` / `graph_from_snapshot()` |
| API surface | **shipped** | `/estate/evidence/twin{,/completeness,/snapshot,/snapshots,/search,/assets/{ref},/why,/crypto-graph,/graph,/simulations}`, `POST /twin/impact`, `POST /twin/simulate`, `POST /twin/graph/load`, `GET /estate/evidence/changes{,/{id}}`, `POST /changes/detect`, `POST /changes/{id}/acknowledge` |
| Navigation (§24) | **shipped as the estate tree** — the sidebar's `Estate` section is grouped `Estate → Network → Supply chain → Cryptography → BOM → Digital twin → Intelligence`, so *Certificates* sits under Network, *Algorithm Catalog* under Cryptography and *PQC Readiness* under Intelligence instead of in one list of nineteen screens. Every route that existed still exists, each appears once, and the grouping is asserted in `Layout.navigation.test.tsx` — a nav cannot be checked by clicking, and the failure that matters is a route moving where nobody looks for it | `frontend/src/components/Layout.tsx` |
| UI (§24, §25) | **shipped as eight views**: *Live estate* (placement, completeness with reasons, search with click-through to an asset view, blast radius with paths and blind spots, simulation with BOM diff and a "live twin unchanged" badge); *Crypto graph* (four planes with their meanings on screen); *Catalogue* (asset records with lifecycle, a type filter, per-asset crypto + edges + refused candidates, and the algorithm registry); *Changes* (the change feed — severity, the named claims with before → after and what each does *not* prove, a *detect now* action, and acknowledge); *History & compare* (capture, persisted-vs-derived, worst-first verdict, and stored simulations listed as **quarantined** with `CURRENT`/`STALE` and an "asked N×" counter); *Graph export* (counts, unresolved separate, not-source-of-truth, a *plan the graph-store load* action that sends `dry_run: true` — the console can never write to a graph store); *Loop* (the twelve phases with their status, the question each answers and the first break named — `REMEDIATE` is drawn as not connected rather than coloured green); *Intelligence* (weak in use vs capability only, unidentified values, post-quantum exposure with its vendor-bound blockers, a "who depends on it" query per algorithm, and the trust paths with where each one stops) | `frontend/src/components/DigitalTwinPanel.tsx` |
| Historical snapshots (§14) | **shipped** — persisted (`POST/GET /twin/snapshots`); falls back to run-derived snapshots with `persisted: false` and says so | `estate_twin_store.py` |
| Store parity (§20–§21) | **shipped** — `POST /twin/graph/verify` and `cryptoscan twin graph-verify` compare the store with the projection **id by id per node kind and count per relationship type**, and name what differs: `PARITY`, `MISMATCH` (missing/extra ids, per-type differences), `STALE_ONLY` (a store holding an accumulating history — report, then prune), `NOT_CONNECTED` (not parity). Counting was not enough: a store holding yesterday's nodes *and* today's passes a `>=` test while holding a superseded estate, so the check compares sets | `estate_graph_loader.parity()` |
| Traversal in a graph store (§20–§21) | **shipped for one question at a time** — `GET /twin/graph/traversal` and `cryptoscan twin graph-traversal <asset>` run a bounded walk **in the store** over the same relationship types and depth the twin uses, and compare the reachable **id sets**: `TRAVERSAL_PARITY`, `TRAVERSAL_MISMATCH` (with `only_in_twin` / `only_in_store` named), `NOT_CONNECTED` (not parity), `NO_MATCH`, `NO_TRAVERSABLE_TYPES`. Relationship types are passed as a parameter rather than interpolated, and depth is clamped. A mismatch is reported as *one side answering a different question*, not as the store being wrong. `/twin/graph/verify` still says `traversal_parity: NOT_CLAIMED` because it did not run the walk | `estate_graph_loader.traversal_parity()` |

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

### The simulation workspace (§15–§17)

The console asks the same engine through four endpoints under `/estate/evidence`, because
an operator needs three steps that are not the same request:

| Step | Endpoint | What it answers |
|---|---|---|
| Catalog | `GET /simulation/catalog` | what this estate can be asked: both families and all ten kinds with the question each answers and what it does *not* answer, the estate's own algorithms, protocols, components and assets with counts, and a set of **presets** built from this estate's values and topology |
| Plan | `POST /simulation/plan` | *would this match, would this reach?* — `WOULD_MATCH` / `WOULD_NOT_MATCH`, the evidence records and assets it would touch (or the seeds and waves it would reach), the unresolved targets, and the coverage it was measured against. It projects nothing, so it is cheap, and a `WOULD_NOT_MATCH` says "not 'no impact'" rather than being silent |
| Run | `POST /simulation/run` | the engine's result above, plus the plan it was run under, the `500 simulation_modified_live_state` refusal if the engine ever reports a changed live projection, and the quarantine state of the stored row |
| History | `GET /simulation/runs` | stored runs with `computed_against`, `superseded` / `superseded_by` and `observations` |

The values in the catalog are the ones the collectors reported. A value that is not in
the catalog is not forbidden — it is a value no collector reported, and a scenario using
it will not match; the payload says so rather than presenting an empty list as a rule.
The console's Simulation workspace (`/simulation`) renders those four steps in order and
will not run a question that has not been previewed as reaching something.

#### Two families, ten questions

A **scenario** edits an evidence fact on a copy and re-projects the six BOMs from it:

| Kind | Question | Inputs |
|---|---|---|
| `REPLACE_ALGORITHM` | every use of *from* became *to* | `from`, `to` (optional `key_size`, `targets`) |
| `RETIRE_ALGORITHM` | *from* is withdrawn entirely | `from` |
| `DISABLE_PROTOCOL` | *from* is switched off | `from` |
| `UPGRADE_COMPONENT` | *from* moves to *to* | `from`, `to` |
| `REMOVE_COMPONENT` | *from* is decommissioned, not replaced | `from` |
| `CHANGE_KEY_SIZE` | *from* moves to a *key_size*-bit key | `from`, `key_size` |
| `MIGRATE_QUANTUM_VULNERABLE` | every Shor-vulnerable algorithm became *to* | `to` (the registry decides which, not a typed list) |

A **cascade** changes no evidence at all. It starts from seeds and propagates a failure
over *declared* predicates, in a declared direction, and reports the waves:

| Kind | Seeds | Question |
|---|---|---|
| `CASCADE_ASSET_UNAVAILABLE` | `targets` | the seed stopped serving — what breaks, wave by wave? |
| `CASCADE_CRYPTO_COMPROMISE` | `targets` | the seed's keys/certificates/algorithm are treated as broken — whose assurance follows? |
| `CASCADE_ALGORITHM_BREAK` | every use of `from` | *from* became untrustworthy tonight — what is reached from every use of it at once? |

The rules are shipped with the answer (`rules`: predicate, direction, meaning) so an
operator can see *why* something arrived in wave 2. Two directions exist:
`object_to_subject` — the subject rests on the object (`api runs_on host`), so the object
stopping reaches the subject — and `both`, for containment: a workload of a stopped
system stops with it, and a system holding a stopped workload is degraded. A predicate
that is not listed does not carry that failure, and the payload says so: the radius is a
floor derived from the established topology, not a claim about the estate.

Because a cascade changes nothing, it has **no BOM diff** — `bom_diff` is empty and
`bom_diff_note` says why. Six empty diffs would read as "nothing changes", which is the
opposite of what a cascade answers. `simulated_projection_id` is therefore the live
projection id (no second estate exists), `estate_copy` is `null`, and the run still
asserts `live_state_modified: false` by fingerprinting the graph before and after.

### What a snapshot identifies, precisely

The snapshot id covers assets, relationships, evidence **content** and collector
outcomes. Coverage was added after a defect was found by writing the compare test:
with only facts in the hash, a run where a plane `FAILED` fingerprinted identically
to one where it succeeded over the same (smaller) set of facts — so "we stopped
looking" was indistinguishable from "nothing changed". That is the single most
dangerous comparison this product can get wrong, and it is now a regression test.

### What each fact said, and when

The catalogue remembers *assets*. It cannot answer "what was this asset's algorithm on
Tuesday": a changed attribute was an overwritten column, and the evidence behind it was
only reachable by finding the stored run. Migration 0114 adds the other half of the
memory.

**Evidence records (`estate_evidence`).** One row per evidence record, keyed by the
record's own content-addressed id. The same record observed in forty runs is *one* row
whose `observation_count` is forty — a quiet estate must not look busy — with
`first_seen_at` held from the first sighting and `last_seen_at` advanced each time. A
record a collector stops producing becomes `STALE`; it is never deleted.

**The address is now the *writer's* rule, not just the importer's.** Two defects made
"content-addressed" true only by convention, and both are closed: `add_evidence` fell
back to `ev-<uuid>` for any record whose collector supplied no id, and `make_evidence`
hashed the *unresolved* collector (`None`) while filing the record under
`collector or source` — so a record created without an explicit collector could never
verify, because the verifier reads `agent` and the writer had hashed nothing. The
collector default is now resolved before the address is computed, the fallback is the
content address, and two planes that observe the same fact land on one record instead of
colliding. `GET /evidence/records/{id}/verify` recomputes the address from the stored
row and reports `CONTENT_ADDRESS_INTACT`, `CONTENT_ADDRESS_MISMATCH`, or
`ID_NOT_CONTENT_ADDRESSED` — the last for rows an importer filed under an assigned id,
which are unverifiable rather than suspect. Provenance (`collector_version`,
`raw_reference`, `observed_at`, the run id annotated later) is deliberately outside the
address: upgrading a probe does not change the fact it observed.

**Observations (`estate_observations`).** One row per `(asset, fact_type, value)` with
the window in which that value was the observed truth. `fact_type` names the fact
plainly: `environment`, `owner`, `attribute:region`, `crypto:algorithm`,
`relationship:USES_HSM`. The window is the point:

* a **changed** value adds a row and retires the previous one to `HISTORICAL` — the old
  row keeps `first_seen_at`/`last_seen_at`, so "it was me-central-1 until the 24th" is
  a fact rather than a lost column;
* the same value observed again is a **refresh** — `observation_count` advances and
  nothing is duplicated;
* a value that **returns** is revived in the row it already had, so a flapping region is
  one fact with two windows instead of a growing pile;
* a fact that is **no longer observed** is retired, never deleted. "The region is no
  longer reported" and "the region is stable" are different observations, and only one
  of them is silence;
* **two values still asserted are two `CURRENT` rows** and are reported as a conflict.
  The twin does not pick one. `GET /history/summary` counts disputed facts and names
  them; `cryptoscan twin history` marks them `!`.

`GET /why/{id}?fact_type=…` (§28) answers the auditor's question — the windows each
value held, and the evidence behind the asset with its collector, source, confidence and
sighting history. It also states its limit rather than overclaiming:

> collectors attach evidence to an **asset**, not to an individual attribute: this shows
> the evidence behind the asset, not one record per attribute value.

That is the honest boundary of the current design. Per-attribute provenance would
require every collector to emit one record per attribute, and until they do, an endpoint
that implied otherwise would be a more convincing lie than no endpoint at all.

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
