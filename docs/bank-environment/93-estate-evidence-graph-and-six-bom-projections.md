# 93 — One Estate Evidence Engine, Six BOM Projections

Status: **spec stored, engine built** on `arena/bb4b80dd-cryproscan`.
Companions: [`67-network-crypto-discovery-engine.md`](67-network-crypto-discovery-engine.md),
[`92-runtime-crypto-scan-engine.md`](92-runtime-crypto-scan-engine.md),
[`04-six-boms-and-evidence.md`](../questions/04-six-boms-and-evidence.md).

## 1. The correct mental model

> **Do not design CryptoScan as six separate scanners. Design one evidence-discovery
> engine that discovers the entire estate once, then produces six different BOM
> projections from the same evidence graph.**

The six BOMs are **views of the same estate**:

```text
                          CRYPTOSCAN
                             │
                    ┌────────▼────────┐
                    │ Discovery Engine │
                    └────────┬────────┘
                             │
                     Raw Observations
                             │
                    ┌────────▼────────┐
                    │ Evidence Layer  │
                    │ provenance      │
                    │ timestamp       │
                    │ source          │
                    │ target          │
                    │ confidence      │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │ Normalization   │
                    │ + Identity      │
                    │ + Correlation   │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │ Estate Graph    │
                    └────────┬────────┘
       ┌──────────┬──────────┼──────────┬──────────┬──────────┐
       ▼          ▼          ▼          ▼          ▼          ▼
     SBOM       CBOM       HBOM       NBOM       VBOM      TechBOM
```

**Evidence is the source of truth. The BOMs are generated projections.**

This prevents the failure mode where

```text
SBOM says X
CBOM says Y
TechBOM says Z
```

and nobody can say why they disagree. Instead:

```text
Evidence A + Evidence B + Evidence C
        ↓
Correlation
        ↓
Normalized fact
        ↓
BOM projections (all six, same snapshot)
```

## 2. One scan is an estate-discovery job

When the bank runs:

```bash
cryptoscan scan --scope production
```

the product must **not** say "SBOM scan, CBOM scan, HBOM scan, NBOM scan, VBOM scan,
TechBOM scan". It says: scope → estate discovery → evidence collection → normalization
→ correlation → estate graph → six projections.

```text
cryptoscan scan
       │
       ▼
Scope Resolver
       │
       ▼
Estate Discovery
       │
       ├── Compute
       ├── Applications
       ├── Containers
       ├── Kubernetes
       ├── Networks
       ├── Load Balancers
       ├── API Gateways
       ├── Databases
       ├── HSM
       ├── KMS
       ├── PKI
       ├── Certificates
       ├── Vendors
       ├── Cloud
       ├── Hardware
       └── Dependencies
       │
       ▼
Evidence Collection → Normalization → Correlation → Estate Graph
       │
       ├── SBOM
       ├── CBOM
       ├── HBOM
       ├── NBOM
       ├── VBOM
       └── TechBOM
```

## 3. "Nothing should be missed" needs a precise meaning

No scanner can honestly guarantee that every cryptographic fact in an unknown bank
environment is discovered. Counter-examples:

```text
Unknown proprietary appliance
Unknown custom protocol
Undocumented crypto inside firmware
Encrypted traffic that cannot be observed
Application crypto executed once every six months
HSM operation unavailable to the collector
```

So the production goal is:

> **Every authorized and technically observable asset must be attempted, and every
> non-observable area must be explicitly represented as UNKNOWN / NOT OBSERVED /
> PARTIAL rather than silently omitted.**

That is a much stronger claim than "nothing was missed", and it is the claim this
engine implements.

## 4. The Estate Coverage Matrix

For every scan, coverage tells the operator what was attempted and what came back:

```text
Target                Expected     Collected     Status
--------------------------------------------------------
Linux hosts              120          118        PARTIAL
Windows hosts              80           80        COMPLETE
Kubernetes clusters         8            8        COMPLETE
Load balancers             14           14        COMPLETE
HSMs                        6            5        PARTIAL
Databases                  42           42        COMPLETE
Network endpoints         840          821        PARTIAL
Certificates            2,400        2,398        PARTIAL
Containers              1,800        1,800        COMPLETE
Vendors                    75           71        PARTIAL
```

Then:

```text
Scan Coverage: 97.4%
```

**NOT** "97.4% of crypto discovered". These are completely different meanings, and the
engine only ever reports the first one.

## 5. Multiple discovery planes

A comprehensive scan combines several collectors. None of them owns an identity: every
plane emits evidence into the same graph.

### Plane 1 — Compute

Linux, Windows, VMs, physical servers, workstations where authorized, hypervisors,
processes, services, installed packages, binaries, shared libraries, OS, configuration,
certificates.

### Plane 2 — Application

Java, .NET, Python, Go, Rust, C/C++, Node.js, PHP, Ruby, Kotlin. Then inspect source,
dependencies, lockfiles, configuration, environment references, crypto APIs, crypto
providers, native libraries, framework configuration, build artifacts.

The distinction the evidence model must preserve:

```text
OpenSSL installed  ≠  OpenSSL used  ≠  AES-256 used
```

### Plane 3 — Container

Image, digest, layers, OS packages, application packages, libraries, binaries,
configuration, certificates, SBOM, crypto references, runtime. Then correlate
container → pod → deployment → service → application → system.

### Plane 4 — Kubernetes

Cluster, namespace, deployment, statefulset, daemonset, pod, container, image, service,
ingress, gateway, configmap, secret *metadata*, networkpolicy, service mesh, mTLS,
certificates. Secret **values** are never collected.

```text
Cluster → Namespace → Deployment → Pod → Container → Image → Package → Crypto library
```

### Plane 5 — Network

IP, hostname, port, protocol, TLS, SSH, VPN, IPsec, IKE, mTLS, service mesh, database
TLS, message-queue TLS. For TLS:

```text
Client → TLS handshake → negotiated protocol → cipher suite → key exchange
       → certificate → public-key algorithm → signature
```

**SUPPORTED ≠ CONFIGURED ≠ NEGOTIATED ≠ OBSERVED.** These are four different facts and
the CBOM keeps them apart:

```text
Supported:    TLS 1.2, TLS 1.3
Configured:   TLS 1.2+
Negotiated:   TLS 1.3
Cipher:       AES-256-GCM
```

### Plane 6 — Load balancer / ADC

Load balancer, virtual server, listener, frontend, backend pool, TLS policy,
certificate, cipher policy, SNI, ALPN, mTLS, upstream TLS, HSM reference, HA pair,
firmware. Distinguish **TLS termination / passthrough / re-encryption**:

```text
Internet ──TLS 1.3 AES-256-GCM──► External LB ──TLS 1.2 AES-128-GCM──► Payment API
```

Two separate crypto observations, two separate graph edges.

### Plane 7 — HSM (metadata only)

Vendor, model, firmware, HSM id, partition, provider, PKCS#11 configuration, supported
algorithms, key types, key sizes, certificate associations, key *references*, usage
metadata, audit metadata. Never private keys, key material, plaintext or customer
secrets.

Support is not use: "RSA-2048 is actively used" is only ever stated with runtime or
network evidence.

### Plane 8 — KMS

Provider, key id, key type, algorithm, key size, state, usage, rotation, HSM-backed,
certificate relationship, application relationship. `KMS supports AES-256` ≠
`application used AES-256`.

### Plane 9 — Database

Oracle, PostgreSQL, MySQL, SQL Server, DB2, Redis, MongoDB. Depending on authorization:
TLS, mTLS, TDE, encryption-at-rest, wallet/keystore metadata, certificate, cipher,
KMS/HSM reference, backup encryption, connection configuration.

### Plane 10 — PKI and certificates

Root CA, intermediate CA, issuing CA, server/client/code-signing/device/VPN
certificates, HSM-associated certificates. Extract subject, issuer, SAN, validity,
public key, key size, curve, signature algorithm, fingerprint, chain, trust. Detect
SHA-1, RSA-1024, weak curves, expired, near-expiry, orphan, duplicate, unknown-owner.

### Plane 11 — Vendor

VBOM is not an afterthought: vendor, product, version, firmware, support lifecycle,
crypto declaration, SBOM, CBOM, certificates, crypto capabilities, PQC readiness,
evidence source. Classification: `OBSERVED | VENDOR_DECLARED | IMPORTED | INFERRED |
UNKNOWN`. "Product supports AES-256" is a declared capability, never proof of use.

### Plane 12 — Hardware

Servers, CPU, TPM, HSM, NIC, security appliances, payment hardware, smart-card
infrastructure, storage appliances, network appliances, load balancers, firewalls, VPN
appliances. Then: hardware → firmware → software → system → crypto capability.

### Plane 13 — Dependencies

```text
Payment API
    ├── Container ──► OpenSSL 3.0.x
    ├── TLS ────────► External LB
    ├── HSM ────────► RSA-PSS
    └── Database ───► TLS 1.3
```

## 6. Canonical asset model

Each BOM must not invent its own identity. One identity system:

```text
Asset
 ├── asset_id
 ├── type
 ├── name
 ├── environment
 ├── owner
 ├── location
 ├── source
 └── evidence_refs[]
```

`System, Application, Host, Container, Process, Package, Library, Network Endpoint,
Certificate, HSM, KMS Key, Vendor, Hardware` all become graph entities. `asset_id` is
deterministic (type + normalized identity keys), so the same host discovered by the
static, runtime and network planes is one node, not three.

## 7. Relationships

```text
Payment System
      │ contains
      ▼
Payment API
      ├── runs_on ─────► Kubernetes Pod ── uses ──► OpenSSL
      ├── connects_to ─► Load Balancer
      ├── uses ────────► HSM
      └── connects_to ─► PostgreSQL
```

Relationships are what make the estate graph more than a BOM generator — and what make
the six BOMs consistent with each other.

## 8. The six BOMs answer different questions

| BOM | Main question |
|---|---|
| **SBOM** | What software/components exist? |
| **CBOM** | What cryptographic assets/capabilities/usage are established? |
| **HBOM** | What physical/virtual hardware exists? |
| **NBOM** | What network-facing assets/connections exist? |
| **VBOM** | What vendors/products/supply-chain components exist? |
| **TechBOM** | What is the overall technology estate and how is it connected? |

They overlap **through relationships**, but they do not silently duplicate the same
fact.

## 9. Worked example — one payment system

```text
Payment System
 ├── 2 Linux servers
 ├── 1 Kubernetes cluster
 ├── 4 containers
 ├── 1 external LB
 ├── 1 API Gateway
 ├── 1 HSM
 ├── 1 PostgreSQL DB
 ├── 23 packages
 ├── 8 certificates
 └── 3 vendors
```

All six BOMs below come from the **same evidence graph**:

```text
SBOM    nginx · OpenSSL · Java · Bouncy Castle · PostgreSQL
CBOM    TLS 1.3 · AES-256-GCM · X25519 · RSA-3072 · ECDSA-P256 · SHA-256
HBOM    Server · HSM · NIC · Load Balancer appliance
NBOM    Internet→LB · LB→API Gateway · API Gateway→Payment API
        · Payment API→PostgreSQL · Payment API→HSM
VBOM    HSM vendor · LB vendor · OS vendor · Database vendor
TechBOM Payment System · Applications · Containers · Kubernetes · Servers
        · Network · Database · HSM · Certificates · Vendors
```

## 10. The correlation engine

```text
Evidence → Normalization → Identity Resolution → Relationship Engine
        → Estate Graph → Asset graph / Crypto graph / Dependency graph
        → BOM Projection
```

## 11. Never silently infer relationships

`Payment API` and `HSM-01` existing in the same environment does **not** mean
`Payment API → uses HSM-01`. A relationship needs a basis:

```text
configuration · PKCS#11 reference · KMS reference · runtime observation
network relationship · deployment configuration · approved mapping
```

Without a basis:

```text
relationship = UNKNOWN     (never TRUE)
```

## 12. Evidence confidence propagates

```text
Runtime observation  → RUNTIME_OBSERVED   → high confidence
Vendor document      → VENDOR_DECLARED    → lower confidence for estate usage
Package supports AES → CAPABILITY         → not usage
```

Every projected component carries the confidence of the *weakest* evidence it depends
on, plus the list of evidence ids that support it.

## 13. Unknown inventory

Not only:

```text
Crypto Assets: 2,381
```

but:

```text
Crypto Estate

Established:        2,381
Configured:           421
Observed Runtime:     187
Network Observed:     892
Vendor Declared:       93
Imported:              71
Inferred:              38

Unknown / unresolved: 217
```

`Unknown Crypto` then becomes a workflow, not a rounding error. The same applies to
unresolved relationships and to collectors that never returned.

## 14. Scan lifecycle

```text
1  Scope                          14 Existing CBOM ingestion
2  Authorization validation       15 Container/K8s discovery
3  Estate discovery               16 Evidence validation
4  Target enumeration             17 Normalization
5  Collector planning             18 Identity resolution
6  Static collection              19 Relationship correlation
7  Runtime collection             20 Conflict detection
8  Network observation            21 Coverage calculation
9  Hardware discovery             22 Policy evaluation
10 HSM/KMS discovery              23 BOM projection
11 PKI/certificate discovery      24 Drift baseline
12 Vendor discovery               25 PQC analysis
13 SBOM ingestion                 26 Report generation
```

## 15. Do not stop when a collector fails

```text
HSM discovery:
STATUS  = FAILED
Reason  = HSM API unavailable
Result  = HSM inventory = UNKNOWN
Impact  = HBOM incomplete, CBOM correlation incomplete, PQC assessment possibly incomplete
```

A network timeout produces `NETWORK COVERAGE = PARTIAL`, never `NO CRYPTO FOUND`.
A failed collector is never rendered as "none".

## 16. What a CBOM becomes

```text
AES-256-GCM
├── Payment API      → runtime observed
├── External LB      → network observed
├── HSM              → capability observed
└── PostgreSQL       → TLS configured

RSA-2048
├── Certificate CERT-1928 → network observed
└── HSM-04                → capability
```

That is cryptographic intelligence, not a list.

## 17. Target architecture

```text
                    ┌─────────────────┐
                    │   CLI / Web UI  │
                    └────────┬────────┘
                    ┌────────▼────────┐
                    │ Scan Orchestrator│
                    └────────┬────────┘
                    ┌────────▼────────┐
                    │ Scope + Targets │
                    └────────┬────────┘
     ┌───────────────────────┼────────────────────────┐
     ▼                       ▼                        ▼
STATIC PLANE            RUNTIME PLANE            NETWORK PLANE
 ├── Source              ├── Process              ├── TLS
 ├── SBOM                ├── JVM                  ├── SSH
 ├── Packages            ├── .NET                 ├── VPN
 ├── Containers          ├── OpenSSL              ├── IPsec
 ├── Config              ├── HSM                  ├── LB
 └── Binaries            └── KMS                  └── Gateway
     └───────────────────────┼────────────────────────┘
              ┌──────────────▼──────────────┐
              │    INFRASTRUCTURE PLANE     │
              │ Linux/Windows/K8s/Cloud/DB  │
              │ HSM/KMS/PKI/Hardware/Vendor │
              └──────────────┬──────────────┘
                    ┌────────▼────────┐
                    │ Evidence Store  │
                    └────────┬────────┘
                    ┌────────▼────────┐
                    │ Normalization   │
                    └────────┬────────┘
                    ┌────────▼────────┐
                    │ Identity Engine │
                    └────────┬────────┘
                    ┌────────▼────────┐
                    │ Correlation /   │
                    │ Estate Graph    │
                    └────────┬────────┘
        ┌────────────────────┼────────────────────┐
        ▼                    ▼                    ▼
      Assets              Crypto              Relations
        └────────────────────┼────────────────────┘
                    ┌────────▼────────┐
                    │ BOM Projection  │
                    └────────┬────────┘
   ┌──────────┬──────────┬───┴────┬──────────┬──────────┐
   ▼          ▼          ▼        ▼          ▼          ▼
 SBOM       CBOM       HBOM     NBOM       VBOM      TechBOM
```

## 18. Build status

Status legend: **done** = implemented and tested on `arena/bb4b80dd-cryproscan`;
**partial** = implemented with a named limit; **open** = not built.

| Capability | Status | Where |
|---|---|---|
| Canonical asset model with deterministic ids | done | `shared_models/estate_graph.py` (`asset_id`, `normalize_asset`, identity `estate:v1`) |
| Evidence layer with provenance + confidence | done | `make_evidence` — every asset/relationship cites evidence ids; 10 evidence types with HIGH/MEDIUM/LOW confidence |
| Identity resolution across planes | done | `EstateGraph.resolve_identity` (host, image digest, certificate fingerprint, key id, vendor product); merges are reported in `merged_identities` |
| Relationship engine that refuses unsupported edges | done | `EstateGraph.assert_relationship` — no approved basis or no evidence ⇒ `UNKNOWN` in `unresolved_relationships`, never drawn |
| Estate graph + unknown inventory | done | `EstateGraph.unknown_inventory` (usage state, capability-only, assets without evidence, failed collectors) |
| Coverage matrix (attempted vs expected, not "crypto found") | done | `coverage_matrix` / `EstateGraph.coverage` — carries `meaning` and `not_observed` in every response |
| Collector-failure semantics (FAILED ≠ none) | done | `collector_outcome` — a failed plane reports `UNKNOWN` + an impact naming the BOMs that lose coverage |
| Conflict detection | done | `EstateGraph.conflicts` — disagreeing facts are reported, not silently resolved |
| Six BOM projections from one snapshot | done | `project_all` — SBOM, CBOM, HBOM, NBOM, VBOM, TechBOM share one `projection_id` |
| SUPPORTED ≠ CONFIGURED ≠ NEGOTIATED ≠ OBSERVED | done | `usage_state` on every CBOM artefact; vendor/imported evidence can never establish in-use usage |
| API: discovery payload, scan, graph, coverage, BOMs | done | `POST /api/v1/estate/evidence/discover`, `POST …/scan`, `GET …/plan`, `GET …/{summary,graph,coverage,boms}` (`routers/estate_graph.py`; the pre-existing `/estate` campaign router is untouched) |
| Live collector fan-out (one job calling every plane) | done | `api/estate_discovery.py` — six read-only adapters (NETWORK, RUNTIME, STATIC, PKI, HARDWARE, VENDOR) reading *persisted* evidence, joined into one graph, with a collector plan, lifecycle phases and per-plane coverage |
| Console: coverage matrix + unknown inventory + BOM switch | done | `EstatePanel` (`frontend/src/components/EstatePanel.tsx`) mounted on `Network.tsx` |
| Signed/anchored projected BOMs | done | `api/security/estate_bom_anchor.py` + `POST /estate/evidence/boms/anchor`, `GET …/boms/anchors`, `POST …/boms/anchor/verify` — HMAC-SHA256 over `{projection_id, per-BOM digests}` with `CRYPTOSCAN_ANCHOR_KEY` held outside the database; no key ⇒ `409 anchor_key_not_configured`, and the receipt says `external: false` until the operator exports it |
| Drift baseline over the estate graph | done | `api/estate_drift.py` + `GET /estate/evidence/drift` — component-level diff of the six projections between the two newest snapshots, plus coverage deltas; a coverage loss is reported as coverage debt, and a BOM empty in both snapshots is `NOT_COMPARABLE`, never "unchanged" |
| Unknown inventory as a workflow | done | `EstateGraph.unknown_workflow` + `GET /estate/evidence/unknown` — every asset in exactly one state (`ESTABLISHED_RUNTIME_OBSERVED` … `UNKNOWN_UNRESOLVED`), each with a next action; `IMPORTED`/`VENDOR_DECLARED`/`INFERRED` are listed as open work, and unresolved relationships plus failed collectors are counted in `open_work` |
| Estate-wide PQC scoring | done (per layer, no aggregate) | `EstateGraph.pqc_readiness` + `GET /estate/evidence/pqc` — per-artefact `POST_QUANTUM / POST_QUANTUM_HYBRID / CLASSICAL_ONLY / NOT_OBSERVED`, bucketed by layer with `harvest_now_decrypt_later` and a `capability_only` split. `single_score` is `null` on purpose, with the reason stated: one number would mix transport, application, storage and HSM evidence (§27) |

Honest limits: this engine is the **joining and projection layer**. It proves that the
six BOMs are consistent views of one evidence graph; it does not fly drones over the
estate. The fan-out job reads persisted evidence only — it does not probe or scan
anything itself, and a plane that did not run is coverage debt with an impact
statement, never an empty plane. Active collection keeps its own approved scope
(`/network/crypto-observe`, `/runtime/crypto-events`), which is what makes re-running
the estate job free of packets.

Verified by three files: `services/api/tests/unit/test_estate_graph.py` (22 tests:
identity merges, layer separation, refusals, capability≠usage, conflicts, coverage
semantics, API), `test_estate_discovery_job.py` (15 tests: fan-out, FAILED plane ⇒
impact, partial read ⇒ `PARTIAL`, empty store ≠ empty estate, six BOMs on one
`projection_id`, lifecycle order, API plan/scan) and `test_estate_anchor_drift.py`
(14 tests: anchor refuses without a key, signature/`PROJECTION_CHANGED` detection,
`NO_BASELINE` vs `NO_DRIFT` vs `DRIFT`, coverage debt ≠ estate change,
`NOT_COMPARABLE` for one-sided or empty-in-both BOMs). With the network and runtime
suites the eight-file API run is **221 passed**, including the unknown-workflow tests
(vendor claims are open work, not answers; every asset is accounted for exactly once) and
the per-layer PQC tests (an HSM's classical claim never contaminates the transport verdict,
and an unobserved algorithm is `NOT_OBSERVED`, not "classical").

Two properties had to be fixed in the engine to make anchoring and drift mean
anything, both with tests:

* **snapshot ids are content ids.** `fingerprint()` now hashes asset ids,
  relationship content and evidence *content* — not the per-build evidence uuid or
  the wall clock — and `make_evidence` derives a deterministic id from what was
  observed. The same stored discovery therefore fingerprints identically on every
  read, which is what makes "all six BOMs share one snapshot" checkable later.
* **BOM digests ignore render timestamps.** `generated_at`/`observed_at` are dropped
  before hashing (`stable_view`), so a re-rendered projection of unchanged evidence
  does not look like drift.
