# CryptoLog — Cryptographic Event Intelligence & Verifiable Audit Ledger

_Product specification (source: user-provided design document, 2026-11-07).
Discover · Record · Verify · Correlate · Investigate._

> Example events in this document are illustrative only. They are not actual
> events from any CryptoScan deployment.

## 1. What is Cryptography Log?

Recommended new product module.

Cryptography Log = a centralized, tamper-evident record of cryptographic
events, operations, configurations, observations and changes across an
organization's authorized technology estate.

Imagine a bank has:

- 500 applications.
- 100 databases.
- 50 network appliances.
- 20 HSMs.
- Multiple cloud KMS services.
- Thousands of certificates.
- Hundreds of cryptographic libraries.

CryptoLog should help answer:

1. Which cryptographic algorithms are being used?
2. Which applications are performing cryptographic operations?
3. When was a cryptographic configuration changed?
4. Which key metadata changed?
5. Which certificate was replaced or expired?
6. Which TLS version and cipher suite were negotiated?
7. Which HSM or KMS performed an operation?
8. Was an unexpected cryptographic downgrade detected?
9. Did a new cryptographic dependency appear?
10. Which business systems are affected?

### CryptoLog — Example event stream (Illustrative)

**CRYPTOGRAPHIC_REGRESSION** — 10:42:15 · Payments API · Network observation
TLS 1.3 changed to TLS 1.2 on an observed connection.
Evidence: EV-10294 · Status: Investigation required

**HSM_KEY_METADATA_CHANGE** — 10:39:08 · HSM-04 · HSM observation
Key version metadata changed.
Evidence: EV-10291 · Status: Change observed

**CERTIFICATE_REPLACEMENT** — 10:35:21 · API Gateway · Certificate observation
A new certificate fingerprint was detected.
Evidence: EV-10287 · Status: Expected change pending validation

**CRYPTO_LIBRARY_ADDED** — 10:30:44 · Customer Portal · SBOM observation
A new cryptographic dependency appeared in a deployment.
Evidence: EV-10282 · Status: Observed

Example events only. These are not actual events from your CryptoScan
deployment.

## 2. Three different types of cryptography logging

Separate three capabilities. They have different purposes and evidence
requirements.

**A. Cryptographic activity logging** — records cryptographic activity
observed from authorized sources. Examples: encryption/decryption operation
metadata; signing and verification events; TLS negotiation; HSM operations;
KMS key usage metadata; certificate validation events.

**B. Cryptographic configuration and change logging** — records changes in
cryptographic configuration and assets. Examples: RSA-2048 configuration
introduced; TLS 1.3 configuration removed; certificate replaced; HSM
firmware updated; crypto library version changed; key metadata or lifecycle
state changed.

**C. Cryptographic evidence and audit logging** — records the integrity and
history of what CryptoScan discovered and did. Examples: collector executed;
evidence received; evidence signature verified; finding created; risk
accepted; migration validated; auditor exported a report.

Recommendation: combine these into one CryptoLog product experience, but
preserve their different event types, trust levels and storage semantics.

## 3. Proposed CryptoLog architecture

**1. Cryptographic Event Sources** — Applications · Libraries · TLS · SSH ·
HSM · KMS · PKI · Network · Containers · Cloud · Operating systems

**2. Collection and Agent Layer** — Read-only collectors · Authorized APIs ·
System events · Runtime telemetry · Signed observations

**3. Event Ingestion Gateway** — Authentication · Schema validation · Tenant
validation · Rate limits · Deduplication

**4. CryptoLog Processing Engine** — Normalization · Asset resolution ·
Evidence validation · Classification · Correlation · Event enrichment

**5A. Event Store** — PostgreSQL · Partitioned events · Indexes
**5B. Evidence Vault** — MinIO/S3 · Hashes · Signatures · Original evidence
**5C. Event Intelligence** — Rules · Correlation · Threat patterns
**5D. Historical Index** — Snapshots · Drift · Timelines

**6. Intelligence Correlation** — Digital Twin · Six BOMs · Threat
Intelligence · Risk Engine · PQC Decision Engine

**7. CryptoLog Experience** — Live event stream · Investigation · Search ·
Timeline · Alerts · Reports · Audit

### How the data flows

Example: a bank changes the TLS configuration on its Payments API gateway.

1. The authorized network/configuration collector observes the new
   configuration.
2. The collector creates a structured observation.
3. The observation is signed or otherwise authenticated according to the
   collection contract.
4. CryptoLog ingestion validates its identity, schema, tenant and evidence
   metadata.
5. The processor resolves the gateway's canonical asset ID.
6. The event is compared with the previous known state.
7. A cryptographic change event is created.
8. The event is linked to the Digital Twin.
9. The NBOM and CBOM projections are updated where supported by evidence.
10. Threat Intelligence evaluates whether this is a regression or suspicious
    change.
11. CryptoLog displays the event with its evidence, affected systems and
    investigation status.

This is a natural extension of the existing change-driven observation
architecture.

## 4. CryptoLog event classification

A well-designed event taxonomy — 12 categories:

| Category | Example events |
|---|---|
| CRYPTO_OPERATION | Encrypt, decrypt, sign, verify, key derivation |
| ALGORITHM | RSA, ECC, AES, SHA and PQC algorithm observations |
| KEY_LIFECYCLE | Key creation, rotation, activation, expiry, revocation metadata |
| CERTIFICATE | Issuance, renewal, replacement, expiry, trust changes |
| TLS | Negotiation, protocol, cipher suite, certificate fingerprint |
| SSH | Host key, KEX, cipher and MAC changes |
| IPSEC_VPN | IKE, CHILD SA, transforms and PFS observations |
| HSM_KMS | Key metadata, operation metadata, device state and firmware |
| CRYPTO_LIBRARY | Dependency addition, removal, version and provider changes |
| CONFIGURATION | Algorithm, protocol and crypto policy changes |
| CRYPTO_DRIFT | Unexpected changes and regressions |
| GOVERNANCE | Approvals, exceptions, risk acceptance and audit actions |

For PQC, include event subtypes such as:

- PQC_CAPABILITY_DISCOVERED
- PQC_CONFIGURATION_CHANGED
- PQC_OPERATION_OBSERVED
- PQC_NEGOTIATION_OBSERVED
- PQC_MIGRATION_VALIDATED
- PQC_REGRESSION_DETECTED

**Do not treat PQC capability discovery as proof of PQC usage.**

## 5. Detailed event data model

Every event should have a consistent schema.

### Core CryptoLog event (illustrative schema)

```json
{
  "event_id": "clog_01JEXAMPLE",
  "tenant_id": "tenant_001",
  "event_type": "TLS_NEGOTIATION_OBSERVED",
  "category": "TLS",
  "severity": "INFO",

  "asset_id": "asset_gateway_001",
  "business_system_id": "system_payments",

  "source": {
    "collector_id": "collector_nbom_01",
    "collector_version": "1.0.0",
    "source_type": "NETWORK_OBSERVATION"
  },

  "cryptographic_context": {
    "protocol": "TLS",
    "protocol_version": "TLS1.3",
    "cipher_suite": "TLS_AES_256_GCM_SHA384",
    "key_exchange": "ML-KEM hybrid profile",
    "evidence_level": "NETWORK_NEGOTIATED"
  },

  "observation": {
    "observed_at": "2026-11-07T04:00:00Z",
    "first_seen": "2026-11-07T04:00:00Z",
    "last_seen": "2026-11-07T04:00:00Z"
  },

  "evidence": {
    "evidence_ids": ["evidence_001"],
    "integrity_status": "VERIFIED",
    "signature_status": "VALID"
  },

  "relationships": {
    "related_asset_ids": ["asset_payments_001"],
    "relationship_evidence_ids": ["evidence_002"]
  },

  "processing": {
    "normalization_version": "1.0",
    "rule_version": "1.0",
    "deduplication_key": "example-key"
  }
}
```

Illustrative schema only. The ML-KEM hybrid profile is an example label;
production events must use the exact negotiated group/profile identifier and
source evidence.

### Additional database tables

A dedicated CryptoLog domain in the existing PostgreSQL database:

| Table | Purpose |
|---|---|
| cryptolog_events | Canonical event records |
| cryptolog_event_attributes | Structured event-specific attributes |
| cryptolog_event_assets | Event-to-asset relationships |
| cryptolog_event_evidence | Event-to-evidence relationships |
| cryptolog_event_signatures | Signature and verification metadata |
| cryptolog_event_links | Correlated event relationships |
| cryptolog_event_corrections | Corrections and superseding records |
| cryptolog_rules | Deterministic event rules |
| cryptolog_alerts | Investigation alerts |
| cryptolog_alert_events | Alert-to-event mapping |
| cryptolog_retention_policies | Retention and archive rules |
| cryptolog_checkpoints | Integrity checkpoint metadata |
| cryptolog_consumer_offsets | Processing progress and recovery |

**Important database rule: never overwrite an original event when a
correction arrives. Preserve the original and create a correction or
superseding event with its own provenance.**

## 6. Cryptographic log integrity architecture

A major differentiator: ordinary application logs can be edited or deleted by
someone with sufficient access. CryptoLog should provide verifiable evidence
of whether its records have changed.

Layered integrity architecture:

**Layer 1 — Event hash.** Every event gets a canonical hash.
`H_i = SHA256(CanonicalEvent_i)`. Canonical serialization must be
deterministic: fixed schema version, stable field ordering, explicit null
handling and consistent timestamp representation.

**Layer 2 — Partitioned hash chain.** Events are ordered within a defined
partition, such as tenant and time window. `Chain_i = SHA256(Chain_{i-1} ‖
H_i)`. This detects changes, deletions or reordering within the verified
chain, assuming the checkpoints and verification keys remain trustworthy.

**Layer 3 — Merkle tree.** Build periodic Merkle roots from batches of event
hashes. This enables efficient proof that an individual event belongs to a
committed batch.

**Layer 4 — Signed checkpoints.** Periodically sign the Merkle root and
checkpoint metadata using a protected signing key, preferably managed through
the bank's HSM or approved key-management infrastructure.

**Layer 5 — Independent checkpoint retention.** Keep signed checkpoints in a
separate protected location or immutable storage system. An attacker who
controls both the event database and its only checkpoint store could rewrite
both.

### Integrity verification states

- VERIFIED
- UNVERIFIED
- INVALID_HASH
- CHAIN_BROKEN
- SIGNATURE_INVALID
- CHECKPOINT_MISSING
- ARTIFACT_MISSING

**Do not claim that a hash chain proves the event itself is true.** It proves
integrity relative to the trusted checkpoint and recorded provenance. The
original observation still needs source validation.

## 7. How CryptoLog connects to existing modules

| Existing module | CryptoLog integration |
|---|---|
| SBOM | New dependency and software release events |
| CBOM | Algorithm, crypto operation and key metadata events |
| HBOM | Hardware, firmware, HSM and TPM events |
| NBOM | TLS, SSH, IPsec and network negotiation events |
| VBOM | Vendor, product and firmware lifecycle events |
| TechBOM | Estate-level technology changes |
| Digital Twin | Event timeline and historical asset state |
| Threat Intelligence | Event correlation and suspicious change detection |
| PQC Engine | PQC readiness, migration and regression events |
| Governance | Approvals, exceptions and audit events |

Example investigation: a new RSA-2048 certificate appears on a Payments
gateway. CryptoLog should: (1) record the certificate event; (2) resolve the
certificate fingerprint; (3) find its endpoint relationship in NBOM; (4)
find related cryptographic metadata in CBOM; (5) find the relevant
application in the Digital Twin; (6) check the certificate's approved change
record; (7) evaluate policy and migration implications; (8) generate an
investigation if the change is unexpected. The result is not just a log
entry — it is an evidence-backed investigation path.

## 8. Threat intelligence rules for CryptoLog

Start with deterministic rules rather than an AI-based detection engine.

| Rule ID | Detection | Suggested severity |
|---|---|---|
| CL-001 | TLS protocol downgrade | High |
| CL-002 | Weak cipher suite observed | High |
| CL-003 | Unexpected certificate replacement | Medium/High |
| CL-004 | New weak algorithm configuration | High |
| CL-005 | Unexpected HSM key metadata change | Medium/High |
| CL-006 | Crypto library version regression | Medium |
| CL-007 | Certificate expiry approaching | Medium |
| CL-008 | Unexpected CA trust change | High |
| CL-009 | Crypto policy disabled | High |
| CL-010 | PQC configuration removed | High |
| CL-011 | HSM connectivity or availability degradation | High |
| CL-012 | Collection visibility lost | Medium/High |
| CL-013 | Unapproved cryptographic provider change | Medium/High |
| CL-014 | Unexpected key rotation pattern | Medium |
| CL-015 | Conflicting cryptographic observations | Investigation |

Severity should be calculated using asset criticality, exposure, evidence
quality and policy — not simply event names.

Every alert should include: triggered rule; supporting event IDs; supporting
evidence IDs; affected assets and business systems; expected versus observed
state; what is proven; what is not proven; recommended investigation;
acknowledgment and resolution history.

## 9. Frontend — CryptoLog workspace

A new main navigation item called CryptoLog. (Investigation and event
evidence are the primary experience — the AI assistant is not the main
CryptoLog interface.)

| Screen | Purpose |
|---|---|
| CryptoLog Overview | Event volume, critical changes, integrity and collection health |
| Live Event Stream | Chronological cryptographic events |
| Event Explorer | Search and filter individual events |
| Event Details | Complete event, evidence and asset context |
| Crypto Timeline | Historical asset-level changes |
| Integrity Monitor | Hash chains, checkpoints and verification |
| Threat Correlation | Related events and investigation cases |
| Asset Activity | CryptoLog history for one Digital Twin asset |
| Reports | Auditor and management exports |
| Retention Management | Archival and retention controls |

Event filters: time range; tenant and environment; business system; asset
type; algorithm; event category; severity; evidence classification;
integrity status; collector; event source; PQC status; investigation status.

Event details — five views: (1) event metadata; (2) cryptographic
parameters; (3) original evidence and provenance; (4) Digital Twin
relationships; (5) threat intelligence assessment.

## 10. Security, privacy and performance requirements

Especially important for banks.

### Never log these values (prohibited by default)

- Private keys.
- Secret keys.
- Plaintext.
- Passwords.
- Authentication tokens.
- Session cookies.
- Decrypted application payloads.
- Full HSM key material.
- Raw cryptographic secrets.
- Unnecessary customer identifiers.

CryptoLog should collect metadata, counters, event identifiers and approved
evidence — not secret contents.

### Performance architecture

Do not log every AES encryption or decryption operation individually across
a high-throughput banking system by default. Support three telemetry modes:

| Mode | Collection approach | Use case |
|---|---|---|
| Event mode | Record security-relevant cryptographic events | Key changes, certificate changes, policy changes |
| Aggregate mode | Counters and time-window summaries | High-volume encryption/decryption activity |
| Investigation mode | Temporary, explicitly approved detailed metadata | Focused incident investigation |

Use sampling or aggregation only when the resulting loss of visibility is
clearly documented. **Never use sampling to claim complete event coverage.**

Other requirements: asynchronous collection and ingestion; backpressure and
bounded queues; idempotent event ingestion; tenant-specific quotas;
partitioned event storage; retention and archival policies; signed agent
communication; strict API authentication; collector isolation; no automatic
remediation.

## 11. Implementation plan (eight phases)

**Phase 1 — Event architecture and contracts** (foundation): define the
event taxonomy; create the canonical event schema; define event identity and
deduplication; define provenance and evidence requirements; define privacy
classification; create the event versioning strategy. _Deliverable: CryptoLog
event contract v1._

**Phase 2 — Database and ingestion:** PostgreSQL event tables; ingestion
APIs; tenant and collector identity validation; schema validation;
idempotency; partitioning and indexing. _Deliverable: secure CryptoLog
ingestion service._

**Phase 3 — Integrity and evidence:** event canonical hashing; partitioned
hash chains; Merkle batch roots; signed checkpoints; independent checkpoint
retention; verification APIs. _Deliverable: verifiable event ledger._

**Phase 4 — Collector integration:** NBOM observations; CBOM changes;
HSM/KMS metadata; certificate and PKI events; SBOM and deployment changes;
runtime telemetry adapters where authorized. _Deliverable: multi-source
cryptographic event collection._

**Phase 5 — Intelligence engine:** deterministic event rules; change
correlation; Digital Twin connection; risk assessment; alert lifecycle;
investigation cases. _Deliverable: cryptographic threat intelligence from
event history._

**Phase 6 — Frontend:** overview; event explorer; event details; timeline;
integrity monitor; threat investigation; reports. _Deliverable: complete
CryptoLog workspace._

**Phase 7 — Enterprise hardening:** retention and archival; role-based
permissions; tenant isolation tests; load and backpressure tests; recovery
and checkpoint verification; bank IAM and agent identity integration.
_Deliverable: enterprise deployment candidate._

**Phase 8 — Qualification:** synthetic event corpus; event ordering and
duplicate tests; tampering and deletion tests; collector integration
qualification; high-volume performance tests; real bank pilot acceptance.
_Deliverable: CryptoLog qualification report._

## 12. Proposed repository structure

Keep CryptoLog as a separate bounded domain inside the existing platform,
reusing shared infrastructure rather than building another independent
evidence system. (Proposed structure below — before creating it, inspect the
existing repository to reuse its shared evidence, database, API,
authentication and worker implementations.)

```
CryptoScan/
├── services/
│   └── cryptolog/
│       ├── cryptolog/
│       │   ├── api/            events · search · integrity · timeline · alerts
│       │   ├── core/           event_schema · event_types · event_validator ·
│       │   │                   normalizer · deduplicator · asset_resolver
│       │   ├── integrity/      canonicalization · event_hasher · hash_chain ·
│       │   │                   merkle · checkpoints · verifier
│       │   ├── intelligence/   rules_engine · correlation · risk_engine ·
│       │   │                   investigations
│       │   ├── integrations/   cbom · nbom · hbom · sbom · vbom · digital_twin
│       │   ├── storage/        repository · partitions · retention
│       │   └── workers/        ingestion_worker · correlation_worker ·
│       │                       checkpoint_worker
│       └── tests/              unit · integration · security · performance
└── docs/cryptolog/             01_PRODUCT_SPEC … 10_IMPLEMENTATION_ROADMAP
```

## 13. Suggested APIs

| Method | Endpoint | Purpose |
|---|---|---|
| POST | /api/v1/cryptolog/events | Ingest events |
| POST | /api/v1/cryptolog/events/batch | Batch ingestion |
| GET | /api/v1/cryptolog/events | Search events |
| GET | /api/v1/cryptolog/events/{event_id} | Event details |
| GET | /api/v1/cryptolog/assets/{asset_id}/timeline | Asset cryptographic timeline |
| GET | /api/v1/cryptolog/alerts | Alert listing |
| GET | /api/v1/cryptolog/investigations/{id} | Investigation details |
| GET | /api/v1/cryptolog/integrity/status | Ledger integrity status |
| POST | /api/v1/cryptolog/integrity/verify | Verify a selected range |
| GET | /api/v1/cryptolog/checkpoints | Signed checkpoints |
| GET | /api/v1/cryptolog/statistics | Aggregated event metrics |
| GET | /api/v1/cryptolog/export | Authorized event export |

Use cursor-based pagination for high-volume event streams, strict time-range
limits and tenant-scoped access.

## 14. How CryptoLog differentiates

| Ordinary logging | CryptoLog |
|---|---|
| Records a system event | Records a cryptographic event |
| Shows timestamps | Shows timestamps and cryptographic context |
| Shows log messages | Links structured evidence |
| Searches log text | Searches algorithms, key metadata, certificates and assets |
| Displays alerts | Correlates cryptographic changes |
| Stores records | Verifies event and checkpoint integrity |
| Shows individual events | Connects events to Digital Twin dependencies |
| Reports system errors | Supports PQC migration and crypto-agility investigations |

The key differentiator is cryptographic context + evidence provenance +
asset dependency + historical intelligence.

## 15. Final recommendation

Position CryptoLog as a major sixth intelligence capability inside CryptoScan,
alongside the existing BOMs and Digital Twin.

**Core product capabilities:** cryptographic activity monitoring;
cryptographic configuration change history; tamper-evident event records;
cryptographic threat detection; Digital Twin event correlation; PQC
migration event tracking; enterprise audit and reporting.

**One architectural decision:** CryptoLog must not become a second evidence
database. It should be an event intelligence domain that references the
existing authoritative evidence records and Digital Twin assets.

## 16. Update 2026-11-12 — the eight internal workspaces (user recommendation)

The user's design supersedes the §9 screen list. CryptoLog contains **eight
internal workspaces**. The architecture, the detection example and the data
flow below are RULES the product works by — the user was explicit on
2026-11-12: they are never narrated to the UI. Nothing here invents an
engine: every workspace reads the recorded stores that Phases 1–5 built,
and thin spots are drawn as thin.

| # | Workspace | Implementation |
|---|---|---|
| 1 | Crypto Event Stream | the chronological stream over `GET /cryptolog/events` — the pipeline, example and data flow below govern how it works and are not rendered |
| 2 | Event Explorer | the server-side search and filter surface (asset, category, severity, investigation state, timestamp, evidence) over `GET /cryptolog/events` |
| 3 | Asset Crypto Timeline | per-asset historical changes over `GET /cryptolog/timeline` |
| 4 | Integrity Verification | event digests, hash-chain continuity, signed checkpoints, Merkle proofs and evidence references over `/cryptolog/integrity/*` |
| 5 | Event Correlation | `GET /cryptolog/correlation`: deterministic groups — shared evidence references and recorded asset identity (evidence-backed) and repeated algorithm names (possible dependency, a hypothesis, never an established edge) |
| 6 | Event Rules & Detection | `GET /cryptolog/rules` (the deterministic CL-001… catalogue — a rule is a detection, never a verdict) with the alert lifecycle beneath it |
| 7 | Crypto Audit & Export | `POST /cryptolog/reports/export` + `/reports/verify`, with the retention policy/plan surfaces folded in |
| 8 | Collector & Coverage Health | `GET /cryptolog/overview` collectors (event counts, per-collector first/last seen, asset lists); missing sources and collector errors are **unmeasured** in this build — never zero, never healthy |

### The pipeline (a working rule — not UI copy)

Authorized event sources (Applications · TLS · Certificates · HSM/KMS ·
OS/Kernel · Cloud · Network · crypto libraries) → Event collectors
(read-only adapters · approved APIs · native events · metrics · scheduled
observations) → Event normalization (canonical schema · timestamp
normalization · asset identity · deduplication · classification) → Evidence
reference (source · digest · provenance · confidence) · Integrity engine
(hash chain · signatures · checkpoints) → CryptoLog intelligence (correlation
· rules · change detection · historical timeline) → consumers (Digital Twin ·
Risk & PQC · Governance · Command Center). The consumers strip is drawn with
state **unknown** wherever they appear in code: they read shared registers
and exports, and an automatic feed is not claimed in this build.

### The illustrative detection example (a working rule — not UI copy)

The eight-step sequence — Observed (10:00) → Change detected (10:30) → Event
recorded (10:31) → Integrity verification (10:32) → Correlation (10:33) →
Digital Twin update (10:34) → Risk assessment (10:35) → Verification (later) —
is synthetic — illustrative only, never events from any deployment, and
never shown on screen as if it were a feed.

### How the data moves between pages (a working rule — not UI copy)

Discovery collects authorized HSM metadata and application evidence →
Evidence Processing stores observations and provenance → HBOM records
hardware and firmware → CBOM records cryptographic assets and observed usage
→ SBOM records software dependencies → TechBOM provides the wider technology
inventory → the Digital Twin connects the application and HSM **only if
evidence or an approved mapping establishes that relationship** → CryptoLog
records the cryptographic events and their integrity → PQC Intelligence
evaluates algorithm exposure and migration constraints → Simulation estimates
the impact of a proposed change → Remediation tracks the approved work →
Rescanning verifies the resulting state. The navigation is one connected
workflow, not a collection of dashboards — and this flow is how the product
works, never a panel the operator is told.
