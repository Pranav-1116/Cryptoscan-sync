# ZELNX Cloud Discovery Engine

A read-only, evidence-chained, multi-cloud **crypto discovery engine** for
AWS, Azure and Google Cloud — the cloud counterpart of the network live
scanner. It builds the full estate tree (organization → business unit →
account → region → resources), inventories every compute workload, and
discovers cryptographic keys, certificates, PKI, encryption state, network
crypto, TLS, Kubernetes, serverless, secret references, IAM access and
cross-cloud relationships — then rolls everything into unified posture,
PQC readiness, migration simulation, cost, compliance, drift and
event-driven monitoring.

Entry point:

```python
from cloud_scanner.enterprise import ZelixCloudDiscoveryEngine

engine = ZelixCloudDiscoveryEngine(providers=[...])   # injected adapters
report = engine.discover()
print(engine.report())
```

All I/O is injected through `ProviderAdapter` enumerators — the engine
never makes live cloud calls on its own, unit tests need no SDKs, and
every failure is recorded (never silently swallowed).

---

## 1. Multi-cloud account discovery (§1)

```
Organization
   ├── Business Unit
   │      └── Cloud Account / Subscription / Project
   └── Region
          └── Resources
```

- **AWS** — Organizations: management + member accounts, OUs, multiple
  regions, partition metadata
- **Azure** — tenant: subscriptions, resource groups, regions
- **GCP** — organization: folders → projects, regions and zones

`OrgHierarchyBuilder` normalizes whatever the injected `enumerate_accounts`
/ `enumerate_regions` callables return; truncation and errors are recorded
on the hierarchy, never fatal.

## 2. Full cloud asset inventory (§2)

Every workload carries the full identity context:

```
workload_id | cloud_provider | account | subscription | project | region |
zone | environment | network | application | owner | runtime | os |
container | crypto_usage | certificate_usage | key_dependencies
```

Compute coverage: AWS EC2/ECS/EKS/Lambda/Elastic Beanstalk; Azure
VM/AKS/Functions/Container Apps/App Service; GCP Compute Engine/GKE/
Cloud Run/Cloud Functions/App Engine.

## 3. Cloud cryptographic key discovery (§3)

Key **metadata only** — private key material is never retrieved, stored or
serialized (the scrub contract is enforced by tests):

- AWS KMS: customer-managed + AWS-managed keys, key spec/state/usage,
  rotation config, multi-region, origin, aliases, grants metadata, resource
  dependencies
- Azure Key Vault / Managed HSM: key types, curves, operations, enabled
  state, expiry, rotation policy, HSM-backed keys, access model
- GCP Cloud KMS: key rings, crypto keys + versions, algorithms, purposes,
  protection levels, rotation schedules, HSM protection, dependencies

## 4. Certificate discovery (§4)

Unified certificate graph across clouds:

```
Cloud Certificate
     ├── Used By Load Balancer
     ├── Used By Application
     ├── Issued By CA
     ├── Stored In Vault
     └── Connected To Domain
```

AWS ACM (+ imported, LB/API Gateway/CloudFront, private CA relations);
Azure Key Vault certs (+ App Gateway/Front Door/App Service, private PKI
refs); GCP Certificate Manager (+ LB certs, CA Service relations, workload
refs). `expiring(days=…)` surfaces near-expiry certs.

## 5. Cloud PKI Intelligence Engine (§5)

CA hierarchy + trust graph: root/subordinate/intermediate/issuing CAs,
templates, consumers, expiry, signature and public-key algorithms.
`weak_chains()` flags any chain containing MD5/SHA-1 signatures or
RSA < 2048 — a PQC migration must replace the whole chain, not just the
leaf.

## 6. Cloud encryption discovery (§6)

Per storage/database resource: encryption at rest, encryption in transit,
customer-managed vs provider-managed key, key reference, certificate
reference, algorithm, rotation status, state
(`ENCRYPTED_CMK / ENCRYPTED_PMK / ENCRYPTED_UNKNOWN_KEY /
NOT_ENCRYPTED / UNKNOWN`). Covers S3/Blob/GCS and RDS/Aurora/Azure
SQL/Cloud SQL/Spanner.

## 7. Cloud network cryptography (§7)

TLS profiles + IPsec/IKE proposals + tunnel relationships for
VPC/TGW/VPN/Direct Connect/LB/CloudFront/API Gateway (AWS),
VNet/VPN GW/ExpressRoute/App Gateway/Front Door/API Management (Azure),
VPC/Cloud VPN/Interconnect/Cloud LB/API Gateway (GCP). Weak proposals
(DES/3DES, MD5/SHA-1, DH groups < 2048, no PFS, TLS < 1.2) are flagged.

## 8. Cloud TLS discovery (§8)

Per endpoint: `tls_version, cipher_suites, certificate,
certificate_algorithm, signature_algorithm, key_exchange,
public_key_size, curve, alpn, sni` and a conservative classification:

```
TLS_SECURE | TLS_WEAK | TLS_LEGACY | PQC_MIGRATION_REQUIRED | UNKNOWN
```

An endpoint is only SECURE with TLS ≥ 1.2 and a modern (elliptic) key
exchange; RSA key exchange → `PQC_MIGRATION_REQUIRED` (hybrid/PQC needed);
RSA < 2048 or SHA-1 signatures → WEAK; TLS 1.0/1.1/SSL → LEGACY.

## 9. Kubernetes crypto discovery (§9)

EKS/AKS/GKE cluster posture: API TLS, etcd encryption metadata, secrets
encryption (KMS key reference), ingress TLS + cert-manager issuers, service
mesh + mTLS mode, workload identity, crypto libraries inside workloads and
container image references.

```
Cluster ├── Node ├── Namespace ├── Workload ── Crypto Dependency
        ├── Ingress ── Certificate └── Service Mesh ── mTLS
```

## 10. Serverless crypto discovery (§10)

Lambda / Functions / Cloud Functions / Cloud Run: runtime + version,
dependencies, crypto-library detection (openssl, libsodium, cryptography,
bouncycastle, node-forge, …), environment metadata, KMS/Key Vault
references, certificate references, API TLS relationships.

## 11. Secret & key reference discovery (§11)

**Never scans secret values.** Only the relationship:
`Application ── REFERENCES ── Key/Secret Store ── Crypto Key` across
Secrets Manager, Parameter Store, Key Vault and Secret Manager. Values in
raw rows are scrubbed before normalization (test-enforced).

## 12. IAM & cryptographic access intelligence (§12)

`Identity ── CAN_USE / CAN_ADMINISTER ── Crypto Key`, with identity type,
source/target account and cross-account flags. AWS actions, Azure Key
Vault roles and GCP Cloud KMS roles are classified to CAN_USE /
CAN_ADMINISTER. Credential secrets are never collected.

## 13. Cloud dependency graph (§13)

One typed graph across all three clouds:

```
Application ── RUNS_ON ── Compute
Application ── USES_KEY ── KMS / Key Vault / Cloud KMS
Application ── USES_CERTIFICATE ── Certificate
Application ── EXPOSED_BY ── Load Balancer ── TERMINATES_TLS
```

Supports transitive `dependents()` / `dependencies()` used by posture and
migration simulation.

## 14. Multi-cloud relationship discovery (§14)

```
AWS Application ──▶ Azure API ──▶ GCP Service
```

Typed cross-cloud edges: CROSS_CLOUD_TLS, CROSS_CLOUD_VPN,
PRIVATE_CONNECTIVITY, API_RELATIONSHIP, CERTIFICATE_DEPENDENCY,
DNS_RELATIONSHIP, IDENTITY_FEDERATION — with crypto dependencies per edge.

## 15. Unified crypto posture (§15)

Per-provider + unified metrics: vulnerable assets, weak algorithms,
expiring certificates, non-rotating keys, externally exposed crypto,
critical crypto dependencies, PQC migration candidates, unknown crypto
configurations.

## 16. Cloud PQC Readiness Engine (§16)

Per-resource `PQC_READINESS_SCORE` (0–10) and verdict
`PQC_READY | HYBRID_READY | MIGRATION_REQUIRED | BLOCKED | UNKNOWN`,
analyzing public-key algorithms, certificate algorithms, provider
capability, service compatibility, application dependency, library
compatibility, HSM dependency, network dependency, vendor readiness.
**Never classifies PQC-ready without supporting evidence** — the engine
starts at UNKNOWN and only upgrades when the evidence checklist is
satisfied (test-enforced).

## 17. Cloud migration simulation (§17)

```
CURRENT (AWS Application ── KMS / ACM / ALB TLS)
   ──▶ PROPOSED PQC / HYBRID CHANGE
        ├── Compatibility Analysis ├── Application Impact
        ├── Network Impact ├── Certificate Impact
        ├── Cloud Cost Impact ├── Performance Impact
        └── Rollback Analysis
```

Connects to the existing **network simulation engine**
(`network_scanner.enterprise.simulation.MigrationSimulator`) — tunnel and
dependency edges are mapped onto a network path graph, so path-level
impacts reuse the network simulator when it is importable.

## 18. Cloud cost intelligence (§18)

Nine components — compute, storage, network, HSM, key management,
certificate, logging, migration engineering, vendor — with AWS/Azure/GCP
pricing models, regional multipliers and multiple currencies. Every figure
is labelled `MEASURED | PROVIDER_REPORTED | ESTIMATED | ASSUMED`.

## 19. Cloud compliance mapping (§19)

A framework, not a hard-coded sector: declarative rules
(`ComplianceRule`) map crypto configuration → policy evaluation → control
mapping → evidence → compliance status. Baseline rules (key strength,
rotation, TLS ≥ 1.2, SHA-256+ certs) are sector-neutral; new sectors
(PCI-DSS, EBA, NIST SP 800-57 …) plug in by registering rule sets.

## 20. Cloud drift detection (§20)

Change kinds: certificate changed, KMS key rotation disabled, TLS policy
changed, new public endpoint, new cloud account, key permission changed,
encryption disabled, new crypto algorithm detected — classified
`EXPECTED | APPROVED | UNEXPECTED | HIGH_RISK` (security-relevant kinds
escalate) with alerts. Approved-change registers suppress noise.

## 21. Cloud event-driven monitoring (§21)

```
AWS Events ──▶ Azure Events ──▶ GCP Events
   ──▶ Cloud Event Normalizer ──▶ Crypto Change Detector
   ──▶ CBOM Update ──▶ Policy Evaluation ──▶ Drift Detection
```

Provider envelopes are normalized to one shape, crypto-relevant changes
detected, the event-sourced CBOM updated, policy rules evaluated against
live CBOM state and drift diffed per pass — keeping the CBOM close to a
live cryptographic environment.

## 22. Cloud evidence collection (§22)

Every observation carries provenance — source provider, account, API
source, timestamp, normalization version, evidence hash, confidence —
then:

```
Raw Evidence → Canonical Serialization → Content Hash → Chain Hash
→ Evidence Record
```

`EvidenceChain` links records (`previous_chain_hash`); `verify()` /
`verify_from(sequence)` detect tampering or reordering; reports expose
`evidence_verified`.

## 23. Cloud scan modes (§23)

`INVENTORY_ONLY`, `CRYPTO_DISCOVERY`, `DEEP_CRYPTO_DISCOVERY`,
`CONTINUOUS_MONITORING`, `EVENT_DRIVEN`. Default enterprise mode is
**INVENTORY_ONLY + CRYPTO_DISCOVERY**. All access is read-only unless an
explicitly authorized workflow exists — enforced by construction and
asserted in tests.

---

## Wiring

CLI:

```bash
python -m cloud_scanner.main --zelix \
    --zelix-modes INVENTORY_ONLY,CRYPTO_DISCOVERY,DEEP_CRYPTO_DISCOVERY \
    --zelix-currency USD -o zelix.json
```

Provider adapters are injectable — see
`cloud_scanner.enterprise.providers.fake_provider` for the unit-test
fast path and the enumerator contract for each discovery stage.

Tests: `services/cloud_scanner/tests/test_zelix_*.py` (+ `zelix_fixtures.py`
fake multi-cloud estate) — 174 tests covering all 23 areas with zero SDKs.
