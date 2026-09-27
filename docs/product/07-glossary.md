# 7. Glossary

| Term | Meaning in CryptoScan |
|---|---|
| **Asset** (crypto asset) | One use of cryptography in the estate — an algorithm/key-size/purpose at a location — deduplicated across collectors. Row in `crypto_assets`; evidence linked via `crypto_asset_evidence`. |
| **Baseline** | The approved state of a system's cryptography. Drift is measured against it. Approval is a recorded human action. |
| **Blast radius** | The set of systems affected if a given component or algorithm is compromised or must change; computed over the dependency graph (BFS; Neo4j or in-database). |
| **Burn-in** | One-shot proof that an integration works against real infrastructure (`scripts/burn_in.py`: GitHub webhook round-trip, live TLS, SMTP, Neo4j, cloud, container). |
| **CBOM** | Cryptographic Bill of Materials — CycloneDX 1.5 document listing crypto components (algorithms, keys, certificates, protocols) with evidence. Covers cryptography found in the estate's **source**; see NBOM for what is exposed on the wire. One of the five Technology BOM views. |
| **Chain hash** | `SHA-256(content_hash ‖ previous chain_hash)` per evidence record; the first record chains to the scan session. Editing or removing any record breaks all later hashes. |
| **CNSA 2.0** | NSA Commercial National Security Algorithm Suite 2.0 — a quantum-resistant algorithm profile; shipped as a policy pack. |
| **Content hash** | `SHA-256` of the canonically serialised finding. |
| **Crypto agility** | How easily an algorithm can be swapped without rewriting the system; scored on six factors per system. |
| **Drift** | A difference between the approved baseline and what a scan observed: asset added, removed or changed, including configuration drift. Produces `drift_events` and can block a CI gate. |
| **Evidence record** | One hashed, chained observation. The unit the chain and the manifest are built from. |
| **Evidence pack** | Hash-manifested export of a scan's evidence for an auditor. |
| **Exception / waiver** | A time-boxed, approved, audited suppression of a specific policy verdict. Never silent. |
| **Fingerprint** | SHA-256 over a canonical Technology BOM state; equal fingerprint → no new snapshot. Also: library fingerprints that identify crypto libraries and versions in binaries. |
| **GA / beta / preview** | Maturity tiers per console surface; see [6. Scope](06-scope-and-readiness.md). |
| **Gate** | A pass / warn / block decision from policy verdicts and drift, used in CI. Also the SBOM gate (advisories, licences, unpinned, signature) with exit codes 0/1/2/3. |
| **HBOM** | Hardware Bill of Materials — HSMs, TPMs, firmware, devices; a Technology BOM view. Depends on hardware-scan coverage. |
| **NBOM** | Network Bill of Materials — CycloneDX 1.5 inventory of what is exposed **on the wire**: listeners, the certificates and cipher suites they serve, and site-to-site tunnels, with a dependency graph. Derived from stored network scans (`network_scan_runs.result`), not declared. Answers a question the CBOM cannot: no repository mentions a load balancer terminating TLS 1.0 for a legacy partner. Conversely the CBOM sees algorithms chosen at runtime that no probe observes — the two are complementary, and the parts that overlap corroborate each other. A Technology BOM view. |
| **HNDL** | Harvest-now-decrypt-later: data protected today by quantum-vulnerable algorithms that an adversary can store and decrypt later. Surfaces in PQC readiness. |
| **Manifest hash** | SHA-256 over all chain hashes of a scan; stored on the scan and included in signed exports. |
| **Materialise** | Build the Technology BOM state from the inventory (`materialize_technology_bom()`). |
| **Monitor** | The daemon that runs scheduled scans of a watch-list and raises alerts once per condition. |
| **Normalisation** | Mapping scanner-specific names and sizes to IANA / NIST / CBOM vocabulary so policy rules apply uniformly. |
| **Platform event** | A durable record (`monitor_events`) plus a live publication for anything notable; delivered over SSE. |
| **Policy pack** | A YAML set of rules with scopes (baseline, PCI-DSS, NIST SP 800-131A, CNSA 2.0, FIPS, HIPAA, UAE). The only source of pass/fail. |
| **PQC** | Post-quantum cryptography. PQC readiness classifies each asset into a NIST IR 8547-aligned migration bucket. |
| **Production guard** | Boot-time refusal to run in `ENVIRONMENT=production` with unsafe configuration (SQLite, demo secrets, `CORS=*`, plaintext admin password). |
| **SBOM** | Software Bill of Materials (CycloneDX 1.5 / SPDX 2.3) per artifact, with resolved and transitive components; a Technology BOM view and the DevSecOps scanner's output. |
| **Blast radius** | For one BOM component, everything that must change if it is replaced. Computed by walking the NBOM dependency graph **backwards** — from a weak certificate to every endpoint serving it and every device terminating those. It is what makes a migration orderable: a flat inventory can say a key is RSA-1024, only the graph can say how much of the estate that key holds up. |
| **Scan** | One execution of a collector over one input, producing findings, evidence and inventory rows. `scans` row; created by a `scan_jobs` job. |
| **Snapshot** | An immutable, fingerprint-addressed version of the Technology BOM (`TECHBOM-YYYYMMDD-HHMMSS`), with a per-layer diff to its parent. |
| **Soak** | A long run of the real pipeline on the real stack, sampling resources every cycle, to find what only shows over time (`scripts/soak.py`). |
| **SSE** | Server-Sent Events — `GET /api/v1/events/stream`, the console's live feed, resumable with `Last-Event-ID`. |
| **Supervisor** | Read-only RBAC role for regulators and external reviewers. |
| **Technology BOM** | The one materialised model with four views — SBOM, CBOM, HBOM, VBOM — plus dependency edges; versioned as snapshots; exported and signed. |
| **VBOM** | Vendor Bill of Materials — vendors, products, lifecycle and risk; a Technology BOM view. |
| **Verify** | Recompute every hash of a scan's chain and compare the manifest (`GET /scans/{id}/verify` → `chain_intact`, `PASS`/`FAIL`). Also `/sbom/{id}/verify` for artifacts and the audit-log verifier. |
| **VEX** | Vulnerability Exploitability eXchange — per-advisory statements (`exploitable`, `not_affected` with justification) attached to an SBOM. |
| **Workspace** | The per-job directory the worker clones and scans in; removed when the job ends. |
| **Scanner gate** | The fail-closed chain (WHO → TENANT → AUTHORIZATION → SCOPE → PRIVACY POLICY → SCAN POLICY → RATE LIMIT → TARGET SAFETY → CREDENTIAL) every scan request passes before a job is queued; pure and deterministic (`privacy/gate.py`). |
| **Vault lease** | A short-lived, scoped grant to use a credential by reference during a scan; the secret itself is never stored by the platform (`services/vaultlease`). |
| **Scan mode** | discovery, standard, deep, passive, continuous, targeted, compliance or pqc — declares active probing, depth and whether the mode ever mutates a target. |
| **Data class** | PUBLIC, SENSITIVE or RESTRICTED — decides whether a value may be retained, masked or only fingerprinted (`privacy/classify.py`). |
| **Verification state** | VERIFIED, PROBABLE, UNVERIFIED, CONFLICTING, UNKNOWN or STALE — how well an asset's existence is corroborated across sources. |
| **Identity key** | (asset type, canonical algorithm, canonical location, key size) hashed with SHA-256 — the formula that makes several sightings one asset (`services/deduplication`). |
| **Merged confidence** | VERIFIED / HIGH / MEDIUM / LOW derived from how many independent scanner families agree. |
| **Mosca's inequality** | x + y > z, with x = data shelf-life, y = migration time (an input), z = years to a cryptographically relevant quantum computer; true means you are already late (`quantum/plan.py`). |
| **Migration wave** | 1, 2 or 3 — the order in which systems should migrate, from agility readiness and quantum score (`services/agility`). |
| **SLA state** | OPEN, ON_TRACK, AT_RISK, BREACHED, RESOLVED against fixed deadlines by severity (CRITICAL 7 d … INFO 365 d). |
| **KeyAssure** | The certificate, key and TLS assurance engine: TLS audit, CT monitoring, expiry rules, HSM residence, trust stores, hybrid-PQC downgrade detection. |
| **Blast radius** | The set of systems reachable from an asset through the dependency graph, with summed business impact. |
| **Sector profile** | One of eleven catalogues (banking, healthcare, energy, telecom, government, manufacturing, automotive, pharmaceutical, retail, cloud_saas, generic) that set frameworks, criticality tiers, allowed scan modes and quantum weight. |
| **Plan** | FREE / PRO / ENTERPRISE tenant quotas for targets, scans per month and users; exceeding one returns 402 quota_exceeded. |
| **SVID** | A short-lived SPIFFE-style workload certificate issued to scanners and workers for mTLS to the API. |
| **Data-lake batch** | An append-only export unit with per-record hashes, a batch digest and a link to the previous batch's digest. |

Back to [the product overview](README.md).

Continue with [8. The engines behind the pages](08-platform-engines.md) and [9. End to end](09-end-to-end.md).
