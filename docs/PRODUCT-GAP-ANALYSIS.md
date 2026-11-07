# Product gap analysis by engineering layer

> Saved verbatim from the product review, 2026-11-07. The status labels below
> are planning assessments based on the previous review, not live repository
> test results.
> - **Foundation exists** — Core implementation or design was identified.
> - **Needs completion** — Partial capability or qualification gap was identified.
> - **Major gap** — Important capability remains incomplete or requires proof.
> - **Needs audit** — Current implementation needs verification.

## A. Frontend and user experience

Needs completion

| Module | Required improvement | Acceptance criteria |
|---|---|---|
| Executive dashboard | Estate-wide crypto risk, coverage and PQC status | Every metric links to its underlying records |
| Digital Twin UI | Full asset and relationship exploration | Select an asset and inspect its evidence and dependencies |
| Crypto inventory | Filter algorithms, keys, certificates and usage states | Every record shows evidence classification |
| Threat intelligence | Findings, change timeline and correlated patterns | Each finding shows evidence, explanation and investigation steps |
| Six BOM workspace | Unified BOM navigation and comparison | Cross-BOM relationships are navigable |
| PQC migration | Migration waves, blockers and readiness | Plans are traceable to assets and rules |
| Evidence explorer | Raw evidence metadata, hashes and provenance | Authorized users can verify evidence |
| Governance | Ownership, approvals and exceptions | All actions are audited |
| Search | Global asset, vendor, certificate and evidence search | Search results preserve tenant and permission boundaries |

UI direction: Use an enterprise intelligence console rather than an AI-chat interface. The central screen should be the estate's cryptographic state, not a chatbot.

## B. Backend and API

Needs completion

| Area | Engineering task | Acceptance criteria |
|---|---|---|
| Asset identity | Canonical IDs and alias resolution | Same asset from different collectors is not duplicated |
| Evidence API | Evidence validation and retrieval | Invalid or unrelated evidence references are rejected |
| Relationship API | Evidence-backed graph edges | No unsupported relationship is silently promoted |
| Observation intake | Signed, validated observation ingestion | Signature and coverage state are explicit |
| Drift API | Snapshot comparison and change classification | Failed collection cannot masquerade as asset deletion |
| Threat API | Deterministic correlation and explanation | Every pattern includes supporting evidence |
| PQC API | Readiness and migration calculations | Results are reproducible and versioned |
| Simulation API | Snapshot-based what-if execution | Simulation never modifies production records |
| Reporting API | CBOM, HBOM, NBOM and other exports | Exported facts link back to provenance |
| Governance API | Assignments, exceptions and approvals | Every decision has an actor and audit record |

Additional backend requirements:

- Consistent API versioning.
- Idempotency for observation ingestion.
- Pagination and resource limits.
- Structured error contracts.
- Background-job status and cancellation.
- Tenant-scoped authorization.
- API rate limiting.
- Explicit partial-success semantics.
- OpenAPI specification and contract tests.

## C. Database and evidence storage

Needs completion

Recommended logical separation:

| Storage | Responsibility |
|---|---|
| PostgreSQL | Authoritative assets, evidence metadata, relationships, ownership, policy, audit and snapshots |
| Neo4j | Rebuildable Digital Twin graph projection |
| MinIO / S3 | Protected raw evidence and report artifacts |
| Redis | Cache, locks and short-lived coordination |
| OpenSearch | Optional high-volume investigation search |

The database must support:

1. Stable asset identity.
2. Historical snapshots.
3. Evidence versioning.
4. Relationship history.
5. Conflict preservation.
6. Evidence retention.
7. Tenant separation.
8. Database migrations.
9. Backup and restore.
10. Data lifecycle and retention policy.

Acceptance criteria:

- Rebuilding Neo4j from authoritative records produces the same logical graph.
- Evidence references cannot point to another tenant's records.
- Historical snapshots remain verifiable.
- Database restoration preserves evidence hashes and audit history.
- Duplicate observations do not create duplicate assets or relationships.

## D. Discovery collectors

Needs completion

| Collection plane | Main engineering improvement |
|---|---|
| Source | Parser qualification and build provenance |
| Linux | Production qualification and runtime coverage |
| Windows | CAPI, CNG, Schannel, TPM and certificate qualification |
| Containers | Image digest, package and deployment correlation |
| Network | TLS, SSH, IPsec, topology and hop-level observation |
| Cloud | Account scope, KMS metadata and permission coverage |
| HSM | Real-device qualification and metadata-only collection |
| PKI | CA, certificate, trust-chain and renewal relationships |
| Database | Cryptographic configuration and supported runtime observations |
| Vendor | Product/version/deployment verification |
| CI/CD | Build-to-deployment identity and release provenance |
| OT/ICS | Passive and explicitly authorized collection qualification |

Each collector should publish a standard contract:

- Collector identity and version.
- Supported asset types.
- Required permissions.
- Collection start/end time.
- Target scope.
- Success, partial, refused or failed state.
- Evidence references.
- Coverage metrics.
- Data sensitivity classification.
- Signature or integrity metadata.

Important: A collector that returns zero assets must explain whether it found nothing, lacked permissions, failed, or did not support the target.

## E. Six BOM integration

Cross-BOM integration needs strengthening

Do not treat six BOMs as six independent inventories.

| BOM | Required improvements | Cross-BOM relationship |
|---|---|---|
| SBOM | Build identity, parser completeness, vulnerability/VEX semantics | Software component → crypto library |
| CBOM | Actual usage verification, key metadata, crypto operations | Library → algorithm → operation |
| HBOM | Physical hardware, firmware and HSM qualification | Hardware → HSM → application |
| NBOM | Network topology, negotiated crypto and TLS-hop evidence | Endpoint → certificate → algorithm |
| VBOM | Product/version matching and lifecycle intelligence | Vendor → product → deployed asset |
| TechBOM | Unified estate and technology relationships | All technology assets and systems |

Required feature: Cross-BOM reconciliation.

Example:

- SBOM identifies OpenSSL in a deployed application.
- CBOM identifies cryptographic capabilities or observed operations.
- NBOM identifies TLS negotiation at a network endpoint.
- HBOM identifies the HSM supporting a key operation.
- VBOM identifies the supplier and product version.
- TechBOM connects these facts to the bank's wider estate.

The system must show where evidence agrees, conflicts or is missing. It must not automatically assume that the OpenSSL library is responsible for every TLS connection made by the application.

## F. Digital Twin

Architecture foundation identified / Integration needs completion

| Feature | Required improvement | Acceptance criteria |
|---|---|---|
| Asset identity | Stable canonical identity across collection planes | Multiple observations resolve to the correct asset |
| Relationship resolution | Evidence-backed edges | Every edge has provenance |
| Historical state | Versioned estate snapshots | Changes can be compared over time |
| Ownership | Business and technical owner mapping | Unknown owners remain explicitly unknown |
| Crypto graph | Separate capability, configuration and observed usage | No capability-to-usage promotion |
| Coverage | Collection status linked to assets | Blind spots are visible |
| Impact analysis | Dependency traversal | Affected systems can be explained |
| Graph projection | Rebuildable Neo4j projection | Projection can be regenerated from authoritative data |

Critical missing product behaviour to validate: Can an investigator start with a certificate, find every asset using it, see the evidence for each connection, and determine which business systems could be affected by its expiry?

That is a meaningful Digital Twin acceptance test.

## G. Threat Intelligence engine

Needs deeper productization

Build these functional areas:

| Engine | Required capabilities |
|---|---|
| Change intelligence | Expected vs unexpected changes |
| Cryptographic regression | Weakening algorithms, protocols and configurations |
| Certificate intelligence | Expiry, replacement and trust changes |
| Dependency intelligence | Vulnerable crypto library impact |
| Trust intelligence | CA, issuer and trust-path changes |
| Vendor intelligence | Unsupported product and supplier changes |
| Collection intelligence | Missing observations and reduced visibility |
| PQC intelligence | Quantum-vulnerable asset and migration blockers |

Every finding should contain a consistent structure:

```
finding_id
tenant_id
pattern_id
affected_asset_ids
affected_system_ids
severity
confidence
first_seen
last_seen
evidence_ids
observed_change
expected_state
reason
not_proven
recommended_investigation
status
owner
```

The engine must distinguish:

- A configuration change.
- A suspicious change.
- A correlated pattern.
- A confirmed security incident.

A pattern should never automatically become a confirmed compromise.

## H. PQC decision and migration engine

Strong strategic opportunity / Needs completion

Build the engine in five stages:

1. Inventory: Identify cryptographic assets and evidence.
2. Assessment: Determine quantum exposure, business impact and evidence confidence.
3. Compatibility: Check software, protocol, HSM, KMS and vendor support.
4. Planning: Generate migration waves, blockers and cost assumptions.
5. Validation: Verify actual migration using post-change evidence.

Each asset should have distinct states:

| State | Meaning |
|---|---|
| UNKNOWN | Insufficient evidence |
| CAPABLE | PQC capability identified |
| CONFIGURED | PQC configuration identified |
| OBSERVED | PQC operation observed |
| NEGOTIATED | PQC negotiation observed |
| VALIDATED | Migration evidence meets defined validation criteria |

The migration plan must record its policy version, algorithm profiles, source snapshot, assumptions, cost model and human approvals.

## I. Risk and compliance engine

Needs productization

Create independent risk dimensions:

- Cryptographic strength risk.
- Quantum migration urgency.
- Business criticality.
- Operational dependency risk.
- Vendor lifecycle risk.
- Certificate and trust risk.
- Evidence confidence.
- Discovery coverage risk.

Do not combine all these into an unexplained number.

Compliance should be mapped to specific requirements, evidence and assessment outcomes. A policy match is not automatically proof of compliance.

## J. Governance and enterprise workflows

Major product gap to validate

Required workflows:

- Finding assignment.
- Asset ownership.
- Risk acceptance.
- Exception creation and expiry.
- Remediation plans.
- Approval and sign-off.
- Change management.
- Evidence attachment.
- Remediation verification.
- Audit history.
- Exportable auditor reports.

Suggested integration targets include Jira, ServiceNow, GitHub Issues and bank change-management systems.

## 3. Cross-cutting non-functional requirements

These are requirements across the entire product, not isolated modules.

| Area | Required standard |
|---|---|
| Security | Least privilege, tenant isolation, secure secrets, signed evidence |
| Privacy | No private keys, passwords, tokens or plaintext collection |
| Performance | Bounded collectors, pagination and resource budgets |
| Reliability | Retries, idempotency, failure recovery and durable jobs |
| Scalability | Distributed workers and partitionable workloads |
| Observability | Metrics, traces, logs and audit events |
| Availability | HA architecture and tested recovery |
| Deployment | On-premises installation and controlled upgrades |
| Interoperability | CycloneDX, SPDX and stable documented APIs |
| Governance | Retention, approvals, audit and ownership |
| Quality | Unit, integration, adversarial and end-to-end tests |

## 4. Master development backlog

This is the consolidated implementation backlog I recommend. It is deliberately ordered by dependencies, not by which feature looks most impressive in a demo.

### Phase 1 — Establish trustworthy foundations

P0

- [ ] Complete the previously identified transport credential-leak fix.
- [ ] Complete canonical evidence manifest and hash-chain verification.
- [ ] Validate evidence IDs against tenant, snapshot and asset.
- [ ] Establish a single authoritative evidence model.
- [ ] Add collector coverage and failure semantics.
- [ ] Define canonical asset IDs and relationship vocabulary.
- [ ] Add security regression tests and migration tests.

### Phase 2 — Connect the estate

P1

- [ ] Integrate all six BOMs into one asset identity model.
- [ ] Complete Digital Twin ingestion and graph projection.
- [ ] Add historical snapshots and drift.
- [ ] Add asset aliases and duplicate resolution.
- [ ] Add application and business ownership mapping.
- [ ] Add cross-BOM reconciliation.
- [ ] Add coverage and unknown-state dashboards.

### Phase 3 — Prove cryptographic usage

P1

- [ ] Separate capability, static reference and configuration.
- [ ] Add runtime crypto observation.
- [ ] Add network-negotiated crypto evidence.
- [ ] Add HSM/KMS operation correlation.
- [ ] Add certificate-to-endpoint relationships.
- [ ] Add evidence freshness and confidence.
- [ ] Add conflict resolution without deleting source observations.

### Phase 4 — Intelligence and decisions

P1

- [ ] Implement deterministic threat correlation.
- [ ] Add explainable cryptographic risk dimensions.
- [ ] Complete PQC compatibility analysis.
- [ ] Generate migration blockers and waves.
- [ ] Complete snapshot-based simulations.
- [ ] Add migration cost assumptions and estimation.
- [ ] Add post-migration validation.

### Phase 5 — Enterprise workflow

P2

- [ ] Finding ownership and assignment.
- [ ] Risk acceptance and expiring exceptions.
- [ ] Approval workflows.
- [ ] Remediation ticket integrations.
- [ ] Audit and executive reporting.
- [ ] Vendor lifecycle and supplier risk workflows.

### Phase 6 — Production qualification

P2 / P3

- [ ] Qualify real Linux and Windows environments.
- [ ] Qualify supported HSM and network devices.
- [ ] Complete cloud and database integration testing.
- [ ] Run synthetic large-estate tests.
- [ ] Perform real backup and restore drills.
- [ ] Test HA and disaster recovery.
- [ ] Validate upgrade, rollback and migration procedures.
- [ ] Complete bank-side pilot acceptance.

## 5. Suggested database domain model

The following is a proposed target logical model. It is not a claim that these exact tables are missing from your current database.

| Domain | Core entities |
|---|---|
| Organization | tenants, organizations, environments, business_systems |
| Asset | assets, asset_identifiers, asset_aliases, asset_ownership |
| Relationships | asset_relationships, relationship_evidence |
| Evidence | evidence_records, evidence_artifacts, evidence_signatures |
| Collection | collectors, collector_runs, collection_targets, coverage_records |
| Crypto | crypto_assets, crypto_operations, crypto_algorithms, crypto_keys_metadata |
| BOMs | bom_documents, bom_components, bom_relationships |
| Network | network_endpoints, tls_observations, ssh_observations, ipsec_observations |
| Hardware | hardware_assets, firmware_versions, hsm_metadata, kms_metadata |
| Vendors | vendors, vendor_products, vendor_releases, vendor_declarations |
| Intelligence | threat_findings, threat_patterns, risk_assessments |
| PQC | pqc_assessments, migration_plans, migration_waves, migration_blockers |
| Simulation | simulation_runs, simulation_scenarios, simulation_results |
| Governance | assignments, exceptions, approvals, audit_events |
| History | estate_snapshots, asset_observations, drift_events |

A key database rule: preserve original evidence separately from normalized facts. If a parser changes or a normalization policy improves, CryptoScan should be able to reprocess retained evidence without losing the original observation.

## 6. Product acceptance gates

Before declaring the platform ready for a supervised bank pilot, I would require these gates.

| Gate | Pass condition |
|---|---|
| Evidence integrity | Tampering and invalid references are detected |
| Discovery coverage | Every authorized target has an explicit collection outcome |
| Asset identity | Cross-collector duplicates are controlled |
| Relationship accuracy | Relationships are evidence-backed |
| Crypto truth | Capability is not reported as actual usage |
| BOM consistency | Cross-BOM references reconcile correctly |
| Digital Twin | Historical state and impact are reproducible |
| Threat intelligence | Findings explain evidence and uncertainty |
| PQC planning | Migration recommendations expose assumptions and blockers |
| Tenant security | Cross-tenant access tests pass |
| Recovery | Backup and restore are demonstrated |
| Collector qualification | Supported integrations have documented test evidence |

The synthetic accuracy figures from the earlier Guide 185 review should remain labelled as synthetic results until real-estate qualification supports stronger claims.
