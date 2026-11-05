# Capability record — every console surface, and what it does not do

> Generated from `shared_models/capability_maturity.py` by
> `scripts/gen_capability_maturity.py`. Served live at
> `GET /api/v1/platform/capabilities`.

**92 shipped surfaces, all supported.** The navigation carries no maturity
badges: a product's sidebar is not the place to negotiate what is proven. What
used to be a `beta` or `preview` label is now the **stated limit** column below,
which is the part that actually told an operator something. A support statement
and a completeness statement are different claims, and only the first one is
uniform across the product.

Unknown routes still default **down** to `preview`, never up: a route nobody
wrote a rationale for is not something we have decided to support.

The sidebar is organized into five sections: **Overview, Discovery, Intelligence,
Governance and Administration**. Pages that answer one question share a group —
the six BOMs, the assurance records, remediation, infrastructure — so a section is
a handful of rows rather than a list of every route, and only the section holding
the current page is open on arrival. Deep-linked routes remain in this record
without being duplicated in the sidebar. See the [Navigation & Feature
Reference](NAVIGATION-FEATURE-REFERENCE.md) for the route-to-page map and
role-guarded actions.

| Route | Area | What it is, and its stated limit |
|---|---|---|
| `/admin` | Administration | Admin user management and audit trail. |
| `/automation` | Administration | Playbooks + ITSM/SIEM delivery; 2.3k LOC, 6 test files. |
| `/identity` | Administration | Users, roles, MFA, OIDC/SAML/LDAP, API keys, lockout, audit chain. |
| `/integrations` | Administration | GitHub webhooks, CI gate, SMTP, ITSM/SIEM connectors (burn-in covers them). |
| `/notifications` | Administration | In-app notifications + SMTP; channels beyond email are connectors. |
| `/onboarding` | Administration | Org/connector onboarding flow for SaaS mode. |
| `/organization` | Administration | Org structure + business context seed. |
| `/platform-p2` | Administration | Phase-2 platform features behind one page (marketplace, datalake, anomaly) — each < 700 LOC. |
| `/resilience` | Administration | Backup/DR/air-gap status; scripts are tested, the page is new. |
| `/scope` | Administration | Platform scope self-description (platform_scope.py) — what we do and refuse to do. |
| `/security` | Administration | Security settings surface; overlaps security-center. |
| `/security-center` | Administration | Security posture of the platform itself (headers, rate limits, audit chain verify). |
| `/settings` | Administration | App settings + org profile persisted in app_settings. |
| `/system-health` | Administration | /health, /readyz, /metrics, DB health. |
| `/tenancy` | Administration | Multi-tenant core landed in migration 0057; artifact tenancy sealed at rest; single-tenant is GA. |
| `/invite-accept` | Auth | Tenant invitations belong to the SaaS mode (beta). |
| `/login` | Auth | Password + MFA + SSO login. |
| `/register` | Auth | Self-service signup is for the multi-tenant SaaS mode (migration 0057), which is beta. |
| `/reset-password` | Auth | Token-based reset with SMTP delivery. |
| `/assets` | Discovery | Unified asset inventory (System/CryptoAsset/Certificate) backed by Alembic-managed tables. |
| `/catalog` | Discovery | Hardware/vendor catalog browse. |
| `/certificates` | Discovery | Certificate inventory + expiry from network and source scans. |
| `/cloud` | Discovery | Read-only AWS/Azure/GCP estate scan; 15k LOC, 25 test files. Needs credentials to show data. |
| `/cmdb` | Discovery | CMDB import/resolution; ServiceNow mapping is field-tested with one schema. |
| `/collector-depth` | Discovery | Four measured matrices compiled from the collectors present in this build: runtime observation depth per family (one family reaches call-level; installed is never reported as executed), network protocol readers per protocol (TLS/database handshakes, SSH/IPsec offers, and the protocols with no reader at all listed as absent), Windows layer-by-layer reach with the server's own NO on whether it is a complete Windows collector, and the depth of each of the six BOM projections on the stored snapshot. A fifth tab prints the maturity register: eight areas and ~46 surfaces, each carrying a readiness (OPERATIONAL, CANDIDATE or FOUNDATION) beside its coverage state, the collector behind it, the work still missing and the route that proves it, plus the claims the product may and may not make and the five capabilities it does not present as operational. A sixth tab prints the simulation boundary: the ten enterprise scenarios an engine is asked for, with EXISTS/PARTIAL/ABSENT, the scenario ids that implement each row, and what each cannot compute. Every number is echoed from the API; no percentage or score is computed anywhere. |
| `/dev-sec-ops` | Discovery | SBOM/container/binary/firmware/mobile/WASM scanning, VEX, licence, gates and correlated binary BOM sidecars; bounded evidence and explicit refusal/partial states. |
| `/hardware` | Discovery | HSM/TPM/firmware plugins exist (ADR-014); live hardware collection needs vendor access and has a short field history. |
| `/live-environment` | Discovery | Live environment roll-up of runtime + network. |
| `/live-scanners` | Discovery | Live scan runner status; same orchestrator as /scanners. |
| `/network` | Discovery | TLS/cipher/cert probes; 15k LOC, 33 test files. |
| `/runtime` | Discovery | Host agent findings; agent rollout is per-deployment. |
| `/scanners` | Discovery | Source/network/cloud/container/OT scan triggers over the worker pipeline (12 stages, 29 test files). |
| `/telecom` | Discovery | 5G NF TLS/cert posture; 1.5k LOC with 24 tests; ran against lab targets only. |
| `/vendor` | Discovery | 68 vendor plugins across 16 categories; 14k LOC, 31 test files. |
| `/vendor-due-diligence` | Discovery | Strict versioned supplier profiles and provenance metadata are implemented; approval completeness and external vendor validation still require customer qualification. |
| `/assurance-coverage` | Governance | A source register can be declared and read, but observation and revision writes still lack a console workflow; registration is not coverage. |
| `/assurance-qualification` | Governance | Read-only qualification views exist; supplier and adapter approval writes require separate operator workflows. |
| `/assurance-records` | Governance | Reads immutable assurance revisions, but does not originate or independently approve them. |
| `/assurance-sampling` | Governance | Shows frozen predictions without a score; domain-owner sampling review is not submitted from this page. |
| `/assurance-trace` | Governance | Displays retained relationship evidence and unresolved links, not a verified runtime call graph. |
| `/audit` | Governance | Who did what, when: the hash-chained audit trail with its chain verdict, filterable by actor and action. |
| `/banking-regulatory` | Governance | Banking/SWIFT CSP mapping over the policy engine; regulator-specific packs still growing. |
| `/compliance` | Governance | Requirement-by-requirement reports from policy evidence, 6 templates. |
| `/crypto-assurance` | Governance | KeyAssure checks; 1.7k LOC but a single test module. |
| `/evidence` | Governance | SHA-256 content/chain/manifest hashes, audit packs, verify endpoint. |
| `/governance` | Governance | Access reviews, exceptions, sign-off; 1.9k LOC, 4 test files. |
| `/sectors` | Governance | Sector profiles (bank/telecom/energy) select policy packs; 900 LOC. |
| `/security-controls` | Governance | Read-only inventory of the bank's own controls (firewall/IDS/WAF/HSM/KMS/PKI, 13 types): it records what each control enforces and exports findings; it is not a firewall, an IPS or a rate limiter, and a spec that would mutate a control is refused at registration. |
| `/security-policy` | Governance | YAML policy packs (BASELINE/PCI/NIST 131A/CNSA 2.0/FIPS/HIPAA), 82 tests, no AI. |
| `/supervision` | Governance | Supervisory-review view for regulators; a read model over evidence, early. |
| `/trust` | Governance | Trust-score surface; scoring inputs still being defined. |
| `/agility` | Intelligence | Crypto-agility scoring; 900 LOC, 37 tests; scoring model still being calibrated. |
| `/cbom` | Intelligence | Shared Technology BOM (SBOM/CBOM/HBOM/VBOM), snapshots and signed exports; system CBOMs carry real estate dependency edges (SystemAsset + SystemDependency, both directions) and scan CBOMs carry the scanner's observed cascade (providers, waves); the unified cross-BOM cascade answers 'what breaks if X changes' across code, network, system graph, process, hardware, vendor and library layers over the digital-twin snapshot, with persisted run history, run-to-run diffs across every layer, migration-wave grouping, point-in-time replay over captured twin snapshots, and watched targets that alert when the blast radius changes; the Dependency Graph page manages edges and runs cascades in the UI; binary scans additionally expose static NBOM and vulnerability sidecars through Applications. |
| `/crypto` | Intelligence | Algorithm registry + normalized crypto view (114 normalization tests). |
| `/crypto-assets` | Intelligence | Crypto inventory from the normalized findings table. |
| `/crypto-changes` | Intelligence | Change timeline from drift + scan history. |
| `/dependency-graph` | Intelligence | Same graph engine as /graph. |
| `/digital-twin` | Intelligence | Estate replica with measured fidelity, evidence reconciliation and ten deterministic scenario types, fed by live state, wire scans, the dependency graph and the hardware fleet; scenario models are heuristic projections, not vendor simulations. Simulation is scenario-specific: the PQC migration foundation is real, the generic enterprise engine is not implemented, and the scenario-models read states which of the ten scenarios compute and what each cannot see. |
| `/drift` | Intelligence | Baseline approval + drift events + CI gate; 15 test files. |
| `/estate-twin` | Intelligence | Walks the twin's own chain over one stored snapshot: estate, assets, relationships, crypto graph, evidence graph, history, impact and simulation. Each link reports POPULATED, EMPTY, NOT_EVALUATED or AWAITING_INPUT as the server measured it, and a link the server could not read is never drawn as empty; it needs a stored discovery run and computes no score of its own. |
| `/findings` | Intelligence | Policy-evaluated findings with evidence links. |
| `/graph` | Intelligence | Neo4j dependency graph is optional at runtime (in-process engine is the fallback and the tenant-isolated path); 3.2k+ LOC. Edge management API with provenance (source/created_by/confidence/last_verified), discovered-edge adoption (scanner cascade + graph snapshots → operator approval), declared crypto↔hardware and vendor-of-vendor linkage, and asset-level blast radius (shared asset → union over every using system) are live with tenant-scoped tests; scale evidence on real Neo4j estates is still open. |
| `/hbom` | Intelligence | Hardware BOM view over the Technology BOM; depends on hardware scan coverage. |
| `/libraries` | Intelligence | Library fingerprint database (ADR-007). |
| `/live-asset-intelligence` | Intelligence | The unified BOM console: materialise → version → compare → export. |
| `/migration` | Intelligence | Scan → project → tasks → velocity forecast; forecast model is simple. |
| `/nbom` | Intelligence | Network BOM from authorized network evidence plus static binary capability candidates. Binary-derived records are marked `observed: false` and do not prove a live listener; corroboration requires a separately authorized network probe. |
| `/pqc` | Intelligence | Quantum classification lives in shared_models (176 tests) and runs as a pipeline stage. |
| `/pqc-map` | Intelligence | Geographic/estate PQC map; needs location context the scanners do not collect yet. |
| `/priorities` | Intelligence | Deterministic prioritisation over findings + business context. |
| `/protocols` | Intelligence | Protocol posture view from network scans. |
| `/remediation` | Intelligence | Owned task lifecycle with machine verification against rescan evidence; new surface over the full task API. |
| `/risk` | Intelligence | Risk roll-up; weights documented but not yet regulator-validated. |
| `/sbom` | Intelligence | A versioned software projection over available evidence; deployments and missing component versions remain unproven. |
| `/security-intelligence` | Intelligence | Cross-scanner identity resolution + profiles; roadmap in SECURITY-INTELLIGENCE-ROADMAP.md. |
| `/simulation` | Intelligence | What-if workspace over the estate twin with two families and thirteen question kinds: seven built-in scenarios that edit an evidence fact on a copy (replace, retire, disable a protocol, upgrade, remove a component, resize a key, replace everything Shor-vulnerable), a custom scenario authored as a bounded expression, a COMPOSITE sequence of up to five of those applied in order to one copy (a step may name a stored twin snapshot with as_of, so a plan written against Q2 evidence is judged on Q2's evidence while its change lands on today's estate — a record that has since left the estate is counted, never resurrected, and a date is refused because a date is not evidence), and four cascades that walk a failure outward from seeds (asset unavailable, crypto compromise, algorithm breaks everywhere, a CA or PKI issuer compromised), each previewed before it runs so nothing is read as a finding before it is known to reach something, each re-projecting or explicitly not re-projecting the six BOMs, each reporting the live projection id unchanged, and each stored quarantined against the evidence state it was computed from; scenarios change evidence facts and cascades travel established edges only — neither models configuration, traffic, redundancy, approvals or a deployment plan. This is not a generic enterprise simulation engine: nine of the ten registered scenarios model only part of the mechanism and each says which part it cannot see. |
| `/twin-walkthrough` | Intelligence | The specification's thirteen investigations on one canvas: pick an asset, then step through coverage, identity, relationships, crypto facts, network, hardware/HSM, vendors, evidence records, observation dates, drift, blast radius, the facts a scenario would read and PQC exposure. Every step reads the twin the full screen reads, a failed read is printed as a failed read rather than a zero, and nothing is written or simulated from the canvas. The network step also carries the protocol floor: pick SSLv3 through TLSv1.3 and it reports which observed handshakes negotiated below it, which protocol values this build cannot rank and which assets carry no handshake evidence — the last two published as findings, never as compliance — beside the blind spots it cannot see, beginning with client acceptance, which is not an asset. |
| `/vbom` | Intelligence | A supplier projection from retained evidence and declarations, not independent supplier validation. |
| `/what-if` | Intelligence | Scenario simulation over the inventory; scenarios are fixed templates today, and a question that is not one of them is answered as not modelled rather than approximated. |
| `/reports` | Output | JSON/HTML/PDF reports and schedules over the evidence chain. |
| `/accuracy` | Overview | Detector precision/recall panel; needs labelled ground truth per estate. |
| `/alerts` | Overview | Alert stage output + monitor events. |
| `/command-center` | Overview | Reads the live stats/summary endpoints; empty until a scan runs. |
| `/executive` | Overview | Executive summary over the same stats; presentation layer. |
| `/launch-readiness` | Overview | Gated independent-report, operational-duty and bounded-pilot records; real assessor execution, site exercises and customer acceptance require external evidence. |
| `/live` | Overview | Connection age, stored changes, six BOM downloads and correlated attack patterns. A quiet estate and a stopped agent look identical, so the age is stated; level 3 (incident) is never assigned by the platform, and a pattern reports which collectors corroborate it without raising its level. |
| `/live-monitor` | Overview | Reads actual daemon and estate streams; a live daemon with no enabled schedule does not provide collection coverage. |
| `/live-stream` | Overview | SSE event stream with Last-Event-ID resume and Redis federation. |
| `/operator-decisions` | Overview | Exact-estate decision and condition-proof workflow; local workloads tested, site capacity and deployment acceptance remain open. |
| `/role-dashboard` | Overview | Per-role landing view. |
| `/search-results` | Overview | Cross-inventory search. |
| `/timeline` | Overview | Estate timeline; aggregates several beta sources. |

## Capability boundaries — five things this build does not do

Every surface above is supported; none of them is complete. These five are the
capabilities that get described as if they were operational, so they are stated
here in the same words the API and the console use. Source:
`shared_models/capability_boundaries.py`, which a test pins to the maturity
register (`GET /api/v1/estate/evidence/discovery/maturity`).

| Capability | What is real | May not be presented as | Check at |
|---|---|---|---|
| **Windows collector** (`CANDIDATE`) — Windows support is a candidate implementation, not a production collector: no universal Windows admission and no complete collector. | candidate collectors for OS/uninstall/file/SCM, public certificates, process/module inventory and TPM device info, with the server's own layer-by-layer NO | a production Windows cryptographic collector, or complete Windows SBOM, NBOM, HBOM, VBOM and TechBOM coverage | `/estate/evidence/discovery/windows-collector` |
| **Hardware discovery** (`FOUNDATION`) — Hardware discovery is partial: it walks synthetic and metadata paths, so the product does not perform complete hardware discovery. | a vendor/model/firmware catalogue and plugin seam, fed where a vendor exposes metadata and by synthetic paths where it does not | complete hardware discovery across a bank estate | `/estate/evidence/discovery/maturity` |
| **HSM** (`FOUNDATION`) — The HSM model is metadata — vendor, model, firmware, algorithm capability, key metadata and certificate relationships. It is not proof of actual HSM cryptographic operations. | a PKCS#11 seam for signing, and metadata plus certificate relationships for the assets that depend on a custodian | proof that a key operation ran inside an HSM, or key custody and key-use assurance | `/estate/evidence/discovery/maturity` |
| **Runtime crypto** (`CANDIDATE`) — Runtime discovery establishes process, binary, library and service metadata. That does not establish that a process actually invoked AES-256-GCM, and the platform never presents the two as the same fact. | processes, libraries, listeners, services, packages, certificates and configuration, each carrying the evidence class that produced it | proof of which algorithms a process executed | `/estate/evidence/discovery/runtime-depth` |
| **Simulation** (`FOUNDATION`) — The simulation foundation is real for PQC migration. The generic enterprise engine — TLS downgrade, certificate compromise, HSM failure, KMS failure, crypto-library compromise, supply-chain compromise, trust compromise, service compromise and custom scenario — is not fully implemented, and the product says which of them compute and which do not. | ten deterministic scenarios, four cascades and a bounded sequence of them over collected evidence, plus a per-scenario statement of what each one cannot see | a generic enterprise simulation engine that answers arbitrary what-if questions across every crypto failure mode | `/estate/evidence/twin/simulation-scenarios` |

Read that table the way an operator would: each row names the artifact that
exists, and then the sentence the artifact does not entitle anyone to. Where a
capability is `FOUNDATION`, nothing is collected from a bank's estate at all —
the model and the seam exist, and that is the whole of it.

### Simulation, counted rather than described

1 of 10 scenarios compute today; 9 model part of the mechanism and say what they cannot see. This is not a generic enterprise simulation engine. The per-scenario statement, including what each one
cannot see, is served by `/estate/evidence/twin/simulation-scenarios` and pinned by
`shared/shared_models/tests/test_enterprise_scenarios.py`.
The same counts are in the platform manifest as `simulation_coverage`
(`GET /api/v1/platform/scope`), so the platform's own self-description and this
page cannot diverge without a test failing.

## Retired sidebar entries

These used to appear in the navigation but had no page behind them (they
redirected to the dashboard). They are removed, and a test keeps them out:

- `/activity`
- `/audit-merkle`
- `/cryptographic-digital-twin`
- `/devsecops`
- `/hsm-fleet-orchestrator`
- `/pqc-code-signing-orchestrator`
- `/quantum-entropy-fabric`
- `/realtime-system`
- `/telecom-signaling-analyzer`
- `/twin-analysis-output`
- `/zero-trust-crypto-enforcer`

## Changing an entry

1. Edit `shared_models/capability_maturity.py` (status + a real rationale).
2. `python scripts/gen_capability_maturity.py`
3. `pytest shared/shared_models/tests/test_capability_maturity.py`
