# Capability record — every console surface, and what it does not do

> Generated from `shared_models/capability_maturity.py` by
> `scripts/gen_capability_maturity.py`. Served live at
> `GET /api/v1/platform/capabilities`.

**89 shipped surfaces, all supported.** The navigation carries no maturity
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
| `/collector-depth` | Discovery | Four measured matrices compiled from the collectors present in this build: runtime observation depth per family (one family reaches call-level; installed is never reported as executed), network protocol readers per protocol (TLS/database handshakes, SSH/IPsec offers, and the protocols with no reader at all listed as absent), Windows layer-by-layer reach with the server's own NO on whether it is a complete Windows collector, and the depth of each of the six BOM projections on the stored snapshot. A fifth tab prints the maturity register: six areas and ~40 surfaces, each naming its collector, the work still missing and the route that proves it, plus the claims the product may and may not make. Every number is echoed from the API; no percentage or score is computed anywhere. |
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
| `/banking-regulatory` | Governance | Banking/SWIFT CSP mapping over the policy engine; regulator-specific packs still growing. |
| `/compliance` | Governance | Requirement-by-requirement reports from policy evidence, 6 templates. |
| `/crypto-assurance` | Governance | KeyAssure checks; 1.7k LOC but a single test module. |
| `/evidence` | Governance | SHA-256 content/chain/manifest hashes, audit packs, verify endpoint. |
| `/governance` | Governance | Access reviews, exceptions, sign-off; 1.9k LOC, 4 test files. |
| `/sectors` | Governance | Sector profiles (bank/telecom/energy) select policy packs; 900 LOC. |
| `/security-policy` | Governance | YAML policy packs (BASELINE/PCI/NIST 131A/CNSA 2.0/FIPS/HIPAA), 82 tests, no AI. |
| `/supervision` | Governance | Supervisory-review view for regulators; a read model over evidence, early. |
| `/trust` | Governance | Trust-score surface; scoring inputs still being defined. |
| `/agility` | Intelligence | Crypto-agility scoring; 900 LOC, 37 tests; scoring model still being calibrated. |
| `/cbom` | Intelligence | Shared Technology BOM (SBOM/CBOM/HBOM/VBOM), snapshots and signed exports; system CBOMs carry real estate dependency edges (SystemAsset + SystemDependency, both directions) and scan CBOMs carry the scanner's observed cascade (providers, waves); the unified cross-BOM cascade answers 'what breaks if X changes' across code, network, system graph, process, hardware, vendor and library layers over the digital-twin snapshot, with persisted run history, run-to-run diffs across every layer, migration-wave grouping, point-in-time replay over captured twin snapshots, and watched targets that alert when the blast radius changes; the Dependency Graph page manages edges and runs cascades in the UI; binary scans additionally expose static NBOM and vulnerability sidecars through Applications. |
| `/crypto` | Intelligence | Algorithm registry + normalized crypto view (114 normalization tests). |
| `/crypto-assets` | Intelligence | Crypto inventory from the normalized findings table. |
| `/crypto-changes` | Intelligence | Change timeline from drift + scan history. |
| `/dependency-graph` | Intelligence | Same graph engine as /graph. |
| `/digital-twin` | Intelligence | Estate replica with measured fidelity, evidence reconciliation and ten deterministic scenario types, fed by live state, wire scans, the dependency graph and the hardware fleet; scenario models are heuristic projections, not vendor simulations. |
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
| `/simulation` | Intelligence | What-if workspace over the estate twin with two families and ten questions: seven scenarios that edit an evidence fact on a copy (replace, retire, disable a protocol, upgrade, remove a component, resize a key, replace everything Shor-vulnerable) and three cascades that walk a failure outward from seeds (asset unavailable, crypto compromise, algorithm breaks everywhere), each previewed before it runs so nothing is read as a finding before it is known to reach something, each re-projecting or explicitly not re-projecting the six BOMs, each reporting the live projection id unchanged, and each stored quarantined against the evidence state it was computed from; scenarios change evidence facts and cascades travel established edges only — neither models configuration, traffic, redundancy, approvals or a deployment plan. |
| `/vbom` | Intelligence | A supplier projection from retained evidence and declarations, not independent supplier validation. |
| `/what-if` | Intelligence | Scenario simulation over the inventory; scenarios are fixed templates today. |
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
