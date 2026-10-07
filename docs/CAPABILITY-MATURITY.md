# Capability maturity — what is GA, what is beta, what is preview

> Generated from `shared_models/capability_maturity.py` by
> `scripts/gen_capability_maturity.py`. Served live at
> `GET /api/v1/platform/capabilities`; the console labels every page from it.

The platform ships ~50 services and ~70 console surfaces. They are not equally
proven, and the console says so on every page header. Unknown routes default to
**preview** — nothing is promoted by omission.

The sidebar is organized into six sections: **Overview, Discovery, Intelligence,
Governance, Output and Administration**. It currently has 32 menu slots and 31
unique primary route paths; deep-linked routes remain in the maturity inventory
without being duplicated in the sidebar. See the [Navigation & Feature
Reference](NAVIGATION-FEATURE-REFERENCE.md) for the route-to-page map and
role-guarded actions.

| Tier | Meaning | Surfaces |
|---|---|---|
| **GA** | Production-supported. Deterministic core, broad tests, in the burn-in. | 33 |
| **Beta** | Real code and real data; thinner test coverage or short deployment history. | 31 |
| **Preview** | Working surface over a small engine, or analysis over inputs not yet collected at scale. | 10 |

Total: 74 surfaces.

## GA (33)

| Route | Area | Why this tier |
|---|---|---|
| `/admin` | Administration | Admin user management and audit trail. |
| `/identity` | Administration | Users, roles, MFA, OIDC/SAML/LDAP, API keys, lockout, audit chain. |
| `/integrations` | Administration | GitHub webhooks, CI gate, SMTP, ITSM/SIEM connectors (burn-in covers them). |
| `/scope` | Administration | Platform scope self-description (platform_scope.py) — what we do and refuse to do. |
| `/security-center` | Administration | Security posture of the platform itself (headers, rate limits, audit chain verify). |
| `/settings` | Administration | App settings + org profile persisted in app_settings. |
| `/system-health` | Administration | /health, /readyz, /metrics, DB health. |
| `/login` | Auth | Password + MFA + SSO login. |
| `/reset-password` | Auth | Token-based reset with SMTP delivery. |
| `/assets` | Discovery | Unified asset inventory (System/CryptoAsset/Certificate) backed by Alembic-managed tables. |
| `/certificates` | Discovery | Certificate inventory + expiry from network and source scans. |
| `/cloud` | Discovery | Read-only AWS/Azure/GCP estate scan; 15k LOC, 25 test files. Needs credentials to show data. |
| `/dev-sec-ops` | Discovery | SBOM/container/binary/firmware/mobile/WASM scanning, VEX, licence, gates and correlated binary BOM sidecars; bounded evidence and explicit refusal/partial states. |
| `/live-scanners` | Discovery | Live scan runner status; same orchestrator as /scanners. |
| `/network` | Discovery | TLS/cipher/cert probes; 15k LOC, 33 test files. |
| `/scanners` | Discovery | Source/network/cloud/container/OT scan triggers over the worker pipeline (12 stages, 29 test files). |
| `/vendor` | Discovery | 68 vendor plugins across 16 categories; 14k LOC, 31 test files. |
| `/compliance` | Governance | Requirement-by-requirement reports from policy evidence, 6 templates. |
| `/evidence` | Governance | SHA-256 content/chain/manifest hashes, audit packs, verify endpoint. |
| `/security-policy` | Governance | YAML policy packs (BASELINE/PCI/NIST 131A/CNSA 2.0/FIPS/HIPAA), 82 tests, no AI. |
| `/cbom` | Intelligence | Shared Technology BOM (SBOM/CBOM/HBOM/VBOM), snapshots and signed exports; binary scans additionally expose static NBOM and vulnerability sidecars through Applications. |
| `/crypto` | Intelligence | Algorithm registry + normalized crypto view (114 normalization tests). |
| `/crypto-assets` | Intelligence | Crypto inventory from the normalized findings table. |
| `/drift` | Intelligence | Baseline approval + drift events + CI gate; 15 test files. |
| `/findings` | Intelligence | Policy-evaluated findings with evidence links. |
| `/libraries` | Intelligence | Library fingerprint database (ADR-007). |
| `/live-asset-intelligence` | Intelligence | The unified BOM console: materialise → version → compare → export. |
| `/pqc` | Intelligence | Quantum classification lives in shared_models (176 tests) and runs as a pipeline stage. |
| `/reports` | Output | JSON/HTML/PDF reports and schedules over the evidence chain. |
| `/alerts` | Overview | Alert stage output + monitor events. |
| `/command-center` | Overview | Reads the live stats/summary endpoints; empty until a scan runs. |
| `/live-stream` | Overview | SSE event stream with Last-Event-ID resume and Redis federation. |
| `/search-results` | Overview | Cross-inventory search. |

## Beta (31)

| Route | Area | Why this tier |
|---|---|---|
| `/automation` | Administration | Playbooks + ITSM/SIEM delivery; 2.3k LOC, 6 test files. |
| `/notifications` | Administration | In-app notifications + SMTP; channels beyond email are connectors. |
| `/onboarding` | Administration | Org/connector onboarding flow for SaaS mode. |
| `/organization` | Administration | Org structure + business context seed. |
| `/resilience` | Administration | Backup/DR/air-gap status; scripts are tested, the page is new. |
| `/security` | Administration | Security settings surface; overlaps security-center. |
| `/tenancy` | Administration | Multi-tenant core landed in migration 0057; artifact tenancy sealed at rest; single-tenant is GA. |
| `/invite-accept` | Auth | Tenant invitations belong to the SaaS mode (beta). |
| `/register` | Auth | Self-service signup is for the multi-tenant SaaS mode (migration 0057), which is beta. |
| `/catalog` | Discovery | Hardware/vendor catalog browse. |
| `/cmdb` | Discovery | CMDB import/resolution; ServiceNow mapping is field-tested with one schema. |
| `/hardware` | Discovery | HSM/TPM/firmware plugins exist (ADR-014); live hardware collection needs vendor access and has a short field history. |
| `/live-environment` | Discovery | Live environment roll-up of runtime + network. |
| `/runtime` | Discovery | Host agent findings; agent rollout is per-deployment. |
| `/telecom` | Discovery | 5G NF TLS/cert posture; 1.5k LOC with 24 tests; ran against lab targets only. |
| `/banking-regulatory` | Governance | Banking/SWIFT CSP mapping over the policy engine; regulator-specific packs still growing. |
| `/crypto-assurance` | Governance | KeyAssure checks; 1.7k LOC but a single test module. |
| `/governance` | Governance | Access reviews, exceptions, sign-off; 1.9k LOC, 4 test files. |
| `/sectors` | Governance | Sector profiles (bank/telecom/energy) select policy packs; 900 LOC. |
| `/agility` | Intelligence | Crypto-agility scoring; 900 LOC, 37 tests; scoring model still being calibrated. |
| `/crypto-changes` | Intelligence | Change timeline from drift + scan history. |
| `/dependency-graph` | Intelligence | Same graph engine as /graph. |
| `/digital-twin` | Intelligence | Estate replica with measured fidelity and ten deterministic scenario types, fed by live state, wire scans and the dependency graph; scenario models are heuristic projections, not vendor simulations. |
| `/graph` | Intelligence | Neo4j dependency graph is optional at runtime; 3.2k LOC, 9 test files. |
| `/hbom` | Intelligence | Hardware BOM view over the Technology BOM; depends on hardware scan coverage. |
| `/migration` | Intelligence | Scan → project → tasks → velocity forecast; forecast model is simple. |
| `/priorities` | Intelligence | Deterministic prioritisation over findings + business context. |
| `/protocols` | Intelligence | Protocol posture view from network scans. |
| `/risk` | Intelligence | Risk roll-up; weights documented but not yet regulator-validated. |
| `/executive` | Overview | Executive summary over the same stats; presentation layer. |
| `/role-dashboard` | Overview | Per-role landing view. |

## Preview (10)

| Route | Area | Why this tier |
|---|---|---|
| `/platform-p2` | Administration | Phase-2 platform features behind one page (marketplace, datalake, anomaly) — each < 700 LOC. |
| `/vendor-due-diligence` | Discovery | Strict versioned supplier profiles and provenance metadata are implemented; approval completeness and external vendor validation still require customer qualification. |
| `/supervision` | Governance | Supervisory-review view for regulators; a read model over evidence, early. |
| `/trust` | Governance | Trust-score surface; scoring inputs still being defined. |
| `/nbom` | Intelligence | Network BOM from authorized network evidence plus static binary capability candidates. Binary-derived records are marked `observed: false` and do not prove a live listener; corroboration requires a separately authorized network probe. |
| `/pqc-map` | Intelligence | Geographic/estate PQC map; needs location context the scanners do not collect yet. |
| `/security-intelligence` | Intelligence | Cross-scanner identity resolution + profiles; roadmap in SECURITY-INTELLIGENCE-ROADMAP.md. |
| `/what-if` | Intelligence | Scenario simulation over the inventory; scenarios are fixed templates today. |
| `/accuracy` | Overview | Detector precision/recall panel; needs labelled ground truth per estate. |
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

## Changing a tier

1. Edit `shared_models/capability_maturity.py` (tier + a real rationale).
2. `python scripts/gen_capability_maturity.py`
3. `pytest shared/shared_models/tests/test_capability_maturity.py`
