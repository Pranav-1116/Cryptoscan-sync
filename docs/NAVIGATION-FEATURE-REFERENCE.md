# CryptoScan console navigation and feature reference

> **Source of truth for this page:** `frontend/src/components/Layout.tsx` for
> the sidebar and `frontend/src/App.tsx` for routed pages. When a menu item or
> route changes, update this page in the same change. This is documentation of
> the current repository, not a product promise or an external assurance claim.

The console has **five primary sidebar sections**, **30 rows** and **74 links**.
Pages that answer one question share a **group** — the six BOMs, the five
assurance records, remediation, infrastructure, monitors, oversight, posture,
dependencies, simulation and system health — and a group is a disclosure: the pages inside it are
one click away and only rendered when it is opened. Only the section holding the
current page is open on arrival, so an operator reads about six rows, not all
seventy-four links.
The duplicate `Security Center` placement is gone: the route is reached once, as
**Audit log** under Governance, and the header's Security Center button opens the
admin drawer rather than a second nav row.

The root route `/` redirects to `/command-center`. Login and account recovery
routes are authentication flows, not primary navigation entries.

## Primary sidebar

**Reviewed 2026-11-11.** The table below matches every current sidebar placement.
Rows with a group render as a disclosure; the `—` rows are links.

### Overview

| Sidebar label | Group | Route | Component | Purpose |
|---|---|---|---|---|
| Dashboard | — | `/command-center` | `CommandCenter` | Current estate summary, scan state, risk and live activity entry points. |
| Live estate | — | `/live` | `LiveEstate` | Connection age, stored changes, six BOM downloads and correlated attack patterns. A quiet estate and a stopped agent look identical, so the age is stated; level 3 (incident) is never assigned by the platform. |
| Activity | — | `/live-stream` | `LiveStream` | Durable activity and event stream with live updates. |
| Monitors | Monitors | `/live-monitor` | — | One row over the two live runners. |
| Live monitor | Monitors | `/live-monitor` | `LiveMonitor` | Watch-list daemon and estate streams; a live daemon with no enabled schedule is not collection coverage. |
| Live scanners | Monitors | `/live-scanners` | `LiveScanners` | Live scan runner status; same orchestrator as /scanners. |
| Oversight | Oversight | `/launch-readiness` | — | One row over the two preview oversight workspaces. |
| Launch readiness | Oversight | `/launch-readiness` | `LaunchReadiness` | Gated independent-report, operational-duty and bounded-pilot records; real assessor execution, site exercises and customer acceptance require external evidence. |
| Operator decisions | Oversight | `/operator-decisions` | `OperatorDecisions` | Exact-estate decision and condition-proof workflow; local workloads tested, site capacity and deployment acceptance remain open. |

### Discovery

| Sidebar label | Group | Route | Component | Purpose |
|---|---|---|---|---|
| Scan | — | `/scanners` | `Scanners` | Start and monitor authorized collection jobs. |
| Assets | — | `/assets` | `Assets` | Browse the unified asset inventory; detail carries identity spine, facts, blast radius and the remediation tasks bound to the asset's evidence. |
| Applications | — | `/dev-sec-ops` | `DevSecOps` | Source, container, SBOM, binary and firmware workflows. |
| Certificates | — | `/certificates` | `Certificates` | Live TLS-scan view plus the persisted estate: fingerprint-deduped rows, where observed, honest revocation checks and ownership assignment. |
| Vendors | — | `/vendor` | `Vendor` | Vendor, product and supply-chain relationships. |
| Infrastructure | Infrastructure | `/network` | — | One row over the three infrastructure surfaces. |
| Network | Infrastructure | `/network` | `Network` | Review network inventory and authorized network-scan results. |
| Cloud | Infrastructure | `/cloud` | `Cloud` | Review connected AWS, Azure and GCP inventory. |
| Hardware | Infrastructure | `/hardware` | `Hardware` | Hardware, HSM, TPM and firmware inventory. |

### Intelligence

| Sidebar label | Group | Route | Component | Purpose |
|---|---|---|---|---|
| BOMs | BOMs | `/cbom` | — | The six projections of one evidence graph, behind one row. |
| CBOM | BOMs | `/cbom` | `Cbom` | Cryptographic assets, algorithms, libraries and protocols in the same shell as SBOM/NBOM/VBOM: headline cards, breakdown panels and an identity inventory, with the estate-wide counts from `/cbom/query`'s own summary. |
| SBOM | BOMs | `/sbom` | `Sbom` | Software components and dependency edges. |
| HBOM | BOMs | `/hbom` | `Hbom` | Live-scan BOM plus the independent unified estate HBOM — content-addressed pins with pin-to-pin diff. |
| NBOM | BOMs | `/nbom` | `Nbom` | Network BOM view; static binary capability candidates remain separate from live network observations. |
| VBOM | BOMs | `/vbom` | `Vbom` | A supplier projection from retained evidence and declarations, not independent supplier validation. |
| Technology BOM | BOMs | `/live-asset-intelligence` | `LiveAssetIntelligence` | Materialize, compare, export and review the unified Technology BOM state. |
| Dependencies | Dependencies | `/dependency-graph` | — | The graph engine and its explorer. |
| Cascade | Dependencies | `/dependency-graph` | `DependencyGraph` | Directional blast radius across the estate graph. |
| Graph explorer | Dependencies | `/graph` | `Graph` | Relationships, dependencies and blast-radius exploration. |
| Posture | Posture | `/findings` | — | What the estate is failing, and how removable it is. |
| Cryptography | Posture | `/crypto` | `Crypto` | Algorithm registry + normalized crypto view (114 normalization tests). |
| Algorithm catalog | Posture | `/crypto-assets` | `CryptoAssets` | Normalized cryptographic asset inventory. |
| Findings | Posture | `/findings` | `Findings` | Policy-evaluated findings with evidence links. |
| PQC readiness | Posture | `/pqc` | `Pqc` | Quantum-vulnerability classification and migration readiness. |
| Crypto agility | Posture | `/agility` | `Agility` | Deterministic replaceability and migration-planning signals. |
| Crypto drift | Posture | `/drift` | `Drift` | Approved-baseline changes and drift events. |
| Digital twin | — | `/digital-twin` | `DigitalTwin` | Estate replica with measured fidelity, evidence reconciliation and ten deterministic scenario types, fed by live state, wire scans, the dependency graph and the hardware fleet; scenario models are heuristic projections, not vendor simulations. |
| Simulation | Simulation | `/simulation` | — | Asking a question of a copy of the twin. |
| What-if workspace | Simulation | `/simulation` | `Simulation` | Two families over the estate twin, each previewed before it runs: **scenarios** (replace / retire an algorithm, disable a protocol, upgrade or remove a component, resize a key, replace everything Shor-vulnerable) are applied to a copy and the six BOMs re-projected from it; **cascades** (asset unavailable, crypto compromise, algorithm breaks everywhere) walk a failure outward from seed assets, wave by wave, and change nothing so they carry no BOM diff. Both report the live projection id unchanged and store the answer quarantined against the evidence state it was computed from; scenarios change evidence facts and cascades travel established edges only — neither models configuration, traffic, redundancy, approvals or a deployment plan. |
| Migration what-if | Simulation | `/what-if` | `WhatIf` | Read-only migration feasibility over the inventory; the scenarios are fixed templates. |
| Reports | — | `/reports` | `Reports` | Reports, exports and report delivery status. |

### Governance

| Sidebar label | Group | Route | Component | Purpose |
|---|---|---|---|---|
| Banking & SWIFT | — | `/banking-regulatory` | `BankingRegulatory` | Banking, payment and SWIFT-oriented regulatory mapping. |
| Policies | — | `/security-policy` | `SecurityPolicy` | Deterministic policy packs, scope and policy decisions. |
| Compliance | — | `/compliance` | `Compliance` | Framework mappings and compliance evidence. |
| Evidence | — | `/evidence` | `Evidence` | Hashes, manifests, scan and per-record verification (with an X-of-Y coverage line), and the filterable, exportable audit ledger. |
| Remediation | Remediation | `/remediation` | — | The task lifecycle, its ranking and the migration plan. |
| Tasks | Remediation | `/remediation` | `Remediation` | Owned task lifecycle with machine verification against rescan evidence. |
| Priorities | Remediation | `/priorities` | `Priorities` | Deterministic prioritisation over findings + business context. |
| Migration | Remediation | `/migration` | `Migration` | Scan → project → tasks → velocity forecast; forecast model is simple. |
| Assurance | Assurance | `/assurance-records` | — | The five assurance surfaces behind one row. |
| Records | Assurance | `/assurance-records` | `AssuranceRecords` | Independent-report and operational-duty records. |
| Coverage | Assurance | `/assurance-coverage` | `AssuranceCoverage` | Registered coverage of the assurance programme. |
| Application trace | Assurance | `/assurance-trace` | `AssuranceTrace` | Requirement trace from an application to its evidence. |
| Accuracy sampling | Assurance | `/assurance-sampling` | `AssuranceSampling` | Sampling plan and measured accuracy. |
| Qualification | Assurance | `/assurance-qualification` | `AssuranceQualification` | Local qualification results; site acceptance requires external evidence. |
| Audit log | — | `/security-center` | `SecurityCenter` | Platform security posture and operational controls. |

### Administration

| Sidebar label | Group | Route | Component | Purpose |
|---|---|---|---|---|
| System health | System health | `/system-health` | — | One row over the two platform-introspection pages. |
| System health | System health | `/system-health` | `SystemHealth` | Health, readiness and platform service status — with independently measured worker-fleet and connector health (never derived from API liveness). |
| State machines | System health | `/state-machines` | `StateMachines` | The canonical state machine register on screen: every state the product can be in — observed from code, never invented — with one tone per semantic class, the transitions code actually makes, the honesty invariants, and machines whose vocabulary is not yet observed listed as such instead of guessed. The same register is machine-readable (shared_models state machines module and the console's library copy, pinned byte-identical by tests). See [state machine register](state-machines/README.md) and the [developer reference](api-reference/state-machines.md). |
| Settings & org | — | `/settings` | `Settings` | Organization and application settings. |
| Users & teams | — | `/identity` | `Identity` | Users, roles, MFA and identity administration. |
| Integrations & API | — | `/integrations` | `Integrations` | Connectors, API and delivery integrations. |

## Sidebar actions and access behavior

- **Start Scan** links to `/scanners` and is rendered only after the server-
  verified session contains one of `superadmin`, `ciso`, `security_analyst`,
  `developer` or `scanner`.
- The sidebar's role check is a usability guard, not authorization. The API
  remains authoritative and must reject unauthorized mutations.
- The sidebar renders **no** maturity pill. Every shipped surface is supported
  (`shared_models/capability_maturity.py`); what a surface does *not* do is
  stated with the surface, on `/scope` and in
  [CAPABILITY-MATURITY.md](CAPABILITY-MATURITY.md). A limitation belongs next to
  the screen it applies to, not in the navigation.
- The signed-in session and roles come from `GET /api/v1/auth/me`; local storage
  is only a first-paint hint and must not authorize an action.
- The collapsed sidebar preserves the same routes and exposes item labels as
  tooltips; group rows expand the sidebar instead of opening a submenu with no
  text in it. English and Arabic layouts share the same route map.
- A section and each group remember whether they are open
  (`zelnx-nav-open`), and a route inside a closed group still opens that group
  on arrival — the navigation follows the page you are on.

## Routed pages reached by deep link

These actual page routes are not current sidebar placements. Some were formerly
deep links and now have sidebar entries; use the primary table rather than an old
menu screenshot. Listed routes are not an assertion of production-profile enablement.

| Route | Component |
|---|---|
| `/accuracy` | `Accuracy` |
| `/admin` | `Admin` |
| `/alerts` | `Alerts` |
| `/automation` | `Automation` |
| `/catalog` | `Catalog` |
| `/cmdb` | `Cmdb` |
| `/crypto-assurance` | `CryptoAssurance` |
| `/crypto-changes` | `CryptoChanges` |
| `/executive` | `Executive` |
| `/governance` | `Governance` |
| `/libraries` | `Libraries` |
| `/live-environment` | `LiveEnvironment` |
| `/notifications` | `Notifications` |
| `/onboarding` | `Onboarding` |
| `/organization` | `Organization` |
| `/platform-p2` | `PlatformP2` |
| `/pqc-map` | `PqcMap` |
| `/protocols` | `Protocols` |
| `/resilience` | `Resilience` |
| `/risk` | `Risk` |
| `/role-dashboard` | `RoleDashboard` |
| `/runtime` | `Runtime` |
| `/scope` | `Scope` |
| `/search-results` | `SearchResults` |
| `/sectors` | `Sectors` |
| `/security` | `Security` |
| `/security-intelligence` | `SecurityIntelligence` |
| `/supervision` | `Supervision` |
| `/telecom` | `Telecom` |
| `/tenancy` | `Tenancy` |
| `/timeline` | `Timeline` |
| `/trust` | `Trust` |
| `/vendor-due-diligence` | `VendorDueDiligence` |

Authentication/entry routes are `/login`, `/register`, `/reset-password` and
`/invite-accept`; self-serve registration is not enabled merely by a route existing.
The root `/` and unknown authenticated paths redirect to `/command-center`.
`/audit` redirects to `/security-center`; `/techbom` redirects to
`/live-asset-intelligence`. The backend still controls authorization and availability.

**Launch readiness** and **Operator decisions** remain **Preview**. Launch records
track independent reports/retests, nine-duty ownership/exercises and a bounded
six-BOM payments pilot; no page manufactures an assessor, SLA or customer acceptance.
See [current implementation status](CURRENT-IMPLEMENTATION-STATUS.md).

## Feature ownership by navigation area

| Area | Main evidence and outputs |
|---|---|
| Overview | Live events, scan status, summary metrics and the current Technology BOM state. |
| Discovery | Authorized source, dependency, container, binary, firmware, network, cloud, hardware, certificate and vendor observations. |
| Intelligence | SBOM/CBOM/HBOM/NBOM/VBOM correlations, vulnerability BOM findings, graph relationships, PQC and agility analysis, and simulation: a scenario previewed against the twin's own selectors and run on a copy with the six BOMs re-projected, or a failure cascaded outward from seed assets wave by wave; both stored quarantined. |
| Governance | Deterministic policy, compliance mappings, approvals, audit history, assurance records, remediation and evidence verification. |
| Administration | Health, the platform's own state vocabulary (the state machine register), organization, identity, security posture, integrations and API access. |
| (folded into Intelligence) | Reports, signed/exportable artifacts and both what-if surfaces now sit under Intelligence — Simulation (the workspace and the older migration what-if) and Reports; the separate Output section existed only to hold three links. |

### Binary application workflow

The **Applications** page is the console entry point for the binary inventory
pipeline. One bounded binary or firmware scan can materialize:

- **SBOM:** binaries, packages, libraries, versions, hashes, dependency edges,
  nested provenance and package/signing metadata;
- **CBOM:** algorithms, cryptographic libraries, protocols, key/certificate
  metadata, evidence level, confidence and PQC/migration status;
- **HBOM:** architecture, machine type, firmware/container identity, device-tree
  and image/bootloader context, with explicit unknown fields;
- **NBOM:** static network capability/listener candidates with `observed: false`
  until a separately authorized network probe corroborates them;
- **VBOM:** vendor, product, provider, package, linked-library and signing
  relationships;
- **Vulnerability BOM:** normalized binary findings, advisory-feed matches,
  malformed/truncated/refused states, hardening failures and weak/deprecated
  algorithm findings; and
- **Technology BOM:** a correlated snapshot with stable references, provenance,
  fingerprint, scan metadata and layer diff support.

Binary evidence is bounded and metadata-only. Imported socket/TLS names do not
prove a live endpoint, package signatures are not trusted merely because a
signature artifact is present, and a clean or empty view does not prove that no
unobserved estate exists.

## Related implementation documentation

- [Product overview](product/README.md)
- [Product features](product/02-features.md)
- [Product architecture](product/03-architecture.md)
- [Binary and firmware scanning](user-guide/binary-firmware-scanning.md)
- [SBOM scanner architecture](architecture/sbom-scanner-architecture.md)
- [Capability maturity](CAPABILITY-MATURITY.md)
- [State machine register](state-machines/README.md) · [developer reference](api-reference/state-machines.md)
- [Vendor and network inventory](user-guide/vendor-network-inventory.md)
- [REST API reference](api-reference/rest-api.md)

Back to [the end-to-end product capability map](PRODUCT-CAPABILITIES-END-TO-END.md).
