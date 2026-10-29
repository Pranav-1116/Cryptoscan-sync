# CryptoScan console navigation and feature reference

> **Source of truth for this page:** `frontend/src/components/Layout.tsx` for
> the sidebar and `frontend/src/App.tsx` for routed pages. When a menu item or
> route changes, update this page in the same change. This is documentation of
> the current repository, not a product promise or an external assurance claim.

The console has **six primary sidebar sections**, **41 menu slots** and **40
unique primary route paths**. `Security Center` intentionally appears twice:
it is available as **Audit Log** under Governance and as **Security Center**
under Administration, but both labels open `/security-center`. The application
also has deep-link pages that are reached from cards, search, alerts, reports,
or links inside primary pages rather than from the sidebar.

The root route `/` redirects to `/command-center`. Login and account recovery
routes are authentication flows, not primary navigation entries.

## Primary sidebar

**Reviewed 2026-10-22 at `698beb38`.** The table below matches every current
sidebar placement, including intentionally duplicated Security Center.

### Overview

| Sidebar label | Route | Component | Purpose |
|---|---|---|---|
| Dashboard | `/command-center` | `CommandCenter` | Current estate summary, scan state, risk and live activity entry points. |
| Launch readiness | `/launch-readiness` | `LaunchReadiness` | Gated independent-report, operational-duty and bounded-pilot records; real assessor execution, site exercises and customer acceptance require external evidence. |
| Operator decisions | `/operator-decisions` | `OperatorDecisions` | Exact-estate decision and condition-proof workflow; local workloads tested, site capacity and deployment acceptance remain open. |
| Activity | `/live-stream` | `LiveStream` | Durable activity and event stream with live updates. |

### Discovery

| Sidebar label | Route | Component | Purpose |
|---|---|---|---|
| Scan | `/scanners` | `Scanners` | Start and monitor authorized collection jobs. |
| Live Scanners | `/live-scanners` | `LiveScanners` | Live scan runner status; same orchestrator as /scanners. |
| Assets | `/assets` | `Assets` | Browse the unified asset inventory; detail carries identity spine, facts, blast radius and the remediation tasks bound to the asset's evidence. |
| Network | `/network` | `Network` | Review network inventory and authorized network-scan results. |
| Cloud | `/cloud` | `Cloud` | Review connected AWS, Azure and GCP inventory. |
| Applications | `/dev-sec-ops` | `DevSecOps` | Source, container, SBOM, binary and firmware workflows. |
| Hardware | `/hardware` | `Hardware` | Hardware, HSM, TPM and firmware inventory. |
| Certificates | `/certificates` | `Certificates` | Live TLS-scan view plus the persisted estate: fingerprint-deduped rows, where observed, honest revocation checks and ownership assignment. |
| Vendors | `/vendor` | `Vendor` | Vendor, product and supply-chain relationships. |

### Intelligence

| Sidebar label | Route | Component | Purpose |
|---|---|---|---|
| Cryptography | `/crypto` | `Crypto` | Algorithm registry + normalized crypto view (114 normalization tests). |
| Crypto Inventory (CBOM) | `/cbom` | `Cbom` | Cryptographic assets, algorithms, libraries, protocols and CBOM views. |
| Algorithm Catalog | `/crypto-assets` | `CryptoAssets` | Normalized cryptographic asset inventory. |
| Technology BOM | `/live-asset-intelligence` | `LiveAssetIntelligence` | Materialize, compare, export and review the unified Technology BOM state. |
| HBOM | `/hbom` | `Hbom` | Live-scan BOM plus the independent unified estate HBOM — content-addressed pins with pin-to-pin diff. |
| NBOM | `/nbom` | `Nbom` | Network BOM view; static binary capability candidates remain separate from live network observations. |
| Dependencies | `/dependency-graph` | `DependencyGraph` | Same graph engine as /graph. |
| Graph Explorer | `/graph` | `Graph` | Relationships, dependencies and blast-radius exploration. |
| Findings | `/findings` | `Findings` | Policy-evaluated findings with evidence links. |
| PQC Readiness | `/pqc` | `Pqc` | Quantum-vulnerability classification and migration readiness. |
| Crypto Agility | `/agility` | `Agility` | Deterministic replaceability and migration-planning signals. |
| Crypto Drift | `/drift` | `Drift` | Approved-baseline changes and drift events. |

### Governance

| Sidebar label | Route | Component | Purpose |
|---|---|---|---|
| Banking & SWIFT | `/banking-regulatory` | `BankingRegulatory` | Banking, payment and SWIFT-oriented regulatory mapping. |
| Policies | `/security-policy` | `SecurityPolicy` | Deterministic policy packs, scope and policy decisions. |
| Compliance | `/compliance` | `Compliance` | Framework mappings and compliance evidence. |
| Evidence | `/evidence` | `Evidence` | Hashes, manifests, scan and per-record verification (with an X-of-Y coverage line), and the filterable, exportable audit ledger. |
| Audit Log | `/security-center` | `SecurityCenter` | Platform security posture and operational controls. |
| Remediation Tasks | `/remediation` | `Remediation` | Owned task lifecycle with machine verification against rescan evidence; new surface over the full task API. |
| Remediation Priorities | `/priorities` | `Priorities` | Deterministic prioritisation over findings + business context. |
| Migration | `/migration` | `Migration` | Scan → project → tasks → velocity forecast; forecast model is simple. |

### Output

| Sidebar label | Route | Component | Purpose |
|---|---|---|---|
| Reports | `/reports` | `Reports` | Reports, exports and report delivery status. |
| What-If Analysis | `/what-if` | `WhatIf` | Read-only migration and scenario analysis. |
| Digital Twin | `/digital-twin` | `DigitalTwin` | Estate replica with measured fidelity, evidence reconciliation and ten deterministic scenario types, fed by live state, wire scans, the dependency graph and the hardware fleet; scenario models are heuristic projections, not vendor simulations. |

### Administration

| Sidebar label | Route | Component | Purpose |
|---|---|---|---|
| System Health | `/system-health` | `SystemHealth` | Health, readiness and platform service status — with independently measured worker-fleet and connector health (never derived from API liveness). |
| Settings & Org | `/settings` | `Settings` | Organization and application settings. |
| Security Center | `/security-center` | `SecurityCenter` | Platform security posture and operational controls. |
| Users & Teams | `/identity` | `Identity` | Users, roles, MFA and identity administration. |
| Integrations & API | `/integrations` | `Integrations` | Connectors, API and delivery integrations. |

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
  tooltips. English and Arabic layouts share the same route map.

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
| Intelligence | SBOM/CBOM/HBOM/NBOM/VBOM correlations, vulnerability BOM findings, graph relationships, PQC and agility analysis. |
| Governance | Deterministic policy, compliance mappings, approvals, audit history and evidence verification. |
| Output | Reports, signed/exportable artifacts and read-only what-if analysis. |
| Administration | Health, organization, identity, security posture, integrations and API access. |

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
- [Vendor and network inventory](user-guide/vendor-network-inventory.md)
- [REST API reference](api-reference/rest-api.md)

Back to [the end-to-end product capability map](PRODUCT-CAPABILITIES-END-TO-END.md).
