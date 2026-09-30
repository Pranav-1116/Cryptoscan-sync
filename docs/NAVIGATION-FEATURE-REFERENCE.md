# CryptoScan console navigation and feature reference

> **Source of truth for this page:** `frontend/src/components/Layout.tsx` for
> the sidebar and `frontend/src/App.tsx` for routed pages. When a menu item or
> route changes, update this page in the same change. This is documentation of
> the current repository, not a product promise or an external assurance claim.

The console has **six primary sidebar sections**, **31 menu slots** and **30
unique primary route paths**. `Security Center` intentionally appears twice:
it is available as **Audit Log** under Governance and as **Security Center**
under Administration, but both labels open `/security-center`. The application
also has deep-link pages that are reached from cards, search, alerts, reports,
or links inside primary pages rather than from the sidebar.

The root route `/` redirects to `/command-center`. Login and account recovery
routes are authentication flows, not primary navigation entries.

## Primary sidebar

### Overview

| Sidebar label | Route | Component | Purpose |
|---|---|---|---|
| Dashboard | `/command-center` | `CommandCenter` | Current estate summary, scan state, risk and live activity entry points. |
| Live Asset Intelligence | `/live-asset-intelligence` | `LiveAssetIntelligence` | Materialize, compare, export and review the unified Technology BOM state. |
| Activity | `/live-stream` | `LiveStream` | Durable activity and event stream with live updates. |

### Discovery

| Sidebar label | Route | Component | Purpose |
|---|---|---|---|
| Scan | `/scanners` | `Scanners` | Start and monitor authorized collection jobs. |
| Assets | `/assets` | `Assets` | Browse the unified asset inventory. |
| Network | `/network` | `Network` | Review network inventory and authorized network-scan results. |
| Cloud | `/cloud` | `Cloud` | Review connected AWS, Azure and GCP inventory. |
| Applications | `/dev-sec-ops` | `DevSecOps` | Source, container, SBOM, binary and firmware workflows. |
| Hardware | `/hardware` | `Hardware` | Hardware, HSM, TPM and firmware inventory. |
| Certificates | `/certificates` | `Certificates` | Certificate and PKI lifecycle inventory. |
| Vendors | `/vendor` | `Vendor` | Vendor, product and supply-chain relationships. |

### Intelligence

| Sidebar label | Route | Component | Purpose |
|---|---|---|---|
| CBOM | `/cbom` | `Cbom` | Cryptographic assets, algorithms, libraries, protocols and CBOM views. |
| HBOM | `/hbom` | `Hbom` | Hardware and firmware materialized view. |
| NBOM | `/nbom` | `Nbom` | Network BOM view; static binary capability candidates remain separate from live network observations. |
| Dependency Graph | `/graph` | `Graph` | Relationships, dependencies and blast-radius exploration. |
| Crypto Inventory | `/crypto-assets` | `CryptoAssets` | Normalized cryptographic asset inventory. |
| PQC Readiness | `/pqc` | `Pqc` | Quantum-vulnerability classification and migration readiness. |
| Crypto Agility | `/agility` | `Agility` | Deterministic replaceability and migration-planning signals. |
| Crypto Drift | `/drift` | `Drift` | Approved-baseline changes and drift events. |

### Governance

| Sidebar label | Route | Component | Purpose |
|---|---|---|---|
| Banking & SWIFT | `/banking-regulatory` | `BankingRegulatory` | Banking, payment and SWIFT-oriented regulatory mapping. |
| Policies | `/security-policy` | `SecurityPolicy` | Deterministic policy packs, scope and policy decisions. |
| Compliance | `/compliance` | `Compliance` | Framework mappings and compliance evidence. |
| Evidence | `/evidence` | `Evidence` | Hashes, manifests, verification and evidence packages. |
| Audit Log | `/security-center` | `SecurityCenter` | Audit and platform-security review from the governance context. |

### Output

| Sidebar label | Route | Component | Purpose |
|---|---|---|---|
| Reports | `/reports` | `Reports` | Reports, exports and report delivery status. |
| What-If Analysis | `/what-if` | `WhatIf` | Read-only migration and scenario analysis. |

### Administration

| Sidebar label | Route | Component | Purpose |
|---|---|---|---|
| System Health | `/system-health` | `SystemHealth` | Health, readiness and platform service status. |
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
- The sidebar displays GA, Beta or Preview pills from
  `shared_models/capability_maturity.py` through `frontend/src/lib/maturity.ts`.
- The signed-in session and roles come from `GET /api/v1/auth/me`; local storage
  is only a first-paint hint and must not authorize an action.
- The collapsed sidebar preserves the same routes and exposes item labels as
  tooltips. English and Arabic layouts share the same route map.

## Routed pages reached by deep link

These routes are real pages in `App.tsx`, but are not current primary sidebar
slots. They should be linked from a relevant page, search result, alert, report,
or role workspace rather than reintroduced as a second competing sidebar.

| Area | Routes |
|---|---|
| Overview and role workspaces | `/accuracy`, `/executive`, `/role-dashboard`, `/search-results`, `/timeline` |
| Discovery and collection | `/admin`, `/catalog`, `/cmdb`, `/live-environment`, `/live-scanners`, `/onboarding`, `/runtime`, `/sectors`, `/telecom` |
| Intelligence and analysis | `/crypto`, `/crypto-assurance`, `/crypto-changes`, `/dependency-graph`, `/findings`, `/libraries`, `/migration`, `/pqc-map`, `/priorities`, `/protocols`, `/risk`, `/security-intelligence` |
| Governance and administration | `/alerts`, `/automation`, `/governance`, `/notifications`, `/organization`, `/platform-p2`, `/resilience`, `/security`, `/scope`, `/supervision`, `/tenancy`, `/trust` |

Authentication and entry flows are also routed but are not sidebar pages:
`/login`, `/register`, `/reset-password` and `/invite-accept`. Unknown routes
fall back to `/command-center`.

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

The **DevSecOps → Binaries** panel is the console entry point for the binary
inventory pipeline. One bounded binary or firmware scan can materialize:

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

After the synchronous scan or queued worker completes, both paths call the same
artifact-store persistence hook. The signed manifest and BOM sidecars are the
authoritative export; migration `0063` additionally writes a tenant-scoped
`binary_scan_records` summary and bounded `binary_scan_observations` projection.
The API exposes these rows at `/api/v1/devsecops/binary/scans` and
`/api/v1/devsecops/binary/scans/{scan_id}`. The panel sends the active tenant
header, shows history/detail only for that tenant, labels indexed/unavailable
states, and renders observed, partial, unsupported and unknown parser evidence
without turning an unavailable index into a clean result.

## Related implementation documentation

- [Product overview](product/README.md)
- [Product features](product/02-features.md)
- [Product architecture](product/03-architecture.md)
- [Binary and firmware scanning](user-guide/binary-firmware-scanning.md)
- [SBOM scanner architecture](architecture/sbom-scanner-architecture.md)
- [Capability maturity](CAPABILITY-MATURITY.md)
- [REST API reference](api-reference/rest-api.md)

Back to [the end-to-end product capability map](PRODUCT-CAPABILITIES-END-TO-END.md).
