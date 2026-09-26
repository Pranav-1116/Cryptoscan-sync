# ZELNX CryptoScan — Navigation & Feature Reference

> A complete, plain-language guide to **every button in the left-hand navigation**.
> Each entry explains **what the button is for (why you'd use it)** and **what its
> page actually does (the features it exposes)**. Everything below is a navigation
> entry to a real, live page. The platform is driven by the unified **Technology
> BOM** model: no page fabricates data — panels render zeros/empty/offline until a
> real scan or operation produces evidence.

---

## Table of contents

- [Overview](#overview)
- [Scanners](#scanners)
- [Assets](#assets)
- [Intelligence](#intelligence)
- [Assess](#assess)
- [Operations](#operations)
- [Govern](#govern)
- [Platform](#platform)

The navigation is grouped into eight sections. The single most relevant page for
the **unified SBOM / CBOM / HBOM** work is **Intelligence → Live asset
intelligence**.

---

## Overview

Landing surfaces that give an at-a-glance picture of the whole estate.

### Command center — `/` (`CommandCenter`)
**Why:** the default landing page — a single pane that answers "what is the
state of my estate right now?" without digging into any specific module.
**Features:**
- Live top-level KPI cards (scope, live BOM, live drift, live alerts) fed by the
  real-time stream — no refresh needed.
- A live scan launcher (`apiLiveScanRun`) so a scan can be kicked off from the
  front door, plus live scan status.
- Quick links/feeds into the most important news (alerts, drift) so an operator
  spots trouble immediately.

### Executive view — `/executive` (`Executive`)
**Why:** a leadership-grade summarised view of the same live data, hiding the
technical plumbing. **Features:** executive KPI rollups, trend/drift numbers, and
a live digest (BOM, drift, alerts) so non-technical stakeholders see posture
without opening each module.

### Role workspace — `/role-home` (`RoleDashboard`)
**Why:** deterministic, per-role landing surfaces (CISO, security analyst, OT
engineer). **Features:** each persona sees only tiles relevant to its job; access
audit attestation, air-gap/SLA posture, and stats summary — all live.

### Discovery — `/onboarding` (`Onboarding`)
**Why:** the "start here" flow that connects a new customer's environment.
**Features:** create an organisation, add environments, define scope, add
connectors (GitHub, cloud, network, scanner agents), test credentials, and launch
a first discovery scan. Also lists sector profiles and lets you update/delete
scope and connections. This is the first-run wizard for the whole platform.

---

## Scanners

Everything about **getting data into** the platform.

### Scanners — `/scanners` (`Scanners`)
**Why:** the central "scanner control center" — see and control every scanning
agent. **Features:** agent discovery + health/control, live scan status, and the
ability to start/stop discovery agents.

### Realtime scanners — `/live-scanners` (`LiveScanners`)
**Why:** the live, streaming scanner console. **Features:** start/stop/run a live
scan and see its live status in real time. This is the scan → event-bus → live
state → SSE → frontend pipeline in action.

### Network — `/network` (`Network`)
**Why:** visualise the network layer of the environment. **Features:** a live
network topology view built from the live inventory, including how devices and
subnets relate.

### Cloud — `/cloud` (`Cloud`)
**Why:** connected, read-only cloud accounts. **Features:** a provider tree of
cloud accounts and their estates (multi-cloud), rendered from connected cloud
accounts.

### Hardware — `/hardware` (`Hardware`)
**Why:** the hardware root-of-trust layer (HSMs, TPMs, firmware) that software
scanning can't see. **Features:** live hardware inventory, the hardware catalog,
live scan status, firmware/TPM/HSM attributes and risk. This is a primary input
to the **HBOM**.

### Vendor — `/vendor` (`Vendor`)
**Why:** drill into the vendors behind your hardware. **Features:** vendor
drill-down derived from the canonical hardware catalog — the manufacturer/product
inventory behind crypto-hardware, feeding the **VBOM**.

### Runtime hosts — `/runtime` (`Runtime`)
**Why:** the live hosts where your workloads run. **Features:** live inventory of
runtime hosts plus runtime findings (live static analysis on the running estate).

### Certificates — `/certificates` (`Certificates`)
**Why:** TLS/PKI is a first-class asset in the CBOM. **Features:** certificate
inventory and a lifecycle panel — create CSR, issue, renew, revoke, renewal queue
and expiry calendar, all powered by live inventory.

---

## Assets

The **unified asset model** — the single source of truth that all BOM views are
materialised from.

### Asset & CMDB — `/cmdb` (`Cmdb`)
**Why:** Configuration-Management-Database view of the estate. **Features:** live
**activity** feed, the full inventory, inventory summary and the unified risk
score — the "all assets in one place" table.

### Assets — `/assets` (`Assets`)
**Why:** the flat asset list. **Features:** live inventory rendered as a browsable
asset list (servers, apps, devices, crypto usages).

### Catalogs — `/catalog` (`Catalog`)
**Why:** the **canonical catalog** — the ground-truth lists that govern how things
are classified. **Features:** algorithm catalog, hardware catalog, protocol
catalog. This is the reference data every scanner's results are validated against.

### Crypto assets — `/crypto-assets` (`CryptoAssets`)
**Why:** the algorithm explorer. **Features:** the canonical algorithm catalog
(live), showing every crypto algorithm the platform knows about and its risk
profile.

### Crypto libraries — `/libraries` (`Libraries`)
**Why:** find where crypto is being used at the library/package level.
**Features:** live inventory of crypto libraries discovered in code/dependencies
(direct input to the CBOM).

### Protocols — `/protocols` (`Protocols`)
**Why:** network protocols & services actually in use. **Features:** a live
catalog of protocols/services from the canonical network inventory.

### DevSecOps pipeline — `/devsecops` (`DevSecOps`)
**Why:** shift-left — check crypto/the BOM at build/CI time. **Features:**
container image scan (on push), Kubernetes scan, cloud posture, SBOM import,
and connector preview, wired into the CI pipeline.

---

## Intelligence

The **analysis / BOM / graph** surface — this is where the unified model is read.

### Cryptography — `/crypto` (`Crypto`)
**Why:** the crypto posture overview. **Features:** the algorithm catalog, live
inventory of where each algorithm is used, and the protocol catalog — the
"what crypto am I running and where" page.

### CBOM — `/cbom` (`Cbom`)
**Why:** the **Cryptographic Bill of Materials** (CycloneDX 1.x). **Features:** an
interactive crypto dependency graph (components → dependencies coloured by quantum
verdict), an explorer, a diff view, history, and a real CycloneDX export (JSON/XML)
built from live components — never a static placeholder.

### HBOM — `/hbom` (`Hbom`)
**Why:** the **Hardware Bill of Materials**. **Features:** the live BOM rendered as
a hardware-focused view — firmware, HSMs/TPMs, devices and their provenance, built
from the same unified model as the CBOM.

### Live asset intelligence — `/live-asset-intelligence` (`LiveAssetIntelligence`)
**Why:** the **one-page unified Technology BOM** the customer asked for — SBOM /
CBOM / HBOM / Vendor are **materialized views of one asset model**, not separate
databases. **Features:**
- Top counts: Assets / SBOM / CBOM / HBOM / Vendors.
- A dependency graph and a live SSE event feed.
- Version **compare** (added/removed components per layer) and an immutable
  snapshot/history (every export has `TECHBOM-YYYYMMDD-HHMMSS` + environment +
  state version + integrity hash).
- **Export Service** (validate → filter → generate → sign/HMAC → audit) with
  JSON / CSV / CycloneDX / XML / SPDX / PDF, plus filtered export by layer, risk,
  key size and search.
- **Scheduled exports** (daily / weekly / monthly / after scan / after major
  change) and export-run history.
- An **Evidence Package** (BOM + certificate posture, content hashed and HMAC
  signed) and a **Vendor BOM (VBOM)** inventory.
- A "LIVE SCAN IN PROGRESS — partially updated" indicator while a scan runs.

### Dependency graph — `/graph` (`DependencyGraph`)
**Why:** the full **asset/relationship graph** behind the BOM. **Features:** the
live graph, connected-components stats, blast radius, dependents/upstream path,
explain, what-if migration simulation, migration plan, vendor chain, and versioned
graph snapshots with a timeline + compare.

---

## Assess

Driving risk and readiness.

### PQC readiness — `/pqc` (`Pqc`)
**Why:** how ready are you for post-quantum cryptography. **Features:** a live
dashboard of quantum-vulnerable algorithms from the live BOM and the algorithm
catalog — "how much of my crypto breaks under Shor's algorithm".

### PQC migration map — `/pqc-map` (`PqcMap`)
**Why:** the deterministic migration plan. **Features:** live quantum-risk
inventory by algorithm family plus the migration waves (non-adjustable,
deterministic phases), rendered as a map of what moves and when.

### Risk — `/risk` (`Risk`)
**Why:** the unified risk score. **Features:** risk score/level/aggregate and
open-drift counts from `apiRisk` and `apiStatsSummary` — a roll-up of the whole
estate's risk.

### Drift — `/drift` (`Drift`)
**Why:** detect when the real environment drifts from what you think it is.
**Features:** drift events and live drift — changes from the recorded baseline,
fed by the real-time stream.

### Alerts — `/alerts` (`Alerts`)
**Why:** the alert feed. **Features:** live alerts (severity, source, time) pushed
over SSE. This is where immediate problems land.

### Crypto agility — `/agility` (`Agility`)
**Why:** how easily the estate can change crypto when it needs to. **Features:** a
live agility response from `/api/v1/agility` — per-system agility and migration
readiness metrics.

### Crypto assurance — `/crypto-assurance` (`CryptoAssurance`)
**Why:** active assurance that the crypto actually behaves as declared.
**Features:** active TLS/cipher enumeration, TLS audit, certificate-transparency
monitoring, expiry alerts, HSM/enclave checks, trust-store review, PQC downgrade
checks and code-rule scanning.

---

## Operations

**What-if / planning / automation** for changing the estate safely.

### What-if simulator — `/whatif` (`WhatIf`)
**Why:** experiment without affecting production. **Features:** the migration
simulator — this surface only **reads** the estate and runs the deterministic
feasibility engine ("if I migrate this algorithm, what breaks?"). It is kept
separate from execution on purpose.

### Migration planning — `/migration` (`Migration`)
**Why:** the actionable post-quantum migration plan. **Features:** replacement
workstreams phased into waves from the live `/api/v1/quantum/plan` engine, with the
specific algorithm→replacement migrations.

### Automation rules — `/automation` (`Automation`)
**Why:** rules that react automatically. **Features:** an automation rule builder
(create/save/delete rules), the list of enabled capabilities a rule can trigger,
and automation runs.

### Live crypto changes — `/crypto-changes` (`CryptoChanges`)
**Why:** a live feed of crypto-related changes as they happen. **Features:** recent
events from `/api/v1/events/recent` — the SSE event store surfaced as a crypto
change log.

### Global timeline — `/timeline` (`Timeline`)
**Why:** the whole platform's event history in one place. **Features:** REAL events
only (backlog loaded from `/api/v1/events/recent`) — scans, discoveries, drift,
exports — not a simulated list.

### Live environment — `/env` (`LiveEnvironment`)
**Why:** see the live environment as the orchestrator sees it. **Features:** live
environment state, orchestrator start/status/history — the multi-instance live
status store (Redis-backed with an in-memory fallback).

---

## Govern

**Policy, compliance and control.**

### Scope & AuthZ — `/scope` (`Scope`)
**Why:** define and enforce scope/authorization. **Features:** scope envelope,
tenant isolation (region → BU → environment → asset), connector catalog and
scope-authorize workflow — the fail-closed ABAC isolation layer.

### Compliance — `/compliance` (`Compliance`)
**Why:** map evidence to frameworks. **Features:** live compliance posture per
framework, the active sector/profile, plus drift digest — pass/fail per
requirement against the canonical frameworks.

### Governance — `/governance` (`Governance`)
**Why:** exception and control governance. **Features:** policy exceptions,
business owners, governance/change requests and the event feed.

### Resilience & DR — `/resilience` (`Resilience`)
**Why:** recovery and attestation. **Features:** compliance reporting, backup
retention plans, backup create/list/restore/scheduled/sweep, air-gap build bundle
+ status + feed import, audit attestation, OT decode/ingest — all live.

### Trust & Keys — `/trust` (`Trust`)
**Why:** the **root-of-trust / key operations** surface. **Features:** payment-crypto
key inventory + rotation forecast, HSM/TPM ceremonies, workload SPIFFE/SVID
identity (issue/verify), API-key rotation report, OT safe-scan policy +
maintenance windows + emergency stop.

### Evidence — `/evidence` (`Evidence`)
**Why:** audit-grade evidence explorer. **Features:** the evidence record list and
the hash **chain** — verify the tamper-evident evidence trail that backs every
finding and BOM component.

### Reports — `/reports` (`Reports`)
**Why:** scheduled, distributable reports. **Features:** report templates and
report-schedule creation/run — the scheduled compliance-report surface, with
immutable signed snapshots and PDF output.

---

## Platform

**Admin, identity and security tooling.**

### Findings — `/findings` (`Findings`)
**Why:** all findings across scans. **Features:** findings list + detail,
runtime findings, trigger a scan and jump to a finding's evidence.

### Integrations — `/integrations` (`Integrations`)
**Why:** connect the platform outbound. **Features:** integration registry,
deliveries (and flush), test an integration, plus the **credential vault**
(create/lease/rotate/release) so connectors never hold raw secrets.

### Notifications — `/notifications` (`Notifications`)
**Why:** where alerts go. **Features:** notification routing (which channels each
severity goes to) — slack/webhook/email/SMS based on the routing config.

### Users & access — `/identity` (`Identity`)
**Why:** who can do what. **Features:** SSO status, SCIM directory (create /
deactivate / activate users), API-key policy/rotation report, workload
SPIFFE/SVID identity.

### Security — `/security` (`Security`)
**Why:** the security policy surface. **Features:** safe-scan policy and the
security controls that gate scanning behaviour.

### Security center — `/security-center` (`SecurityCenter`)
**Why:** the **Security Operations Center**. **Features:** security posture +
trend, alerts, ABAC grants (`apiMyGrants`), audit list + verify, agent control,
control-plane health, anomaly flags, safe-scan policy and live inventory — a
single command console.

### Scanning policy — `/security-policy` (`SecurityPolicy`)
**Why:** the policy that decides what can be scanned and when. **Features:** get/put
security & scanning policy plus the policy gate decision — the fail-closed gate
that blocks disallowed scans.

### Settings — `/settings` (`Settings`)
**Why:** platform-wide settings. **Features:** active sector, sector list,
notification routing, safe-scan policy, scope, SSO status — the "configure the
platform" page.

### Organization — `/organization` (`Organization`)
**Why:** the whole customer hierarchy. **Features:** org → region → business unit →
environment → assets → crypto, built from the live `/api/v1/onboarding/state`.

### Sector profiles — `/sectors` (`Sectors`)
**Why:** multi-sector (regulated) profiles. **Features:** list sectors, read/switch
the active sector — each sector carries its own compliance/risk profile.

### Accuracy — `/accuracy` (`Accuracy`)
**Why:** measure the detector itself. **Features:** detection quality metrics from
`/api/v1/crypto/accuracy` — precision / recall / F1 for the crypto detection
engine (deterministic, regression-guarded).

### P2 console — `/platform` (`PlatformP2`)
**Why:** the enterprise platform console. **Features:** plugin registry
(enable/disable), anomaly flags + acknowledgment, governance requests + decisions,
data-lake batches/export/verify, API keys, agent upgrades, automation runs/rules,
benchmark runs, SLA posture, credential leases, OT maintenance windows,
post-migration validation and health sweep.

### Administration — `/admin` (`Admin`)
**Why:** the RBAC policy matrix. **Features:** the authoritative role → permission
policy (config, not code) and the admin security surface — who can do what across
the platform.

---

## How it ties together

```
Scan  →  Evidence  →  Normalize  →  Resolve asset  →  Build graph
     →  Materialize SBOM/CBOM/HBOM/Vendor   (one unified Technology BOM)
     →  Version the state (immutable snapshot, TECHBOM-…)
     →  Live investigation (Live asset intelligence, graphs, compare)
     →  Export an exact snapshot (JSON/CSV/CycloneDX/XML/SPDX/PDF + Evidence Package)
```

- **Assets & Scanners** get data *in*.
- **Intelligence** reads the unified model *out*.
- **Assess & Operations** act on it.
- **Govern & Platform** restrict, audit and administer it.
