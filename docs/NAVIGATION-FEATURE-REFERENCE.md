# CryptoScan console navigation and feature reference

> **Source of truth for this page:** `frontend/src/components/Layout.tsx` for
> the sidebar and `frontend/src/App.tsx` for routed pages. When a menu item or
> route changes, update this page in the same change. This is documentation of
> the current repository, not a product promise or an external assurance claim.

The console has **five primary sidebar sections**, **25 rows** and **79 links**
(66 distinct routes — a group's row links to its first page). Pages that answer
one question share a **workspace group** — asset discovery, scan, the six-BOM
inventory, crypto intelligence, PQC migration, twin & dependencies, operations,
oversight, policy & compliance, remediation, evidence & assurance, security
center and system health — and a group is a disclosure: the pages inside it are one
click away and only rendered when it is opened. Only the section holding the
current page is open on arrival, so an operator reads about five rows, not all
seventy-nine links. The header's Security Center button opens the admin drawer;
the security surfaces themselves sit under **Governance → Security center**
(Posture, Control estate); audit and reporting live in the Evidence & assurance
workspace beside them.

The root route `/` redirects to `/command-center`. Login and account recovery
routes are authentication flows, not primary navigation entries.

## How the console is built

The frontend is a single React/TypeScript application (Vite, React Router,
vitest + testing-library). Understanding these layers makes every page below
readable:

**Entry and routing.** `frontend/src/App.tsx` mounts a `BrowserRouter`; every
page is a `lazy()` import behind a `<Route>`, wrapped in a keyed `ErrorBoundary`
so one broken page cannot take the shell down. `/login`, `/register`,
`/reset-password` and `/invite-accept` render through `PublicEntry` (no sidebar);
`/` and unknown paths redirect to `/command-center`, and `/techbom` redirects to
`/live-asset-intelligence`.

**The sidebar** (`components/Layout.tsx`) is the two-level tree printed below:
five sections, twenty-five rows, seventy-nine links. Section and group disclosures
persist in `zelnx-nav-open`; arriving at a route inside a closed group opens that
group, so the navigation follows the page you are on. The collapsed sidebar keeps
the same routes and exposes labels as tooltips. **Start Scan** is shown only to
sessions holding `superadmin`, `ciso`, `security_analyst`, `developer` or
`scanner` — a usability guard, not authorization; the API remains authoritative.
There are no maturity badges in the navigation; each surface states its own
limits (see [CAPABILITY-MATURITY.md](CAPABILITY-MATURITY.md)).

**The page frame.** Every page is built from the same primitives
(`components/ui.tsx`): `PageHead` (breadcrumb, title, one-line scope statement,
right-hand slot for live counts), `Panel` (the corner-framed card that carries a
title and a sub-caption), `Table` (dense rows), `Tabs` (ARIA tablist with arrow
key/Home/End movement), `Drawer` (detail overlays, used heavily on inventory
pages), `Feed`, `Code`, `Badge` (tone-coloured), `Kpi`/`Stat` headline numbers,
`Button` and `ProgressBar`. `PageHead.sub` is deliberate: the first line an
operator reads states the scope and the limit of what the page claims.

**The visualisation kit** (`components/viz.tsx`) is hand-rolled SVG — no chart
library. `HBars` (labeled comparisons), `StackedBar` (composition), `Donut`
(distribution), `Sparkline` (trend), `TickStrip` (event ticks), `Meter` /
`KpiMeter` / `GapBar` (progress and gaps), `FlowStrip` and `StepRail` (stage
chains whose states are done/active/pending/unknown/failed), `Matrix`
(row × column heat tables), `DeltaChip` (change), `StateCell` and `VizEmpty`
(honest empties). Colours resolve through one `toneColor` map with aliases; an
alias never invents a state — muted/unknown/none map to slate, never to a pass
or a failure, and a typo renders neutral rather than invisible. Empty states are
**drawn**, not blank: a dashed placeholder ring, ghost tracks and labelled
absence ("not a clean estate") so an empty screen is visibly an empty reading.

**Data behaviour** (`lib/api.ts`). Typed calls return `ApiResult {ok, error}`; a
failed read renders a failure banner ("Read failed" with the cause) and **never
prints zeros instead**. An empty result is labelled absence, never a clean
estate. Writes go through `lib/requestFeedback.ts`: validation failures keep the
draft, authority failures keep the draft, and an unconfirmed outcome is shown as
unknown — the server may already have retained the write. Tenant resolution
(`ensureActiveTenant`) adopts the first ACTIVE membership and never guesses; the
Performance and Binary pages show a non-blocking "resolving" strip while it runs
and re-read the moment the tenant lands. Realtime surfaces (Live stream, Live
scanners, Runtime) stream over WebSocket/SSE with paginated polling fallbacks
and state their gaps explicitly (a reset cursor is shown as a gap, not as
continuous history).

**State vocabulary.** `lib/stateMachines.ts` is the TypeScript projection of the
canonical [state machine register](state-machines/README.md): eleven semantic
state classes, one tone each, so the same state looks the same on every page
(`unknown` renders slate — never a green zero). `/state-machines` draws the
register itself.

**Auth, language, motion.** The session and roles come from
`GET /api/v1/auth/me`; local storage is only a first-paint hint and never
authorizes an action. English and Arabic layouts (RTL included) share one route
map (`frontend/src/i18n`). Motion respects `prefers-reduced-motion`. The design
contract bans gradients, glow and chatbot-style panels across all source files
(`intelligence/design.contract.test.ts`).

**Testing.** Every page has a colocated `*.test.tsx` rendered through
`test/render.tsx` (`renderWithProviders`) with `mockFetch`/`offlineFetch`; the
navigation tree, copy strings and honesty wordings are pinned by tests, so the
explanations below are backed by executable expectations, not prose.

## Primary sidebar

**Reviewed 2026-11-11.** The tables below match every current sidebar placement,
row for row. Rows with a group render as a disclosure; the `—` rows are links.

### Overview

| Sidebar label | Group | Route | Component | Purpose |
|---|---|---|---|---|
| Command center | — | `/command-center` | `CommandCenter` | The main operational overview: estate summary, scan state, risk and the entry points into every live workspace. |
| Operations | Operations | `/live` | — | One workspace over the live estate map, the activity stream and the monitors that feed them. |
| Live estate | Operations | `/live` | `LiveEstate` | Business systems as the agents see them now: hosts per declared system, liveness, CPU, collector completeness, quantum-vulnerable uses and the alerts that name each system; estate-wide collection health. Reads `/operations/{monitor,fleet,hosts}`. |
| Activity | Operations | `/live-stream` | `LiveStream` | One timeline of estate changes, correlated patterns, agent lifecycle and remediation actions, attributed to agents and systems; filters, itemised change detail and acknowledgement. The platform event bus sits below, collapsed. |
| Live monitor | Operations | `/live-monitor` | `LiveMonitor` | Overall status (OPERATIONAL / DEGRADED / DOWN / NOT_CONNECTED), deterministic alerts with rule, threshold, since and next action, and every agent's heartbeat against its late/offline thresholds with CPU and memory. Wallboard mode. |
| Live scanners | Operations | `/live-scanners` | `LiveScanners` | The Cryptava agent fleet: heartbeat, delivery, link and version per agent, and each of the six collectors with every source behind it (READ, EMPTY, ABSENT, DISABLED, NOT_CONFIGURED). The on-demand server scanners sit below, collapsed. |
| Runtime hosts | Operations | `/runtime` | `Runtime` | Per host: running services, listening sockets, crypto libraries with the process that loaded them, certificates, keys and algorithms with their quantum verdict, and signed load samples. A host with no sample is NOT_SAMPLED, never idle. Runtime crypto sensors sit below, collapsed. |
| Oversight | Oversight | `/launch-readiness` | — | One row over the two preview oversight workspaces. |
| Launch readiness | Oversight | `/launch-readiness` | `LaunchReadiness` | Gated independent-report, operational-duty and bounded-pilot records; real assessor execution, site exercises and customer acceptance require external evidence. |
| Operator decisions | Oversight | `/operator-decisions` | `OperatorDecisions` | Exact-estate decision and condition-proof workflow; local workloads tested, site capacity and deployment acceptance remain open. |

### Discovery

| Sidebar label | Group | Route | Component | Purpose |
|---|---|---|---|---|
| Asset discovery | Asset discovery | `/assets` | — | One workspace over the six discovery domains — every domain answers "what is in this estate" — with domain tabs across the top of each domain page. |
| Assets | Asset discovery | `/assets` | `Assets` | Browse the unified asset inventory; detail carries identity spine, facts, blast radius and the remediation tasks bound to the asset's evidence. |
| Applications | Asset discovery | `/dev-sec-ops` | `DevSecOps` | Source, container, SBOM, binary and firmware workflows. |
| Certificates | Asset discovery | `/certificates` | `Certificates` | Live TLS-scan view plus the persisted estate: fingerprint-deduped rows, where observed, honest revocation checks and ownership assignment. |
| Network | Asset discovery | `/network` | `Network` | Review network inventory and authorized network-scan results. |
| Cloud | Asset discovery | `/cloud` | `Cloud` | Review connected AWS, Azure and GCP inventory. |
| Hardware | Asset discovery | `/hardware` | `Hardware` | Hardware, HSM, TPM and firmware inventory. |
| Scan | Scan | `/scanners` | — | One row over the two scan surfaces. |
| Scanners | Scan | `/scanners` | `Scanners` | Start and monitor authorized collection jobs. |
| Collector depth | Scan | `/collector-depth` | `CollectorDepth` | How far each collector actually reaches, measured per family, protocol, platform and BOM projection. |
| CryptoLog | — | `/cryptolog` | `CryptoLog` | Cryptographic event intelligence: recorded events, their evidence and their provenance — recorded observations, never verdicts. |
| Vendors | — | `/vendor` | `Vendor` | Vendor, product and supply-chain relationships. |

### Intelligence

| Sidebar label | Group | Route | Component | Purpose |
|---|---|---|---|---|
| Inventory | Inventory | `/cbom` | — | One inventory workspace: the six BOMs of one estate, with TechBOM as the broader technology inventory view the other five project out of. |
| CBOM | Inventory | `/cbom` | `Cbom` | Cryptographic assets, algorithms, libraries and protocols in the same shell as SBOM/NBOM/VBOM: headline cards, breakdown panels and an identity inventory, with the estate-wide counts from `/cbom/query`'s own summary. |
| SBOM | Inventory | `/sbom` | `Sbom` | Software components and dependency edges. |
| HBOM | Inventory | `/hbom` | `Hbom` | Live-scan BOM plus the independent unified estate HBOM — content-addressed pins with pin-to-pin diff. |
| NBOM | Inventory | `/nbom` | `Nbom` | Network BOM view; static binary capability candidates remain separate from live network observations. |
| VBOM | Inventory | `/vbom` | `Vbom` | A supplier projection from retained evidence and declarations, not independent supplier validation. |
| Technology BOM | Inventory | `/live-asset-intelligence` | `LiveAssetIntelligence` | The broader technology inventory view: materialize, compare, export and review the unified Technology BOM state. |
| Crypto intelligence | Crypto intelligence | `/findings` | — | One cryptographic intelligence workspace: the catalogs, the findings and the migration posture are one question answered at three depths. |
| Cryptography | Crypto intelligence | `/crypto` | `Crypto` | Algorithm registry + normalized crypto view (114 normalization tests). |
| Algorithm catalog | Crypto intelligence | `/crypto-assets` | `CryptoAssets` | Normalized cryptographic asset inventory. |
| Findings | Crypto intelligence | `/findings` | `Findings` | Policy-evaluated findings with evidence links. |
| Crypto assurance | Crypto intelligence | `/crypto-assurance` | `CryptoAssurance` | Active TLS/cipher enumeration, certificate-transparency monitoring, expiry alerts & SLA, HSM/KMS/PKCS#11 residence, trust-store inventory, hybrid-PQC downgrade detection and weak-primitive code rules. |
| Crypto agility | Crypto intelligence | `/agility` | `Agility` | Deterministic replaceability and migration-planning signals. |
| Crypto drift | Crypto intelligence | `/drift` | `Drift` | Approved-baseline changes and drift events. |
| Intelligence workbench | Crypto intelligence | `/intelligence` | `Intelligence` | Roadmap models over live estate rows — evidence-linked findings, risk dimensions, PQC claim stages. |
| PQC migration | PQC migration | `/pqc` | — | One PQC Migration Intelligence workspace: quantum-vulnerable inventory, candidates, migration waves, blockers, interoperability and verified progress. |
| PQC readiness | PQC migration | `/pqc` | `Pqc` | Quantum-vulnerability classification and migration readiness. |
| Migration map | PQC migration | `/pqc-map` | `PqcMap` | The migration map and the persisted plan register — waves, blockers, interoperability notes and verified progress (`verified` only against an evidence reference). |
| Binary Intelligence | — | `/binary-intelligence` | `Binary` | Evidence-backed cryptographic discovery from compiled artifacts — static analysis only. |
| OS & Kernel Intelligence | — | `/os-kernel-intelligence` | `OSKernel` | Read-only OS/kernel cryptographic inventory; registrations are never proof of runtime use. |
| Twin & dependencies | Twin & dependencies | `/digital-twin` | — | One workspace: the replica, the dependency graph and the simulations are one model asked what it holds, what depends on it and what if. |
| Replica & scenarios | Twin & dependencies | `/digital-twin` | `DigitalTwin` | Estate replica with measured fidelity, evidence reconciliation and ten deterministic scenario types, fed by live state, wire scans, the dependency graph and the hardware fleet; scenario models are heuristic projections, not vendor simulations. |
| Cascade | Twin & dependencies | `/dependency-graph` | `DependencyGraph` | Directional blast radius across the estate graph. |
| Graph explorer | Twin & dependencies | `/graph` | `Graph` | Relationships, dependencies and blast-radius exploration. |
| Twin chain | Twin & dependencies | `/estate-twin` | `EstateTwin` | estate → assets → relationships → crypto graph → evidence graph → history → impact → simulation, link by link. |
| Thirteen-step walkthrough | Twin & dependencies | `/twin-walkthrough` | `TwinWalkthrough` | One asset, thirteen investigations on one canvas. |
| BOM migration simulation | Twin & dependencies | `/simulation` | `Simulation` | The Digital Twin's six BOMs (CBOM, NBOM, SBOM, HBOM, VBOM, Tech BOM) with each component's systems. For one algorithm change, it shows the status, cause and action per component, the issues per BOM layer, and the effect on every system-to-system connection. The scenario and cascade workspace is folded under Advanced. |
| Migration what-if | Twin & dependencies | `/what-if` | `WhatIf` | A one-screen go / no-go answer for any from → to change. It reads the live estate graph with the same engine as `/simulation` and shows the verdict, seven feasibility checks and the plan. |
| Performance intelligence | — | `/performance` | `Performance` | ZELNX Performance Intelligence: infrastructure, network, application, database, TLS and HSM/KMS performance — measured samples with unknown counts kept visible. |

### Governance

| Sidebar label | Group | Route | Component | Purpose |
|---|---|---|---|---|
| Banking & SWIFT | — | `/banking-regulatory` | `BankingRegulatory` | Banking, payment and SWIFT-oriented regulatory mapping. |
| Ownership & approvals | — | `/governance` | `Governance` | Ownership, exceptions, approval requests and risk acceptance — every decision recorded against who made it and when. |
| Trust & keys | — | `/trust` | `Trust` | Key inventory & rotation · HSM/TPM ceremonies · workload SPIFFE/SVID · OT safe-scan policy with the emergency stop. |
| Policy & compliance | Policy & compliance | `/security-policy` | — | The policy you set, the frameworks it maps to and the evidence trail behind both. |
| Policies | Policy & compliance | `/security-policy` | `SecurityPolicy` | Deterministic policy packs, scope and policy decisions. |
| Compliance | Policy & compliance | `/compliance` | `Compliance` | Framework mappings and compliance evidence. |
| Remediation | Remediation | `/remediation` | — | The task lifecycle, its ranking and the migration plan, all read from the agents' estate graph. |
| Tasks | Remediation | `/remediation` | `Remediation` | Owned task lifecycle. Tasks are opened from estate weaknesses or from a simulated migration, and verified against the agents' next report (or a rescan for scan tasks). |
| Priorities | Remediation | `/priorities` | `Priorities` | Every crypto weakness the agents observed, ranked by severity × system criticality, each with its cause, fix, owner and closing observation. |
| Migration | Remediation | `/migration` | `Migration` | Systems that need a post-quantum migration in dependency-ordered waves (providers first), plus estate-wide workstreams that link to Simulation and Tasks. |
| Evidence & assurance | Evidence & assurance | `/evidence` | — | One workspace over provenance, confidence, freshness, coverage gaps, verification, audit and customer assurance. |
| Evidence | Evidence & assurance | `/evidence` | `Evidence` | Hashes, manifests, scan and per-record verification (with an X-of-Y coverage line), and the filterable, exportable audit ledger. |
| Records | Evidence & assurance | `/assurance-records` | `AssuranceRecords` | Independent-report and operational-duty records. |
| Coverage | Evidence & assurance | `/assurance-coverage` | `AssuranceCoverage` | Registered coverage of the assurance programme. |
| Application trace | Evidence & assurance | `/assurance-trace` | `AssuranceTrace` | Requirement trace from an application to its evidence. |
| Accuracy sampling | Evidence & assurance | `/assurance-sampling` | `AssuranceSampling` | Sampling plan and measured accuracy. |
| Qualification | Evidence & assurance | `/assurance-qualification` | `AssuranceQualification` | Local qualification results; site acceptance requires external evidence. |
| Audit trail | Evidence & assurance | `/audit` | `Audit` | Who did what, when — the platform's hash-chained record. |
| Reports | Evidence & assurance | `/reports` | `Reports` | Reports, exports and report delivery status — the customer-assurance artifacts. |
| Security center | Security center | `/security-center` | — | One row over the three security surfaces. |
| Posture | Security center | `/security-center` | `SecurityCenter` | Platform security posture, threat feed, agents, audit integrity and control-plane health. |
| Control estate | Security center | `/security-controls` | `SecurityControls` | The estate of security controls themselves: findings, health, verification and export. |

### Administration

| Sidebar label | Group | Route | Component | Purpose |
|---|---|---|---|---|
| System health | System health | `/system-health` | — | One row over the two platform-introspection pages. |
| System health | System health | `/system-health` | `SystemHealth` | Health, readiness and platform service status — with independently measured worker-fleet and connector health (never derived from API liveness). |
| State machines | System health | `/state-machines` | `StateMachines` | The canonical state machine register on screen: every state the product can be in — observed from code, never invented — with one tone per semantic class, the transitions code actually makes, the honesty invariants, and machines whose vocabulary is not yet observed listed as such instead of guessed. See [state machine register](state-machines/README.md) and the [developer reference](api-reference/state-machines.md). |
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

## Every page: what is on screen and how the UI works

Per navigation entry, in sidebar order. Each entry names the page, what the
operator sees, how the interactions and data behave, and the honesty rules the
screen applies. All of these are current shipped behaviours in
`frontend/src/pages/*.tsx`.

## Every page: what is on screen and how the UI works

Per navigation entry, in sidebar order. Each entry names the page, what the
operator sees, how the interactions and data behave, and the honesty rules the
screen applies. All of these are current shipped behaviours in
`frontend/src/pages/*.tsx`.

### Overview

#### Command center

**`/command-center` — Command center (`CommandCenter`).** The landing page:
headline cards (estate counts, risk, coverage), then panels for platform
records, realtime scanner state, local inventory, certificate posture, PQC
posture, CBOM classification, telemetry, open drift and migration. The "Start
here — run your first real scan" panel appears when nothing has been scanned
yet. Visuals: `HBars`, `StackedBar`, `TickStrip`, `KpiMeter`, `GapBar`; empty
readings draw `VizEmpty` placeholders and `StateCell` chips. Each panel states
its own source and freshness — the page never implies one global snapshot.

#### Operations

All five Operations pages read one read model, `GET /api/v1/operations/{fleet,hosts,activity,monitor}`
(`api/operations_monitor.py`), built from what the Cryptava agents actually sent: the
control-plane registry and heartbeats, each agent's signed estate slice, its signed
performance samples, the estate change feed, correlated threat patterns and the audit log.
Every page polls on a visible interval (5–60 s, pausable), keeps the last good answer
when a read fails and says so, drops the previous tenant's answer on a tenant switch, and
carries a "what this screen proves" list. Liveness is computed from the heartbeat:
LIVE inside 3× the heartbeat interval, LATE after it, OFFLINE after the stale window,
NEVER_REPORTED with no heartbeat. Absence is never drawn as health: a host with no
performance sample is NOT_SAMPLED, a source that was not read is named as such.

**`/live` — Live estate (`LiveEstate`).** The bank's business systems, most critical
first, each with the hosts whose agent declares it, their liveness and heartbeat age,
CPU, running services, quantum-vulnerable algorithm uses, collector completeness and the
alerts that name the system. Hosts with no declared system are listed as such. Below:
collection health across every source, estate-wide alerts and the twin being read.

**`/live-stream` — Activity (`LiveStream`).** One timeline, newest first and grouped by
day: estate changes caused by agent observations (itemised before → after, acknowledgeable
from the row), correlated threat patterns, agent lifecycle (enrolled, activated, refused,
went silent) and remediation actions, each attributed to agents and systems. Filters by
kind, severity, agent and text; a 24-hour histogram; newly arrived events are marked. An
unchanged agent report stores a heartbeat, not an event. The platform event bus, the 13
attack-detection rules and the hash-chained Live CBOM sit in a collapsed section.

**`/live-monitor` — Live monitor (`LiveMonitor`).** The overall status and its reason,
KPIs (agents live, critical/high alerts, estate age, collection coverage, unreviewed
changes), the alerts produced by deterministic rules (AGENT_OFFLINE / LATE /
NEVER_REPORTED, DELIVERY_FAILING / BUFFERED, PLANE_FAILED / UNKNOWN, HOST_CPU_HIGH,
COVERAGE_LOW, THREAT_PATTERN, CHANGES_UNREVIEWED, NO_TRUSTED_COLLECTOR_KEY…) each with
since-when and a next action, and an agent-freshness grid drawing heartbeat age against the
late and offline thresholds. A wallboard mode fills the screen. A quiet monitor means the
agents report, not that the estate is safe.

**`/live-scanners` — Live scanners (`LiveScanners`).** The agent fleet table (host, IP,
system, liveness, heartbeat bar, delivery and buffer, link, version, plane chips, slice
size) with search and liveness filters. Opening an agent shows its host identity, signing
key, issues and each of its six collector planes with every source, its state, the count
it found and why a source was not read. The on-demand scanners that run on the CryptoScan
server itself (SSE activity, run control) sit in a collapsed section and make no request
until opened.

**`/runtime` — Runtime hosts (`Runtime`).** A host list with live CPU / memory and a
CPU sparkline; the selected host shows gauges (CPU, memory, disk, load, connections, TLS
and HSM latency when sampled), running services and the libraries each loads, listening
sockets (loopback vs exposed, TLS version), crypto libraries with the processes that
mapped them (from `/proc/<pid>/maps` runtime edges), certificates with days to expiry,
keys, and algorithms with their quantum verdict. The eBPF/adapter runtime crypto sensors
sit in a collapsed section.
#### Oversight

**`/launch-readiness` — Launch readiness (`LaunchReadiness`).** The external
acceptance panel, nine operating duties over the selected estate, scoped gate
reads and structured revision-checked actions. `StackedBar`/`GapBar`/`StateCell`
draw each duty's state with `toneColor`; blocks stay explicit (no on-site
validation → not marked done). Live read from the scoped gate registers.

**`/operator-decisions` — Operator decisions (`OperatorDecisions`).** The
attention → evidence → coverage → owner → independently observed fix workflow:
register sections in the current read, coverage denominators (never a score),
and the condition-level remediation workflow. `GapBar` renders the incomplete
denominators with refusal wording; there is no substitute risk score on this
page by design.
### Discovery

#### Asset discovery

**`/assets` — Assets (`Assets`).** The asset inventory table with a detail
`Drawer` (opened by row click) carrying identity spine, identity variants,
per-source facts, blast radius, technology context and the remediation tasks
bound to the asset's evidence (with preview and verify actions). Panels:
Inventory, detail tabs; `Table`, `Badge`, `Drawer`. Reads are tenant-scoped; a
failed read shows the failure banner instead of an empty table that looks like
an empty estate.

**`/dev-sec-ops` — Applications (`DevSecOps`).** Ten panels across three tabs:
container image scan, Kubernetes misconfig rules, cloud posture, the SBOM
scanner (CycloneDX 1.5 / SPDX 2.3), persisted hash-signed SBOM artifacts, SBOM
diff between two bills of materials, NTIA validation, SBOM import with pinning,
license compliance, and the component & advisory index. `StackedBar` draws
severity mixes; `Code` shows raw manifests. The tabs are pure front-end
switches over the same reads.

**`/certificates` — Certificates (`Certificates`).** The certificate estate:
fingerprint-deduped rows (subject, issuer, key algorithm/size, SANs, chain,
validity, where observed, revocation posture), record detail in a `Drawer`, and
trust-store inventories. Revocation states read `active` / `unknown ·
unverified` / `error` / `revoked` — checked per record, never "Active" from
absence. Certificate-revocation checks are stated as unverified when they are.

**`/network` — Network (`Network`).** Ten panels: structured network inventory
(import of declared destinations, 24/7 observation worker, approved network
scope with explicit authorization, emergency stop), service discovery ("port ≠
protocol"), network transport crypto risk & PQC readiness, evidence integrity
(chain, anchor, single writer), message-layer (Kafka/MQ) crypto, and
cross-layer correlation (static + runtime + network). `StackedBar`/`GapBar`
draw exposure; the observation-safety panel carries the emergency-stop control
and the page never infers crypto from a port number.

**`/cloud` — Cloud (`Cloud`).** Cloud inventory and posture for the connected
AWS/Azure/GCP accounts: resource tables, read-only posture states, L1 access
certainty vs. L2 check outcomes kept visibly distinct in the posture charts
(`Donut`, `HBars`, `GapBar`, `StateCell`). A failed source read renders unknown,
never a green zero.

**`/hardware` — Hardware (`Hardware`).** Root of trust, discovered devices,
firmware vs. baseline, hardware timeline, the hardware security catalog with
per-device detail `Drawer`, capabilities and evidence (including a hardware
scanner upload panel). HSM/TPM/HSM-fleet state is read-only inventory; "no TPM"
is never presented as "no hardware trust" — the page says what was observed.

#### Scan

**`/scanners` — Scanners (`Scanners`).** The scan launcher: scope picker, the
authorized jobs list and live job progress with `HBars`, `Meter`,
`VizEmpty`/`StateCell`. Running a scan calls the orchestrator; failures render
"Read failed"-style banners and never zeroes.

**`/collector-depth` — Collector depth (`CollectorDepth`).** Five panels:
Runtime, Network protocols (one protocol at a time), Windows, Six BOMs (one
projection engine, six depths), and five capabilities the build does not present
as operational. `FlowStrip` draws collector pipelines stage by stage and `Donut`
draws per-BOM reach. Every measured number is per family/protocol/platform —
the page never generalises one collector's reach to another.

#### CryptoLog and vendors

**`/cryptolog` — CryptoLog (`CryptoLog`).** The event intelligence shell: event
explorer with filters, event detail (`Evidence` and `Provenance` sub-panels),
and six in-page views switched by the view control (sibling page modules, not
separate routes): overview (event volume, integrity, collection health with the
"collection gap, not a healthy estate" wording), timeline (hash-chain
checkpoints and corrections), alerts (threat investigation + alert detail),
integrity (checkpoints, verification, Merkle proof), retention (policy + plan)
and reports (export). Events are labelled **recorded observations, never verdicts**; empty
explorers render "0 events loaded" as an empty state with that honesty line —
never a clean-estate conclusion. Correction APIs exist per event (reason
required, auth-checked).

**`/vendor` — Vendors (`Vendor`).** The hardware vendor registry: vendor
table, per-vendor device drill-down with verdict mix and a PQC roadmap watch.
`Table` + `Badge` verdict chips; rows come from the canonical hardware catalog,
and vendors without a catalog presence say so instead of showing an empty
verdict bar.
### Intelligence

#### Inventory — the six BOMs

**`/cbom` — CBOM (`Cbom`).** Cryptographic assets, algorithms, libraries and
protocols in the shared BOM shell (headline cards, breakdown panels, identity
inventory) with the estate-wide counts from `/cbom/query`'s own summary in the
page head. Empty is labelled absence, never a clean estate.

**`/sbom` — SBOM (`Sbom`).** Software components and dependency edges: top
suppliers, BOM coverage and integrity panels with `HBars`/`StackedBar`/`Donut`.
The pinned copy strings say the model classifies from evidence; missing
coverage is a gap, not health.

**`/hbom` — HBOM (`Hbom`).** Live hardware by type, estate composition,
integrity posture — plus the independent unified estate HBOM snapshots,
content-addressed pins and pin-to-pin diffs (`apiHbomSnapshotDiff`). Snapshots
are listed with their own hashes; a diff over unknown states stays unknown.

**`/nbom` — NBOM (`Nbom`).** Network surface by kind, blast-radius signal and
observation health. Static binary capability candidates are kept separate from
live network observations — the page never merges the two evidence classes.

**`/vbom` — VBOM (`Vbom`).** A supplier projection from retained evidence and
declarations: critical vendors, supply coverage and integrity panels. The page
states it is a projection, not independent supplier validation.

**`/live-asset-intelligence` — Technology BOM (`LiveAssetIntelligence`).** Ten
panels (three tabs): Pre-Deploy admission gate, VEX prioritisation, xBOM
correlation, runtime verification, supervisor action plan, HNDL, HSM fleet
readiness, mainframe ingest (z/OS), z/OS deep analysis and regulator exports.
`Stat`/`Kpi`/`Feed`/`Bar`/`Ring`/`Table` in the densest layout in the console.
Materialize/compare/export actions are gated writes reported through the
request-feedback wording.

#### Crypto intelligence

**`/crypto` — Cryptography (`Crypto`).** Catalog composition, priority
algorithms, network-service posture, observed certificates and live crypto
libraries observed on runtime hosts. `HBars`/`GapBar` draw catalog vs. observed
mixes; when no live inventory exists the library panel says so ("No live
inventory: run a runtime scan" — an unrun scan is not an empty host, and a scan
reporting zero libraries is not proof the host loads none). The normalized
crypto view has 114 pinned normalization tests behind it.

**`/crypto-assets` — Algorithm catalog (`CryptoAssets`).** The algorithm
explorer table; clicking a row opens the verdict `Drawer` (quantum + lifecycle
verdicts) and a usage/evidence panel. Badges state verdicts per algorithm; an
algorithm with no usage evidence shows none — never implied use.

**`/findings` — Findings (`Findings`).** Algorithm distribution, compliance
split and confidence panels; the filter bar; the evidence findings table and the
live runtime findings table side by side (each labelled with its evidence
class); "Why it matters" drawer; evidence chain (`Code`), normalized crypto and
policy evaluation panels. Findings rows carry content-hash + chain-hash
provenance and open the detail drawer with verify actions.



**`/crypto-assurance` — Crypto & key assurance (`CryptoAssurance`).** Seven
panels in `Tabs` with `Code` output: active TLS / cipher enumeration,
certificate-transparency monitoring, key / cert expiry alerts & SLA, HSM/KMS/
PKCS#11 key residence, trust-store inventory, the hybrid-PQC downgrade detector
and weak-primitive code rules. Each panel states its evidence class — CT
monitoring is declared-source, TLS enumeration is live-observed — and an
unverified check stays `unknown`, never a pass.
**`/agility` — Crypto agility (`Agility`).** Deterministic remediation signals
and scorecards: replaceability, migration readiness, dependencies and the
remediation task surfaces (`HBars`, `GapBar`, `StateCell`). Reach is computed
from evidence coverage, not assumed.

**`/drift` — Crypto drift (`Drift`).** Drift by severity, by family and
disposition progress (`Ring`, `Bar`, `HBars`): approved-baseline changes and
drift events with their sources. A missing baseline is shown as a gap — never
"no drift".

**`/intelligence` — Intelligence workbench (`Intelligence`).** The roadmap
models over live estate rows: evidence-linked findings, five risk dimensions,
PQC claim stages, snapshot diffs and the model-catalog tabs. Copy strings pin
the honesty lines ("A library supporting ML-KEM is not PQC readiness",
"UNKNOWN — not zero", "not computed (denominator incomplete)", "Absence of rows
is not absence of risk"). The `BACKEND OFFLINE` banner appears instead of
fabricated model output when reads fail.

#### PQC migration

**`/pqc` — PQC readiness (`Pqc`).** Instances per migration phase, transition
momentum and "what the estate model does not classify" panels (`Ring`, `Bar`,
`HBars`). Phase and momentum are drawn only over classified instances — what
the estate model cannot classify stays unclassified rather than guessed, and a
library supporting ML-KEM is never drawn as PQC readiness (the full claim ladder
is on the Intelligence workbench, where the real stage names are shown).

**`/pqc-map` — Migration map (`PqcMap`).** The PQC Migration Intelligence
workspace: the live quantum-risk inventory by family (from `/api/v1/quantum/plan` —
counts come only from live reads), the NIST candidate algorithms (declared
reference data, labelled as such, never estate observations), migration
complexity guidance, and the **persisted plan register**
(`/api/v1/pqc-migration/workspace`): migration waves, blockers, interoperability
notes and verified progress. A recorded claim is rendered as asserted, never as
proven ("a recorded claim is not progress proven"); a `verified` verdict requires
an evidence reference and is refused without one; an accepted blocker is drawn as
a recorded decision, never a silent close; and absence of rows is absence of a
plan — never a plan that is safe. Wave states follow the register
(`pqc.wave_status`): a wave verifies only over verified progress records.

#### Binary and OS & Kernel intelligence

**`/binary-intelligence` — Binary Intelligence (`Binary`).** Evidence-backed
cryptographic discovery from compiled artifacts — **static analysis only**:
binary scan jobs, per-scan detail, CBOM projection and the at-rest/batch
panels. Results carry artifact hashes and evidence IDs; an empty scan is an
empty result, not a clean estate.

**`/os-kernel-intelligence` — OS & Kernel Intelligence (`OSKernel`).** Observed
hosts, estate overview, Kernel Crypto API registrations, loaded modules,
config-flag states, disk-encryption metadata, hardware trust facts, public
certificate attributes and Tier-2 runtime sessions (metadata events only).
Failed reads render a "Read failed" banner instead of an empty host list;
registrations are never presented as runtime use (the page repeats it in its
captions), and Tier-2 runtime rows carry the metadata-only collection boundary.

#### Twin & dependencies

**`/digital-twin` — Replica & scenarios (`DigitalTwin`).** Twin overview,
fidelity, asset journal (time-travel), twin ↔ evidence reconciliation, the
scenario launcher and scenario results. Scenario models are heuristic
projections over the twin copy — never vendor simulations — and every result
labels its projection id and evidence state.

**`/dependency-graph` — Cascade (`DependencyGraph`).** Directional blast radius:
root picker, direction toggle, edge list with provenance links to the expanded
first-party graph service and a lineage panel stating that edges come from
observed relations and imports only. Node rows are clickable and open the asset
detail view.

**`/graph` — Graph explorer (`Graph`).** The relationship explorer: force
layout of nodes/edges, edge-provenance panel and impact summary. Every drawn
edge is backed by evidence; unproven relations are not drawn as edges.

**`/estate-twin` — Twin chain (`EstateTwin`).** The chain, link by link:
estate → assets → relationships → crypto graph → evidence graph → history →
impact → simulation, each link's status vocabulary and a "what this is" panel.
A broken read shows "No chain read" — the chain is never drawn as complete when
a link failed.

**`/twin-walkthrough` — Thirteen-step walkthrough (`TwinWalkthrough`).** One
asset, thirteen investigations on one canvas: the thirteen steps with per-step
panels reusing the same asset reads as `/assets`, with `HBars`/`StackedBar`
summaries. The steps are navigation, not a new evidence class.

**`/simulation` — BOM migration simulation (`Simulation`).** The page has three parts:

- **Inventory.** The Digital Twin's six BOMs as tabs, each with its components and the business systems they belong to, next to the business-system cards.
- **Migration.** A *Migrate from → to* form; choosing systems is optional. Each component gets AFFECTED / AT RISK / UNKNOWN / READY / NOT AFFECTED with a cause and an action, and every BOM shows its issues (cause, what happens if ignored, what to do).
- **Connections.** A connection map and one card per connection: which side changes, the effect on each side, the shared crypto components, and the ripple through the dependency chain.

It is read-only (`/estate/evidence/simulation/twin-boms`). The previous scenario/cascade
workspace (`components/WhatIfWorkspace.tsx`) is folded under *Advanced*: the question picker (with "start from a question this estate can
already be asked"), the step flow (choose → build → run → result), run history
and the permanent "What this workspace cannot tell you" panel. Scenarios copy
the twin and re-project the six BOMs; cascades walk established edges and
change nothing. Results report the live projection id unchanged; a failed
simulation says "The simulation did not run" — and "no impact" is never
rendered as zero impact ("this is not 'no impact'").

**`/what-if` — Migration what-if (`WhatIf`).** The one-screen go / no-go answer for
a crypto change.

- **Inputs.** Type any current and target algorithm; the algorithms the estate holds are
  offered, each with a suggested target.
- **Source.** The page reads the same live estate graph (the sandbox agents' data) and the
  same engine as `/simulation`, through `twin-boms`, so the two pages always agree.
- **Verdict.** BLOCKED / FEASIBLE — PARALLEL RUN / FEASIBLE — DIRECT CUT-OVER / NOTHING TO
  MIGRATE, with the systems that change and the issue counts.
- **Seven checks.** Crypto in use, certificates and CAs, crypto libraries, HSMs and key
  stores, declared vendors, network endpoints, and connected systems. A check with nothing
  recorded says *unknown*.
- **Plan.** The engine's phased plan.
- **Link.** One button opens `/simulation?from=…&to=…` with the same change already run.

It no longer uses the fixed-template `platform/whatif` engine or its hard-coded protocol
answers, and nothing is mutated.

#### Performance

**`/performance` — Performance (`Performance`).** ZELNX Performance
Intelligence: Overview, Infrastructure, Storage, Network, Application,
Database, Cryptographic, Cloud/Container and Capacity Planning panels, each
rendered through the page's own tile gauges (`TileView`) and summary tables,
plus alerts, baselines, capacity projections, a benchmark lab, an investigation
panel and collector health. Reads are tenant-scoped; while the
tenant resolves a non-blocking "Resolving this session's tenant" strip shows
above the content. Failed or unknown readings render **"unknown, never zero"**
rows and never print a numeric zero; an estimated exhaustion is labelled a
forecast, not a fact.



#### Banking, ownership and trust

**`/banking-regulatory` — Banking & SWIFT (`BankingRegulatory`).** The banking,
payment and SWIFT regulatory mapping: framework tables, control mappings and
evidence links (`Bar`, `Ring`, `Table`). Mappings are repository records, not
regulator assurances, and the page says which is which.

**`/governance` — Ownership & approvals (`Governance`).** Four panels:
ownership, exceptions, approval requests and the audit trail. Every decision is
recorded against who made it and when; an exception without an owner stays open,
and nothing on this page marks an external approval done from inside the repo.
**`/trust` — Trust & keys (`Trust`).** Payment/crypto keys and the rotation
forecast, HSM/TPM ceremonies, API-key rotation, workload identity (SPIFFE/SVID
issue & verify) and the OT safe-scan policy with the emergency-stop control and
maintenance windows. Ceremonies record participants and outcomes; the OT
emergency stop is a real control whose state is shown; "no TPM" is never
presented as "no hardware trust".
#### Policy & compliance

**`/security-policy` — Policies (`SecurityPolicy`).** Scanning policy,
rate-limiting (four layers) and privacy policy panels with read/edit controls.
Policy changes are writes (auth-checked, audited) reported with the
draft/unknown/outcome wording.

**`/compliance` — Compliance (`Compliance`).** Framework posture, evidence
pinning, retention and sign-off: requirement tables with per-requirement
evidence, pin/sign-off actions and the `Bar`/`Ring` posture visuals. Sign-off
records who accepted what and when; the page never marks an external
assurance done from inside the repo.



#### Remediation

All three Remediation pages read the same estate graph as the Digital Twin and the
Simulation, which on the sandbox means the Meridian agents' observations. The planner is
`agility/estate_remediation_plan.py`, served by `api/estate_remediation_work.py` under
`/estate/evidence/remediation/*`.

**`/remediation` — Tasks (`Remediation`).** The remediation task list, with
accept / complete / verify actions. Tasks are created in two ways:

- **From estate weaknesses.** One click opens tasks for every critical and high finding.
- **From a migration.** Type a change such as RSA → ML-KEM-768 and every issue the
  simulation raises becomes a task candidate. `?from=&to=` pre-fills the change; the
  Simulation and Migration pages link here that way.

The server re-reads the estate for every request. It refuses ids the estate no longer shows
and skips findings that already have an open task. Estate tasks are verified against the
newest agent report:

- gone, with the asset still observed → `VERIFIED`;
- still there → `FAILED`;
- no newer report, or the asset vanished → `INCONCLUSIVE`, and the task stays `COMPLETED`.

An unchanged report is recognised through the ingestion heartbeat. Scan tasks keep their
rescan comparison.

**`/priorities` — Priorities (`Priorities`).** Every crypto weakness the agents observed,
most urgent first. The checks are:

- broken or deprecated algorithms, including HSM key slots;
- RSA keys under 2048 bits;
- expired or expiring certificates;
- TLS 1.0 / 1.1 and weak or non-forward-secret cipher suites;
- hard-coded keys;
- Shor-vulnerable algorithms;
- libraries without ML-KEM or ML-DSA;
- HSMs outside FIPS mode;
- vendors that declare no post-quantum release or have no support contract.

The rank is severity × the most critical system's weight, plus a small bonus for shared
assets; the formula is shown on the page. Each row explains why it matters, what to do, who
acts and which observation closes it, and offers "Open task". Gaps in what the agents
recorded are listed, not hidden.

**`/migration` — Migration (`Migration`).** The post-quantum migration plan, built from the
estate:

- Systems holding broken, deprecated, quantum-vulnerable or short-key crypto are put into
  waves. A system moves after every changing system it calls, and systems that call each
  other move together.
- Each system card shows its quantum-safe share, what moves to what, its open findings and
  the reason for its place in the order.
- Workstreams (for example RSA → ML-KEM-768 / ML-DSA-65) link to `/simulation` and to
  `/remediation?from=&to=`.
- Systems with nothing to migrate are listed separately; that is not stated as proof.

#### Evidence & assurance

**`/evidence` — Evidence (`Evidence`).** The evidence chain: hashes, manifests,
scan verification with an "X of Y verified" coverage line (an incomplete
denominator stays visible), per-record verification buttons, the filterable
audit ledger and export actions. Verification results are per record — a passed
read never inflates the coverage line.

**`/assurance-records` — Records (`AssuranceRecords`).** Independent-report and
operational-duty records with revision-checked structured actions. Blocks are
explicit (no on-site validation → not marked done); live read from the scoped
gate registers.

**`/assurance-coverage` — Coverage (`AssuranceCoverage`).** Registered coverage
of the assurance programme: denominators, not a score; `GapBar` draws the
incomplete ones with refusal wording.

**`/assurance-trace` — Application trace (`AssuranceTrace`).** Requirement
trace from an application to its evidence: the trace table and per-hop evidence
links; a broken hop is shown as broken, never skipped.

**`/assurance-sampling` — Accuracy sampling (`AssuranceSampling`).** The
sampling plan and measured accuracy: sample table, result panels and the
coverage line. Accuracy is reported only over what was sampled.

**`/assurance-qualification` — Qualification (`AssuranceQualification`).**
Local qualification results with explicit external gates — site acceptance
requires external evidence and is never marked done from local runs.

**`/audit` — Audit trail (`Audit`).** The platform's hash-chained audit record:
the filterable ledger, verification and export — who did what, when.
### Administration

**`/reports` — Reports (`Reports`).** Compliance frameworks, report schedules,
the PoC exit report, snapshot pinning ("Pin a scan's report now") and generated
reports. Schedule/pin actions are writes with the request-feedback semantics;
generated artifacts carry their evidence hashes.
### Governance

#### Security center

**`/security-center` — Posture (`SecurityCenter`).** Security posture over
time, the live threat feed and event stream, agents, plugins, audit & evidence
integrity and control-plane health (`Feed`, `Table`, `Code`, `Bar`/`Ring`).
Each panel names its source; plugin/agent inventories list what is connected,
not what is possible.

**`/security-controls` — Control estate (`SecurityControls`).** The security
controls themselves: findings, health, verification and export URL controls.
Verify/export actions report the server's answer through request feedback.



**`/system-health` — System health (`SystemHealth`).** Health, readiness and
platform service status with independently measured worker-fleet and connector
health (`Badge` states) — never derived from API liveness. A failed probe shows
unknown.

**`/state-machines` — State machines (`StateMachines`).** The state vocabulary
on screen: how to read the register, the state classes with their tones
(`toneColor`), the transitions code actually makes and the honesty invariants
("unknown is never zero", "Capability is never usage", "NEVER means used").
Machines whose vocabulary is not yet observed render "Vocabulary not yet
observed" in slate instead of a guessed state.

**`/settings` — Settings & org (`Settings`).** Organization sector, identity &
SSO, safe-scan policy, notification routing and platform scope, each with
read/edit controls. Changes are audited writes; a failure keeps the draft and
says so.

**`/identity` — Users & teams (`Identity`).** The user/role tables and the
invite/role-action surfaces, plus account-level operations: MFA
enrol/disable, SSO status and session details. Mutations are explicit buttons
with confirmation and server-reported outcomes.

**`/integrations` — Integrations & API (`Integrations`).** The credential
vault, connected systems and the outbound delivery log for real signed HTTP
fan-out (SIEM/SOC, ticketing, CMDB). Every attempt is audited and listed —
including failures — and credential operations (create/rotate/lease/release)
report through request feedback.

### Routed pages outside the sidebar

Deep-linked surfaces exist as their own routes (see the table below). What each
presents, briefly:

- `/scope` — the module→deterministic action map, the deterministic-vs-heuristic
  split, and the `[!]` capability boundaries (bank validation, Ghidra,
  HSM/KMS/PQC performance, Windows/macOS live collection, OT/banking vendor
  telemetry, universal discovery, real exporter wiring).
- `/crypto-changes` — the change stream that feeds drift, CBOM bumps and alerts.
- `/libraries` — the crypto library center: library · version · source package ·
  processes · verdict from the live runtime scanner.
- `/protocols` — the network protocols & services catalog: port, transport,
  category, encryption, exposure and risk verdict per named service.
- `/catalog` — the three canonical catalogs on one screen: algorithms, network
  services and hardware devices, each with its own verdict mix.
- `/live-environment` — the unified live graph across network, cloud, vendor,
  hardware, cryptography and applications: scan orchestrator, environment map,
  live events, dependency topology and run history.
- `/cmdb` — CMDB-style live activity, asset types, unified risk (with "why this
  score" inputs spelled out) and PQC posture.
- `/platform-p2` — plugin marketplace, anomaly flags, governance approvals,
  policy exceptions, the tamper-evident data-lake export chain, machine API
  keys, remediation SLA, OT safety gates, vault leases and automation runs.
- `/automation` — the automation workspace: the action safety ladder, rule
  builder, active rules, ITSM/SIEM delivery and built-in playbooks.
- `/alerts` — the findings alert feed ("All findings") with per-finding detail.
- `/notifications` — in-app notification feed, event→channel routing and outward
  delivery, including the durable delivery receipts view (`NotificationReceipts`
  renders inside this page).
- `/telecom` — the telecom realtime scanner (5G SBA/EPC/IMS/signalling/NDS-IP
  classification), scan panel, event feed, PQC journey, roadmap, roaming
  partners and estate registry.
- `/organization` — org → region → BU → environment → assets → crypto, with
  region comparison.
- `/supervision` — the read-only supervisory portal: group posture, DORA
  register, migration roadmap (requires `supervision.read`).
- `/tenancy` — the SaaS control plane: switch organization, plan usage, members
  and invites.
- `/sectors` — the multi-sector profiles: which assets matter per sector and
  which policy packs/frameworks apply, with the active-sector switch.
- `/resilience` — backup policy/runs and the air-gap build/import tools
  (authenticated flow with session-scoped import tokens).
- `/security` — RBAC matrix, tenant isolation (ABAC), audit chain integrity,
  safe-scan policy and baseline HTTP controls.
- `/admin` — the live security enforcement panel, RBAC matrix, your own grants
  and tenant administration.
- `/security-intelligence` — scan profiles, universal asset identity,
  verification & freshness, finding dedup/risk chain and scan triggers.
- `/accuracy` — accuracy sampling truth: per-dataset breakdown, how accuracy is
  verified and the honesty constraints, with explicit zero-denominator handling.
- `/timeline` — one global timeline across the platform, for audits and
  incidents.
- `/vendor-due-diligence` — ten-section operational vendor profiles with
  explicit unknowns, evidence provenance and immutable revisions.
- `/onboarding` — the first-run organization/scope/connection wizard.
- `/risk` — the weighted risk model (0–100, explained per factor, versioned),
  per-system explanations and open drift/findings.
- `/executive` — the board view: overall posture, priority queue and coverage
  status, derived only from stored scan evidence; no targets or illustrative
  figures.
- `/search-results` — the global search screen with scope boundaries spelled
  out (reached from the header search).
- `/role-dashboard` — the persona dashboard for the signed-in role.
- `/login`, `/register`, `/reset-password`, `/invite-accept` — authentication
  flows rendered through `PublicEntry`, not sidebar entries.

## Routed pages reached by deep link

These pages are routed but are not primary sidebar rows. They are reached from
deep links, search, report templates or other workspaces. The root `/` and
unknown paths redirect to `/command-center`; `/techbom` redirects to
`/live-asset-intelligence`.

| Route | Component | Why it is outside the sidebar |
|---|---|---|
| `/scope` | `Scope` | Deterministic action map, the deterministic-vs-heuristic split and the `[!]` capability boundaries. |
| `/crypto-changes` | `CryptoChanges` | The change stream for crypto-relevant deltas. |
| `/libraries` | `Libraries` | The live runtime scanner's library inventory. |
| `/protocols` | `Protocols` | The canonical network-service registry with verdicts. |
| `/catalog` | `Catalog` | The combined canonical catalogs (algorithms, network services, hardware devices). |
| `/live-environment` | `LiveEnvironment` | The cross-domain live environment map and orchestrator. |
| `/cmdb` | `Cmdb` | CMDB-style inventory, unified risk with explained factors and PQC posture. |
| `/platform-p2` | `PlatformP2` | Plugin marketplace, anomaly flags, governance, lake export, machine API keys, SLA, OT gates, vault leases and automation. |
| `/automation` | `Automation` | Automation rules with the action safety ladder and ITSM/SIEM delivery. |
| `/alerts` | `Alerts` | The findings alert feed. |
| `/notifications` | `Notifications` | Notification feed, routing and outward delivery — including the durable delivery receipts (`NotificationReceipts` renders inside this page). |
| `/telecom` | `Telecom` | Carrier-realtime scanner, event feed, PQC journey, roadmap, roaming and estate registry. |
| `/organization` | `Organization` | Organization → region → BU → environment → assets → crypto. |
| `/supervision` | `Supervision` | Read-only supervisory portal with role gate and declared limits. |
| `/tenancy` | `Tenancy` | Organization switcher, plan usage and membership. |
| `/sectors` | `Sectors` | Sector profiles and the active-sector switch. |
| `/resilience` | `Resilience` | Backup/attestation operations and air-gap bundles. |
| `/security` | `Security` | RBAC, tenant isolation, audit chain, safe-scan policy and baseline HTTP controls. |
| `/admin` | `Admin` | Live security enforcement, RBAC matrix, your grants and tenants. |
| `/security-intelligence` | `SecurityIntelligence` | Scan profiles, identity, verification, dedup and scan triggers. |
| `/accuracy` | `Accuracy` | Accuracy truth tables with zero-denominator handling. |
| `/timeline` | `Timeline` | The global timeline across the platform. |
| `/vendor-due-diligence` | `VendorDueDiligence` | Operational vendor profiles with immutable revisions. |
| `/onboarding` | `Onboarding` | The first-run organization/scope/connection wizard. |
| `/risk` | `Risk` | Weighted risk model, per-system explanations and open drift. |
| `/executive` | `Executive` | Board-level posture derived only from stored evidence. |
| `/search-results` | `SearchResults` | Global search with explicit boundaries (from the header search). |
| `/role-dashboard` | `RoleDashboard` | Persona dashboard for the signed-in role. |
| `/login` | `PublicEntry` | Sign-in. |
| `/register` | `PublicEntry` | Account registration. |
| `/reset-password` | `PublicEntry` | Password recovery. |
| `/invite-accept` | `PublicEntry` | Invitation acceptance. |

## Feature ownership

| User workflow | Primary module or workspace |
|---|---|
| See every discovered crypto asset | Cryptography |
| Find weak or vulnerable cryptography | Risk, Findings |
| Prepare quantum-safe migration | The PQC migration workspace (readiness, map, plan register), Migration |
| Understand key and certificate lifecycle | Certificates, Trust & key operations |
| Measure cryptographic performance | Performance |
| Investigate machine-level crypto behavior | OS & Kernel Intelligence, Runtime |
| Produce audit or regulator evidence | The Evidence & assurance workspace (Evidence, Records, Audit trail, Reports) |
| Track remediation ownership | Remediation, Priorities |
| Study binary and SDK cryptography | Binary Intelligence |
| Work with operational technology | Trust & key operations (OT policy), hardware telemetry |
| Work the banking estates | Banking & SWIFT (Governance), payment keys & ceremonies (Trust), HSM fleet / HNDL / mainframe (Technology BOM) |
| Understand the live environment | Live estate, Live environment |
| Follow live security changes | Live crypto changes, Live stream |
| Run realtime investigations | Realtime scanners, Live monitor, CryptoLog |
| Plan and govern remediation | Governance |
| Configure secure operations | Scope, Security policy, Tenancy |
| Apply sector policy packs | Multi-sector profiles |

## Binary artifact scanning workflow

Developer-facing `/dev-sec-ops` exposes container, Kubernetes, cloud, SBOM,
license and component workflows. Artifact ingestion is routed through the
signed `/api/v1/binary/*` upload, scan-job and CBOM surfaces, which accept
`sha256`, `sha1` and `md5` digests and return canonical
`evidence_class: static`. The completed binary workflow and its boundaries are
recorded in [PRODUCT-CAPABILITIES-END-TO-END.md](PRODUCT-CAPABILITIES-END-TO-END.md);
absent live dynamic analysis and Ghidra, the static pipeline is bounded and
stated.

## Related developer documentation

- [State machine register](state-machines/README.md) — the canonical state
  vocabulary every page renders through `stateTone()`.
- [API reference](api-reference/rest-api.md) — how each page's reads and writes
  map to the platform's typed operations.
- [PLATFORM-STATUS.md](PLATFORM-STATUS.md) — what the whole platform supports
  today, measured from source.
