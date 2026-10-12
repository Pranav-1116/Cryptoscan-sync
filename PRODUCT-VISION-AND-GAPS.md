# CryptoScan Product Vision and Missing Pieces

**Working-tree snapshot:** 2026-10-12 · branch `arena/01a106c8-cryproscan` · committed HEAD `0b972668`.  
**Purpose:** Define the enterprise Cryptography Threat Intelligence product being built, describe what the repository actually does today, and identify the remaining implementation and qualification work. This is a product/delivery brief, **not** an audit certificate or a declaration of production readiness.

> **Read this distinction first:** many services, routes, tests and UI pages exist. Existence is not the same as an integrated, authorized, evidence-backed workflow; a passing local test is not customer or production qualification. The current working tree has extensive **uncommitted** frontend and drift changes, plus an untracked `IMPLEMENTATION_STATUS.md`. Those changes must not be presented as a released build.

## 1. The product to build

CryptoScan should become a self-hosted, tenant-aware **Cryptography Threat Intelligence platform**. An operator should be able to discover where cryptography is used across applications, source and binaries, containers, networks/TLS, cloud services, hardware/HSMs, OT, telecom and vendors; see exactly which authorized collector produced each observation; and make defensible security, compliance and post-quantum migration decisions from verifiable evidence.

The product is not an AI chatbot or a collection of disconnected scanner reports. Its authoritative chain is:

```text
Authorized tenant, target and scan mode
  → bounded collector and explicit coverage/failure result
  → structured observation with collector/version/source/time
  → sanitized, immutable, hash-verifiable evidence
  → deterministic normalization and tenant-local crypto fact
  → stable asset identity, owner and meaningful dependency
  → versioned CBOM / HBOM / VBOM / NBOM / Technology BOM
  → observed/declared knowledge-graph relationship
  → explainable policy verdict, risk and PQC migration priority
  → approved baseline and drift/reintroduction event
  → owned remediation task and authorized change
  → new scan, condition-level verification and auditable closure
  → signed/exportable report and honest authenticated UI
```

**Non-negotiable product rules**

- Evidence and deterministic code—not AI text—decide facts, risk formulas and compliance verdicts. AI, if added, may explain or help an analyst; it must not rewrite evidence, facts, decisions or audit history.
- Never retain private-key bytes, credentials or unredacted source snippets as a convenience for a finding. Unknown, blocked, partial, not observed and not evaluated are distinct from PASS and from zero.
- A tenant must not read or mutate another tenant's customer-owned resources by guessing an ID. Platform-NULL legacy rows have a separate, explicit meaning; they are not a tenant's own approved baseline.
- A scan is not complete merely because an API returned 202, a worker ran one detector, or an optional source failed softly. Every reported result needs source coverage, freshness and provenance.
- An algorithm appearing in two BOMs is an **association**, not proof that both rows are the same physical key or device. A graph edge must have a real source and an appropriate relationship meaning.
- A ticket is not a fix. `ACKNOWLEDGED` and administrative `RESOLVED` are not the same as a verified remediation after an adequate rescan.
- The interface should be a dense, accessible enterprise security workspace, not an AI product. Its restrained cryptography-themed motion must never impersonate a live verification event or hide a value; reduced-motion users receive static content.

These boundaries are consistent with `docs/architecture/platform-boundaries.md:72-87` and the enterprise maturity distinction in `docs/product/enterprise/16-boundaries-maturity-and-readiness.md:3-31`. They are **target behavior**, not a claim that every source already satisfies them.

## 2. What an operator should be able to do

| User journey | Product outcome required |
|---|---|
| Onboard an estate | Create organization/environment, declare authorized targets and active/passive limits, assign owners, validate connector permissions and record consent/maintenance windows. |
| Run discovery | Start a specific authorized collector, receive a durable run ID and live status, know what was attempted, skipped, partial, refused or failed, and see real observations rather than an estimate presented as scan output. |
| Investigate a finding | Follow finding → exact observation/evidence → fact → asset/system/owner → BOM component → dependency/risk/policy result, with tenant scope and timestamps intact. |
| Plan PQC and resilience | Explain why a system is exposed, where harvested-now/decrypt-later exposure or migration blockers come from, which dependencies prevent an upgrade, and what assumptions are unknown. |
| Monitor change | Approve a baseline, compare later successful scans, classify new/removed/changed/reintroduced crypto deterministically, acknowledge or dismiss events, and distinguish administrative disposition from actual condition clearance. |
| Remediate and prove it | Assign a task, make an authorized change, scan the affected source again, verify the same condition in an adequately covered rescan, and retain both old and new evidence. |
| Report and operate | Export versioned BOMs and evidence/report packages, verify integrity, inspect audit/health/job failure state, restore data, and qualify a specific immutable release in its target environment. |

Primary readers are security analysts, cryptography/PQC architects, asset and business owners, auditors, DevSecOps operators and platform administrators. They need different permissions and views over the **same** underlying evidence, not separate hand-entered truths.

## 3. Status vocabulary and source of truth

- **Implemented slice:** source code and focused tests exist; says nothing by itself about production deployment.
- **Partial/disconnected:** functionality exists, but a path, data contract, authority link or operational loop is incomplete.
- **Missing:** the required contract/control is not implemented in the path under discussion.
- **Unverified:** code or a test exists, but the requested live, tenant, hostile-input, scale or external proof has not been run.
- **Blocked externally:** customer/provider authorization, third-party assurance, release controls or other non-code evidence is required.

Use current source, schema, tests and freshly run evidence before narrative documents. Old `ANALYSIS.md`, `FULL-REPO-STUDY.md`, root changelog and first pages of the audit reports are dated snapshots; later addenda and code may supersede them. `IMPLEMENTATION_STATUS.md` is an earlier **untracked** local progress record, not a release sign-off.

### Current evidence boundary

The committed worker can queue a scan through central admission, perform source plus optional collector stages, hash/load evidence, normalize/evaluate policy, materialize tenant-local facts, then run drift/gate and a workspace CBOM (`services/api/api/routers/trigger.py:153-205`; `services/worker/worker/pipeline/pipeline_runner.py:226-279`; `services/evidence/evidence/core/pipeline.py:53-113`). Migration `0087` aligns derived facts with tenant-local, NULL-safe identity (`services/database/migrations/versions/0087_fact_identity_tenancy.py:24-50`). Stored-scan verification and export have real API paths (`services/api/api/routers/export.py:23-48,241-254`). A local source scan previously persisted and verified evidence, facts and asset–evidence links, but the **entire target chain above has not been demonstrated in one run**.

The last checked-in bank-readiness gate is dated **2026-10-04** and marked **FAIL** for an older revision; its green subcategories cover limited local tests, not this working tree or a bank estate (`PRODUCTION-READINESS.md:39-77,100-126`; `docs/readiness-evidence/bank-readiness.json:31-132`). Do not promote it to current production approval.

## 4. Missing pieces by platform layer

### 4.1 Authorized collection and scanner safety — **P0 partial / missing common enforcement**

**Current:** queued repository jobs pass common admission and local source-root checks; the worker carries tenant context across the queue. Static, binary/container, network/TLS, cloud IaC/live, passive OT, telecom, payment/hardware and vendor modules provide meaningful separate capabilities. Normal repository scanning uses network discovery without live TLS probing by default and reads OT observations passively (`services/api/api/security/scan_admission.py:256-335`; `services/worker/worker/pipeline/stage_network_scan.py:13-31`; `services/worker/worker/pipeline/stage_ot_scan.py:13-47`).

**Missing/disconnected:** common queue admission is **not** a guarantee for every API scanner path. Synchronous cloud, OT and container scan routes accept request-selected filesystem targets and run outside the common queued job/evidence transaction; a network-scan route has SSRF target validation but is not the same central safe-scan policy (`services/api/api/routers/cloud_scans.py:16-26`; `services/api/api/routers/ot.py:16-37`; `services/api/api/routers/container_scans.py:20-54`; `services/api/api/routers/network_scans.py:41-94`). This is a source-level trust-boundary gap requiring targeted authorization tests, not a claim that all collectors are absent or exploitable. The default source scanner still executes inside a credentialed worker process; optional multiprocessing is not a proven hostile-repository sandbox (`services/scanner/scanner/core/scanner.py:27-63`).

**Done when:** all entry points share tenant/resource authorization, declared source roots, scan-mode/OT approval, durable job identity, bounded inputs, failure/coverage reporting and a tested process/container isolation boundary. Prove that a refused target launches no scan and that malicious archives/files cannot control the host or consume unbounded resources. Qualify each live provider/HSM/OT integration with its authorized operator; a supplied report or simulated estate is not field coverage.

### 4.2 Evidence, observations and database truth — **P0/P1 partial**

**Current:** content sanitization precedes hashing, evidence is linked into a scan chain, and loader verification checks the stored scan. Committed changes reject unsupported independent unhashed provenance/integrity sidecars. Derived facts have evidence references and can be rebuilt; vanished observations can mark facts stale; fact-store reads expose page-scoped freshness (`services/database/db/loader/provenance.py:21-46`; `services/database/db/repositories/fact_repository.py:42-118`; `services/api/api/routers/facts.py:136-221`). Production DB startup is Alembic-owned rather than silently `create_all`-owned (`services/database/db/connection/session.py:39-94,130-155`).

**Missing/qualified:** old already-committed evidence may contain source snippets; an API projection that hides a field is **not deletion** from hash-chained storage. Inventory, asset and fact write paths have not become one stable source of physical identity; `crypto_assets` remains a separate fused write-side model while the fact store is a derived projection. Per-record evidence verification and a single durable scan-run-to-versioned-BOM-to-report authority are not established merely by scan-level PASS. Development and production datasets need measured migration, index, constraint, transaction, tenant and historical-state tests at scale. `docs/PRODUCTION-GAP-HANDOFF-2026-10-08.md:8-15,32-43` identifies historical snippet disposition as a P0 operator decision.

**Done when:** every accepted observation has collector/version, target, tenant, time, location, confidence, source hash and coverage status; hashes commit to the **sanitized** authoritative payload; source-side sidecars cannot carry uncommitted data; legitimate deletions retain an auditable tombstone/reissue story; and a tenant-isolated PostgreSQL schema can reconstruct current, baseline and point-in-time fact/asset state across multiple scans. Historical sensitive rows require controlled inventory/disposition rather than silent chain rewriting.

### 4.3 Normalization, policy and compliance — **P1 partial; UI P0 trust gap**

**Current:** deterministic exact/alias/pattern normalization, YAML policy packs and PASS/FAIL/unknown-like verdict paths exist. The current worker evaluates evidence and records policy results. The API has a compliance-evidence endpoint and retention configuration, but its platform-control evidence pack is not a blanket per-framework certification (`services/normalization/normalization/core/processor.py:78-191`; `services/policy/policy/core/engine.py:71-105`; `services/compliance/compliance/engine.py:49-153`).

**Missing/qualified:** demonstrate cross-scanner alias equivalence, complete enabled-rule coverage and pack-version integrity; do not call a rule-ID mention report a behavioral test. Separately map each requirement to exact evidence, gaps, expiry and reviewer sign-off. The current `/compliance` UI still shows **100%** for an empty/failed controls response, supplies a seven-year retention default, says “Harmonized” without proof, and its standard buttons do not filter the controls (`frontend/src/pages/Compliance.tsx:13-48,83-129,134-197`). The Compliance frontend was modified by an agent stopped mid-task and has no new focused test; treat that working-tree page as **unverified**.

**Done when:** unevaluated/unsupported requirements remain visible as such; framework scores have explicit denominators and source scopes; retention text reflects configured and enforced storage behavior; and the interface never turns missing API data into a green compliance score.

### 4.4 Unified BOMs and physical identity — **P1 partial**

**Current:** CBOM, NBOM, VBOM, Technology BOM and hardware-layer generation/import/export modules exist. The live cross-query uses crypto asset inventory, stored network probes for NBOM, vendor rows for VBOM and actual hardware assets as the TechBOM HBOM layer when present (`services/api/api/routers/cbom.py:270-328,1011-1077`; `services/cbom/cbom/technology_bom.py:159-238`). Cross-BOM comparison retains BOM/ref/value provenance, distinguishes variation inside one BOM from cross-BOM disagreement, and labels algorithm matches as associations, not confirmed same-device identity (`services/cbom/cbom/cross_bom.py:169-253`).

**Missing/qualified:** the HBOM layer is **not** an independent, unified hardware generator. Source gathering is bounded; the newest stored network run wins per endpoint within that window, which is not proof of all network assets or historical completeness. Algorithms alone cannot join two observations to the same key/HSM/system. The pipeline CBOM is written to an ephemeral workspace while API CBOM may be regenerated from stored evidence; no single signed, persisted scan-run/BOM/report version is demonstrated (`services/worker/worker/pipeline/stage_cbom_generate.py:13-32`; `services/api/api/routers/cbom.py:836-874`).

**Done when:** stable source-specific asset identity and evidence references flow into versioned BOM components, cross-BOM edges carry source/relationship/tenant/scope and independent-versus-derived provenance, repeated scans produce comparable snapshots, and every exported BOM can be traced to the exact admitted scan and evidence version without inventing a merged physical asset.

### 4.5 Knowledge graph, dependency and business impact — **P1/P0 tenancy qualification**

**Current:** the platform builds system/asset/vendor/cert/network relationships and offers graph and blast-radius APIs. The latest fact/code-graph slice has tenant-local stable fact IDs and evidence references. For tenant-scoped reads the graph facade deliberately uses a filtered in-memory graph because Neo4j read-side queries are not tenant-scoped (`services/graph_engine/graph_engine/core/facade.py:20-38`; `services/api/api/routers/graph.py:263-314`).

**Missing/qualified:** distinguish observed traffic, declared topology, scanner-derived dependency and inferred association in each edge. No code-level CALLS or complete live cloud/Kubernetes dependency graph is demonstrated; a graphical line must not manufacture a call or an Internet exposure path. The graph is not yet proven to join a specific physical key/device → actual application/service dependency → owner/business process → evidence-backed risk across tenants at production scale. Neo4j tenant-safe reads or an explicit alternative with equivalent performance/coverage require testing.

**Done when:** every node/edge has stable tenant-local identity, type, source observation, timestamp and confidence; blast-radius traversal is bounded, permission-filtered and reproducible; unknown edges do not silently become known dependencies; graph API and UI agree on node IDs and traversal fields.

### 4.6 Explainable risk, PQC and threat intelligence — **P1 partial / field calibration missing**

**Current:** deterministic risk and PQC modules plus threat-advisory input exist. System risk considers evidence, open drift, CVEs, declared environment/criticality and dependency counts; quantum planning can consume system-linked crypto assets (`services/api/api/routers/risk.py:108-243`; `services/api/api/routers/quantum.py:16-33`).

**Missing/qualified:** a dependency count is not an observed blast-radius or calibrated exposure score. Every high risk should answer what asset is affected, where the evidence lives, why a control fails, who owns the business impact, which assumptions are declared versus observed, and why a particular remediation/PQC wave is recommended. Held-out/customer corpora, HNDL longevity inputs, real provider advisories, operational migration blockers and HSM challenge verification are not qualified by synthetic bank-shaped fixtures. Do not turn algorithm-name guesses or inventory coverage into a PQC-ready verdict.

### 4.7 Drift, baselines and remediation closure — **working-tree partial**

**Current:** committed drift detector/repository and API paths exist. The **uncommitted** working tree adds tenant-exact baseline selection, explicit NO_APPROVED_BASELINE/BASELINE_UNAVAILABLE/PARTIAL_CONFIG_UNAVAILABLE states, deterministic idempotent events with evidence IDs, and an isolated SQLite/ASGI lifecycle regression for baseline → NEW/REMOVED/CHANGED → acknowledgement → administrative resolution (`services/worker/worker/pipeline/pipeline_runner.py:1344-1503`; `services/database/db/repositories/drift_repository.py:17-78`; `services/api/tests/integration/test_crypto_drift_lifecycle.py:92-254`). The frontend Drift view has uncommitted paging and server-confirmed dispositions (`frontend/src/pages/Drift.tsx:113-329`).

**Missing/qualified:** do not treat that uncommitted test as a live collector→worker→PostgreSQL→UI two-scan proof. Acknowledgement is analyst triage; `RESOLVED` is an administrative state, not condition-level VERIFIED remediation. Drift-to-task creation is optional and bounded, and a ticket or vanished path alone cannot prove adequate rescan coverage (`services/api/api/routers/drift.py:54-135,225-253`). The `/priorities` UI is a read-only ranker, not an owned task/change/rescan workflow (`frontend/src/pages/Priorities.tsx:55-120`).

**Done when:** an auditor-approved baseline is tenant/target exact; new, removed, changed and reintroduced crypto is classified deterministically; repeated scans neither duplicate events nor reset dispositions; tasks identify owner/action/due state; a later authorized scan of the affected surface proves the underlying condition; false-positive/administrative closure is labeled separately; historical evidence and timeline remain accessible.

### 4.8 Backend, integrations and observability — **P0/P1 partial**

**Current:** FastAPI has authenticated routes, RBAC, API keys, tenant-scoped middleware and worker jobs; local PostgreSQL/Redis/API/frontend/worker can start. The committed queued pipeline has separate live job telemetry and sanitized public failure messages. A smoke script checks live API surfaces without writing session tokens to predictable files.

**Missing/qualified:** direct scanner routes need the same admission/tenant/resource rules as queued jobs. Per-run IDs and real progress are missing for some specialized live scanner modes; the `/scanners` UI therefore disables those selections instead of queueing a different workflow (`frontend/src/pages/Scanners.tsx:10-17,94-152`). Process-local API-key quotas and trusted-forwarded-IP assumptions need edge and multi-replica tests (`services/apikeys/apikeys/policy.py:147-181`; `services/api/api/dependencies.py:140-149`). A completed scan can still include failed optional derived/provider stages; status, coverage and operator alerts must disclose that rather than imply complete observation. No claim is made that every one of the many API operations has a verified IDOR, tenant, validation and audit-log test.

**Done when:** every important endpoint has input/tenant/resource checks, safe error shapes and mutation audit data; all scanner entry points return durable, scope-bound job identity; queue, worker, database and connector health are independently measured; operators can distinguish RUNNING, stuck, partial, refused and failed jobs without exposing SQL parameters or credentials.

## 5. Frontend: intended interface versus today's UI

The requested console is an **enterprise Cryptography Threat Intelligence workspace**: dense but readable inventory tables, search by real asset/finding ID, source coverage, evidence timeline, dependency graph, PQC/drift planning, remediation status, audit and export. It must work in light/dark, at phone width, with keyboard/screen-reader support and reduced motion. Cryptography-themed animation should be brief, conceptual and nonessential—not an AI orb, a looping “verification” signal or a substitute for actual data.

Current **uncommitted** UI work improves the login cipher reveal, route/navigation links, tenant-safe paged Assets, source-qualified Command Center, onboarding-versus-scan state, paged Drift dispositions and scan-level Evidence/Audit separation. The current working tree passed **209 frontend tests and typecheck** during this document's preparation; the stopped Compliance agent left no new verified Compliance test. These checks use mocked fetches and do **not** prove an authenticated browser walkthrough of every page. The local login page rendered in a sandboxed browser, but that is not a full UI gate.

| View or workflow | Current reality | Product gap / required UI contract |
|---|---|---|
| Command Center | Polls real but differently scoped stats, local inventory, events and scanner status; recent working-tree changes now label unavailable/partial measures. | Authoritative estate crypto-asset denominator, PQC readiness, migration velocity, evidence integrity and defined event rates need backend contracts before showing numeric KPIs. |
| Assets / Crypto Inventory | `/assets` is paged CryptoAsset rows and detail evidence **IDs**; `/crypto-assets` is largely a reference algorithm catalog. | Do not call reference entries observed usage. Link real source facts, owner, asset identity, evidence and graph; search across server pages, not only loaded rows. |
| Findings / Certificates | Real paged findings and local certificate/API operations exist. | Correct page-versus-estate totals and unknown badges; link specific finding/cert to evidence, owner, task and verification. Local cert operations are not proof of external CA/HSM coverage. |
| CBOM / HBOM / VBOM / NBOM / TechBOM | BOM APIs/generators exist and live cross-query can source network/hardware inventory. | **P0 UI contract bug:** `frontend/src/pages/Cbom.tsx:49-85` calls `comps.forEach` although backend catalog `systems[*].components` is an integer (`services/api/api/routers/cbom.py:221-267`), then invents asset IDs, risk, owner, location and PQC status. Use a real component/export endpoint and source coverage; never label catalog JSON a CycloneDX component export. |
| Dependencies / Graph | Two graph views call real graph/blast APIs. | `/dependency-graph` reads `affected_systems` while the API returns `systems` and defaults unknown backend to “Neo4j Cluster”; correct response shape, identity, edge provenance and memory-fallback label (`frontend/src/pages/DependencyGraph.tsx:128-139,245-275`). |
| Evidence / Audit | Working tree separates scan evidence and action audit, and verifies selected scans through the server. | Scan-level PASS is not a per-record seal. Provide evidence-ID proof contract and exact cross-links; audit workspace should be browsable/exportable and not claim an unverified ledger. |
| Drift / Compliance | Drift page has working-tree paging and administrative actions. Compliance page calls actual platform-control and retention APIs. | An empty/failed Compliance response currently becomes green 100%, retention defaults to seven years, and standard buttons do not filter (`frontend/src/pages/Compliance.tsx:36-48,83-129,134-197`). Distinguish NOT_EVALUATED, configuration from enforcement, and third-party attestation. |
| Remediation / Migration | `/priorities` ranks OPEN signals; `/migration` shows planning surfaces. | Expose real task owner/status/change/rescan/verification and separate administrative closure from verified correction. Do not call a ranker a complete remediation workflow. |
| Scans | Working-tree page offers real authorized active CIDR sweep and onboarding registration; unsupported specialized modes are disabled. | Backend needs tenant-bound per-target durable jobs and status for cloud/source/container/hardware/cert/passive TAP. A registered scope or shared latest cycle is not that user's completed scan. |
| Health / Admin | `/healthz`, `/readyz`, audit and operational endpoints exist. | **P0 trust bug:** `frontend/src/lib/api.ts:3680-3747` currently derives Policy/TimescaleDB/WORM/Twin/Queue and every scanner “Operational/Healthy,” synthetic latencies, fixed zero errors and 100% availability from API liveness. Replace with independent observed service metrics or “Not measured.” |

Global search currently queries mainly the reference algorithm catalog; its label implies asset search (`frontend/src/components/Search.tsx:33-49`; `frontend/src/pages/SearchResults.tsx:38-74`). Navigation links now point to real routes, but a route existing is not proof the page has an authoritative data contract. Current pages under `/evidence`, `/drift`, `/assets`, `/scanners` and the dashboard are **uncommitted candidate improvements**, not yet a clean released UI.

## 6. Production and assurance still required

**Local progress:** production Compose overlays now validate with only nginx host ports; API/frontend, PostgreSQL, Redis and worker have run in the local development stack. Targeted migration rollback and PostgreSQL fact-identity tests passed earlier; real local scans persisted evidence/facts and earlier stored chains verified PASS. A current frontend typecheck/Vitest run passed 209 tests. These are scoped checks, not a production build/start of every artifact in its final topology.

**Missing qualification and release controls**

1. Full backend gate remains unresolved: the earlier all-service run reported **7,187 passed, 20 skipped and 17 errors** before test-path fixes, including a missing declared Hypothesis dependency; a complete current-tree rerun has not passed. Do not convert targeted passing suites into an overall green test claim.
2. Active `.github/workflows/ci.yml` runs only a subset of backend services, frontend typecheck/build **without Vitest**, and PostgreSQL parity. Named scanner, migration and image-build workflows are tracked as zero-byte files while staged copies under `.github/workflows-pending/` are inactive (`.github/workflows/ci.yml:48-122,158-197`; `.github/workflows-pending/README.md:1-14`). Enforced branch protection, secret scanning, reproducible digest-pinned images and release provenance require workflow/admin access and proof.
3. Real target-environment cloud, Neo4j, container, HSM and external IdP/connector burn-ins, held-out customer accuracy corpora, hostile-repository sandbox tests, independent pen test, multi-day target-scale soak, DR/RPO/RTO and signed closure are outstanding. The October 4 readiness gate is FAIL, with engineering FAIL and HSM/closure/external categories SKIP (`PRODUCTION-READINESS.md:39-77`).
4. Checked-in operational policies, questionnaire answers and old product maturity labels are not external certifications. No SOC 2/ISO/FIPS/PCI approval, paid customer adoption or bank-specific authorization may be inferred from local fixtures.

**Production acceptance is BLOCKED** until a clean immutable revision, full tests, real operator-authorized sources, measured data accuracy, security assessment and the target deployment's evidence all pass. A supervised pilot/pre-production recommendation in `PRODUCTION-READINESS.md:100-126` is narrower than a general bank production claim.

## 7. Delivery order and proof required

| Priority | Work to complete | Minimum proof before calling it done |
|---|---|---|
| **P0 — truth and safety** | Unify admission/resource/tenant checks for direct and queued scanners; isolate hostile inputs; close sensitive historical evidence disposition; remove CBOM and health/compliance false-green UI claims; make incomplete optional stages visible. | Negative authorization and hostile-input tests; real PostgreSQL transaction/evidence verification; UI tests on null/error/empty/partial; no unsupported PASS/status. |
| **P0 — authoritative identity** | Stable tenant-local fact→physical asset→BOM/graph linkage with sourced edges, versioned scan-run coverage and historical reconstruction. | Two-tenant, repeated-scan, ambiguous-algorithm and deleted/retired-asset cases; exact evidence IDs and no invented same-device association. |
| **P1 — operator loop** | Approved baseline → deterministic drift → owner/task → authorized change → adequate rescan → condition-level verification → audit/report. | Execute the entire chain on a realistic authorized estate twice, including failed, inconclusive and reintroduced cases; no ticket-as-fix shortcut. |
| **P1 — complete frontend** | Connect requested views and actions to versioned, tenant-scoped APIs; correct graph/BOM/health/compliance contracts; preserve accessible enterprise visual language and reduced-motion cryptography reveal. | Authenticated browser traversal of every critical route in empty, populated, denied and degraded estates; mobile/RTL/keyboard/screen-reader checks; screenshots and no fake runtime fallback. |
| **P1 — release qualification** | Activate full scanner/frontend/security/image CI, immutable images, backup/restore and target topology observability; complete provider, customer and external gates. | Fresh readiness gate for exact release and target environment with no mandatory FAIL/SKIP, independent review and signed evidence. |
| **P2 — additional breadth** | More connectors, threat-intel enrichment and optional AI explanation, only after authority/coverage contracts hold. | Labeled source/provider provenance, measurable false-positive/negative rates, explicit “assistance only” AI boundary. |

### Full end-to-end acceptance test

The platform is **not complete** when Docker starts, tests alone pass, or a dashboard renders. The release test must use an authorized real input and prove, under at least two tenants and with a negative scope case:

1. Create scoped tenant/environment/target and reject an unauthorized active target **before** any collector runs.
2. Start a durable scan, observe stage/coverage/failure state and collect actual crypto observations without storing key bytes or unredacted snippets.
3. Recompute and independently verify stored evidence hashes, chain and manifest; normalize facts with stable tenant identity and link them to real assets/owners.
4. Produce versioned sourced BOM layers and meaningful graph edges; explain a policy failure and risk/PQC priority from exact evidence rather than an algorithm-name guess.
5. Approve a baseline, change the underlying condition, detect drift and create an owned remediation task without calling a ticket a fix.
6. Rescan the same affected surface, prove adequate coverage and the condition's state, verify the new evidence, preserve the old history and issue a report/audit export.
7. Follow those **same IDs** through the authenticated desktop/mobile UI; verify denied/offline/unknown states and that every displayed number names its source and time window.
8. Repeat in the production-shaped topology, then obtain target-environment and independent qualification. If any link is absent or not tested, mark the result **PARTIAL, BLOCKED or UNVERIFIED**, never DONE.

**Related records:** `ROADMAP-TO-ENTERPRISE.md` gives adoption priorities; `PRODUCTION-READINESS.md` is the last dated evidence gate; `IMPLEMENTATION_STATUS.md` records a previous local implementation slice. This document explains the desired product and current gaps; it does not replace code, tests or a fresh release decision.
