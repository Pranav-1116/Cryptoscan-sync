# Documentation status and coverage map

> Current 2026-10-23 qualification: [ninth workflow/browser/PostgreSQL record](readiness-evidence/quality-workflow-qualification-2026-10-23.md),
> migration **0106**. Older dated0105 execution/publication statements below remain
> historical; no generated readiness verdict or external acceptance is promoted.


**Review date:** 2026-11-11
**Repository:** CryptoScan
**Purpose:** identify which documentation is authoritative, which material is historical, and which product areas still require evidence or deeper guides.

This file is a navigation and documentation-quality control. It is not a
production approval, customer certification, legal commitment, or claim that
every documented capability is generally available.

## 1. Repository-wide inventory

The `docs/` tree currently contains **1,076 files**, including **655 Markdown
files** (working-tree actuals, including the untracked user-local
`readiness-evidence/` store), plus generated diagrams, JSON/CSV evidence,
templates, and scoped qualification artifacts. The files cover product behavior,
architecture, user workflows, deployment, security, operations, company
diligence, commercial planning, and historical evidence.

Counts are a documentation snapshot. At this refresh the repository carries **701
tracked Markdown files**, **588 of them under `docs/`**; the `docs/` working-tree
total counts actual files and includes the untracked evidence store, so the two
numbers answer different questions. Regenerate these counts rather than copying
them into product claims.

## 2. Source-of-truth order

When two documents disagree, use this order:

1. **Running code, tests, and API schemas** for behavior.
2. **`shared_models/capability_maturity.py` and generated
   `docs/CAPABILITY-MATURITY.md`** for GA/Beta/Preview labels.
3. **`frontend/src/components/Layout.tsx` and `frontend/src/App.tsx`**, with
   `docs/NAVIGATION-FEATURE-REFERENCE.md` updated in the same change, for
   navigation and route coverage.
4. **`shared_models/state_machines.json`** (canonical, mirrored byte-identical to
   `frontend/src/lib/stateMachines.json`) for every state vocabulary, transition
   and honesty invariant — see `docs/state-machines/README.md` and
   `docs/api-reference/state-machines.md`.
5. **`docs/api-reference/rest-api.md`** for the generated API snapshot. Its
   header contains the generation date and count; it is not a promise that an
   old snapshot contains later endpoints.
6. **Root `PRODUCTION-READINESS.md` and
   `docs/readiness-evidence/bank-readiness.{json,md}`** for the current
   evidence gate.
7. **`docs/PRODUCT-CAPABILITIES-END-TO-END.md`, product manuals, and
   `docs/PLATFORM-STATUS.md`** for explanatory context. Historical updates in
   those files must retain their original date and commit context.
8. **Market, pricing, roadmap, pilot, company, and policy documents** for
   planning or templates. They must not be read as proof of revenue, valuation,
   certification, customer count, market share, or production qualification.

The current API reference was generated **in-process on 2026-11-11** and reports
**1,319 paths / 1,445 operations** across **122 tagged groups**. No application
server or deployment was started for schema generation. The current maturity
snapshot reports **98 GA surfaces (0 Beta, 0 Preview)** — 98 classified console
surfaces. The dates and scope matter: do not merge historical counts
with the current snapshot.

## 3. Documentation family map

| Family | Entry point | Coverage |
|---|---|---|
| Product narrative | [product/README.md](product/README.md) | Product thesis, features, architecture, dataflow, scan trace, engines, glossary, readiness |
| Cryptography Threat Intelligence | [product/cryptography-threat-intelligence-roadmap.md](product/cryptography-threat-intelligence-roadmap.md) | Current foundation; planned intelligence, detection, response, defence, and research boundaries |
| Market and commercial | [market/global-cryptography-threat-intelligence-market-value.md](market/global-cryptography-threat-intelligence-market-value.md), [business-model.md](business-model.md), [price-model.md](price-model.md) | Market context, customer value, illustrative pricing/revenue, valuation boundaries and commercial assumptions |
| User workflows | [user-guide/](user-guide/) | Scanning, inventory, CBOM, PQC, certificates, cloud, binary, network, vendor, evidence, reports and operations |
| Vendor/network evidence | [user-guide/vendor-network-inventory.md](user-guide/vendor-network-inventory.md) | Versioned vendor profiles, network inventory sections, endpoint lifecycle, provenance, tenant isolation and no-secret rules |
| Administration | [admin-guide/](admin-guide/) | Installation, production, air-gap, hardening, policy, scanners, backup/restore, integrations and system configuration |
| Architecture and decisions | [architecture/](architecture/), [decisions/](decisions/) | Service boundaries, dataflow, evidence, tenancy, scanners, BOMs, graph, roadmap and ADRs |
| API and developer | [api-reference/rest-api.md](api-reference/rest-api.md), [api-reference/state-machines.md](api-reference/state-machines.md), [plugin-sdk.md](plugin-sdk.md), [dev/](dev/) | Generated API snapshot, state machine register interfaces (Python/TypeScript/CLI), plugin extension, testing, live scanning and developer workflows |
| State machines | [state-machines/README.md](state-machines/README.md) | The canonical state machine register: 100 machines, 306 states, 94 model fields — every state observed from code, honesty invariants, the full inventory table and the drift-guard rules |
| Security and privacy | [security/](security/), [company/security-architecture.md](company/security-architecture.md), [company/privacy-documentation-index.md](company/privacy-documentation-index.md) | Threat model, hardening, network controls, dependency audit, privacy and assurance material |
| Operations and qualification | [operations/](operations/), [ops/](ops/), [runbooks/](runbooks/), [production-qualification-runbook.md](production-qualification-runbook.md) | Production procedures, vendor due diligence, scanner qualification, recovery, DR, telecom, monitoring and support |
| Readiness evidence | [readiness-evidence/README.md](readiness-evidence/README.md), [root production gate](../PRODUCTION-READINESS.md) | Timestamped PASS/FAIL/SKIP artifacts; synthetic or skipped checks are not approvals |
| Pilots and adoption | [pilot-standard.md](pilot-standard.md), [pilot-duration-and-phases.md](pilot-duration-and-phases.md), [poilet/README.md](poilet/README.md), [proposals/](proposals/) | Pilot scope, acceptance, market entry, first customers, demo and engagement material |
| Company and compliance | [company/README.md](company/README.md), [compliance/](compliance/), [enterprise-readiness.md](enterprise-readiness.md) | Templates, questionnaire answers, control mappings, external-readiness gaps and boundaries |
| Accuracy and validation | [accuracy/](accuracy/) | Detector benchmarks, external validation, synthetic estate results and bank-readiness limitations |

## 4. Gaps identified by the documentation review

### 4.1 Route and maturity reconciliation

The primary **`/vendor-due-diligence`** route now has an explicit generated
**Preview** row in the maturity inventory. Its profile/provenance machinery is
implemented, but approval completeness and external vendor qualification remain
unverified; it must not be described as GA.

### 4.2 Structured vendor and network workflows

The refreshed generated reference now enumerates the structured network-inventory
family. The dedicated [user guide](user-guide/vendor-network-inventory.md)
describes its provenance contract. An operation's presence in OpenAPI does not
mean its execution profile is enabled: expanding inventory discovery remains
refused until qualified. The [API contract companion](api-reference/execution-and-replay.md)
adds semantics not visible in the operation table.
The implementation still requires authorized sources, evidence, tenant scope,
and reviewer qualification; a schema or endpoint is not proof of complete
network visibility or vendor assurance.

### 4.3 Cryptography threat detection and defence

CBOM, PQC, policy, drift, evidence, vendor context, and deterministic
correlation form the current foundation. Cryptography-specific threat feeds,
attack-path analysis, cryptographic abuse detection, autonomous blocking,
response orchestration, and continuous cryptographic defence remain planned or
research capabilities in the roadmap. They must not be described in user guides
as shipped detections.

### 4.4 External assurance and customer evidence

The repository contains controls, tests, templates, and qualification runbooks.
It does not by itself establish ISO 27001 or SOC 2 attestation, independent
penetration testing, multi-site DR, 24/7 support, customer count, customer ROI,
market share, or a current CryptoScan valuation. The company, customer, and
qualified assessor still own those actions.

### 4.5 Historical evidence needs dates

Load tests, soak runs, dependency audits, product-surface audits, readiness
reports, and market reports are time-scoped. Keep the original date and result;
add a newer dated artifact rather than silently rewriting an old pass/fail record.
Historical documents that contain obsolete counts should link back to the current
source of truth and label the old measurement as historical.

### 4.6 Links into the untracked evidence store (2026-11-11 link audit)

`docs/readiness-evidence/` is a **user-local, untracked evidence store** (the
repository history deliberately returns it to untracked state). Tracked documents
link into it as their local-validation record; those links resolve in a working
checkout that carries the store, not in a fresh clone. The 2026-11-11 audit of
all `docs/` Markdown links found **2,976 local links**, of which **58 do not
resolve in this working tree** — all of them concern the untracked store: 45
links from tracked documents into store artifacts (dated 2026-10-25/26
local-validation records) and 13 links inside store reports pointing at
`quality-*-2026-10-23/` log directories absent from this checkout's copy.
Those references are recorded here as **UNAVAILABLE in this checkout** — not
rewritten and not silently assumed present; a checkout that carries the full
store resolves them. The audit also found one tracked-to-tracked break
(`94-digital-twin.md` → `94-cryptoscan-digital-twin.md`), now fixed.

## 5. Required documentation invariants

All new or updated docs must preserve:

- no fabricated scanner, vendor, certification, incident, financial, customer,
  compliance, production, or ROI claims;
- explicit `UNKNOWN`, `UNVERIFIED`, `INCOMPLETE`, `STALE`, `UNAVAILABLE`, and
  `SKIP` states where evidence is missing;
- evidence provenance, capture time, source, hash, limitation, and reviewer
  where applicable;
- tenant isolation for reads, writes, history, exports, and events;
- no passwords, tokens, credentials, private keys, raw secrets, or key material
  in profiles, CBOMs, logs, examples, or evidence artifacts;
- safe, authorized, approval-gated production actions with rollback evidence;
- clear separation between shipped behavior, planned roadmap, research, and
  external/company actions;
- links to the current readiness gate when quoting production status.

## 6. Documentation update procedure

When a capability changes:

1. Update the code and tests first.
2. Regenerate the API reference and capability-maturity output from the running
   application/source-of-truth scripts.
3. Update the navigation reference if a route or sidebar item changed.
4. Update the relevant user guide, admin/runbook, architecture, and enterprise
   documentation, not only the release note.
5. When qualification actually runs, retain a new timestamped PASS/FAIL/SKIP
   artifact in the approved evidence store. A docs-only refresh must not
   rewrite historical evidence or imply the deployment gate was rerun.
6. Run a repository-local Markdown link check and `git diff --check`.
7. Review claims for tenant scope, provenance, no-secret behavior, unknown
   handling, and production qualification before publishing.

The documentation index is [docs/README.md](README.md). This status file should
be updated when a review discovers a new family, source-of-truth conflict, or
material documentation gap.

## 7. Execution/replay reconciliation — 2026-10-21

The Markdown corpus was searched for queue-authority, SSH receipt, Redis TLS/ACL/
Sentinel, numeric resume, ring-buffer and recovery claims. Related root/product,
architecture, API, user/admin, security, bank, enterprise, recovery and Kubernetes
instructions were reconciled with implementation `e9bfbef7`. Unrelated documents,
original test artifacts, archived audits, dated benchmark numbers and image
binaries were not mechanically rewritten or requalified.

| Current documentation | Purpose |
|---|---|
| [API contract companion](api-reference/execution-and-replay.md) | Ownership, retry 409, SSH results and opaque replay wire behavior |
| [Upgrade/recovery](runbooks/execution-and-replay-upgrade.md) | Coordinated producers/workers, legacy pins, RUNNING reconciliation, TLS/CA and cursor resets |
| [Queue runbook](runbooks/job-queue.md) | Transport recovery versus SQL claim; no unsafe terminal-row reset instructions |
| [Realtime user guide](user-guide/realtime.md) | Estate pages, error/control events and primary-bound reset behavior |
| [Network/SSH user guide](user-guide/network-scanning.md) | Durable attempt/result IDs, failed observations and unverified baselines |
| [Guide 44](bank-environment/44-queued-authority-and-durable-ssh.md) | Implemented queue/SSH design, local tests and remaining authority limits |
| [Guide 45](bank-environment/45-redis-tls-sentinel-qualification.md) | Verified transport, command readiness, subscriber recovery and destructive disposable lab |

The REST generator's conventions now link to the companion and no longer assert
that every list is paginated or every export has the same integrity contract.
The schema was regenerated from the application without startup or network probes.

Recorded implementation evidence remains **1315 passed / 4 skipped**, followed
by **205 focused passes** after final provenance changes, plus **28 real TLS/
Sentinel and unit passes**. Counts overlap; this refresh does not rerun those
suites, certify PostgreSQL parity or change the external production gate.
Documentation validation passed for all **64 changed Markdown documents**:
relative file links and heading anchors, exact generated schema/route agreement
(**848 paths, 936 operations, 103 groups**), idempotent generation, the new SSH
JSON example against its Pydantic model, edited Bash syntax, generator lint and
whitespace. No application source or CI workflow changes are part of this
refresh; the only Python change is the documentation generator template.
These checks are not new runtime or deployment qualification evidence.

All six BOMs remain distinct: SBOM package/release evidence, NBOM network
observations, CBOM crypto facts, TechBOM technology relationships, HBOM hardware/
firmware and VBOM supplier evidence. Neither a durable SSH receipt nor Redis
replay upgrades missing evidence, changes ownership or supplies bank approval.

## Controlled-execution increment (2026-10-21, migration 0102)

The [upgrade/acceptance matrix](runbooks/controlled-execution-upgrade.md) and
[API contract](api-reference/controlled-execution.md) document the new approvals,
original credential provenance, shared budgets/fairness, stop/checkpoint,
region/destination, hostile-source staging, attempt and SQL-outbox controls.
Production availability is deliberately **local-source only**; other API/monitor/
WebSocket/collector paths are refused. This is a breaking supported-profile
restriction, not an assertion that all six P0 gaps or external qualifications are
closed. At that increment the 75 console-surface maturity inventory was unchanged; it
adds no qualified console UI. The generated REST schema includes all development
routes and must not be read as the production enablement list.


## 8. Complete documentation refresh — 2026-10-22

Source reviewed: **698beb38**, on `arena/bb4b80dd-cryproscan`. Start with
[current implementation status](CURRENT-IMPLEMENTATION-STATUS.md). This adds
the latest 0105 migration, active/reusable CI, unsigned release preflight,
first-call runtime metadata, OCSP verification, file receipts and CBOM SSE
connection behavior to the current-reading map. The detailed
[CI/product-build guide](CI-WORKFLOW-AND-PRODUCT-BUILD-PLAN.md) reconciles the older
long-form six-BOM plan with the subsequently tracked CI implementation guide;
already configured checks are separated from remaining hardening work.

Active root/product/navigation/enterprise, developer/CI, administration, runtime,
API and bank/launch handoffs are reconciled with current code. Historical image
assets, generated machine evidence and dated audit/test results retain their
original revision and qualification limits. A file outside the affected behavior
is not needlessly rewritten just to change its date.

The repository-wide Markdown inventory and relative-link check include all
tracked Markdown, not just edited guides. Generated API and maturity outputs
are checked against source and regenerated twice to check idempotence. These are
documentation/source checks, not a new full backend/frontend run or external
deployment qualification. See the validation record below for actual results.

The user reports one remaining failing workflow. Actions/check-result access
returned HTTP 403 to this session; no lane/run identity or independent green
verdict is claimed, and no workflows are changed or dispatched by this refresh.


## 9. Validation retained from the preceding documentation refresh

The results below belong to the docs refresh published as `bfc42df0`. They are
not fresh runtime test results for the quality-program addition in section 10.

| Check | Result | Scope / limits |
|---|---|---|
| Focused source contracflows are changed or dispatched by this refresh.


## 9. Validation retained from the preceding documentation refresh

The results below belong to the docs refresh published as `bfc42df0`. They are
not fresh runtime test results for the quality-program addition in section 10.

| Check | Result | Scope / limits |
|---|---|---|
| Focused source contracts | **43 passed**, 7 existing Alembic deprecation warnings, 3.42 s | `scripts/tests/test_ci_suites.py`, `services/devsecops/tests/test_ci_workflow_contract.py`, `shared/shared_models/tests/test_capability_maturity.py`, `services/database/tests/unit/test_monitor_event_type_migration.py`; local Python 3.11.2, locked requirements. Not a full-suite/live-PostgreSQL rerun. |
| API regeneration | **917 paths / 1,008 operations / 105 groups** | In-process OpenAPI; no application server or provider probes. Existing reference already matches this baseline. |
| Maturity regeneration | **33 GA / 32 Beta / 12 Preview** | Shared source, generated Markdown and frontend artifact match; no tier promotion. |
| Repeated generation | Byte-for-byte identical API/maturity outputs | Includes `frontend/src/lib/maturity.ts`; no frontend source change. |
| Navigation reconciliation | **6 sections / 41 placements / 40 unique primary routes** | Every current sidebar label/route/component matched against Layout/App; deep-link table refreshed. |
| Repository-wide local Markdown links | **474 files**, no missing relative targets or unresolved local heading anchors | Static local check; external URLs are not fetched. Fenced-code examples are excluded from link interpretation. |
| Edited shell examples | **18 labeled shell blocks**, all pass `bash -n` | Syntax only, not execution of installation/destructive examples. |
| Installed Python constraints | `pip check` passes | Local environment only; not a cross-platform or hash-locked reproducibility proof. |
| Patch integrity | `git diff --check` passes; documentation-only changes | No runtime code, workflow definitions, lockfiles, dated machine evidence or image assets changed. |

No GitHub Actions run, CI dispatch, deployment, release signing/publication,
full frontend/backend test run or readiness-gate execution was performed by this
refresh. The reported remaining workflow failure is left for the user.


## 10. Quality-only product-improvement pack — 2026-10-22

The new [product-improvement pack](product-improvement/README.md) contains **10 new
Markdown files**: an index and nine detailed guides. It is based on checkout
`bfc42df0` (docs-only successor to reviewed implementation `698beb38`). It
recommends deeper quality of existing behavior, not more product features.

Coverage: baseline and priorities; correctness and all six BOMs; security,
privacy and isolation; durable execution, measured performance and recovery;
existing operator/frontend workflow and accessibility; test reliability,
maintainability, dependency and release discipline; real nine-duty operations,
independent security/site/customer qualification; dependency-ordered work packages,
acceptance/stop criteria; and a fictional end-to-end example with deliberately
unexecuted review/evidence templates.

Recommendations are distinguished from observed defects, retained results and
external acceptance. No collector/profile, API, menu or feature is added. Existing
local-source/v1 refusals, history/CAS, original evidence, independent review and
UNKNOWN/INCONCLUSIVE semantics are preserved. The user's rem source/test-path checks and patch whitespace. Application/runtime suites,
CI, site drills and external assessments are **not run** by this documentation task.


Quality-pack validation results: **484 Markdown files / 1,692 local links**,
zero missing targets or unresolved heading anchors; **2 labeled shell examples**
pass `bash -n`; **13 changed/new Markdown files** have balanced fences; referenced
existing source/test paths resolve; `git diff --check` passes. External URLs are
not fetched, and syntax checking does not execute installation or test commands.


## 11. Direct bank on-premises deployment guide — 2026-10-22

[Bank on-premises deployment](BANK-ON-PREMISES-DEPLOYMENT.md) is a new standalone
end-to-end explanation based on `bfc42df0` / application review `698beb38`.
It covers bank-owned Kubernetes/VM infrastructure, external-to-workload (not
external-to-bank) PostgreSQL/Redis, dedicated dispatcher/parser isolation,
source/evidence and six-BOM boundaries, sizing limits, network and identity,
secret/CA/storage custody, signed full packages, offline transfer, guarded cluster
preflight, coordinated migration through 0105, installation, actual smoke and
negative checks, daily operation, backup/recovery and independent site acceptance.

Specific deployment caveats are explicit: no generic Compose production approval,
no shared hostile-tenant Docker-daemon boundary, no live-collector activation,
no implicit SSO/HA qualification, no false readiness from an HTML response, and
no current-frontend zero-egress claim while external font references remain.
Examples are guarded operator procedures, not executed bank commands or fabricated
credentials/digests. No runtime/workflow or frontend hardening change is performed.

The inventory above includes this file. Earlier validation records retain their
own counts and dates. This addition is checked for local links/anchors, balanced
fences, shell syntax, referenced implementation paths and whitespace only; actual
installation, image builds, migrations, CI and site qualification are not run.

Validation after adding the on-premises guide: **485 Markdown files / 1,721 local
links**, no missing targets or unresolved heading anchors. All **7 labeled shell
blocks** across the pending docs (5 in the deployment guide, 2 in the improvement
pack) pass `bash -n`; fences, referenced implementation spot checks and
`git diff --check` pass. These are documentation checks, not deployment execution.


## 12. Continuous operation and weekly support model — 2026-10-22

The new [24/7 bank operation and weekly vendor-support procedure](BANK-24X7-OPERATIONS-AND-WEEKLY-SUPPORT.md)
documents the user's intended operating model: continuously running on-premises
service; bank security/SOC monitoring with accountable bank infrastructure owners;
weekly product-team health/error/advisory/update reviews; tested corrections and
bank-authorized changes. Urgent incidents do not wait for weekly meetings.
Actual vendor after-hours coverage, objective times, staffing and service terms
must be agreed—not inferred from a weekly calendar or successful installation.

The on-premises guide, quality/qualification manual, operating-ownership guide
and navigation cross-reference this procedure. It includes monitoring/daily/weekly
responsibilities, incident routing, error-to-fix verification, controlled updates,
restricted remote support, a deliberately unexecuted review template and operating
model acceptance exercises. It does not enable collectors/monitor loops, implement
alerts or auto-updates, promise HA/100% uptime, or change `sla_authorized=false`.

All pending quality-pack, on-premises and operating-model docs are included in
the requested documentation publication. Earlier dated validation counts remain
historical; the inventory above includes the new support guide. Only documentation
checks run for this addition—no application test suite, CI dispatch, deployment,
migration or actual operating/incident exercise is represented as executed.

Publication validation: **486 Markdown files / 1,736 local links**, zero missing
relative targets or unresolved heading anchors; **16 pending Markdown files**
with balanced fences; **7 labeled shell examples** pass `bash -n`; patch whitespace
passes. External URLs are not fetched, and no example mutating command is executed.


## 13. Quality implementation starts — 2026-10-22

The [implementation ledger](product-improvement/IMPLEMENTATION-STATUS.md) and
[dated engineering record](readiness-evidence/quality-increment-2026-10-22.md)
track the first bounded code changes after `69faec96`. Existing source coverage
now validates actual parser receipts and coherent job/scan intervals at intake
and rechecks backing evidence on current reads, without per-target SQL growth or
rewriting immutable history. Known external frontend font bootstrap/CSP origins
are removed with existing system fallback fonts. No new feature/profile/collector,
workflow definition, dependency lock or migration is added.

Unlike the preceding docs-only publications, this increment actually runs
selected backend source/assurance regressions, package/migration checks and the
full frontend DOM/typecheck/build/toolchain sequence. Exact counts and limitations
are retained in the dated record, not merged into historical evidence or a
readiness percentage. Independent review, actual PostgreSQL/browser/site/recovery,
assessor/operations/customer qualification remain open. The user's unspecified
workflow failure is not fixed or waived here.


## 14. Second bounded quality correction — 2026-10-22

The [dated package-identity record](readiness-evidence/quality-package-identity-2026-10-22.md)
retains the next actual baseline, red reproduction and accepted local regressions.
Known unresolved package versions no longer fill exact SBOM/cascade/crypto paths;
legacy current projections are re-evaluated without changing historical evidence.
The [implementation ledger](product-improvement/IMPLEMENTATION-STATUS.md) keeps
first/second-increment results, review/rollout limits and next work distinct.
No frontend check is falsely described as rerun, no dependency/workflow/schema
change is made and no whole-product/site readiness percentage is granted.


## 15. Third quality increment and accumulated source publication — 2026-10-22

The [authority/privacy engineering record](readiness-evidence/quality-authority-privacy-2026-10-22.md)
retains the role-store failure reproduction, probe/log privacy corrections,
actual scoped tests and disposable-PostgreSQL skip. The
[implementation ledger](product-improvement/IMPLEMENTATION-STATUS.md) separates all
three increments and their actual evidence from external review/site acceptance.
All three accumulated increments were pushed in `2fd8fc8f` to the current PR branch
using `[skip ci]`, with no workflow, dependency lock, schema or deployment change.
Frontend/typecheck/build/toolchain checks are actually rerun for this publication;
prior dated records keep their original scope/results rather than being rewritten.
A source publication is not a signed full release, bank upgrade or customer acceptance.


## 16. Published-source documentation reconciliation — 2026-10-22

The current-reading pages now identify **`2fd8fc8fba255333f605202ebb68d04c4029c610`**
as the published quality implementation, with original broad-review and dated
test baselines kept separate. PR #34 is open at this update, not merged or deployed.
The [publication ledger](product-improvement/IMPLEMENTATION-STATUS.md#published-engineering-snapshot)
records actual source publication and retained test/skip scope, not another test run.

The Unreleased changelog, quality index/roadmap, on-premises/support guides and
[evidence-assurance runbook](runbooks/evidence-assurance-upgrade.md#current-quality-source-handoff-2fd8fc8f)
now explain changed refusals, offline supplier engine re-exercise, safe health
categories and rebuilt frontend rollout. The runbook explicitly marks its original
0103 sequence historical; 2fd8fc8f still targets 0105 and adds no migration.
The next interruption/duplicate-delivery/UNKNOWN recovery work remains planned.

This follow-up changes documentation only. No application test, schema/API/maturity
regeneration, workflow dispatch, migration, image build/signing or site exercise is
performed. The three dated engineering records and historical readiness artifacts
are not rewritten. No new all-suite/Actions/production approval is inferred.


Documentation-only validation: **490 Markdown / 1,784 local links**, zero missing
relative targets or unresolved heading anchors; **10 changed Markdown files**
with balanced fences and **5 labeled shell examples** syntax checked. **53 external
links** were not fetched. Patch whitespace passes. Read-only checks confirm all
**20 retained source/lock hashes** still match; application tests are not rerun.
No example's mutating deployment command is executed.
olved heading anchors; **10 changed Markdown files**
with balanced fences and **5 labeled shell examples** syntax checked. **53 external
links** were not fetched. Patch whitespace passes. Read-only checks confirm all
**20 retained source/lock hashes** still match; application tests are not rerun.
No example's mutating deployment command is executed.

## 17. Documentation refresh — state machine register (2026-11-11)

This refresh accompanies the canonical **state machine register** (100 machines /
306 states / 94 `db.models` fields — every state observed from code, never
invented; 15 vocabularies honestly marked unobserved). Documentation changes:

- **New:** [state machine register](state-machines/README.md) (inventory, rules,
  consumers) and the [developer/agent reference](api-reference/state-machines.md)
  (Python API, TypeScript API, CLI, register shape, drift guards).
- **Regenerated:** [REST API reference](api-reference/rest-api.md) in-process from
  the OpenAPI schema — **1,319 paths / 1,445 operations / 122 tagged groups**
  (was 917 / 1,008 / 105); withdrawn-route markers retained and re-verified.
- **Navigation reference** updated in the same change as the sidebar edit:
  `/state-machines` added under a System health group; counts re-measured
  (**five sections / 25 rows / 79 links**, 66 distinct routes).
- **Current counts re-measured and corrected** in the root README, platform
  status, current-implementation status and capability map: 56 services, 139 API
  router modules, 148 migrations (head **0148**), 105 frontend page components,
  1291 backend test files, 1294-test/143-file Vitest suite with clean `tsc`
  (measured this refresh; the full backend suite was last run 2026-10-16 and is
  labelled as such). Maturity is **98 GA / 0 Beta / 0 Preview**. Dated
  historical snapshots in those files keep their original scope and numbers.
- **Link audit:** 2,976 local links under `docs/`; 58 unresolved, all within the
  untracked user-local evidence store (see §4.6); the one tracked-to-tracked
  break is fixed. Code fences balanced in every changed file.

Validation for this refresh: `scripts/gen_rest_api.py` and
`scripts/gen_capability_maturity.py` re-run from source; shared-models battery
(1,440 tests incl. 19 register pins), register/stack pins (40) and the
claim-hygiene surfaces reviewed for the banned claims. No application behavior
changed by this documentation set beyond the register work it documents; no
historical evidence record is rewritten; no readiness verdict or external
acceptance is promoted.
