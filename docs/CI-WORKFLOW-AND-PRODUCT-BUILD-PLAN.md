# CryptoScan CI Workflow and Product Build Plan

**Status:** Implementation plan and local validation snapshot; GitHub Actions execution, required checks, release publication and production approval must be evidenced separately

**Baseline before local implementation:** `arena/01a106c8-cryproscan` at `8915806f` (2026-10-22)

**Audience:** engineering, security, release, operations and customer-assurance owners

## 1. Purpose and release boundary

Build one reproducible route from a changed source file to a tested, attributable product artifact, then to a separately qualified customer deployment. The delivery chain is:

```text
reviewed commit → hermetic tests → real PostgreSQL migration/parity checks
→ frontend contract and browser checks → scanner/evidence security checks
→ digest-pinned images + SBOM/provenance → controlled deployment rehearsal
→ site/provider exercises + independent reviews → strict readiness decision
```

A green unit suite, a built image, a generated SBOM, a signed document and a running local stack each answer **different** questions. None alone proves that CryptoScan is safe for unattended regulated production. CI must fail on missing required checks, never transform `SKIP`, unavailable providers, absent evidence or partial scanner coverage into PASS. Do not remove failing tests or invent customer attestations to obtain green status.

The product target remains the deterministic, tenant-scoped observation → sanitized verifiable evidence → fact/asset/BOM/graph → policy/risk/drift → authorized remediation → independent rescan/condition proof → pinned report and UI chain described in [Product Vision and Gaps](../PRODUCT-VISION-AND-GAPS.md). That document is dated and must be checked against source before using its gap labels. This plan describes **how to build and verify** changes, not a claim that every collector is already approved.

### Critical distinction: development product versus controlled production profile

The repository contains broad source, network, cloud, container, OT, telecom, hardware, BOM, graph and UI capabilities. In the current controlled production profile the **reviewed execution adapter is `local-source/v1` only**. Other collector/monitor/GraphQL/export/realtime/notification surfaces are refused until separately adapted and qualified; a development-mode pass must never silently enable them in production (`services/api/api/middleware/controlled_surface.py:18-45`; `docs/runbooks/controlled-execution-upgrade.md:13-40`). Plan separate gates for (a) development integration and (b) the smaller deployable controlled profile. No workflow should imply parity between them without evidence.

## 2. Pre-implementation repository baseline: what ran versus what was parked

The table describes the baseline commit `8915806f`, **not** the CI definitions added after it. The implementation populates three formerly empty workflows as reusable lanes called by `ci.yml` and adds a manual **unsigned** release preflight. Source-controlled YAML is only configured CI; actual checks, required branch rules and release publication need separately observed GitHub evidence.

| Surface | Current checked-in state | Planning consequence |
|---|---|---|
| `.github/workflows/ci.yml` | The one substantive active workflow. Configured triggers: PRs, pushes to `main`, manual dispatch. Jobs: Ruff; a **fixed 15-service** Python 3.11 matrix; frontend Node 22 `npm ci`, typecheck and build (**no Vitest/toolchain test**); production Compose/config guard; PostgreSQL 16 parity. There is no final aggregate gate. | Keep existing check contexts stable while adding discovered suites, frontend tests and fail-closed artifacts. Check actual GitHub runs before saying a configured job executed. |
| `.github/workflows/{db-migration,docker-build,scanner-tests}.yml` | Tracked as **zero-byte** blobs. | Do not cite them as executing jobs; publishing replacements requires a workflow-scoped change and review. |
| `.github/workflows-pending/` and `deploy/ci-workflows/` | Staged **alternatives**, not active Actions. The pending `ci.yml`/DB smoke is SQLite metadata bootstrap, not Alembic parity; pending scanner matrix is fixed and PR path-filtered; pending image workflow publishes only API/worker on tags/manual runs with `provenance: false`. The deploy image proposal covers six images but has an nginx build-context mismatch. | Treat as design inputs, not passed gates or drop-in replacements. Design separate unprivileged build-only and approved publisher jobs. |
| Local commands | `make test` discovers service/shared suites; `make test-frontend` runs typecheck + Vitest; `scripts/postgres_parity.sh`, `scripts/check_prod_compose.py`, frontend `npm run test:toolchain`, `make release-check` and `make security-scan` exist. The last two are **not active CI jobs**. | Use the same reviewed commands with pinned inputs and JUnit/artifact retention. A local target existing is not a required GitHub status check. |
| Release and site tooling | Compose overlays, digest-rendered operator packages, SBOM/release checks and strict bank-readiness scripts exist. | Distinguish build-only, published digest, verified external signature, dry-run, deployed site and independent acceptance. |

A recent local engineering record reports **157 focused passes** and **398 frontend tests**, while a broader selected backend/worker run recorded **1 failure / 1,864 passes / 16 skips / 1 deselection**, and another wider run was stopped after a separate reproducible failure (`docs/readiness-evidence/launch-engineering-2026-10-22.md:46-105`). Those counts overlap and are not a new green full-suite gate. Many recent commit subjects include `[skip ci]`; do not infer that GitHub validated those revisions. Branch protection and GitHub Administration permissions were **not** verified in this document.

**Local implementation checkpoint (not GitHub execution):** four CI workflow files now contain a `ci.yml` PR/main/requested `arena/bb4b80dd-cryproscan` push entrypoint plus reusable scanner, database and build-only lanes; `release-preflight.yml` is manual and unsigned. Suite discovery partitions 54 test directories (48 non-scanner, 6 scanner). CI contract/discovery tests **31 passed**; all six standard images built locally without push; Ruff passed. The first PG15 parity run found a real `monitor_events.event_type` width error. Forward migration `0105` fixed that schema boundary; the disposable PG15 rerun passed **6 migration tests, 959 worker tests (1 deselected), and 2 API estate tests**. PG16 full parity and actual GitHub runs remain unverified. Local Node 22.22.0 is below the committed transitive lock's 22.22.2 floor; `npm ci` and the strict local frontend lane are blocked here, although an isolated frontend image build completed. An earlier local npm audit query reported no advisories, but a later permission decision blocked sending private dependency metadata to an external registry: no automatic npm audit or historical secret scanner is installed as a required CI check. Those checks need an explicitly approved dependency-audit service/tool. These are scoped observations, not branch-required checks or site qualification.

## 3. Required CI architecture

### 3.1 Pull-request checks: fast, complete and fail-closed

1. **Repository hygiene:** check formatting/lint, import/test collection, dependency resolution from committed manifests/locks, workflow YAML/schema and changed-file policy. Fail if a requested test module is missing or a job is skipped without a documented environmental reason. Publish a machine-readable test inventory and JUnit reports so the job cannot pass after silently omitting service trees.
2. **Backend unit and integration lanes:** enumerate every tracked `services/**/tests` and `shared/**/tests` directory instead of relying on the current selected 15-service matrix (54 test directories are present). Reuse `scripts/ci_suites.py`/`--scanners-only` or `make test`, then compare the emitted inventory with disk and capture JUnit from every shard. `scripts/check_junit.py` rejects *any* skip as well as missing/empty XML; apply it only to lanes whose contract forbids skips, and give optional live-provider lanes an explicit reviewed skip policy. Pin Python/dependency versions, isolate DB/Redis/network access and retain timeouts. Put scanner-heavy suites in a separately required lane, **not** `continue-on-error`. Report per-suite passed/failed/skipped/deselected and failed node IDs.
3. **Frontend lane:** install from `frontend/package-lock.json` using `npm ci` under the declared engine policy (project floor Node `^22.12.0 || ^24.0.0 || >=26.0.0`, npm ≥10; the committed transitive lock currently needs at least Node 22.22.2, so pin CI to Node 22.22.3 or another verified compatible version). Run `npm run typecheck`, `npm test`, `npm run build`, `npm run test:toolchain`. Mocked/jsdom page tests are necessary for fast regression, but they are not a browser/live-API qualification. Require route, auth/tenant switch, actual data/unknown states, reduced-motion/keyboard and a separately labeled browser integration lane.
4. **Database lane:** start an ephemeral PostgreSQL service; existing `scripts/postgres_parity.sh` already runs the full Alembic chain, worker-on-PostgreSQL and API estate readback. Extend it with previous supported revision → `head` on a disposable populated schema, model/index/constraint parity, tenant-local NULL/uniqueness semantics and downgrade only where supported. Make PostgreSQL 15 the required shipping-parity lane (`docker-compose.yml` pins `postgres:15-alpine`) and retain PostgreSQL 16 as a separately required compatibility lane; do not silently substitute the current PG16-only CI result or change the shipping image as a side effect. Never drop, stamp or mutate a developer/customer DB in CI; name disposable databases explicitly.
5. **Collector/evidence lane:** test deterministic scanner fixtures and hostile input bounds (archives, symlinks, file/CPU/time limits, source admission and parser isolation). Verify rejected targets launch no collector. Execute a real fixture source → observation → pre-hash sanitation → stored chain/manifest verification → facts → pinned BOM/graph/policy/drift → rescan proof. Test negative/partial/unknown outcomes and both tenant-owner and wrong-tenant requests. External network/provider scans are separate approved integration jobs, never hidden in a routine PR lane.
6. **Security and configuration:** check committed secrets, vulnerable dependencies, production-settings refusal, Compose merged ingress (only nginx published), non-root/capability/seccomp expectations, API authorization/resource ownership and safe error/log boundaries. A static pass does not claim actual runtime confinement.

**Merge rule:** every required lane above must complete for the exact PR head SHA. A timeout, canceled job, collection error, `continue-on-error`, skipped required matrix shard or missing JUnit is **not PASS**. Add one stable, `always()`-evaluated final check that fails if any required upstream job is absent, skipped, canceled or failed; path-filtered jobs must not make unrelated PRs appear green. Keep fixtures synthetic and non-secret; retained logs must not contain tokens, key bytes or source snippets.

**Proposed lane map (not installed today):**

| Required check | Suggested repository mechanism | Result to retain |
|---|---|---|
| `lint-and-collection` | Ruff + full test inventory from `scripts/ci_suites.py`; compare with disk | inventory, linter output, collection errors |
| `backend-all` / `scanner-offline` | Discovered service/shared matrix, offline scanner fixtures, pytest/JUnit | per-shard XML and fail/skip/deselect counts |
| `frontend` | `npm ci` + typecheck + Vitest + build + toolchain test | test XML/summary, build manifest, tool versions |
| `postgres-parity` | `bash scripts/postgres_parity.sh` + explicit prior-revision upgrade fixture | Alembic heads, schema/index assertions, JUnit |
| `security-config` | secret/dependency gate, production guard and `scripts/check_prod_compose.py` | policy result; no leaked secrets |
| `images-build-only` | reviewed Docker contexts with `push: false` | image build digests/logs, no registry publication |
| `ci-required` | final unconditional aggregate over required lane statuses/artifacts | a stable branch-protection status for the exact SHA |

These names are proposals, **not** current GitHub check contexts. Validate action syntax, action digest pins, fork permissions, concurrency/cancellation and artifact retention before installing them; do not mark the final check required until it exists and a deliberately red PR proves it blocks merge.

### 3.2 Main-branch and release-candidate checks

- Rerun the full backend/shared/frontend/real-PostgreSQL set after merge. Do not rely only on the last PR result or a matrix assembled from an earlier commit.
- Build every shipping image from an exact clean commit and pinned base/toolchain versions; build the reviewed parser and API/worker/frontend images with a recorded build graph. The staged six-image build proposal needs nginx context `.docker/nginx` (not repo root), and the separately reviewed worker-runtime Dockerfile has its own digest inputs; correct/decide both before requiring a build lane. Run container smoke tests against the built digests, not rebuilt mutable tags. Check that the controlled profile actually **refuses** unqualified API/WS/collector routes.
- Generate the platform SBOM from the built artifacts, bind source commit, dependencies, image digests, release identity and deployment assertion separately, and retain provenance. A build-only job with `push: false` cannot supply registry digests; only a reviewed release/publish job with scoped credentials may do that.
- Reserve `scripts/release_check.py` for a release candidate with its required digest-rendered manifests and optional strict evidence flags; its default evidence runner can legitimately report skips outside a prepared production environment. `scripts/security_scan.sh` is a local helper (pin audit, Ruff F/E9 and tracked-file grep), not a required history-aware secret-scanning gate.
- The locally added `release-preflight.yml` is a **manual, read-only, unsigned handoff**. It requires a tag-selected dispatch and a configured `release-review` variable, validates supplied digest syntax and renders templates with `site_qualified:false`. It does **not** verify the registry's ownership, publish images, sign an operator package or deploy. Image publication was not authorized in this session and needs separate review outside auto mode. Verify an eventual signed operator package with approved public keys and exact hashes; a dry-run or `site_qualified:false` package is not bank approval.
- Run a production-shaped local integration rehearsal: migrations; PostgreSQL/Redis; API/worker; approved parser runtime; supported source scan; evidence verification; one bounded report; negative authorization/admission; safe shutdown/restart. Label any optional dependency not present and gate its qualification separately.

### 3.3 External/site qualification: never synthesized by CI

Release approval must separately obtain approved topology and residency, customer/provider target authorization, real HSM/cloud/network/SSH/OT evidence where claimed, independent penetration/escape testing, measured PostgreSQL/Redis crash/partition/recovery and target-scale soak, real customer-reviewed accuracy, staffed operator exercises, independently signed assessor retests, and technical/customer/legal acceptance of the bounded pilot. These are attributable artifacts bound to **the exact release digest, estate, environment, operator, reviewer, timestamp and scope**. Synthetic fixtures, SoftHSM, a local browser screenshot or a generated template cannot fill their slots.

The unified strict readiness gate must receive all required categories—including readiness closure—and return PASS with **no mandatory FAIL/SKIP**. Until then, describe the deployment as supervised pilot/pre-production at most (`PRODUCTION-READINESS.md:7-12,180-185`; `docs/production-qualification-runbook.md:188-218`).

## 4. Workflow rollout sequence and ownership

| Stage | Repository change and owner | Exit criterion |
|---|---|---|
| **0 — Baseline truth** | Engineering + CI owner inventory all service tests, active Actions, current red tests, required workflow permissions/status names and runtime versions. | A reviewed matrix of *actual* jobs, skips and failed tests; no claim of all-green from partial results. |
| **1 — Restore red tests** | The local changes now preserve the remediation `INCONCLUSIVE` assurance gate and correct the Dubai field-accuracy reader to use an authorized platform operator; both formerly red SQLite cases passed focused reruns. Test owner must still rerun the wider backend/worker suites and review any further failures. | Both cases and neighboring tests pass without invented evidence; a complete required CI run, not two focused reruns, supplies the release check. |
| **2 — Expand PR gates** | CI owner incrementally adds full suite discovery, frontend Vitest/toolchain, database migration and scanner/security lanes. | Clean PR reports all required shards with JUnit/artifact retention; intentional skips documented and reviewed. |
| **3 — Publish workflow files** | Repo administrator obtains normal repository write plus GitHub workflow-file permission (e.g. applicable `workflow` scope or GitHub App Workflows write), reviews parked proposals, installs active workflow files, and inspects actual Actions runs before setting branch protection/rulesets and required checks. | An ordinary PR, main push and applicable manual/tag/scheduled jobs run under the intended permissions; a deliberately failing required check blocks merge. No permission workaround through another credential/session. |
| **4 — Reproducible artifact** | Release/security owners build without publishing on PR; reviewed release path publishes immutable digests, SBOM/provenance and externally verified signatures. | Exact source→image→SBOM→operator manifest mapping can be independently checked and reproduced; no mutable tag in deployment input. |
| **5 — Controlled rehearsal** | Platform/SRE and DB owners deploy the **supported** local-source/v1 profile into a disposable production-shaped environment, including parser staging/runtime, backup/restore, replay and failure drills. | Admit/deny/stop/recover/verify cases and service metrics pass with retained logs and no secret leakage. |
| **6 — Target acceptance** | Customer, operator, provider and independent assessor supply site evidence and separately approve scope, duties, retests and one bounded pilot. | Strict gate PASS for the exact clean release/site; any unavailable category remains open, not waived by CI. |

**Change control:** do not copy a parked workflow verbatim into `.github/workflows/` without checking current suite names, environment variables, GitHub permissions, third-party action pinning, artifact retention, exit-code behavior and product profile. Never enable a disallowed production API to make a smoke job pass. Keep PR and release publishing credentials separate; review all outward-facing releases before publication.

## 5. Product-build workstreams tied to these gates

1. **Execution and tenant authority:** one source of truth for original actor, selected estate, target/mode, positive approval, queue claim, shared budgets, stop and bounded recovery. Finish exact-owner history/GraphQL/stream/export negative tests; a legacy platform-NULL inventory row is not automatically a private-history grant.
2. **Observations and evidence:** each collector must report attempted/observed/failed/not-attempted sources and parsed-file/target receipts. Hash only sanitized authoritative payloads; retain tenant-bound evidence IDs, verifier outcomes and historical tombstones. Reconcile current source observations, facts and assets without introducing a second hand-edited truth.
3. **Six BOMs and graph:** SBOM/NBOM/CBOM/TechBOM/HBOM/VBOM keep distinct source semantics, versioning and content addresses. Pin scan-run CBOM and report to exact verified evidence; keep independent estate HBOM separate from TechBOM's HBOM layer. Cross-BOM algorithm matches are associations, never proof of physical key identity. Graph edges label observed/declared/inferred source and bounded traversal witness.
4. **Risk, drift and remediation:** deterministic policy and explainable risk cite evidence and confidence; approved same-estate baseline comparisons are idempotent; administrative dispositions are not independently verified condition clearance. A work item closes only at the appropriate authorized rescan/proof boundary; missing coverage yields INCONCLUSIVE/UNKNOWN.
5. **Operator UI:** display real tenant-scoped API rows, pagination, observation freshness and explicit unmeasured states. Keep the enterprise CTI console accessible, non-chatbot and reduced-motion safe. A route existing, a mocked Vitest page mounting or a 202 accepted response is not a completed operator workflow.
6. **Operational controls:** measured queue/job/DB/scanner/dependency SLOs, origin-qualified notifications, site backups/recovery, signed operator decisions and independently reviewed launch duties. An at-least-once HTTP notification receipt is not exactly-once delivery; ambiguous ACKs require reconciliation.

Each workstream should add positive and negative automated tests, retain exact source/coverage provenance, and be admitted to the **controlled production allowlist only after** its runtime and operator evidence pass. Building a broad development image does not widen the supported production adapter.

## 6. Concrete verification checklist for the plan itself

- [ ] Enumerate active workflows and zero-byte placeholders directly from Git; reconcile `.github/workflows-pending/README.md` with what GitHub actually executes.
- [ ] Capture a baseline full local suite and exact failing node IDs; do not infer the status of `8915806f` from older engineering records.
- [ ] Run workflow syntax and permissions review in a PR; test one deliberate red case to prove required checks block merge.
- [ ] Run the ephemeral PostgreSQL fresh/upgrade tests, and the full frontend typecheck/Vitest/build/toolchain sequence under pinned versions.
- [ ] Build images on a PR without pushing; inspect SBOM and digest/provenance chain after an approved release publication.
- [ ] Deploy the supported controlled profile to a disposable environment and verify unsupported endpoints refuse, approved source scan persists verifiable evidence, and site recovery keeps exact owner/history boundaries.
- [ ] Capture real provider/customer/assessor/operator evidence and rerun the strict unified gate for that exact release and site. Do not change this plan's checkboxes to DONE from repository text alone.

## 7. Non-goals and open decisions

This document does **not** activate GitHub workflows, change branch protection, run CI, install tools, publish an image, deploy a site or approve a bank. Decisions requiring actual owners: protected-branch required checks and workflow-file permissions; registry/signing authority and retention; supported Python/Node/runtime matrix; approved customer topology/region; specific collector adapters beyond local-source/v1; acceptance thresholds for workload/soak/DR; external HSM/provider/assessor contracts; and pilot/SLA/legal scope. Record each decision as a dated, attributable artifact rather than interpreting silence as approval.

**Primary references:** `.github/workflows/ci.yml`, `.github/workflows-pending/README.md`, `Makefile`, `scripts/postgres_parity.sh`, `scripts/check_prod_compose.py`, `scripts/bank_readiness.py`, `scripts/operator_release.py`, `docs/runbooks/controlled-execution-upgrade.md`, `docs/readiness-evidence/launch-engineering-2026-10-22.md`, `PRODUCTION-READINESS.md` and `docs/production-qualification-runbook.md`. Current source and actual job logs take precedence over these written descriptions.
