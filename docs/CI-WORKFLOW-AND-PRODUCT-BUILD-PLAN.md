# CryproScan — product build plan and CI workflow

**Reviewed:** 2026-10-22 UTC
**Repository baseline reviewed:** `698beb38`
**Purpose:** explain what we want to build, how the product should work end to end,
what CI checks today, and the workflow needed to move safely from a code change
to a reviewed release and a bounded customer pilot.

> This is a documentation/design guide, not a new GitHub Actions implementation.
> “Current” below means present in repository files, not that the latest GitHub
> checks have passed. “Proposed” means work still to be implemented or qualified.
> This document does not change or execute CI, deploy infrastructure, or declare
> production approval.

## 1. What we want to build

We want **an evidence-driven cryptographic inventory, exposure and remediation
platform for a bank**, beginning with one useful, bounded application workflow.
The platform should help a customer answer:

1. Which application, release, package, endpoint, hardware and supplier identities
   are actually in the agreed scope?
2. What cryptography is observed, where is it used, and what is its purpose?
3. Which relationships are directly evidenced, customer-reviewed assertions,
   supplier declarations or still unknown?
4. Which conditions are applicable risks rather than just algorithm-name matches?
5. Who owns the work, who approved it, and what exact replacement is intended?
6. Was work merely reported complete, or did a later independent observation
   verify the intended condition?
7. What has not been collected, tested, reviewed or accepted?

The goal is **not** a dashboard that treats empty results as safety, joins assets
by similar names, or claims whole-bank visibility after a feature demonstration.

### 1.1 All six BOM layers are required

| Layer | What we want it to explain | Evidence boundary |
|---|---|---|
| **SBOM — Software Bill of Materials** | Which versioned software components belong to a specific release? | Preserve the SBOM document hash separately from the executable/image artifact digest. Unresolved component versions remain unresolved. |
| **CBOM — Cryptographic Bill of Materials** | Which algorithms, keys, modes, sizes and purposes are observed at which locations? | An import or algorithm name is not proof of security use, runtime invocation or an exploitable condition. |
| **NBOM — Network Bill of Materials** | Which approved endpoints and protocol/cryptographic observations are known? | Successful exact-endpoint receipts matter. An open port is not application identity or proof that every path/node was tested. |
| **TechBOM — Technology Bill of Materials** | How do application, deployment, artifact, package and service identities relate? | Use explicit typed identity links and their evidence, not matching names or invented runtime dependencies. |
| **HBOM — Hardware Bill of Materials** | Which hardware, firmware and cryptographic capabilities support the scoped workflow? | Metadata and supplier assertions do not automatically prove actual operating mode, attestation or certification. |
| **VBOM — Vendor Bill of Materials** | Which suppliers/products contribute evidence or dependencies for the release? | A valid supplier signature establishes origin/integrity, not independent factual truth or vendor certification. |

The six layers complement one another; adding SBOM does not replace the other
five. Each relationship must retain its estate, provenance, observation/review
time, validity, uncertainty and supporting evidence.

### 1.2 Start with one valuable payments pilot

The first customer workflow should cover:

- One payments application and a known release/deployment.
- Approved local source evidence and an actual release-bound SBOM.
- Separately approved TLS and SSH endpoint evidence.
- Meaningful hardware metadata and attributable supplier evidence.
- One finding → owner → approved change → reported completion → later exact proof.
- Independent security records, operating ownership and explicit exclusions.
- Technical-owner review and a different designated customer-owner acceptance.

This demonstrates a useful evidence-to-remediation loop. It does not establish
whole-bank coverage, commercial rollout approval, infrastructure qualification,
product certification or an SLA.

## 2. Keep three different workflows separate

| Workflow | What it checks | What it cannot establish alone |
|---|---|---|
| **CryproScan repository CI** | Whether changes to this platform satisfy automated engineering checks. | The safety of a customer's application, actual deployment readiness, assessor independence or customer acceptance. |
| **Customer application CI integration** | Whether an authorized scan of a specific customer change/release violates an agreed cryptographic policy or baseline. | Full customer-estate coverage, production invocation or permission to scan arbitrary systems. |
| **Release/site acceptance** | Whether the exact package, intended environment, operating capability and externally supplied evidence satisfy the release/customer gate. | It cannot be inferred solely from a green pull request or a hosting provider's certificate. |

**CI** means continuous integration: validate a change before integration.
**CD** means continuous delivery/deployment: package or promote a validated
release. We should automate evidence collection and delivery safely, but not
silently turn a CI result into production deployment or customer approval.

## 3. Product workflow we want to support

```text
Customer agrees one application/release and explicit exclusions
    ↓
Register expected targets independently of scanner discoveries
    ↓
Select exact estate + verify current identity, permissions and residency
    ↓
Approve the specific collection scope/method/window where required
    ↓
Admit work → durable job → isolated/bounded collection and parsing
    ↓
Retain observations, failures, refusals, UNKNOWN outcomes and evidence hashes
    ↓
Build six-BOM views using explicit typed identities and reviewed links
    ↓
Evaluate purpose/applicability, freshness, coverage and uncertainty
    ↓
Assign accountable owner → different authorized reviewer approves change
    ↓
Owner reports actual completion, with evidence
    ↓
A later independent collector/retest observes the exact intended condition
    ↓
Record VERIFIED / failed / inconclusive, without rewriting history
    ↓
Review independent security records and operational capability
    ↓
Technical review → separate bounded customer acceptance
```

### Current production support boundary

The reviewed reference profile is
`kubernetes-external-services/local-source-v1`. It uses API/worker/frontend,
external PostgreSQL, verified-TLS Redis and the approved isolated parser runtime.
The controlled production acquisition boundary remains local source; unqualified
legacy live TLS/SSH/cloud/vendor collection and other unsupported surfaces stay
refused. Retained qualified receipts can be reviewed as metadata, but that does
not qualify a live collector or grant new collection permission.

Broader collection is part of the desired product direction and requires its
own adapter, authorization, isolation, negative tests and site qualification.
The CI plan must not bypass those restrictions merely to make a demo work.

## 4. What GitHub Actions CI actually contains today

Source of truth: [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) and its
reusable workflows at `698beb38`. They are active definitions, no longer empty
placeholders. This section describes configuration, not independently observed
successful Actions runs.

### 4.1 Triggers, permissions and concurrency

- `ci.yml`: pull requests, pushes to `main` **and** `arena/bb4b80dd-cryproscan`,
  and manual dispatch.
- Read-only `contents: read` permissions; checkout does not persist credentials.
- Third-party Actions are pinned by full commit SHA.
- Concurrency uses source repository plus branch identity, so a branch push and
  its PR run can coalesce; older in-progress runs in the same group are cancelled.
- The workflow does not use production registry/signing credentials or publish images.

```text
PR / main push / integration-branch push / manual dispatch
    ├── lint
    ├── discover non-scanner services/shared → backend matrix
    ├── reusable scanner discovery → scanner matrix
    ├── reusable PostgreSQL 15/16 migration + parity
    ├── reusable six-image build-only matrix
    ├── frontend typecheck / Vitest / coverage smoke / build / toolchain
    └── production configuration guard
             ↓ all required lane results
         ci-required (always evaluated; only success is accepted)

Separate manual tagged dispatch → release-review → unsigned preflight artifacts
```

### 4.2 Main and reusable jobs

| Configured lane | Actual work | Limit |
|---|---|---|
| `lint` | Python 3.11; Ruff F/E9 across services, scripts and shared, constrained by the lockfile. | Not every lint rule or an independent security assessment. |
| `discover` → `backend` | `scripts/ci_suites.py --non-scanners` discovers outermost tests under services/shared; matrix max parallelism 10; pytest non-live with socket restrictions and JUnit. API unit fixture directory is added only for the API suite. | Imports do not themselves prove tests executed; failures and missing reports must remain visible. |
| `scanner-offline` | Calls `scanner-tests.yml`; discovers all declared scanner families, rejects missing families, runs offline pytest shards with max parallelism 3 and retains JUnit. | Fixtures do not qualify authorized live collectors or container escape resistance. |
| `db-migration` | Calls `db-migration.yml`; disposable PostgreSQL **15 and 16**; explicit URL/major checks; actual Alembic chain, PostgreSQL worker/API parity and focused migration JUnit. | Not a customer backup/restore, HA or capacity result. Migration fixtures are destructive to their designated disposable databases. |
| `images-build-only` | Calls `docker-build.yml`; builds API, worker, scanner, frontend, legacy dashboard and nginx with their declared contexts. `push:false`, no registry credentials. | No published registry digest, runtime/site health, vulnerability qualification or signed release. |
| `frontend` | Node **22.22.3**, `npm ci`, typecheck, **all Vitest tests**, V8 coverage instrumentation smoke on `src/lib/api.test.ts`, production build and toolchain tests. | The smoke is not full-suite coverage measurement or a percentage threshold; DOM tests are not real-browser/site endurance. |
| `prod-config-guard` | Compose exposure check; reject a known weak secret; accept structurally valid controlled-profile configuration using synthetic values, TLS Redis shape and disabled graph. | Not connectivity, actual secret provisioning, certificate validity or deployment acceptance. |
| `ci-required` | `if: always()`; requires lint, discovery, backend, scanner, migration, images, frontend and production guard to report success. | Must still be configured/verified as required in GitHub rulesets. A YAML name does not enforce merge policy. |

Suite discovery partitions the reviewed tree into **54 test roots: 48 non-scanner
and 6 scanner roots**. The matrix is generated, not a fixed 15-service list.
This count is a source inventory, not passed tests. Discovery searches only
`services/` and `shared/`: **`scripts/tests/test_ci_suites.py` is outside that
selection**, and no current workflow explicitly runs that directory. Add an
explicit required invocation in a separately reviewed CI change if intended.

### 4.3 Non-live selection, skips and retained evidence

Backend/scanner commands exclude live-marked tests, disable xdist inside shards,
and use pytest-socket restrictions with loopback and Unix sockets allowed.
Relevant live-provider switches are disabled. Dependency installation/build steps
still need approved registries/network; this is not a completely networkless runner.

`scripts/check_junit.py --allow-skips` permits reported optional skips but rejects
failures/errors, no testcases and **all-skipped** reports. Its default mode rejects
any skipped case; the focused required migration proof uses this strict mode.
An ordinary suite having at least one executed test is not proof that every
required behavior ran. Review skips, including missing platform tools, explicitly.

Backend/scanner JUnit uploads use `if: always()` and 14-day retention; focused
migration reports use 7 days. A setup failure/missing report is not fabricated as
success. The aggregate rejects failed, skipped and cancelled upstream job results.

### 4.4 Build and dependency policy

Python CI and API/worker/scanner images install `requirements.txt` constrained by
`requirements.lock.txt`. Pip caching is no longer disabled globally in workflows
using setup-python cache support. Frontend uses its committed npm lockfile.

These are version constraints, **not hash-verified cross-platform reproducibility**.
Python minor/tool dependencies, mutable base images and PostgreSQL tags still need
an explicit reviewed pin/update policy. Do not force dependency upgrades or add
unapproved external audit uploads just to obtain a clean report. No automated
required historical-secret scanner or dependency-audit service is established by
these changes.

### 4.5 Manual release preflight, not publishing or site-package acceptance

`release-preflight.yml` is manual only. It uses `environment: release-review`,
requires `CRYPTOSCAN_RELEASE_REVIEW_READY=true` and a selected `v*` tag, and takes
reviewed API, worker and **Neo4j** digest inputs. It renders **unsigned** manifests
and explicitly writes `signed:false`, `site_qualified:false` and
`production_approved:false`.

This is the older three-image rendering contract, **not** the complete controlled
API/worker/frontend/parser package; Neo4j remains disabled in that controlled
profile. It does not verify registry ownership, sign/publish images, deploy a
cluster or validate the strict customer gate. Use the separate operator-package
procedure for the actual site topology. The environment variable/tag prefix alone
cannot prove configured reviewers, trusted tag policy or independent approval.

### 4.6 Current run status is reported, not independently confirmed here

The user reports all workflows passing except one unresolved failure, to be fixed
later. This session's GitHub Actions/check-result API access returned HTTP 403;
we do not know the failing lane/run SHA from the report. The remaining failure is
not fixed or waived in this documentation change. See
[current implementation status](CURRENT-IMPLEMENTATION-STATUS.md).

## 5. CI/release target and remaining hardening work

The discovered test lanes, frontend checks, reusable migration/scanner/image
workflows and final aggregate are now configured. The sections below describe
the target acceptance depth; they are not a claim that every test/security/release
requirement is implemented. Keep protected release/site decisions separate.
Workflows should produce clear evidence rather than a single misleading
“bank ready” badge.

```text
Untrusted PR / feature change
    ↓
Fast hermetic checks: lint + contracts + affected unit tests + frontend tests/build
    ↓
Broader scanner/security/database/Redis integration checks
    ↓
Human review + verified required branch checks
    ↓
Approved trusted revision / release candidate
    ↓
Build exact API, worker, frontend and parser images
    ↓
Image/dependency checks + release inventory + external signing verification
    ↓
Protected delivery approval — not automatic customer deployment
    ↓
Customer-site preflight, migration/install and witnessed recovery/capacity checks
    ↓
Independent security evidence + operating capability + scoped pilot review
    ↓
Explicit authorized release/customer decision
```

### 5.1 Lane A — fast pull-request engineering gate

**Current foundation:** lint, discovered service/shared suites and frontend
tests/build/toolchain are configured. **Remaining target:** dependency-aware fast
selection, generated-output gates and explicitly required script-directory tests,
without production secrets or customer targets.

Required checks should include:

1. Existing whole-repository F/E9 lint; ratchet additional rules through reviewed
   cleanups rather than broad ignores.
2. Shared Pydantic contracts, schema serialization, unknown/extra fields, explicit
   timestamps and validation boundaries.
3. Changed service tests plus an explicit shared-model test lane. Shared imports
   alone do not execute shared tests.
4. Frontend `npm run typecheck`, `npm test`, `npm run build`, and the existing
   `npm run test:toolchain` where relevant.
5. Generated schema/OpenAPI/maturity consistency checks. Regeneration must leave
   tracked generated outputs unchanged for a correct change.
6. Secret/sensitive-output checks and safe configuration assertions.
7. An explicit aggregate engineering result that cannot silently pass when a
   required lane was cancelled, skipped, failed or never scheduled.

Path-based selection can make checks faster, but shared contract, authentication,
estate, parser and migration changes need dependency-aware expansion. A changed
shared model must not run only the test file that directly changed.

### 5.2 Lane B — deterministic scanners and six-BOM contracts

The scanner-family discovery/offline workflow is configured. Extend its
deterministic approved fixtures and acceptance depth as needed; do not describe
its mere presence as completed hostile-input or live qualification. Also exercise the cross-layer joins:

- Release artifact → exact SBOM → versioned package → crypto evidence.
- Endpoint receipt → reviewed application/service assertion.
- Application → deployment → release artifact.
- Hardware metadata → firmware/crypto evidence, with declared provenance.
- Supplier signature → exact estate/build/product evidence → reviewed assertion.

Check unsupported inputs, empty results, partial extraction, parser failures,
resource exhaustion, stale evidence and unresolved relationships. Do not convert
an empty result, missing dependency or unavailable scanner into a successful scan.
The fixture report helper `scripts/scanner_qualification.py` explicitly leaves
external authorization/sign-off unresolved; a fixture run is not live scanner
qualification.

### 5.3 Lane C — mandatory security and trust regression tests

At minimum, retain the negative categories required by the independent-assurance
scope:

| Area | Automated tests to require |
|---|---|
| Tenant/estate isolation | Cross-read, cross-write, guessed foreign IDs, NULL/platform scope, stale estate replies and cross-estate raw evidence downloads. |
| Identity and authorization | Expired/revoked sessions, deactivated users, removed roles, machine credential versus human approval, and different-human review. |
| Upload/parser isolation | Traversal, symlinks, expansion/nesting limits, oversized/duplicate-key JSON, bounded CPU/memory/output and no privileged parser fallback. |
| Secrets and evidence | No private keys/source secrets in outputs; blob digest integrity; immutable history; failed writes do not leave partial report/finding success. |
| Supply/deployment | Tampered payloads/digests, wrong estate/release, untrusted/withdrawn keys, report replay, stale authority and misconfigured secrets/CA mounts. |

Test launch-specific lifecycle rules as well: a ticket is not resolution,
completion must precede retest, a retest must bind the approved replacement and
current finding, assignment changes invalidate exercises, and changed evidence
invalidates current pilot acceptance.

Automated regression checks support an independent assessment; they do not
replace one or establish genuine assessor independence.

### 5.4 Lane D — database, Redis and recovery integration

- Exercise migrations on a clean and representative populated database, verify
  migration head/model parity, and retain data-preservation results.
- Keep SQLite tests for fast feedback **and** PostgreSQL coverage for SQL behavior,
  concurrency, exact-estate uniqueness, transaction rollback and revision CAS.
- Use isolated disposable Redis configurations for TLS/ACL/reconnect/replay tests;
  never connect ordinary unit suites to a persistent shared rate-limit store.
- Test job claims/fencing, interruption, UNKNOWN outcomes, reconciliation, outbox
  publication and replay reset. A restarted healthy snapshot is not evidence that
  earlier acknowledgements or events survived.
- Treat real site restore, contention, failover and recovery-time/data-loss
  measurement as a separate authorized acceptance lane.

Tests requiring containers, network or external systems need a clearly declared
runner and failure policy. A missing required service should be BLOCKED/FAIL for
its required gate, not an unnoticed optional SKIP.

### 5.5 Lane E — trusted release-candidate build and package integrity

Six-image build-only CI is configured. Publication, signed production provenance,
registry verification and site-package promotion remain separate work; the
manual unsigned preflight does not implement this complete lane.

1. Build from the reviewed exact revision, using approved dependency/build inputs.
2. Build the coordinated API, worker, frontend and isolated parser images needed
   by the selected support profile. Do not enable an optional service merely
   because an old development topology includes it.
3. Record immutable image digests, release identity, migration compatibility,
   component/SBOM information, dependency findings and declared exceptions.
4. Verify the complete operator-package inventory, including manifests, runbooks,
   templates and retained scoped evidence. Detect extra, missing and modified files.
5. Obtain the approved external release attestation/signature and verify against
   a separately trusted public key. Never generate production signing authority
   inside an untrusted PR job or store a private key in repository files.
6. Publish only from a trusted protected context with minimum permissions and
   explicit approval. OIDC/short-lived credentials are a design option, not a
   configured capability claimed by this document.
7. Retain exact build/package verification evidence. Artifact expiry or deletion
   must not leave a release “approved” without required evidence.

The existing `scripts/operator_release.py`, `scripts/pin_release_images.py` and
`scripts/verify_release_attestation.py` provide package/pinning/verification
building blocks. Their presence does not mean GitHub Actions currently builds,
signs or publishes production images.

### 5.6 Lane F — external site and customer acceptance

Do not require every ordinary PR to have bank credentials or real HSM access.
Instead, bind the final release/site decision to attributable evidence for the
exact build and intended environment:

- Independent security scope/report, tracked remediation and later signed retests.
- Actual active primary/backup owners, procedures, acknowledgements and reviewed
  fresh exercises for all nine operating duties.
- Witnessed install/upgrade/restore, realistic capacity/fault tests and browser
  qualification for the intended deployment.
- Real bounded customer pilot with exclusions, current proof and separate
  technical/customer review.
- Approved residency, infrastructure controls and commercial/legal decisions.

The existing readiness orchestrator `scripts/bank_readiness.py` supports strict
failure on required SKIP/FAIL states. It is not invoked by the current main CI
workflow. Its report categories and the newer launch record API are distinct
surfaces: do **not** assume launch acceptance automatically feeds or closes the
unified readiness gate. Any bridge needs an explicit, reviewed evidence adapter
with build/environment/freshness binding.

A green repository CI result must never automatically set “certified”, “SLA
achieved”, “whole bank covered” or “customer accepted”.

## 6. Customer application CI integration — the second CI workflow

The desired customer-facing loop is:

```text
Customer opens an application PR / prepares a release
    ↓
Approved pipeline identifies exact source/release and agreed baseline/policy
    ↓
Authorized CryproScan scan is admitted and finishes with durable evidence
    ↓
Evaluate purpose-aware findings and changes against that baseline
    ↓
Return policy decision and evidence references to the customer pipeline
    ↓
Owner fixes the relevant condition
    ↓
Fresh authorized rescan proves the exact replacement, or remains inconclusive
```

There is an existing client helper, `scripts/ci_gate.py`, for the `/ci/gate`
contract. It requires a scan ID and an authenticated token, can require a baseline,
select a policy profile and emit JSON/PR-oriented output or SARIF. Its current
exit behavior returns zero for `PASS` **or `WARN`**; do not assume every warning
blocks a merge. Review and test profile-specific policy before making it a
customer's required check.

This helper is **not invoked by the repository's current GitHub Actions workflow**.
It does not create collection permission, ensure a scan completed on the intended
release, manage customer token custody or configure customer branch protection.
Its availability must also respect the deployed support profile; do not enable a
refused legacy API route as a shortcut to integration.

Before onboarding a customer pipeline, explicitly implement/verify:

- Exact tenant/estate, release/source identity, current credential authority and
  permitted source/collection scope.
- Protected baseline creation/change approval; no untrusted PR can replace its
  own baseline to hide a regression.
- Real job completion, evidence integrity and agreed freshness before policy
  evaluation; HTTP acknowledgement alone is not scan completion.
- Agreed PASS/WARN/FAIL/UNKNOWN/unavailable behavior. Required coverage or unavailable
  proof must not quietly become a successful customer check.
- Least-privilege, revocable automation credentials with safe secret injection;
  automation must never impersonate a human reviewer or accept its own risk.
- Scrubbed output/SARIF and controlled access to sensitive detailed evidence.
- Required-check configuration and an audited, expiring human exception process
  where the customer's policy permits one.

## 7. Change and release decision rules

| Observed result | Honest interpretation | Required behavior |
|---|---|---|
| PASS with retained evidence | The specified check passed on the stated revision/environment. | Continue only for that check's scope. |
| FAIL | A required check failed. | Block the relevant integration/promotion; fix or follow a documented approved exception process. |
| SKIP / unavailable / unconfigured | Required behavior was not exercised. | Never relabel as PASS. Block a gate that requires that evidence. |
| Cancelled run | No completed verdict for that execution. | Require a completed check for the revision being accepted. |
| UNKNOWN / INCONCLUSIVE | Evidence cannot establish success or failure of the intended condition. | Retain the state and request usable independent evidence. |
| Reported complete | An owner declared that an action happened. | Require later exact-condition verification/retest for resolution. |
| Historical acceptance, evidence now stale/changed | Acceptance happened previously, but its current evidence basis no longer holds. | Recompute blockers and obtain the appropriate fresh reviews. |
| `[skip ci]` publication | Code/docs were published without the normal automatic check result. | Do not call it CI-validated or production-approved; required-check enforcement must be reviewed separately. |

No `continue-on-error`, `|| true`, hidden exclusion or changed assertion should be
used merely to manufacture a green required gate. If a test is stale, correct
its fixture/expectation against the intended security contract and retain evidence;
do not weaken the contract to satisfy the old fixture.

Branch protection/rulesets, required check names, reviewer policy and bypass
permissions must be verified in GitHub. They are not established by a workflow
file or by this document. A skipped required workflow can leave a PR waiting for
a check rather than providing a successful status.

## 8. What CI must retain as evidence

For each relevant lane retain, with appropriate classification and retention:

- Commit SHA, test/build revision, runner environment, dependency/tool versions,
  command, start/end and exit status.
- Test totals **including failures, skips, deselections and cancellations**;
  results from overlapping suites must not be summed as independent coverage.
- Structured test reports and sanitized logs; no customer source secrets, private
  keys, tokens or production credentials.
- Artifact/image/SBOM/package hashes and schema/migration compatibility.
- Explicit synthetic-fixture versus authorized live/site evidence labels.
- Unresolved blockers, known failed tests, approved exceptions with owner/expiry,
  exclusions and links to supporting evidence.
- Separate authorized identities for release, security, operational and customer
  decisions; a CI bot cannot manufacture those human approvals.

A displayed green badge without this scope and attribution is insufficient for
a banking release decision.

## 9. Practical implementation order

| Step | Deliverable | Done when |
|---|---|---|
| 1 | Reconcile active workflow contracts, historical copies and remaining failures. | Executed coverage matches documentation; unresolved failures have owners and are not suppressed. |
| 2 | Maintain configured frontend/shared checks; add missing explicit script tests. | Relevant suites actually execute and their failure blocks the engineering result. |
| 3 | Qualify and extend the configured scanner/security lanes. | Every declared family and cross-BOM contract has an explicit result; missing coverage is visible. |
| 4 | Strengthen database/Redis/concurrency and generated-output checks. | Required integration dependencies exist and failures/corruption do not produce success. |
| 5 | Agree and adopt reproducible build inputs and safe dependency updates. | Exact tools/dependencies/actions/images are attributable and updates pass compatibility checks. |
| 6 | Implement trusted image/package build and attestation verification. | Exact release artifacts are inventoried, verified and published only from approved contexts. |
| 7 | Configure/verify required checks and protected release decisions. | Merge/promotion rules and bypass authority are reviewed, enforced and auditable. |
| 8 | Qualify the intended customer site and complete the bounded pilot. | Real external evidence and separate accountable reviews satisfy the scoped release/customer gate. |
| 9 | Add new applications/adapters gradually. | Every expansion has explicit scope, permission, evidence, negative tests and fresh acceptance. |

Some foundation steps above are now configured in source; their remaining
acceptance depth and GitHub enforcement must still be verified. This document
does not change GitHub Actions definitions.

## 10. Existing local verification entry points

These are repository commands to run deliberately in an appropriately prepared
development/test environment, **not commands executed by this documentation
change**. Use a supported Node version and the project's Python virtual environment.

```bash
# Repository-managed Python environment and dependencies.
make setup

# Broad non-live backend/shared test collection; includes integration tests
# whose disposable local dependencies must be provisioned as their harnesses require.
make test JOBS=2

# Frontend checks, matching the commands now configured in the Actions frontend job.
cd frontend
npm ci
npm run typecheck
npm test
npm run build
npm run test:toolchain
```

Ruff and generated-contract checks, from the repository root after environment
setup:

```bash
export PYTHONPATH="$(find services shared -mindepth 1 -maxdepth 1 -type d | paste -sd:)"
.venv/bin/ruff check services scripts shared
.venv/bin/python scripts/gen_rest_api.py
.venv/bin/python scripts/gen_capability_maturity.py
# Inspect generated changes; a check lane should fail on unexpected tracked diff.
git diff --exit-code -- docs/api-reference/rest-api.md docs/CAPABILITY-MATURITY.md frontend/src/lib/maturity.ts
```

The generation scripts intentionally write files and may update date metadata;
review changes instead of treating regeneration itself as proof of correctness.
Database parity, live qualification, release publication and strict customer
readiness require their own provisioned environment/evidence and should not be
launched casually from an untrusted PR.

## 11. Validation state and later corrections

The [launch engineering record](readiness-evidence/launch-engineering-2026-10-22.md)
retains its original scoped results: 157 final changed-code passes, 398 frontend
passes and the broader failures encountered at that revision. Later commits
corrected the field-accuracy operator identity and the exact-site/post-action
legacy remediation fixtures while preserving INCONCLUSIVE without approved proof.
Those fixture corrections do not rewrite the historical test record or prove a
new full-suite green result.

The GitHub-side implementation guide previously reported local CI contract tests
(31 passes), six local non-published image builds, and disposable PostgreSQL 15
checks (6 migration tests, 959 worker passes with 1 deselected, 2 API estate tests).
Those counts are **retained author-reported local observations**. This docs
refresh separately ran 43 focused CI-discovery/workflow-contract, maturity and
0105 migration tests (all passed); it did not rerun the image builds, full worker
parity or live PostgreSQL tests. PostgreSQL 16 and actual Actions status require
their own current records.
The author also reported a local Node 22.22.0 limitation; CI pins 22.22.3. Do not
confuse a previous local environment limitation with the later user-reported
workflow status.

The user now reports one outstanding workflow failure. Actions/check APIs remain
403 for this session, and the failed lane/run SHA is unspecified. No repair,
workflow dispatch, all-green claim or site qualification is part of this refresh.

## 12. Related implementation and acceptance guides

- [Current production-readiness decision boundary](../PRODUCTION-READINESS.md)
- [Six-BOM evidence paths](bank-environment/49-six-bom-evidence-paths.md)
- [Independent remediation verification](bank-environment/54-independent-remediation-verification.md)
- [Measured workloads and capacity limits](bank-environment/55-measured-workloads-and-capacity-limits.md)
- [Independent security assurance](bank-environment/56-independent-security-assurance.md)
- [Operational ownership and demonstrated service](bank-environment/57-operational-ownership-and-demonstrated-service.md)
- [Focused payments customer pilot](bank-environment/58-focused-payments-customer-pilot.md)
- [Operator install/upgrade/recovery](runbooks/operator-install-upgrade-recover.md)
- [Launch assurance handoff](runbooks/launch-assurance-handoff.md)
- [Editable launch templates](templates/launch/README.md)

**In one sentence:** build a traceable six-BOM evidence-to-remediation platform,
use CI to prove scoped engineering behavior, and require real independent,
operational and customer evidence before claiming a qualified release.
