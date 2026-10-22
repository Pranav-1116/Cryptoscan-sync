# 6. Improve tests, maintainability and release discipline

[Pack index](README.md) · [Previous: user workflow](05-user-workflow-and-frontend-quality.md) ·
[Next: operations and bank qualification](07-operations-and-bank-qualification.md)

## 6.1 Objective: trust the evidence behind every small change

More tests are useful only when they execute the behavior that matters. Improve
isolation, realistic fixtures, meaningful assertions, required execution and exact
release binding. Do not introduce a new test service, rewrite framework or parallel
release system merely to make this plan appear complete.

The [current CI contract](../dev/release-automation.md) and
[build plan](../CI-WORKFLOW-AND-PRODUCT-BUILD-PLAN.md) are authoritative for configured
jobs. This guide recommends follow-up work; it does not change those workflows.

## 6.2 Existing foundations and specific remaining proof

| Present in source | Improve/verify next | Do not claim |
|---|---|---|
| Discovered backend/shared and six scanner test roots | Check that selected critical behaviors actually execute and test collection is stable | Discovery/import success equals passed tests. |
| PostgreSQL 15/16 migration/parity lanes | Retain actual successful results for the intended candidate and deployment database | SQLite success proves PostgreSQL locking/transaction behavior. |
| Frontend typecheck, Vitest, build and toolchain | Add/retain regressions for actual user/estate/error behavior; perform real-browser acceptance | DOM mocks prove browser endurance/site usability. |
| Coverage instrumentation smoke | Review critical untested failure paths, not only aggregate line coverage | The smoke is whole-suite coverage or a threshold gate. |
| JUnit validation and `ci-required` | Verify strict versus optional skip handling and GitHub enforcement | A workflow name configures branch protection. |
| Six-image build-only workflow | Review exact immutable release inputs and controlled-package inventory separately | Builds publish signed images or qualify a site. |
| Manual unsigned preflight | Keep its limitations explicit; do not substitute it for full operator package | Its API/worker/Neo4j render is the complete API/worker/frontend/parser site package. |

The discovered directories are under `services/` and `shared/`.
**`scripts/tests/test_ci_suites.py` is outside that discovery.** The pack recommends
an explicit reviewed required invocation if the team intends it in CI, but makes
no workflow edit here. This is an execution-coverage issue, not a new product feature.

## 6.3 A practical regression structure

For each corrected quality issue, preserve:

1. A minimal deterministic reproduction with an explicit contract.
2. A focused unit/contract regression for the exact failure.
3. A storage/integration regression where persistence, transactions or authority matter.
4. A browser regression if the error was a rendering/action/race problem.
5. A selected end-to-end check showing the correct user outcome and limitation.

Do not mock away the component being tested. If a fixture claims durable evidence,
assert real retained rows/IDs and owner scope. If it represents a legacy candidate
without approved proof, expect INCONCLUSIVE—not VERIFIED because a task was closed.

For timing/concurrency tests use controlled coordination and bounded waits. Do not
silence hangs with broad skips or random sleeps. Clean up resources deterministically
and ensure teardown failures are visible without exposing secrets.

## 6.4 Prevent order-dependent and fixture-contaminated passes

The repository's history contains examples where aggregate ordering hid a worker
failure. This is a historical lesson, not a claim that the same bug is still open.

Recommended checks:

- run the affected service in isolation and the relevant combined suites;
- use fresh durable identities/databases, not a login fixture from an unrelated suite;
- isolate environment variables, monkeypatches, global caches and event loops;
- test synchronous/asynchronous client doubles against the actual expected interface;
- use real completed jobs/results where the contract requires them;
- preserve platform versus tenant identity: supervisor role alone does not grant all-estate history;
- include a fresh-process regression for one-time initialization paths;
- repeat suspicious failures before assigning a flake label, retain diagnostics and an owner.

For example, the C shim already has first-call crypto metadata initialization
regression coverage. Keep the one-call fresh-process scenario: a later call can
hide initialization-order failure.

## 6.5 Skip and failure policy

Ordinary backend/scanner lanes use `check_junit.py --allow-skips`; they reject
failures/errors and empty/all-skipped reports but allow reported optional skips.
Default checker mode rejects any skip; focused required migration proof uses it.

Review skipped behaviors individually. A suite with one executed test does not
prove every required security/migration condition ran. An unavailable required
environment must stay blocked/unexecuted, not be converted to an optional skip.
Retain failing artifacts even if a later retry passes; investigate recurring
nondeterminism rather than select only a favorable run.

The user will handle the unspecified remaining workflow failure separately.
Do not disable it, loosen assertions or remove it from `ci-required` for this plan.
A failed/skipped/cancelled required lane blocks the aggregate.

## 6.6 Maintainability without an architectural rewrite

Identify hotspots using actual incidents, repeated fixes, review difficulty and
coupled changes. Then refactor narrowly under contract tests:

1. Map an existing business invariant and every caller that enforces it.
2. Remove demonstrated duplicate authority/identity validation only through the
   established shared boundary; avoid a second inconsistent implementation.
3. Split an overgrown function/module by responsibility when it improves a proven
   change path, not to reach an arbitrary file-size target.
4. Replace broad exception swallowing with typed/meaningful failures and safe diagnostics.
5. Remove unreachable/dead paths after verifying no supported profile uses them.
6. Make fixture/config defaults explicit; no implicit production permission or seeded approval.
7. Keep changes small enough that a reviewer can explain old/new behavior and rollback.
8. Re-run negative, storage and affected caller tests after the extraction.

Do not merge policy, evidence and UI semantics into a generic “status” abstraction
that loses distinctions. Do not replace append-only history/CAS with convenient
in-place edits. Reduce complexity while preserving observable contracts.

## 6.7 Dependency and build-input hygiene

Maintain committed Python constraints and npm lockfiles through reviewed updates.
For each change retain why it is needed, affected code/profile, compatibility
and security tests, changed transitive inputs and rollback implications.

Current CI pins Node 22.22.3; preserve toolchain compatibility rather than use
force-install/force-fix. Pinning an Action SHA or Python version is useful but not
complete supply-chain evidence. Review container base identities, actual build
inputs, dependency advisories, license/support constraints and release SBOMs.
Do not upload private repositories/customer evidence to unapproved audit services.

## 6.8 Exact release and migration discipline

Use existing `scripts/operator_release.py`, `scripts/pin_release_images.py` and
`scripts/verify_release_attestation.py` according to the
[operator runbook](../runbooks/operator-install-upgrade-recover.md). No production
signing keys/digests are invented by a template or generated in an untrusted PR.

Release rehearsal must bind:

- exact source revision, clean/dirty state, dependency/build inputs and image digests;
- coordinated API/worker/frontend/shared-model/parser compatibility;
- supported profile, approved regional configuration and separately provisioned secrets/CAs;
- complete package inventory, migrations, runbooks/templates and retained limitations;
- separately trusted signature/attestation verification and required independent reviews;
- install, health/readiness, critical journey, failed upgrade and recovery evidence.

The current schema head is **0105**. It widens monitor event types to 120 characters;
downgrade refuses while values longer than 30 remain. Do not truncate audit history
to force rollback. Rehearse representative populated-data migration and choose
an approved forward-recovery/compatible-binary strategy when schema rollback is unsafe.

The manual unsigned preflight does not publish images, sign a release, deploy a
site or include the full controlled package. A non-publishing CI build cannot
supply a production registry digest/signature by itself.

## 6.9 Safe local examples—not a claim they ran for this pack

Run only in the intended isolated locked development environment. Test fixtures
may create/remove databases; never configure these commands against customer data.

```bash
export PYTHONPATH="$(find "$PWD/services" "$PWD/shared" -mindepth 1 -maxdepth 1 -type d | tr '\n' ':')"
python scripts/ci_suites.py --non-scanners
python scripts/ci_suites.py --scanners-only
python -m pytest -q -p no:xdist scripts/tests/test_ci_suites.py \
  services/devsecops/tests/test_ci_workflow_contract.py \
  shared/shared_models/tests/test_capability_maturity.py \
  services/database/tests/unit/test_monitor_event_type_migration.py
```

```bash
cd frontend
npm ci
npm run typecheck
npm test
npm run build
npm run test:toolchain
```

Those selected tests are not a complete backend/security/real-browser/site gate.
Use the reviewed PostgreSQL parity procedure only with explicitly disposable
fixture databases. This documentation task does not run these examples or CI.

## 6.10 Exit criteria

Each material fix has a reproduction, regression and independent review. Critical
checks actually run and their required outcomes cannot be bypassed. The intended
release is immutable/verifiable and has rehearsed migration/recovery compatibility.
No new service/framework or customer-visible feature was required to achieve it.
