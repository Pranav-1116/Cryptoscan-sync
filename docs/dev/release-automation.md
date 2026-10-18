# Release automation: implemented checks and remaining proof

Updated: 2026-10-17. Scope: internal CI coverage and build/schema validation.
This does **not** approve a release or close customer/provider qualification.

## Active definitions

`.github/workflows/` is the source of truth. Copies under
`.github/workflows-pending/` and `docs/dev/github-workflows/` are historical
proposals, not instructions to overwrite the active workflows.

| Workflow | Implemented contract | What it does not prove |
|---|---|---|
| `ci.yml` | Discover every outermost `tests` directory under `services/` and `shared/` (54 in this checkout), run suites serially within bounded matrix jobs; lint; frontend frozen install, all-dependency npm advisory gate, toolchain/HTTP contracts, typecheck, Vitest, V8 provider smoke and build; production config rejection/acceptance; existing PostgreSQL parity lane. A final check named `ci` requires every prerequisite to succeed, including discovery and the matrix. | No full GitHub run has been observed for these changes. Offline tests exclude `live`; ordinary platform-dependent skips are not production qualification. |
| `scanner-tests.yml` | Run process timeout/seccomp and hostile archive regressions; retain JUnit results, including failures/skips. | Not a container isolation boundary or a hostile-input qualification on another OS/architecture. |
| `db-migration.yml` | Apply the actual Alembic chain and test schema parity/auditing on file-backed SQLite. Run fresh PostgreSQL migration/schema/tenant-index tests and a latest-revision downgrade/upgrade against a disposable PostgreSQL 16 service. | Not a production restore test, complete downgrade-to-base guarantee, or authorization to run destructive tests on a real database. |
| `docker-build.yml` | Build API, worker, scanner, frontend, legacy dashboard and nginx with their actual Docker build contexts; validate dev/prod Compose configuration. Read-only token, no registry credentials, `push: false`. | No image publication, immutable registry digests, vulnerability scanning, signature/provenance attestation, deployment or runtime health proof. |

### Fail-closed details

- `scripts/ci_suites.py` discovers new service/shared suites automatically, stops
  at the outermost test directory, ignores dependency/cache directories and
  symlinks, rejects unsafe path names, and refuses an empty or over-limit matrix.
- The backend command quotes the matrix suite via an environment variable and
  disables xdist inside each matrix job, avoiding cross-suite process state.
- The aggregate uses `if: always()` and rejects every prerequisite result other
  than `success`: failure, cancellation and skipped prerequisites cannot become
  a green aggregate.
- Migration tests previously could skip when PostgreSQL was unavailable.
  `scripts/check_junit.py` now checks actual test cases, not summary counts, and
  rejects no-test, skipped, failed or error cases in the required migration lanes.
- JUnit results are uploaded even when a test command fails. A missing result
  after setup failure is visible; it is not fabricated as passing evidence.
- The production configuration fixture now supplies all fields the current
  runtime guard requires. These are synthetic validation values, never actual
  deployment secrets, and the command does not connect to those services.

## Dependency lock

CI Python installs use:

```sh
python -m pip install -r requirements.txt -c requirements.lock.txt
```

The reconciliation retained all 56 existing pins and added 37 missing test/provider
and transitive dependencies from a compatible Python 3.11 Linux environment,
including `pytest-xdist`, `execnet`, `pytest-timeout`, `pytest-socket`, `fakeredis`,
`hypothesis`, coverage and cloud-provider libraries. `pip check` passes.

This is a version-constraint lock, **not** a hash-verified, cross-platform supply
chain lock. Runtime Dockerfiles still install `requirements.txt`; using the same
constraints and immutable base images in release builds remains separate work.
A regression test requires every direct dependency to have a unique compatible
exact pin. Review and test dependency updates rather than silently regenerating
all versions from an unrelated environment.

## Local checks

With dependencies installed and all service/shared directories on `PYTHONPATH`:

```sh
python scripts/ci_suites.py
python -m pytest -q -p no:xdist services/devsecops/tests/test_ci_workflow_contract.py
python -m pytest -q -p no:xdist \
  services/devsecops/tests services/database/tests services/scanner/tests \
  services/container_scanner/tests shared/shared_models/tests
python -m pip check
ruff check services scripts shared
```

For real PostgreSQL proof, use only a disposable local/CI database: the migration
fixture drops and recreates its test database. The workflow supplies that isolated
service, enables `-m live`, then checks its JUnit report for skips.

## Validation and limitations of this implementation

- Discovery includes all 54 currently present service/shared test roots.
- Workflow YAML parses, and every embedded shell block passes `bash -n`.
- Contract tests cover automatic inclusion, safe paths, symlink/dependency
  exclusion, empty/oversized matrices, prerequisite gating, migration proof,
  image coverage/build contexts, compatible dependency pins and current positive
  and negative production configuration fixtures.
- A negative run with an intentionally unavailable local PostgreSQL endpoint
  produced five skipped tests; `check_junit.py` rejected the report as intended.
- Local affected-suite regressions: **1,760 passed, 13 skipped, 5 live
  deselected, 0 failed**, including all 21 new contract tests. Repo-wide ruff
  and `pip check` pass. This is not a full backend or frontend rerun; see the
  round-status ledger.
- Docker/Compose and a PostgreSQL server are not available in this sandbox, so
  builds, Compose validation and positive PostgreSQL execution are **not run**.
- Full Actions expression validation with actionlint was not completed: its binary
  download was blocked by the sandbox's network restrictions. YAML parsing and
  contract tests are narrower checks, not a substitute for a GitHub Actions run.
- No commit/push, check-run result, registry write or branch-protection change is
  implied by these local files.

## Before calling release automation qualified

1. Review and push the complete intended checkout through an authorized GitHub
   connection; retain actual successful Actions runs for that exact revision.
2. Require the aggregate `ci` check and the migration/container check names (shown
   by GitHub) in branch protection. Path-filtered auxiliary checks should not be
   unconditional required checks unless their trigger strategy is adjusted.
3. Verify positive PostgreSQL proof and real Docker/Compose builds. Fix failures;
   do not waive them because local YAML validation passed.
4. Separately implement/authorize image publication, pin exact registry digests,
   qualify signing/provenance, and run deployment/restore/security checks.
5. Activate and qualify secret scanning; its historical proposal is still inactive.

## Notification receipt extension (2026-10-17)

The migration workflow now also includes SQLite receipt-handoff/tenant-insert
regressions and a required-proof PostgreSQL receipt upsert/concurrent-claim
lane. Those receipt tests use a uniquely named temporary schema, not a database
drop (the existing full-chain PostgreSQL test still owns a disposable database
as documented above). A missing URL skips; configured connection/schema errors
fail. JUnit proof rejects skips in the qualification lane. Local positive
PostgreSQL/GitHub execution is still unverified. See
[notification delivery](notification-delivery.md) for at-least-once semantics
and the existing-data handoff/rollback boundary.

### Frontend dependency security follow-up (R87)

The frontend lane explicitly audits development dependencies, requires supported
Node engines and keeps the coverage provider exercised. The Docker install now
requires the committed lock and uses `npm ci`. Local qualification, preserved
browser compilation targets and the no-Docker/no-GitHub-run boundary are recorded
in [Frontend toolchain hardening](frontend-toolchain-security.md). These controls
do not turn an npm advisory result into product-wide security approval.
