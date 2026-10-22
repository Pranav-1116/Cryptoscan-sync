# CI and release automation

**Current source review:** 2026-10-22, `698beb38`. The complete explanatory
workflow and six-BOM product-build plan is
[CI workflow and product build plan](../CI-WORKFLOW-AND-PRODUCT-BUILD-PLAN.md).
For the source snapshot and qualification limits, use
[current implementation status](../CURRENT-IMPLEMENTATION-STATUS.md).

## Active workflow contract

Only `.github/workflows/` defines configured Actions. Files under
`.github/workflows-pending/`, `deploy/ci-workflows/` and
`docs/dev/github-workflows/` are historical/proposed copies. **Do not copy them
over current workflows.**

| Active file | Trigger and work | Boundary |
|---|---|---|
| `ci.yml` | PR, main/integration-branch push, manual; lint, discovered backend/shared matrix, reusable scanner/migration/image lanes, Node 22.22.3 frontend typecheck/Vitest/coverage smoke/build/toolchain, production-config checks, final `ci-required`. | Read-only, no publication; source definitions are not observed green results or configured branch protection. |
| `scanner-tests.yml` | Reusable/manual; six scanner roots discovered dynamically, deterministic offline pytest and retained JUnit. | No nightly schedule is currently configured. Offline tests do not qualify live collectors. |
| `db-migration.yml` | Reusable/manual; disposable PostgreSQL **15 and 16**; major/URL validation, actual Alembic chain and worker/API parity, focused no-skip live migration JUnit. | Destructive only to explicitly disposable fixture databases. Not customer DR, upgrade acceptance or capacity. |
| `docker-build.yml` | Reusable/manual; API, worker, scanner, frontend, legacy dashboard and nginx; actual build contexts. | `push:false`, no registry credentials. Worker-runtime image is separate and needs reviewed base digests. |
| `release-preflight.yml` | Manual selected `v*` tag, `release-review` environment, explicit ready variable and API/worker/Neo4j digest inputs; renders unsigned artifacts. | `signed:false`, `site_qualified:false`, `production_approved:false`. Not full controlled-site packaging, signing, publishing or deployment. |

The frontend coverage command instruments `src/lib/api.test.ts` as a smoke check;
it does not establish whole-suite coverage or a coverage threshold. All Vitest
tests are a separate configured command. Toolchain/advisory checks do not replace
independent product security testing.

## Discovery, skip policy and evidence

- `scripts/ci_suites.py` discovers outermost service/shared test directories,
  rejecting missing scanner families, unsafe names, symlinks, dependency/cache
  trees, empty matrices and oversized matrices. At review: **54 roots = 48
  non-scanner + 6 scanner**. This is not a count of executed tests.
- API fixtures include `services/api/tests/unit` on that shard's `PYTHONPATH`;
  discovery still **does not include `scripts/tests/`**. Its CI-discovery tests
  need a separate invocation if they are to be required.
- Ordinary backend/scanner lanes use `check_junit.py --allow-skips`: errors,
  failures, missing/empty reports and all-skipped reports fail, while optional
  skips remain visible. Default checker mode rejects any skipped case; required
  live migration proof uses that strict mode.
- Socket restrictions allow loopback and Unix sockets; provider/live switches
  are disabled for offline suites. Registry installation/build steps still use
  approved outbound network access.
- Backend/scanner JUnit upload is always attempted, with 14-day retention;
  focused migration reports retain 7 days. Missing artifacts after setup failure
  cannot count as a pass.
- `ci-required` evaluates with `if: always()` and accepts only success for every
  prerequisite, including discovery and reusable workflows. Failure, cancellation
  or a skipped prerequisite fails the aggregate.
- Pip cache support is enabled consistently with setup-python caching. Concurrency
  coalesces push/PR runs by source repository and branch; older runs may cancel.

## Dependency policy

```bash
python -m pip install -r requirements.txt -c requirements.lock.txt
python -m pip check
```

The committed version constraints are now used by CI **and API/worker/scanner
Dockerfiles**. Frontend uses the committed npm lock and `npm ci`; CI pins Node
22.22.3. Third-party workflow Actions use full SHA pins.

This is not a hash-verified cross-platform lock. Immutable base-image policy,
reviewed update procedures, independently retained release SBOMs, historical
secret scanning and signed registry provenance remain separately reviewable.
Do not use force-fix commands or send customer repositories to unapproved audit
services to obtain an advisory pass.

## Local validation examples

Run from the repository root using the intended locked environment. These
commands do not dispatch CI and do not connect to a real production database.

```bash
export PYTHONPATH="$(find "$PWD/services" "$PWD/shared" -mindepth 1 -maxdepth 1 -type d | tr '\n' ':')"
python scripts/ci_suites.py --non-scanners
python scripts/ci_suites.py --scanners-only
python -m pytest -q -p no:xdist scripts/tests/test_ci_suites.py \
  services/devsecops/tests/test_ci_workflow_contract.py
python -m pip check
ruff check services scripts shared
```

For PostgreSQL use the disposable CI service or the separately reviewed parity
procedure only. Migration fixtures may drop/recreate their designated test
databases; never point them at a customer/retained database.

## Current observed/reporting boundary

The user reports all workflows passing except one remaining failure they will
resolve later. Actions/check-result API access returned HTTP 403 to this session;
the failed lane/run SHA is unspecified. This documentation does not repair,
waive, dispatch or independently confirm those runs. A red aggregate can reflect
an upstream failure; do not count it as necessarily a second defect.

Earlier author-reported local runs, Docker builds and PostgreSQL 15 checks remain
historical observations in the build plan and audit ledger. A docs refresh does
not reproduce them or establish PostgreSQL 16 execution. See the dated
[launch engineering evidence](../readiness-evidence/launch-engineering-2026-10-22.md)
for its original mixed/scoped results, not a current all-suite verdict.

## Before release approval

1. Retain successful required Actions results for the exact intended revision;
   resolve the outstanding failure separately.
2. Verify GitHub rulesets require **`ci-required`** and that review-environment
   protection/tag trust actually exist. YAML cannot establish those settings.
3. Separately authorize build publication, registry digest verification,
   signatures/provenance and release SBOM retention.
4. Create the full supported [operator package](../runbooks/operator-install-upgrade-recover.md),
   including frontend/parser/external services; do not substitute the older
   three-image unsigned preflight.
5. Perform site security, upgrade/recovery, backup/restore, capacity and customer
   acceptance with independent retained evidence. No CI lane grants these approvals.
