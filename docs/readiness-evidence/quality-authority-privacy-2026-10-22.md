# Third quality increment: authority/dependency failure privacy — 2026-10-22 UTC

## Scope and starting state

This continues [implementation progress](../product-improvement/IMPLEMENTATION-STATUS.md)
and roadmap B3/B4 from [security/privacy/isolation](../product-improvement/03-security-privacy-and-isolation.md).
Git HEAD at execution was `69faec96adad43848950c74c4c939151ef7b93d1` on
`arena/bb4b80dd-cryproscan`, with increments 1–2 retained uncommitted. The user
has now authorized pushing **all accumulated code and documentation**. Workflow
files, dependency locks and the earlier unspecified CI failure remain untouched;
publication uses `[skip ci]`, not a claim about required CI results.

This increment hardens existing session-role/estate dependencies and existing
health probes. No route, collector, service, identity model, deployment profile,
schema migration or authorization grant is added.

## 1. Reproduced issues

### Role storage failure could enter the legacy admin compatibility path

`_user_roles` swallowed lookup exceptions and returned an empty role list;
`require_roles` treated a failed provisioning lookup as an affirmatively absent
legacy identity. The isolated post-authentication gate could therefore run its
guarded action rather than refuse. Missing production identities also qualified
for legacy admin/platform-estate handling, and current disabled/deleted user
rows could still supply privileged roles at those lookup boundaries.

The initial adverse role tests deliberately override the already-authenticated
principal and DB dependency on a **test-only isolated route**. They prove the
role-gate failure behavior, not an end-to-end login exploit, real database outage,
actual bank disclosure or general authentication bypass. Existing upstream
session/store controls may independently refuse a request before this boundary.

Four later safety regressions also exercise the **actual artifact-registration
HTTP route**, real durable fixture sessions and tenant resolution. A targeted
role-stage storage fault begins only after normal authentication/estate checks.
Both writer and readonly principals, under test and production-strict dependency
settings, receive 503 and create no artifact. These four were added after the
initial red run; they are not falsely counted as part of that reproduction.

### Public health errors and selected failure logs exposed exception payloads

`_probe`, readiness and shared database-health failure paths returned raw driver
exception strings. A synthetic connection URL/password/SQL canary appeared in
public error details or selected role/tenant/database failure tracebacks. Database
engine construction also occurred outside the health helper's catch boundary.

Only synthetic canaries and keys are used; no real credentials were supplied or
published. This is not a claim that every exception/log path in the product has
been audited or scrubbed.

## 2. Bounded correction

- Unavailable role storage raises **503** with a fixed safe message, not empty
  roles, stale token authority or an implicit admin fallback.
- Disabled/deleted and missing production identities refuse with **403**, not an
  ambiguous empty role list that a legacy caller might treat as privilege. The
  scope projection supplies no platform roles for those identities. Only an
  affirmative absent-row non-production compatibility case remains supported;
  no new authentication mode is introduced.
- Selected role, provisioning, tenant-scope and database-health failure logs retain
  stable event names and `error_type`, not raw exception text/SQL/tracebacks.
- Public dependency failures retain down/degraded status and safe categories;
  database readiness still returns 503 and liveness remains independent of it.
- Shared database-health construction/connect failures are caught and marked
  unhealthy. Existing readiness timeout, migration-head and production dependency
  requirements are not relaxed.
- The existing probe contract test is updated to assert the intentional safe
  diagnostic contract, not continued exposure of a sample exception message.

Operators should use the safe failure category, current service telemetry and an
approved restricted diagnostic procedure. Do not re-enable raw connection/SQL
exception dumping or bypass authorization to restore a green health view.

## 3. Executed evidence

Environment: Python **3.11.2**, locked venv at
`/home/user/docs-refresh-venv`; Node **22.22.3** / npm **10.9.8** for the accumulated
frontend validation. Synthetic SQLite/mock/network-free dependency faults are
not PostgreSQL/TLS/HA/escape/assessor/site qualification.

| Stage | Actual result | Meaning |
|---|---|---|
| Selected unchanged multi-user/RBAC/dependency-health/controlled baseline | **27 passed**, 4 warnings, **5.89 s** | Existing baseline before these changes. |
| Expanded adverse/compatibility set before correction | **31 failed / 5 passed**, 4 warnings, **1.33 s** | 36 cases; expected red reproduction, no waived failures. |
| Initial corrected set plus selected baseline | **63 passed**, 4 warnings, **5.73 s** pytest execution | Overlaps the baseline; process shutdown also waits for an existing synthetic hanging-probe thread. |
| Expanded new regression set, including four real-session HTTP safety cases | **40 passed**, 4 warnings, **6.23 s** | Before the final helper guard review; overlaps later runs. |
| Final new regression set after explicit 403 helper guard review | **40 passed**, 4 warnings, **4.49 s** | 29 authority/scope cases and 11 health/privacy cases; explicitly asserts direct helper refusal so legacy callers cannot misread disabled/missing-production identity as empty roles. |

The 40 cases distinguish unavailable from affirmatively absent storage, deny
stale/disabled/deleted role authority, retain non-production compatibility,
assert no guarded write, test safe logging and exercise anonymous root/API probe
paths with constructor/connect failures.

Final broader checks for publishing the accumulated changes:

| Check | Actual result | Boundary |
|---|---|---|
| API/auth/account/RBAC/key/security, exact-estate/history/SSE/queue, assurance, six-BOM and inventory contracts | **641 passed**, 12 warnings, **317.40 s** | Selected suites; zero failed/skipped/deselected in this run. Not every repository test or a live bank. |
| Shared-model/full-CBOM/selected-SBOM, operator package/signature, guarded 0105 migration and production database gate | **1,146 passed / 1 skipped**, 26 warnings, **10.60 s** | Existing PostgreSQL fixture skip: `test_disposable_postgres_requires_migrations_and_never_reconciles` requires `pg_virtualenv` and explicit disposable-PG opt-in. Not a passed/waived live-PG test. |
| Full frontend Vitest | **398 passed / 45 files**, **126.99 s** | DOM/mock tests, not real bank-browser/network traces. |
| Existing frontend toolchain | **7 passed**, **1.45 s** | Includes remote-bootstrap/CSP contract tests and loopback smoke, not live nginx. |
| Frontend typecheck and production bundle | Passed; **1.45 s** bundle build phase | Local TypeScript/Vite, not image registry/package signing or site deployment. |

Warnings retain existing Pydantic Config, cloud/network field-shadowing,
Starlette/httpx and HTTP-422 deprecations, three existing asyncio-marker warnings,
and Alembic path-separator warnings. They were not hidden to obtain these results.

Local logs and JUnit use `/home/user/quality-authority-*` and
`/home/user/quality-final-*` outside Git. They are engineering records, not
externally signed customer evidence. Counts overlap across runs and must not be
summed into a readiness percentage. Original failure evidence is retained.

### Reproduction

Run only in an isolated test environment:

```bash
export PYTHONPATH="$PWD/services/api/tests/unit:$(find "$PWD/services" "$PWD/shared" -mindepth 1 -maxdepth 1 -type d | tr '\n' ':')"
export ENVIRONMENT=test
python -m pytest -q -p no:xdist \
  services/api/tests/unit/test_authorization_dependency_failure.py \
  services/api/tests/unit/test_health_failure_privacy.py \
  services/api/tests/unit/test_dependency_health.py \
  services/api/tests/unit/test_multiuser_auth.py \
  services/api/tests/unit/test_rbac_roles.py \
  services/api/tests/unit/test_assurance_controlled_boundary.py
```

Executed commands use the explicit locked venv interpreter and existing synthetic
test secret settings; no real secrets are stored here. Tests are in existing
collected test roots; no Actions lane was edited or disabled to obtain a result.

### Source identities and documentation checks

These identify the final work-tree source being published, not signed release
images or external attestations. Earlier dated records retain their own source
identities and original results.

```text
services/api/api/dependencies.py
cd1a8aa32cd257a6df86f7541cd6612791f08ad18072aa0ad88e409cdf8a6a64
services/api/api/routers/health.py
1065083474dfebaaddd7115398381c3bbe1f29cef40d2708eafc6bdaefa3c104
services/database/db/connection/engine.py
66e9e1de08ced3bfc05e017b497896fa1e0f1c1dc7c9186bcb5106a685b3fa4a
services/api/tests/unit/test_authorization_dependency_failure.py
b6820f39ecb6e48d0225685dc3d066b0a6914780bb6e56327fe8bb59aef484f4
services/api/tests/unit/test_health_failure_privacy.py
0ffaa530b41e2ea4dcfe658fe60f033a6e44b313a4e80607c359bce5062a4061
services/api/tests/unit/test_dependency_health.py
181e987612528c9e399ce1ce0a94a650f9f48ecef1ffe637b47646f54e1216f0
```

Final Python lint: `ruff check services scripts shared` passed. Locked Python
`pip check` reports no broken requirements. Documentation checks cover **490
Markdown / 1,771 local links**, zero missing relative targets or unresolved heading
anchors; 48 external links were not fetched. **14 changed Markdown files / 8 labeled
shell examples** pass fence/shell syntax checks. `git diff --check` passes. No
example's mutating deployment command is executed. The `docs/` inventory is
455 files / 385 Markdown. Workflow files and dependency locks remain unchanged.

## 4. Compatibility, publication and open acceptance

- Authority-store failures may now surface as 503 instead of a legacy empty-role
  result. Missing production users and current disabled/deleted identities do not
  gain roles from old token claims or compatibility handling. Production must
  retain actual current durable identities, sessions and memberships.
- Health failure detail strings intentionally stop returning raw exceptions.
  Consumers should use existing status/down checks and safe error category, not
  parse driver messages. No new monitoring endpoint or dashboard is introduced.
- These tests do not qualify a real PostgreSQL/Redis outage, certificate/ACL
  failure, restore/RPO, dependency isolation or all races/logging paths.
- All six BOM meanings, exact-estate evidence/CAS/history and controlled adapter
  refusals remain unchanged. Schema head stays 0105.
- Rebuild/review externally signed coordinated images/full package before an
  authorized site rollout. A source push does not update bank deployments.
- Independent security/domain review, actual operator/recovery/browser/site
  evidence and customer acceptance remain open. No SLA, readiness percentage,
  certificate or production approval is granted by these changes.
