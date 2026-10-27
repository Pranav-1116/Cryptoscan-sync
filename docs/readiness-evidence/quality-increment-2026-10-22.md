# First quality-only implementation increment — 2026-10-22 UTC

## Scope and evidence provenance

Starting commit: **69faec96adad43848950c74c4c939151ef7b93d1**, branch
`arena/bb4b80dd-cryproscan`. Results below apply to the working-tree changes in
this increment, not a clean published release or a bank-site qualification.

Environment: Python **3.11.2**, Node **22.22.3**, npm **10.9.8**; Python dependencies
installed under `/home/user/docs-refresh-venv` with committed constraints;
frontend installed with `npm ci --no-audit --no-fund`. No dependency lock change.

Constraint identities:

```text
requirements.lock.txt
1b935cfe5230ea6f37affaab45044617ce402ecd1037f4c62b22404da4cedf2b
frontend/package-lock.json
94e58e21705e304238037cd7569bd6332fc9f73ae8d17a3b37ab205880fa839b
```

The quality scope is existing local-source coverage and existing frontend bootstrap.
All six BOM contracts, current-estate authority, original observation history,
production adapter refusals and schema head **0105** remain unchanged. No new
collector, page, service, deployment profile or production permission is introduced.

## 1. Reproduced source coverage defect

Before the correction, `coverage.record` required only a truthy
`file_observation_receipts` value after limited completion checks. Authenticated
synthetic tests demonstrated that `[{}]`, false/missing parser completion,
invalid checksums, ambiguous file identity and incoherent job/scan intervals
could establish OBSERVED coverage. Current reads also retained OBSERVED counts
after the backing job/scan/evidence became invalid.

Initial new adverse regressions against unchanged implementation:
**25 failed / 1 passed**, 4 warnings, **8.28 s**. Failures were expected assertions
showing the defect, not waived test failures. The positive partial-coverage case
already passed. Seven additional malformed/bounded-query regressions were added
later; they are not falsely described as part of the initial red run.

Correction:

- Validate a bounded primary-file list with unique relative file identities,
  valid lowercase SHA-256, typed parser outcomes and at least one completed parser.
- Require exact completed job/scan/target binding and coherent nonfuture observation
  intervals. Missing actual start/end cannot be filled from submission time.
- Revalidate current source evidence on read using exact-estate batched SQL lookups.
  Missing/invalidated proof returns 409, including dependent operator summaries,
  instead of returning stale green counts or manufacturing empty success.
- Preserve all immutable revisions/hashes and scope limitations. Partial primary
  source evidence does not become complete source coverage or whole-bank safety.
- Keep proof lookup bounded: ten valid source targets use **two** job/scan proof
  queries in the fixture, rather than a per-target lookup chain. This measures query
  shape only, not PostgreSQL latency/capacity.

## 2. Reproduced on-prem frontend bootstrap issue

The entry HTML requested Google Fonts and preconnected externally; the runtime
nginx CSP allowed the font and stylesheet origins. Two new existing-toolchain
contract checks failed against the unchanged frontend.

Correction removes those remote entrypoint references and CSP allowances while
retaining existing local/system font fallback stacks. Both adverse contracts then
passed. Full frontend results below are separate from this two-test focused run.

This is **not** a network capture or a claim that all application/runtime behavior
is offline. No real bank browser, RTL layout/zoom acceptance, nginx container,
actual CSP enforcement or site egress firewall was exercised. Rebuild/verify the
intended frontend image/package; an already deployed older image is unaffected.

## 3. Executed validation

Counts overlap; do not sum baseline, focused, related and full-frontend results
into a product-readiness percentage.

| Check | Actual result | Boundary |
|---|---|---|
| Existing assurance/operator/controlled-boundary baseline, before fixes | **57 passed**, 4 warnings, 29.58 s | Authenticated synthetic SQLite; selected baseline only. |
| Initial source adverse regressions, before fix | **25 failed / 1 passed**, 4 warnings, 8.28 s | Expected red reproduction; not a green test run. |
| Initial fixed source/assurance/operator/controlled/launch set | **124 passed**, 4 warnings, 83.58 s | Intermediate overlapping acceptance, before seven additional regression cases. |
| Final source/assurance/operator/controlled/launch/readiness/Redis-client/software-supply-chain/SSH-contract set | **194 passed**, 4 warnings, 109.93 s | Includes **33** new source receipt/current-read/bounded-query regressions. Synthetic SQLite/mocked collectors, not live collection/site tests. |
| Remote bootstrap/CSP contract reproduction | **2 failed** before correction; **2 passed** after | Static source/DOM/config inspection, no network access or live nginx. |
| Frontend typecheck | Passed | TypeScript compiler only. |
| Complete frontend Vitest suite | **398 passed / 45 files**, 124.75 s | DOM/mock tests, not real-browser endurance. |
| Production frontend bundle | Passed, 1.24 s build phase | Local Vite output, not a Docker/registry/site build. |
| Existing toolchain suite plus two new contracts | **7 passed**, no skips, 1.37 s | Includes loopback dev-server smoke; not a public deployment. |
| Operator package/signature and guarded 0105 migration regressions | **24 passed**, 11 warnings, 3.17 s | Local package fixtures/SQLite migration; not image signing/publication or a live PostgreSQL/site upgrade. |

Existing warnings concern deprecated Pydantic Config, cloud/network `register`
field shadowing and the Starlette/httpx test client. They are retained, not
suppressed by this change. The package/migration run also retains existing Alembic
path-separator deprecation warnings. Documentation/lint checks are recorded below.

Additional local checks:

- `ruff check services scripts shared`: passed.
- `python -m pip check` in the locked Python environment: no broken requirements.
- Built artifact inspection: seven same-origin entry HTML asset references,
  embedded favicon, no external preconnect/DNS hint, one built stylesheet without
  remote imports/URLs. Static inspection only, not a browser network capture.
- Documentation: **488 Markdown / 1,752 local links**, zero missing relative targets
  or unresolved heading anchors; 48 external links not fetched. **9 changed Markdown
  files**, **6 labeled shell examples** syntax checked, no errors. No mutating
  example command executed.
- `git diff --check`: passed; no workflow or dependency lock changes.

### Reproduction commands

Run in an isolated test environment, not against a bank/customer database:

```bash
export PYTHONPATH="$PWD/services/api/tests/unit:$(find "$PWD/services" "$PWD/shared" -mindepth 1 -maxdepth 1 -type d | tr '\n' ':')"
export ENVIRONMENT=test
python -m pytest -q -p no:xdist \
  services/api/tests/unit/test_coverage_receipt_integrity.py \
  services/api/tests/unit/test_assurance_workflows.py \
  services/api/tests/unit/test_operator_decisions.py \
  services/api/tests/unit/test_assurance_controlled_boundary.py \
  services/api/tests/unit/test_launch_readiness.py \
  services/api/tests/unit/test_readiness_assurance.py \
  services/api/tests/unit/test_assurance_redis_clients.py \
  services/api/tests/unit/test_software_supply_chain_api.py \
  services/api/tests/unit/test_ssh_receipt_contract.py
```

The executed Python command used the explicit locked venv interpreter and the
existing synthetic test secret settings; no real credentials were supplied.
Frontend sequence: `npm run typecheck`, `npm test`, `npm run build`, then
`npm run test:toolchain`. The new coverage test is under the already discovered
API test root; the frontend regressions are in the already invoked toolchain file.
No workflow definition was changed to obtain those executions.

Local raw diagnostics/JUnit are outside the repository under
`/home/user/quality-*`; they are sandbox engineering records, not independently
signed bank evidence. The before/after counts above are retained here for review.

### Source identities for this engineering increment

These identify the work-tree source being reviewed, not signed release image
digests or external attestations.

```text
services/api/api/assurance/coverage.py
fa79182fe4707b75ab56af64dab9dd6a36f03452cdbcb7051e8a3df33fbe202e
services/api/tests/unit/test_coverage_receipt_integrity.py
c057a0a51d08d2ed98eb195abde859fd6e2903b18dc7d346cbec02c0835c9915
frontend/index.html
268c9c2b023333e307f45d8cd76ddb2e083e612c2503d1187be7e53d7afaa5f3
frontend/scripts/toolchain.test.mjs
ebba54974eb5817cdbce4a08c281e32e45064cd9e94734fb26b2df6beca29c1b
.docker/frontend/nginx.conf
dcd646c53770604cc144b0354b1ff44dc9d31985d0ab10ec342894620c294795
```

## 4. Deployment, review and remaining acceptance

Current source reports may now return **409** for previously accepted legacy or
invalidated source observations. Retained history is still readable. Obtain a
new actual eligible source observation under current authorization; do not edit
old receipts, truncate history, bypass scope checks or reset job states.

Build new reviewed API/frontend images and the full signed operator package
before site promotion. No schema migration or customer deployment was executed.
Actual PostgreSQL contention/fault/restore, browser/no-egress/accessibility,
independent security, human operating exercises and customer acceptance remain open.
No different human reviewer or real site approval is fabricated by the agent's tests.

The earlier user-reported remaining CI failure stays outside this change. No
Actions run/check verdict is independently confirmed, no CI is dispatched, and
no failing lane is waived. No production-readiness gate, SLA, certification or
bank-ready percentage is changed.

Progress and the next bounded work are tracked in
[implementation status](../product-improvement/IMPLEMENTATION-STATUS.md).
