# Sixth quality increment: current-trace integrity and freshness — 2026-10-23 UTC

## 1. Selection, scope and starting source

This continues [guides 2/3](../product-improvement/README.md) and the
[quality-only ledger](../product-improvement/IMPLEMENTATION-STATUS.md): improve
existing answers before expanding feature breadth. Starting clean Git HEAD and
remote were `9f3fa5a9e873aa8f0cd44e2d16996a32154860a2` on
`arena/bb4b80dd-cryproscan`. PR [#34](https://github.com/ZKChainForge/CryproScan/pull/34)
was open. The containing Git commit and PR publication comment identify the
pushed increment; hashes below identify tested source without a self-referential
commit field. Publication uses `[skip ci]`, not a workflow edit or main merge.

Only the existing relationship service changes in production code. There is one
new regression module plus documentation. No new collector, BOM, route, service,
profile, migration, lock, binary, deployment or architecture is introduced.
SBOM, CBOM, NBOM, TechBOM, HBOM and VBOM retain separate evidence requirements;
this specifically strengthens the application/release/SBOM/package/crypto trace
and shared relationship-review freshness, not the complete six-BOM matrix.

Environment: Python **3.11.2**, pytest **9.1.1**, Ruff **0.16.5**, existing
requirements/lock and `/home/user/recovery-venv`. API tests use authenticated
synthetic typed human sessions, exact estate selection, real SQLite ORM/SQL,
FastAPI middleware, a local document store and synthetic CycloneDX/observations.
No bank data, actual deployment observation or production identity is involved.

## 2. Defects reproduced before final correction

### Loaded revision integrity was not checked by trace

The ordinary assurance latest/history/public helpers verify revision envelopes.
The application trace instead queried bounded revisions directly, selected the
latest per subject and projected a reviewed path/hash without `store.verify`.
Test-only storage faults therefore left eligible paths for modified payloads,
digest, actor, previous hash, revision or subject ID. A corrupt loaded predecessor
also went undetected when the latest envelope itself still verified. A proposal
with its stored state changed to REVIEWED could produce a reviewed-looking path
without a genuine second revision.

**Fault boundary:** these tests deliberately use SQLAlchemy Core UPDATE to bypass
the unchanged append-only ORM guard. They model corrupt/unauthorized storage,
not an authenticated API write bypass or a demonstrated outside exploit. They
do not show protection against an administrator recomputing a consistent chain.

### Only the upper freshness bound was rechecked

Creation already required `observed_at <= now < expires_at`. Review and trace
only rechecked expiry. After a synthetic clock rollback to one second before the
stored observation, review still approved it and a reviewed trace still included
it. The clock is patched only in the relationship service; auth/session time is
not patched. This tests eligibility under clock correction, not actual site NTP,
restored PostgreSQL or customer-provided observation truth.

### Actual adverse sequence

- Existing baseline: **85 passed**, 4 warnings, **57.75 s** across assurance
  workflows, package identity, software supply-chain and relationship lifecycle.
- Initial 22-case probe: **12 failed / 10 passed**, **20.57 s**; one failure was a
  test helper argument collision on `revision`, not a product defect. A first
  provisional combined run consequently had **106 passed / 1 helper failure**,
  **79.26 s**. Neither is represented as a green acceptance run.
- Rename the helper selector argument, then rerun all 22 against the exact
  unchanged baseline `relationships.py`: **12 failed / 10 passed**, 4 warnings,
  **20.68 s**. All failures now reach product assertions. Baseline source was
  compared with `git show` and corrected source restored in `finally`, checked
  byte-for-byte. This corrected red run is the defect reproduction of record.
- Final broad API run below: all **22 new cases pass**, alongside the original
  baseline and other selected integration/compatibility cases.

## 3. Minimal correction and preserved contracts

1. Call the existing `store.verify` on every loaded relationship revision before
   it contributes to newest-revision selection. This includes loaded predecessors
   and happens before reading review/trust fields or projecting a returned path.
   Integrity failure propagates as the existing safe **409** category; it is not
   swallowed as an ordinary missing edge or returned as a partial green trace.
2. Reuse a small current-window predicate at review and trace:
   **`observed_at <= now < expires_at`**. Observation equality is eligible;
   expiry equality is not. Ineligible review returns 409 without appending;
   current trace leaves the component unresolved without changing history.
3. Preserve exact-estate queries/foreign application 404, current human review,
   optimistic concurrency, typed endpoints, active binding/deployment/evidence
   checks, original evidence and append-only guards. No read silently repairs
   corruption. Existing query/history/path budgets remain unchanged.
4. Preserve `CUSTOMER_REVIEWED_ASSERTION_NOT_INDEPENDENT_RUNTIME_PROOF` and
   `deployed_verified=False`, `invocation_verified=False`, `runtime_verified=False`.
   Valid envelope bytes and customer review do not prove an independent fact.

Hash checks apply to envelopes actually loaded by the existing scoped/bounded
query. This is **not full-chain/database completeness verification**, predecessor
existence/link traversal, detection of deleted/filtered-away rows, rollback
prevention, external anchoring, or cryptographic protection against an authorized
administrator rewriting consistent history. No such guarantee is added here.

## 4. New regression matrix — 22 cases

| Area | Cases | Required result |
|---|---:|---|
| Latest reviewed envelope faults | 6 | Payload, digest, actor, previous hash, revision and subject ID corruption each refuse trace with 409; no payload canary or read-side repair. |
| Loaded predecessor faults | 2 | Modified old state/evidence reference refuses even when the latest envelope verifies. |
| Storage-forged review state | 1 | Modified PROPOSED payload cannot become a positive reviewed trace. |
| Current-trace clock boundaries | 4 | Before observed time unresolved; observed equality eligible; just before expiry eligible; expiry equality unresolved. |
| Review clock boundaries | 4 | Same boundary semantics; refusal appends no revision. |
| Current upstream lifecycle | 4 | Actual lifecycle API marks deployment/binding STALE; normal ORM fixtures tombstone object/supporting observations. No eligible path; assurance history unchanged. |
| Intact path and scoped corruption privacy | 1 | Exact relationship/hash and false runtime flags remain; foreign/unselected platform reads 404; other estate's own application stays unaffected; selected owner/admin refuses corruption. |

The four upstream cases are preservation controls, not newly discovered lifecycle
defects. Tombstones use a normal ORM fixture, not a claimed production deletion
endpoint. Canary assertions cover these public responses, not every log/traceback.

## 5. Final executed local checks

| Check | Actual result | Scope |
|---|---|---|
| Selected API/assurance/coverage/six-BOM/operator/evidence/graph checks, 24 files | **452 passed**, 6 warnings, **253.61 s** | Includes all 22 new cases and all 85 baseline cases; authenticated synthetic SQLite/local/mock fixtures. |
| Separate authorization compatibility, 9 files | **113 passed**, 10 warnings, **31.48 s** | Current account/session/roles/API keys and selected refusal/privacy compatibility. |
| Shared models, all CBOM, selected identity/SBOM/gate and assurance migration checks | **1,114 passed**, 10 warnings, **17.69 s** | Library/local/mock and SQLite migration exercise, not a PostgreSQL round trip. |
| `ruff check services scripts shared` | Passed | Existing configured F/E9 rule set, not a new style baseline. |
| `python -m pip check` | Passed | Installed dependency consistency, not a fresh reproducible production build. |
| Documentation links/anchors, changed fenced-shell syntax, source hashes and whitespace | Passed | Local-only validation; external links not fetched. |

These three final test runs have **zero failures, skips or deselections**. New
cases overlap the 452 total; do not add baseline/adverse/subset counts. Prior
recovery/parser results remain historical, not reruns for this increment. Existing
warnings remain Pydantic Config deprecations, network/cloud field shadowing,
Starlette/httpx and HTTP 422 deprecations, and Alembic path-separator configuration.
The local documentation validator checked **494 Markdown files / 1,844 local
links**, with **8 changed Markdown files / 1 shell block / 33 retained source
hash values** and zero errors. **55 external links were not fetched**. The 33
hash values include 21 from the preserved recovery/parser records and 12 here;
overlapping historical input hashes are not distinct files or test cases.

No all-repository, frontend/browser, Actions or independent assessment verdict is
inferred. No workflow was edited or explicitly dispatched; `[skip ci]` publication
is not a claim that GitHub ran or passed required checks.

## 6. Reproduction and local artifacts

Use synthetic test settings and existing dependency inputs, never bank credentials.
From repository root, exact final selections were:

```bash
export PYTHONPATH="$PWD/services/api/tests/unit:$(find "$PWD/services" "$PWD/shared" -mindepth 1 -maxdepth 1 -type d | tr '\n' ':')"
export ENVIRONMENT=test
export SECRET_KEY=test-secret-key-for-sessions-min-32-chars
export GITHUB_WEBHOOK_SECRET=test-webhook-secret-abc123
PYTHON=/home/user/recovery-venv/bin/python

"$PYTHON" -m pytest -q -p no:xdist \
  services/api/tests/unit/test_relationship_trace_integrity.py \
  services/api/tests/unit/test_assurance_workflows.py \
  services/api/tests/unit/test_package_identity_integrity.py \
  services/api/tests/unit/test_software_supply_chain_api.py \
  services/api/tests/unit/test_relationship_lifecycle_api.py \
  services/api/tests/unit/test_assurance_controlled_boundary.py \
  services/api/tests/unit/test_assurance_redis_clients.py \
  services/api/tests/unit/test_coverage_receipt_integrity.py \
  services/api/tests/unit/test_launch_readiness.py \
  services/api/tests/unit/test_operator_decisions.py \
  services/api/tests/unit/test_operator_profile.py \
  services/api/tests/unit/test_readiness_assurance.py \
  services/api/tests/unit/test_ssh_receipt_contract.py \
  services/api/tests/unit/test_technology_bom_endpoints.py \
  services/api/tests/unit/test_sbom_scan_api.py \
  services/api/tests/unit/test_hardware_live_api.py \
  services/api/tests/unit/test_vendor_api_scan.py \
  services/api/tests/unit/test_vendor_profile_api.py \
  services/api/tests/unit/test_network_collection_contract.py \
  services/api/tests/unit/test_cbom_enterprise_endpoints.py \
  services/api/tests/unit/test_cbom_snapshots.py \
  services/api/tests/unit/test_evidence_soft_delete.py \
  services/api/tests/unit/test_evidence_disposition.py \
  services/api/tests/unit/test_graph_edge_provenance_api.py

"$PYTHON" -m pytest -q -p no:xdist \
  services/api/tests/unit/test_auth_account_lifecycle.py \
  services/api/tests/unit/test_auth_lifecycle.py \
  services/api/tests/unit/test_authorization_dependency_failure.py \
  services/api/tests/unit/test_custom_roles.py \
  services/api/tests/unit/test_multiuser_auth.py \
  services/api/tests/unit/test_rbac_roles.py \
  services/api/tests/unit/test_api_keys.py \
  services/api/tests/unit/test_production_hardening.py \
  services/api/tests/unit/test_health_failure_privacy.py

"$PYTHON" -m pytest -q -p no:xdist \
  shared/shared_models/tests \
  services/cbom/tests \
  services/devsecops/tests/test_software_identity.py \
  services/devsecops/tests/test_sbom_assurance.py \
  services/devsecops/tests/test_sbom_lockfiles.py \
  services/devsecops/tests/test_sbom_scan.py \
  services/devsecops/tests/test_sbom_gate_cli.py \
  services/database/tests/unit/test_assurance_migration.py

/home/user/recovery-venv/bin/ruff check services scripts shared
"$PYTHON" -m pip check
```

The original baseline command selected the four existing modules named in section
2. The corrected red command selected only
`services/api/tests/unit/test_relationship_trace_integrity.py` with baseline
relationship implementation; do not overwrite a production or current checkout
to reproduce a storage fault. Use an isolated disposable review environment.

Local artifacts outside Git are not a bank-controlled retained evidence store:

- `/home/user/trace-baseline.log` and `.xml`;
- `/home/user/trace-red.log` and `.xml` (initial helper collision);
- `/home/user/trace-green.log` and `.xml` (provisional combined helper failure);
- `/home/user/trace-red-corrected.log` and `.xml` (corrected adverse reproduction);
- `/home/user/trace-api-final.log` and `.xml`;
- `/home/user/trace-auth-final.log` and `.xml`;
- `/home/user/trace-library-final.log` and `.xml`;
- `/home/user/trace-doc-validation.json` (final local validator output).

## 7. Tested source/input SHA-256 identities

The first two are changed implementation/test files. The remaining unchanged
inputs identify the verifier, API boundary, model, identity helper, reused fixtures
and dependencies; this inventory is not a signed build manifest.

```text
services/api/api/assurance/relationships.py
b857c02dba9ba18e1d5ed2c2131c7baa576a13c9f3806af124baad6f5682dbd6

services/api/tests/unit/test_relationship_trace_integrity.py
d74b64f6ef3d6f83302b78aaa0c708557dbaaea78028bc9939532d72fa846a9e

services/api/api/assurance/store.py
f52099078db198750e76ed5a4d78d4e5f8ff5ec03d32138df664c900b74d423f

services/api/api/routers/assurance.py
415b8413a8b42877c2654ad85d058ecc4346dcd86a7f496f5b0e9c1aedf18b95

services/database/db/models/assurance.py
360bd3ab97c37a26f38956bd21077451583b7ecccea828a100c1207e47bc98b0

shared/shared_models/shared_models/software_identity.py
7a574301479197f5f2ee336736fecef1e33262b285251fede5bfbb74e3456401

services/api/tests/unit/test_assurance_workflows.py
43b6ec4211cdf9b0d767aad0e0f9a9627ef4aefd3847fbd39e2221dd01cedb7b

services/api/tests/unit/test_package_identity_integrity.py
c7cd6b4343e86890129f49b82e42fa2e90600698d212497fd9dcc27c8202ff32

services/api/tests/unit/test_software_supply_chain_api.py
e71f214adbce82437c60ba6dcc972125b94f2addae33c1af160e472fb06df0e3

services/api/tests/unit/test_relationship_lifecycle_api.py
29edbcbfa0272a84334a584566d9a4d860c5336d561fd7e665fd1fbad3087985

requirements.txt
15c2c7d4ceacf2bde509b4bf5ac635923cc470986d13047a3cdc42a8214c8bb1

requirements.lock.txt
1b935cfe5230ea6f37affaab45044617ce402ecd1037f4c62b22404da4cedf2b
```

## 8. Publication, operation and remaining acceptance

All implementation/test/documentation changes are published together on the
existing PR branch with `[skip ci]`. This is source publication, not a signed
release, installed customer upgrade or bank approval. Use the
[current operator handoff](../runbooks/evidence-assurance-upgrade.md#current-trace-integrity-source-handoff-2026-10-23)
for the new refusal categories and safe response. Preserve suspect evidence and
restricted diagnostics; never rewrite hashes/history, backdate observations,
override the clock or resurrect stale edges to recover a green path.

Still open: different-human code/security review; actual PostgreSQL isolation,
concurrency and restore qualification; signed coordinated package and site
installation/recovery exercises; representative browser/capacity measurements;
production time synchronization and storage grants/backup/incident controls;
remaining six-BOM wrong-build/estate/stale/partial matrices; independent security
assessment and distinct customer acceptance. No 24/7 staffing, SLA, production
uptime, complete bank coverage, zero egress or independent runtime truth is
established by these local tests.
