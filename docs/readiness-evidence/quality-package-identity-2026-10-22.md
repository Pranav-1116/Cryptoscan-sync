# Second quality increment: unresolved package identities — 2026-10-22 UTC

## Scope and starting state

This continues the [quality-only implementation ledger](../product-improvement/IMPLEMENTATION-STATUS.md),
after the [first increment](quality-increment-2026-10-22.md). Starting Git HEAD
remains `69faec96adad43848950c74c4c939151ef7b93d1` on
`arena/bb4b80dd-cryproscan`, with the first increment's **uncommitted** working-tree
changes retained. This is not a new published release or a clean baseline commit.

The next work package is Q01/Q02, roadmap B1/B2/B4: check existing exact package
identity through SBOM → artifact/deployment → reviewed crypto assertion. It does
not add BOM types, collectors, APIs, profiles, range resolution or new predicates.
All six BOMs retain distinct evidence burdens; this patch does not claim to
complete the whole six-BOM negative matrix.

Environment remains Python 3.11.2 with the locked venv at
`/home/user/docs-refresh-venv`; test fixtures use authenticated synthetic users,
SQLite, redacted source fixtures and synthetic signing keys. No customer data,
real collector, bank browser, live PostgreSQL or production authority is used.
Dependency locks and workflows remain unchanged.

## 1. Demonstrated defect

The existing `package_identity` helper rejected missing versions and several
ranges, but accepted known unresolved forms after PURL decoding:

- `${crypto.version}`, `$cryptoVersion`, `@VERSION@`;
- variables embedded in `${revision}-SNAPSHOT` or `1.0-${buildNumber}`;
- wildcard segments `1.x` / `1.2.X`;
- interval syntax `[1.0,2.0)` / `(,1.5]`.

Before correction, these could produce `unresolved_component_count=0`, eligible
package cascade matches and reviewed PACKAGE_CRYPTO trace paths. A different
human's review did not resolve the missing actual package version. Previously
stored derived identities also remained eligible on current reads.

Existing selected baseline before this change: **136 passed**, 4 warnings,
**38.29 s**. New initial regression set against unchanged identity implementation:
**29 failed / 6 passed / 39 deselected**, 4 warnings, **7.28 s**. These are actual
adverse assertions, not infrastructure failures or waived checks.

A further paired check exposed a consistency problem in the provisional fix:
three legacy artifact cascade cases displayed an unknown package identity while
still displaying an old zero unresolved count. That targeted run had **3 failed /
21 deselected**, **0.27 s**. The current derived cascade projection now recomputes
both identity and unresolved count without editing the captured snapshot.

## 2. Bounded correction

1. Decode the existing version-bearing PURL before testing known unresolved
   variable, wildcard-segment and interval forms. Return unknown, never guess a
   replacement version or expand a range.
2. The existing CycloneDX/SPDX normalizer and import/binding routes consume the
   corrected helper, retain raw metadata and count these components unresolved.
3. Re-evaluate persisted derived package identities when validating/reviewing
   PACKAGE_CRYPTO assertions and producing current application traces. Legacy
   proposals cannot be newly approved from unresolved identities; old reviewed
   assertions remain historical but cannot supply current exact-package paths.
4. Current cascade projections clear ineligible derived identity/count claims,
   retaining original PURL/version and explicit artifact/deployment evidence.
   Captured snapshots and retained run results are not mutated or backfilled.
5. The existing signed supplier package validator uses the same identity helper.
   A valid origin signature over an unresolved package fact stays origin-verified
   but quarantined as MALFORMED; it is not independently true or auto-joined.

Concrete labels, encoded local-version `+`, scoped package names, qualifiers and
exact case remain supported. A literal version label such as Maven SNAPSHOT is
not itself an immutable artifact digest; declared-versus-measured artifact and
runtime limitations remain unchanged. This is a conservative coordinate check,
not full Package URL conformance or a new ecosystem/version-range engine.

## 3. Executed local validation

Initial focused acceptance after the helper/current-read fix: **35 passed /
39 deselected**, 4 warnings, **8.62 s**. After the paired unresolved-count correction
and three added signed-supplier safety regressions, the focused set is
**38 passed / 39 deselected**, 4 warnings, **10.63 s**.

The 38 added cases comprise:

| Area | New cases | Assertion |
|---|---:|---|
| Shared exact identity | 13 | Nine unresolved forms refuse, four concrete/encoded/scoped/qualified cases remain eligible. |
| CycloneDX/SPDX normalization | 8 | Six unresolved cases preserve original document/version; two concrete cases remain resolved. |
| Legacy cascade projection | 6 | Invalid package target cannot seed exposure; artifact/deployment remains visible with unknown package and corrected count. |
| Authenticated SBOM/current-trace/legacy-review | 8 | Six import/binding cases remain unresolved; two pre-upgrade histories cannot supply current exact paths or new approval. History and estate isolation remain intact. |
| Signed supplier safety | 3 | Valid signature does not resolve variable/range package facts; quarantine/uncertainty retained. |

Broader executed checks:

| Check | Result | Boundary |
|---|---|---|
| All shared-model tests, all CBOM tests, selected software-identity/SBOM assurance/lockfile/scan/gate tests | **1,113 passed**, 4 warnings, **10.64 s** | Synthetic pure-library/local/mock checks, not all repository tests or live collectors. |
| Package/coverage integrity, assurance, operator, controlled boundary, launch/readiness/Redis-client, software supply chain, SSH contracts, TechBOM/SBOM/HBOM/VBOM APIs | **256 passed**, 4 warnings, **155.61 s** | Authenticated fixtures and SQLite/mock inputs; includes first increment's coverage regressions. |
| `ruff check services scripts shared` | Passed | Existing configured Python lint rules. |

Both broad runs have zero failed/skipped/deselected checks. Existing warnings
remain Pydantic Config deprecation, cloud/network `register` field shadowing and
the Starlette/httpx test client. Counts overlap across baseline, focused and
broader runs. Do not sum them into a readiness percentage or describe the focused
run's deselected checks as passed. Frontend/build/package/migration checks were
not rerun in this increment; earlier results retain their original provenance.

Local diagnostics/JUnit use `/home/user/quality-identity-*` outside Git. These are
engineering records, not independently signed customer/assessor evidence.

### Reproduction

Run in an isolated synthetic test environment, not a bank/customer database:

```bash
export PYTHONPATH="$PWD/services/api/tests/unit:$(find "$PWD/services" "$PWD/shared" -mindepth 1 -maxdepth 1 -type d | tr '\n' ':')"
export ENVIRONMENT=test
python -m pytest -q -p no:xdist \
  shared/shared_models/tests/test_software_identity.py \
  services/devsecops/tests/test_software_identity.py \
  services/cbom/tests/test_software_cascade.py \
  services/api/tests/unit/test_package_identity_integrity.py \
  -k 'quality_increment or unresolved_sbom_package or preupgrade_unresolved or signed_supplier_package'
```

Executed commands used the explicit locked venv interpreter and existing synthetic
test secret settings, never real credentials. New tests are under existing
collected test roots; no CI lane was added or skipped to obtain the result.

### Final source identities and documentation checks

These identify reviewed work-tree source, not signed images or external attestations.

```text
shared/shared_models/shared_models/software_identity.py
7a574301479197f5f2ee336736fecef1e33262b285251fede5bfbb74e3456401
services/api/api/assurance/relationships.py
b5f1d7c44bfeec0044d3951f70dcab9ffbebc9e6521fc6ac3fce802577e04feb
services/cbom/cbom/software_cascade.py
88405abc860fbef481b0bd04200944ac14228485164797b89053994a71f2f56e
shared/shared_models/tests/test_software_identity.py
045d12fe9a36fe6f92725c1cdf5a6e21cddf0dcb0b228b8ee317734e7bd77449
services/devsecops/tests/test_software_identity.py
557399a2e86df2927c9fd44e526401a74bb77b0c75d9722774bc263853ea987e
services/cbom/tests/test_software_cascade.py
756f7e10b95ae29d557d2da475926ad1e9cc22bfda764765efdca8409980e8b4
services/api/tests/unit/test_package_identity_integrity.py
c7cd6b4343e86890129f49b82e42fa2e90600698d212497fd9dcc27c8202ff32
```

Documentation validation after both increments: **489 Markdown / 1,762 local
links**, zero missing relative targets or unresolved heading anchors; 48 external
links were not fetched. **12 changed Markdown files / 7 labeled shell examples**
passed fence and shell-syntax checks. `git diff --check` passed. No example's
mutating command was executed. The inventory is 454 files / 384 Markdown in
`docs/`. Workflow definitions and Python/frontend dependency locks are unchanged.

## 4. Rollout and acceptance limitations

- Existing history, SBOM documents, raw stored projections and retained cascade
  run results are not rewritten. An old stored unresolved count may therefore
  remain in its original record; current cascade identity/count projections and
  current assurance traces apply the corrected identity rule.
- Recover an unresolved component using actual resolved build/SBOM input and
  authorized review. Do not patch historical SBOM rows or approval hashes to
  manufacture an exact version or green path.
- Changes to this helper change the existing offline supplier engine fingerprint.
  Previously exercised qualifications tied to the old engine are not current;
  re-exercise the approved exact offline profile. Do not edit qualification hashes
  or bypass NOT_QUALIFIED. This is not live vendor qualification.
- Current traces still keep `complete=false`, `runtime_verified=false`,
  `deployed_verified=false` and `invocation_verified=false`. Exact package
  coordinates and reviewed assertions do not prove runtime invocation.
- No migration is introduced; schema head remains 0105. Rebuild/review externally
  signed coordinated images/packages before any authorized site rollout.
- Actual PostgreSQL/browser/load/recovery, independent security/domain review,
  operator exercises and customer acceptance are still open. The earlier
  user-owned unspecified CI failure is neither changed nor waived. No workflow
  definition, Actions verdict, production deployment or publication is claimed.
