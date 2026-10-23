# Seventh quality increment: withdrawn source-remediation proof — 2026-10-23 UTC

## 1. Starting state and bounded selection

Starting HEAD/remote were `7e00d37e81540f343e7d94065cff054a5962dbe2`, clean on
`arena/bb4b80dd-cryproscan`; PR [#34](https://github.com/ZKChainForge/CryproScan/pull/34)
was open. Continue [guides 2/3](../product-improvement/README.md), roadmap B2/B3/B4:
existing evidence-to-remediation correctness, not feature breadth. The containing
commit/PR identifies publication; source hashes below bind the tested inputs.

Three existing assurance modules change: source remediation, operator projections
and the pilot's current-proof gate. One regression module is added. No new route,
BOM, collector, service, profile, architecture, migration, dependency lock,
workflow, binary or installed-site update. SBOM, CBOM, NBOM, TechBOM, HBOM and VBOM
retain separate evidence requirements; this does not complete their whole matrix.
TLS_CERTIFICATE collection/predicates are unchanged.

Environment: Python **3.11.2**, pytest **9.1.1**, Ruff **0.16.5**, existing dependency
inputs in `/home/user/recovery-venv`. Tests use actual typed session auth, tenant
middleware, SQLite ORM/SQL, local synthetic source observations/documents and
existing audited finding withdrawal/restore APIs. Assessor/supplier keys, endpoint
results, scans/jobs and people are synthetic fixtures, not external site evidence.

## 2. Defects actually reproduced

The source comparison loaded all observations, including tombstones, into its
snapshot. A retracted original could still seed a change; later withdrawal did
not invalidate approval/reporting. A withdrawn compliant replacement could still
supply VERIFIED. A stored VERIFIED proof remained current in the operator view
when one of its original/replacement observations was subsequently retracted.
Repeated verification could create another VERIFIED record from the withdrawn data.

The pilot status separately checked approval, proof hash/result and time but did
not recheck the source replacement's live membership. Following that caller
reproduced a missing `CURRENT_INDEPENDENT_REMEDIATION_PROOF_MISSING` issue after
withdrawal, even after the provisional operator/verification fix.

These are authorized retraction/current-consumption consistency defects, **not an
unauthorized write bypass**. All normal withdrawal/restore tests use the existing
selected-estate auditor API. The comparison-boundary case explicitly stamps a
normal ORM tombstone in one session via a controlled callback; it is not a real
concurrent PostgreSQL/production race drill.

### Actual diagnostic sequence

| Step | Observed result |
|---|---|
| Existing operator, assurance, evidence-soft-delete and remediation-task baseline | **68 passed**, 6 warnings, **31.67 s** |
| First 14 new adverse cases on unchanged implementation | **12 failed / 2 passed**, 4 warnings, **7.51 s** |
| Provisional combined fix run | **80 passed / 2 failed**, 6 warnings, **39.12 s**; both remaining assertions compared creation-time UTC-offset serialization with a SQLite-reloaded DateTime. |
| Correct persisted-GET-to-persisted-GET history comparison; rerun unchanged source | **12 failed / 2 passed**, 4 warnings, **7.68 s**; all remaining failures are product eligibility assertions. |
| Focused provisional correction | **14 passed**, 4 warnings, **15.50 s** |
| Add two real pilot-status cases against provisional correction | **1 failed / 1 passed / 14 deselected**, 4 warnings, **3.87 s**; replacement withdrawal still lacked the required pilot issue. |
| Complete 16-case set against all three unchanged baseline modules | **14 failed / 2 passed**, 4 warnings, **11.50 s** |
| Complete focused correction | **16 passed**, 4 warnings, **21.80 s** |

Temporary baseline files were checked against `git show HEAD:<path>`; corrected
files were restored in `finally` and checked byte-for-byte. An initial broad API
run was intentionally stopped/superseded when the pilot caller gap was found;
partial progress is not counted as a passed or failed acceptance run. The final
broad selections below were rerun after the final three-module correction.

## 3. Minimal correction and why

1. Source intake rejects a bounded comparison containing any tombstone. It does
   **not silently filter withdrawn observations**, which could manufacture clean
   absence or remove a regression input. Keep the 5,000-observation bound.
2. A shared eligibility check counts the exact IDs in a frozen source corpus
   against live observations in the exact estate. Missing/duplicate/unusable,
   empty or over-bound sets do not qualify. Current baseline eligibility flows
   through proposal/approval/report/verification and current projections.
3. Before publishing a positive result, recheck current baseline/approval and
   replacement membership after comparison. This catches the explicit injected
   boundary; it is not a transaction-level fence against every concurrent write.
4. Operator task/proof projections and the existing pilot proof gate recheck
   replacement membership too. Withdrawing any captured member invalidates current
   use of the entire comparison; do not guess that the withdrawal is harmless.
5. Preserve observation content/hash fields, previous proof payload/hash/history
   and GET-side task labels. A stored VERIFIED verdict remains historical, while
   `current_condition_verified=False`, `needs_attention=True` and proof freshness
   is `STALE_OR_UNAVAILABLE`. Reverification appends INCONCLUSIVE, not a rewrite.
6. Existing justified auditor restore can restore live membership while policy,
   assignment, approval and freshness still qualify. Restore is not a new scan,
   new independent proof, automatic restore or a way around stale authority.

Each membership query is bounded to a source snapshot's 5,000 IDs, but these checks
add read-side database work. No representative PostgreSQL query-plan/latency or
capacity objective is measured here. This checks ID/owner/tombstone membership,
**not arbitrary mutable-content/scan/job revalidation, full-chain completeness,
rollback detection, cryptographic origin, or serializable PostgreSQL isolation**.
No stronger timing/atomicity guarantee is inferred from the single-session test.

## 4. New regression matrix — 16 cases

| Area | Cases | Required result |
|---|---:|---|
| New proposal from withdrawn baseline | 1 | 409; no new change revision. |
| Withdrawal before approval/report | 2 | 409; existing change history unchanged. |
| Withdrawal before first proof: original/replacement | 2 | INCONCLUSIVE, not current operator resolution. |
| Current read plus audited restore: original/replacement | 2 | Current proof unavailable, old verdict/task label/history intact; authorized restore can restore eligibility without appending proof. |
| Other captured baseline/replacement members | 2 | Refuse current use, never drop the tombstone as clean absence. |
| Denied/foreign withdrawal | 1 | Reader 403/selected foreign admin 404; own proof unchanged. |
| Unrelated estate withdrawal | 1 | Own current proof remains eligible. |
| Reverification after withdrawal | 2 | Append INCONCLUSIVE; retain the earlier VERIFIED GET projection exactly. |
| Withdrawal during comparison | 1 | Explicit same-session callback; final eligibility check prevents a positive proof/task. |
| Pilot status: original/replacement withdrawal | 2 | Missing-current-proof issue appears; stored pilot history unchanged. |

The pilot fixture has other unmet operating/technical review requirements and is
PROPOSED. These tests isolate the proof issue; they do **not** demonstrate a fully
accepted customer pilot being revoked or actual technical/customer acceptance.
Hash-field preservation is not certification of synthetic source fixture chains;
existing pipeline-backed soft-delete tests run separately in the broad selection.

## 5. Final local validation

**480 API/assurance/remediation/six-BOM passed**, 6 warnings, **283.01 s**; **113 auth passed**, 10 warnings,
**37.85 s**; **1,159 library/package/database passed**, 10 warnings, **20.42 s**.

The API selection has 27 files and includes all 16 new cases, the existing 68-case
baseline, and prior trace/lifecycle/coverage/operator/six-BOM/refusal regressions.
The library run includes shared models, all CBOM, selected SBOM/identity/gate,
SQLite assurance migration and all remediation-library tests. Authorization is a
separate nine-file compatibility run. No failures/skips/deselections in any of
these three runs; new/baseline/focused totals overlap, not additive coverage.

Full configured `ruff check services scripts shared`, `python -m pip check`,
local documentation/anchor/shell/source-hash and whitespace checks pass. Existing
warnings remain Pydantic Config deprecations, cloud/network field shadowing,
Starlette/httpx/HTTP 422 deprecations and Alembic path-separator configuration.
The local documentation check passed **495 Markdown files / 1,852 local links**,
**9 changed Markdown / 1 shell block / 47 retained source hash values**, zero
errors. **57 external links were not fetched**. Hash values include 33 from the
preserved recovery/parser/trace records and 14 here; overlaps are not distinct
files or test cases. No all-repository, frontend/browser, Actions or independently
reviewed verdict. Earlier recovery/parser/trace totals retain their historical scopes.

## 6. Exact final reproduction selections and artifacts

Use synthetic test settings and the existing dependencies, not bank credentials:

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
  services/api/tests/unit/test_graph_edge_provenance_api.py \
  services/api/tests/unit/test_remediation_evidence_retraction.py \
  services/api/tests/unit/test_remediation_tasks.py \
  services/api/tests/unit/test_remediation_endpoint.py

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
  services/database/tests/unit/test_assurance_migration.py \
  services/remediation/tests

/home/user/recovery-venv/bin/ruff check services scripts shared
"$PYTHON" -m pip check
```

The focused command selects only
`services/api/tests/unit/test_remediation_evidence_retraction.py`. The baseline
selected the four existing modules named in section 2. For adverse reproduction,
use an isolated disposable environment with the starting implementation and new
tests; never overwrite a current/production checkout or inject a storage fault
into customer data.

Local logs/JUnit are outside Git, not a bank-controlled evidence store:
`/home/user/retraction-baseline`, `retraction-red`, `retraction-green`,
`retraction-red-final`, `retraction-focused-final`, `retraction-pilot-red`,
`retraction-red-complete`, `retraction-focused-complete`, `retraction-api-final`,
`retraction-auth-final` and `retraction-library-final` (each `.log`/`.xml`).
`retraction-api-superseded.log` is incomplete and not acceptance evidence.
The final local docs output is `/home/user/retraction-doc-validation.json`.

## 7. Tested source/input SHA-256 identities

First four are changed implementation/test files; unchanged helpers/models/inputs
identify fixture and predicate dependencies. This is not a signed build manifest.

```text
services/api/api/assurance/remediation.py
30af87917db45f683e917f70bde88cdea9ec0ec3e18ea30235a11a8ccbed16e1

services/api/api/assurance/operator.py
dd5f52646260d68a7904958eb702efc1eb19519956490653bc90bcf1796be6ed

services/api/api/assurance/launch.py
76489fe0057aeff71af371d8ca79877aa38fcb62836a717a5980808926ea3ebc

services/api/tests/unit/test_remediation_evidence_retraction.py
e4f0c2200bee1a48007f81a5870b424863a46907bd6ade996400243d187ab50d

services/api/tests/unit/test_operator_decisions.py
d4babf117114eb1fd852f5096e9578cd176c6def7499665f559fca75e69b5236

services/api/tests/unit/test_launch_readiness.py
96a1b137a3d864ab9d2a07940559539ec63d0bee1dfd461ea9d2fe4c5c966e3a

services/api/tests/unit/test_assurance_workflows.py
43b6ec4211cdf9b0d767aad0e0f9a9627ef4aefd3847fbd39e2221dd01cedb7b

services/api/api/routers/findings.py
c2185abc4e0ed6cf66b9a940c0c8b876517b92e6cdb7180e428446c7baa25643

services/api/api/routers/remediation.py
9da673a4ae99b83b79cb9f2f823bc5aa11095536807222d28cac530b147af223

services/database/db/models/evidence_record.py
d869d906e52765e8eca32b73de12473070b08ec275c5602e6003984e302af405

services/database/db/models/remediation_task.py
8230ee5b74c673211eba1169c0e7ab330b143b30a4a91ab6389177a3c0d0dd20

services/remediation/remediation/verification.py
d8e474ccf8fd8beb1c7ff24d0cfbbc5faea20de9cb0a6fcf7898ac3bde69343c

requirements.txt
15c2c7d4ceacf2bde509b4bf5ac635923cc470986d13047a3cdc42a8214c8bb1

requirements.lock.txt
1b935cfe5230ea6f37affaab45044617ce402ecd1037f4c62b22404da4cedf2b
```

## 8. Publication, operator response and remaining work

Publish all implementation/test/documentation on the existing branch/PR with
`[skip ci]`, preserving older dated evidence. No workflow edit or explicit CI
dispatch; no Actions verdict, main merge or installed bank upgrade is claimed.
Use the [current source-withdrawal handoff](../runbooks/evidence-assurance-upgrade.md#current-source-evidence-withdrawal-handoff-2026-10-23).
Retain withdrawn data and history; obtain eligible evidence/review where needed.
Never reset hashes, silently drop tombstones, backdate evidence, extend expiry
or restore without justified authorized audit to force a current green result.

Open: different-human code/security review; actual PostgreSQL transaction/race/
restore and representative query-capacity qualification; signed coordinated
release/install/recovery; bank browser and operating-owner exercises; remaining
six-BOM negatives; independent assessor report/retest and separate technical/
customer acceptance. These tests establish no SLA, staffing/24x7 capability,
production uptime, whole-bank coverage, zero egress or independent runtime truth.
