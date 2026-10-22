# Launch workflow engineering evidence — 2026-10-22 UTC

## Scope and verdict

Implementation evidence for 5.1 independent-security records, 5.2 operational
ownership records and 5.3 a bounded payments pilot. Branch:
`arena/bb4b80dd-cryproscan`, based on published `1ad68f8e`.
**Preview; not independent assessment, certification, site qualification, SLA or
real customer acceptance.** No assessor contract/key/report, actual operating
roster, witnessed bank exercise or customer pilot data was supplied. Synthetic
keys, users, collector fixtures and test results are explicitly test-only.

No main-branch or CI-workflow changes, CI dispatch, image build, site deployment,
production collector activation or database migration were performed. Existing
0104 remains the migration head. API/shared models/frontend must be rebuilt
coherently; existing local-source/v1 collection refusals remain in force.

## Delivered controls

- Five security scope areas with 13 mandatory negative case IDs; reviewed external
  independence assertion and authenticated public Ed25519 key; canonical signed
  report intake bound to exact estate, approved scope/revision, artifact digest,
  deployment checksum, environment, original-report blob and monotone sequence/time.
- Explicit NOT_TESTED/INCONCLUSIVE results, immutable finding case identity, complete
  subsequent dispositions, approved replacement/owner action and later exact signed
  retest. Ticket completion alone does not record resolution. Report/finding writes
  commit atomically. Withdrawal preserves the historical review assertion rather
  than inventing a prior approval. Current status checks freshness and raw evidence
  availability/integrity; origin verification is not proof of factual truth.
- Nine operating duties, active human primary/backup IDs, separate acknowledgements,
  retained procedure hashes, exercise timing/evidence, separate review, expiry and
  reassignment invalidation. Reviewed assertions never authorize an SLA.
- One payments application/release manifest with source/SBOM/deployment, exact TLS
  and SSH permission references/receipts, meaningful hardware metadata and approved
  signed supplier evidence. Current condition proof, security and operating gates,
  source/SSH coverage identity checks, technical review and different customer-owner
  acceptance. Changing evidence invalidates the current acceptance fingerprint.
  Generic external-export coverage gaps remain visible, not manufactured OBSERVED.
- Preview console with bounded record/history reads and revision-checked actions;
  state/drafts reset on estate/auth changes, delayed old-estate replies ignored.
  External-signing payload tool never reads/generates/stores private keys.
- Detailed bank procedures 56–58, operator handoff and editable templates; package
  inventory includes the runbook, notes, templates and signing helper. Templates
  are deliberately unexecuted NOT_TESTED/INCONCLUSIVE records with placeholders.

## Validation actually performed

Environment: Python 3.11.2, Node v22.22.3, npm 10.9.8. Dependencies installed from
repository requirements and `npm ci --ignore-scripts`; lockfiles unchanged.
Results overlap and must **not** be added together.

| Check | Result | Limitation |
|---|---|---|
| Final changed-code acceptance: launch, assurance workflows/controlled boundary/Redis clients, operator condition proofs, release package and maturity | **157 passed**, 4 warnings, 68.75 s | Authenticated SQLite/synthetic evidence; not external or bank execution. Includes the final shared boundary extraction and withdrawal semantics. |
| Earlier focused launch + package + controlled boundary + maturity | 73 passed, 4 warnings, 60.76 s | Subset/overlap of final acceptance. |
| Broader selected API/auth/estate/execution/SSH + all worker/shared-model suites + assurance migration | **1 failed, 1,864 passed, 16 skipped, 1 deselected**, 21 warnings, 430.26 s | Not green. Completed before the last three negative-test additions/final boundary extraction; those changes are covered by final acceptance above. Failure detailed below. |
| Full frontend suite after UI-copy correction | **398 passed**, 45 files, 153.21 s | DOM/synthetic fetch tests, not real-browser endurance or bank acceptance. |
| Frontend typecheck and production build | Passed in the final frontend command | Build output is not an image/deployment qualification. |
| Standalone launch router import and generated OpenAPI | Passed; **917 paths / 1,008 operations / 105 groups** | Schema/route generation, not end-to-end deployment. |
| Maturity generation | GA 33 / Beta 32 / Preview 12 | Launch readiness remains Preview. |
| Changed Python Ruff F/E9 and whitespace diff check | Passed | Selected lint categories, not a security assessment. |
| Eight changed/new handoff/engineering Markdown files | 128 local links, 4 Bash blocks, no link/shell-syntax errors | Static validation, not execution of production instructions. |
| Final release-package recheck after inventorying launch evidence | **19 passed**, 3 warnings, 1.41 s | Package integrity only; not site/security qualification. |
| Canonical external-report preparation CLI | 2,503 bytes; SHA-256 `84f619c5a5ab1984aa029252917baccf1d75560a2fba70ec3948f7cf1d597914` | Unexecuted template, all 13 NOT_TESTED; **unsigned**, not assurance evidence. |

Final changed-code acceptance command (repository root):

```bash
export PYTHONPATH="$(find services shared -mindepth 1 -maxdepth 1 -type d | paste -sd:):services/api/tests/unit"
python -m pytest services/api/tests/unit/test_launch_readiness.py \
  services/api/tests/unit/test_assurance*.py \
  services/api/tests/unit/test_operator_decisions.py \
  services/api/tests/security/test_operator_release.py \
  shared/shared_models/tests/test_capability_maturity.py -q
```

Frontend: `cd frontend && npm run typecheck && npm run build && npm test`.
REST and maturity copies regenerated using the existing generator scripts.

## Broader failures retained, not hidden

1. `services/worker/tests/integration/test_full_chain_e2e.py::test_link_remediation_task_verified_by_rescan[sqlite]`
   expects VERIFIED, but the conservative existing verifier returns INCONCLUSIVE:
   `no rescan evidence available — run a scan of the same target and re-verify`.
   The failed expectation is outside the new launch workflow. Do **not** weaken
   the verifier or treat a closed ticket/missing evidence as successful resolution
   to satisfy this legacy integration fixture.
2. An initial wider API/worker run collected 4,113 selected tests and was stopped
   rather than represented as a completed run after encountering
   `services/api/tests/integration/test_dubai_banks_group_e2e.py::test_dubai_banks_end_to_end[sqlite]`.
   Its field-accuracy API expectation was `NO_FIELD_DATA`, actual `None`. An isolated
   rerun reproduced the same failure (1 failed, 5 warnings, 15.38 s). The remaining
   initial wider run is **not validated** by this work.

Both failures reproduced with the two changed existing API integration modules
(`api.security.rbac` and `api.routers.assurance`) loaded from published pre-5.x
HEAD `1ad68f8e`, with no launch route included: worker 1 failed / 2.29 s; Dubai
1 failed / 14.09 s. This was an in-process module overlay, **not a second complete
baseline checkout/suite**. The shared verifier and the field-accuracy route were
not modified. These failures remain explicitly open; this record makes no
repository-wide all-green claim.

The initial full frontend attempt found two new UI-copy/smoke failures from
visible raw API-path text. The copy was corrected, bounded record browsing added,
and the final full 398-test run passed; no tests were skipped to hide that issue.

## Remaining external acceptance

Independent provider procurement and due diligence; actual agreed-scope testing
and report signatures/retests; real active owner/backup assignments and site
exercises; witnessed recovery and capacity/browser qualification; approved
customer endpoint permission and evidence; one real pilot and technical/customer
review; legal/commercial approval of any service agreement. Infrastructure
certificates, local synthetic tests and signed document assertions do not close
these gates. See [launch handoff](../runbooks/launch-assurance-handoff.md).
