# Step 8 — demonstrated maintenance and trustworthy adverse tests

**2026-10-23 UTC.** Scope is demonstrated existing-product defects, not speculative
cleanup. Test totals alone do not establish correctness or acceptance.

## Small changes with a reason

- `frontend/src/lib/requestFeedback.ts` centralizes body-independent HTTP
  categories used by Launch and shared live reads.400/422 is an ordinary
  validation refusal;409 requires reconciliation; an uncertain mutation is not
  auto-retried. This avoids raw exception/server detail and duplicated divergent
  logic.16 focused cases cover the category boundaries. This is **not** a rewrite
  of every legacy API helper.
- `operating_interval` is shared at exercise intake and current status reads.
  Both enforce assignment≤start≤end≤current time. Previously intake rejected
  future work while current reads could promote reviewed future work after clock
  rollback. One assessed instant is used for interval/age checks within that
  status call; no extra timestamp was added to gate fingerprints.
- The Launch20second request deadline fences late success and releases its
  single-flight lock even if body reading ignores abort. It is a UI uncertainty
  boundary, not a transaction cancellation guarantee.
- Error focus handles **identical** repeated validation text as well as a new
  message; otherwise React can skip the state update and its effect.
- A legacy Remediation test called itself “shows refusals verbatim” but only
  asserted that ACCEPT is absent for an ACCEPTED task. Its mocked409 endpoint
  was never called, and a trailing unrelated completion click had no awaited
  assertion. The test now says what it checks; dead setup/click are removed.
  **No refusal coverage is claimed from that case.** No product remediation
  action logic was changed by that correction.
- Existing language switcher reuse and a narrow CSS override fix observed
  shell/reflow defects. No new dependency, route, screen or architecture.

## Actual red→green evidence

All text logs below have ANSI styling removed for review. Red logs are preserved
as adverse evidence, **not** passing qualification reports. Source changes and
current relevant files are bound in the
[results/hash manifest](quality-usability-release-operations-results-2026-10-23.json).

| Meaningful adverse check | Observed failure before correction | Current evidence |
|---|---|---|
| Original8 Launch task cases on baseline implementation | **7 failed / 1 passed**: estate/help, focused validation,400/422, state distinctions, history label and technical direction missing. Existing outage uncertainty case already passed. | New9-case suite passes within complete542; [initial red](quality-usability-release-operations-2026-10-23/ui-red.log). |
| Non-cooperative body at20seconds | **1 failed / 8 deselected**; submit remained disabled. | Exactly one POST; feedback uncertain; submit unlocked; late receipt absent. [Timeout red](quality-usability-release-operations-2026-10-23/timeout-red.log). |
| Repeated identical local validation | **1 failed / 8 deselected** after first-error focus already worked. | The same feedback regains focus without clearing ID/body. [Repeat-focus red](quality-usability-release-operations-2026-10-23/repeat-focus-red.log). |
| Existing shell Arabic control | **1 failed / 15 skipped** in name-filtered run; actual button absent. | Shell integration and browser Arabic cases pass. [Locale red](quality-usability-release-operations-2026-10-23/locale-red.log). Skips here are deliberate name-filter exclusions, not qualification. |
|320CSS-pixel Arabic reflow | Actual40px client /241px scroll; browser failure. | Same clipping assertion passes after cascade correction. [Browser red](quality-usability-release-operations-2026-10-23/browser-reflow-red.json). |
| Current operating clock rollback | **1 failed / 1 passed**: future reviewed exercises incorrectly remained current; existing historical-expiry case already passed. | Both pass in current92-case suite; history remains intact. [Operations red](quality-usability-release-operations-2026-10-23/operations-red.log). |
| Coordinated package release/source/dependency binding | **4 failed / 20 deselected**: valid re-signing hid mixed release IDs/dependency edits; source provenance absent. |27 package tests in current92 include retained version-1 nonapproval, strict clean-source check and build-race refusal/cleanup. [Release red](quality-usability-release-operations-2026-10-23/release-red.log). |

The three later release cases extend compatibility/clean-source/race protection;
no claim is made that their exact full test bodies ran against the old baseline.
Likewise16 feedback category unit cases are regression checks, not16 independently
discovered failures. Do not turn “deselected” in a targeted red run into silent
passing qualification.

## Test timing and harness incidents

Initial animation-visible assertions exposed synchronization mistakes; they use
bounded `waitFor`, not arbitrary sleeps or disabled product animation. The
non-cooperative timeout uses fake timers and an explicitly controlled promise;
it counts POST calls from the correct mutation mock. Browser tests use bounded
barriers and native keyboard/form behavior rather than timing-only sleeps.

The initial Chromium launch lacked `libnspr4.so`; setting the external runtime
library path fixed the harness, not product code. A later expanded native run
omitted `CRYPTOSCAN_MEASURE_OUT` and `CRYPTOSCAN_COHORT_OUT`:17 passed,2 failed
while writing required records. After setting explicit external output paths,
the same native19 tests passed serially. The retained
[harness-failure log](quality-usability-release-operations-2026-10-23/native-harness-failure.log)
omits its environment repr to avoid copying synthetic key/sandbox metadata.
Neither incident counts as a product red→green improvement. No assertions were
removed, tests skipped, animations disabled or warnings globally filtered to
obtain final green results.

## Warnings: visible debt, not silently accepted cleanliness

| Warning | Current location / count | Interpretation and next action |
|---|---|---|
| React state updates outside `act` |20 occurrences in full frontend log: `CriticalScope` (6), `Tenancy` (14). | Existing scope/reset/async-provider test synchronization debt. CriticalScope intentionally tests synchronous fencing before effect reset; don't wrap away the race or mute warnings. Maintain that assertion and drain later work separately. Tenancy should await provider settlement. These are **not** zero-warning tests. |
| Pydantic class-based Config deprecated | Auth response in API suites; EvidenceRecord/ScanManifest additionally in native. | Compatibility debt for Pydantic3; plan isolated ConfigDict migration with schema regressions, not a broad cleanup hidden in this increment. |
| `register` shadows BaseModel attribute | Network and cloud request models, two warnings per selected API run. | Review public-schema compatibility before renaming; preserve existing clients or use explicit aliases under tests. |
| Starlette TestClient/httpx deprecation | One per API process. | Future toolchain compatibility work; migrate in an isolated dependency change with auth/transport tests, not forced upgrades here. |
| Alembic `path_separator` fallback | One in92-case suite;17 in native19, making native23 total. | Existing configuration deprecation; explicit separator and cross-platform path tests should accompany a future change. No migration skipped. |

Current API warning totals are **5** in92, **4** in248 and **23** in native19.
The frontend's20 act warnings are retained in its log. Warnings are not globally
suppressed; no new-locale-test act warning was left behind. Vitest's suggestion
to disable module isolation is informational and **was not followed**: isolation
must not be traded away just to improve test timing.

## Relevant regression scope and remaining limits

Current full frontend:542 cases/51 files. Built browser:15 PASS,0 page errors.
Selected API/release/operations:92. Broader API/auth/SQL/worker contracts:248,
including all six distinct BOMs. Native PostgreSQL:19, zero skips, including
populated upgrades, concurrent revision/approval winners, evidence withdrawal,
UNKNOWN capacity, failed SQL restore, measured trace and synthetic cohort
restore/failback. These are selected suites, not a claim all repository tests,
CI, production callbacks, hostile infrastructure or real-user behavior pass.

Test inputs are synthetic. Source hashes record the actual changed inputs, not
just a Git label. Reviewers should inspect adverse assertions and untested gaps,
not approve on the basis of a large passing count.
