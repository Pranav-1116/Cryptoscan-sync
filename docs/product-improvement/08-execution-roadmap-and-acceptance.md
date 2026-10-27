# 8. Execute the quality-only roadmap and decide completion

[Pack index](README.md) · [Previous: operations](07-operations-and-bank-qualification.md) ·
[Next: worked example/templates](09-worked-example-and-review-templates.md)

Seven bounded increments have been published: first three in `2fd8fc8f`,
execution recovery/parser boundaries in `9f3fa5a9`, current-trace integrity/
freshness in `7e00d37e`, and source-proof withdrawal in `08b48df0`.
The [implementation ledger](IMPLEMENTATION-STATUS.md) retains their original
scope/results. The current
[eighth increment](../readiness-evidence/quality-remediation-browser-scope-2026-10-23.md)
continues C3 and B3/B4 on the existing Remediation browser lifecycle. Its local
mock/DOM regressions do not complete real-browser/site objectives or the rest of
C3. Earlier dated evidence is preserved, not relabeled as a rerun.
Production fault/recovery, different-human review and bank acceptance remain open.
This roadmap is the full target, not a claim that every work package has finished.

## 8.1 Program rules

1. Freeze feature breadth; use the same supported profile and critical workflow.
2. Diagnose first. The tasks below are recommended checks, not confirmed defects.
3. Every work item has an accountable owner, different reviewer and exact evidence.
4. Preserve original observations, current authority, history/CAS and explicit uncertainty.
5. Change small, reproduce locally, verify on the relevant intended environment.
6. Keep operator/customer/assessor actions separate from code completion.
7. Do not grant progress percentages or scheduled production approval without results.

The original roadmap was planning only; subsequent bounded implementation is
explicitly tracked in the ledger and dated records. No workflow edit, explicit
CI dispatch or site drill is performed by this roadmap. Publication uses
`[skip ci]`; the user owns the remaining unspecified CI failure separately.

## 8.2 Dependency order

```text
A. Scope + baseline + measurable objectives
      ↓
B. Correctness + authority/privacy + critical negative regressions
      ↓
C. Durable execution + measured resource/query/UI improvements
      ↓
D. Exact candidate + required executed tests + package/migration rehearsal
      ↓
E. Site/security/operations evidence + bounded customer acceptance
      ↓
F. Current gate/review decision + continued requalification
```

External assessor procurement, owner assignment and site/data permissions should
start during A, because their lead time may dominate. Actual acceptance must
still bind the final candidate: assess/retest changes made after an earlier run.

## 8.3 Step-by-step work packages

| Step | Work on existing product | Primary owner → independent reviewer | Deliverable and exit check |
|---|---|---|---|
| A1 | Freeze one local-source/v1 journey, actual supported topology and non-goals | Product + technical lead → bank technical owner | Agreed charter; deliberately refused adapters listed; no new feature dependency. |
| A2 | Capture exact revision/environment and present failures/unknowns | QA → technical reviewer | Reproducible baseline with original results and evidence references, not copied historical test totals. |
| A3 | Set workload, coverage, accuracy, user-task and recovery objectives | Domain/site owners → customer/security reviewer | Measurable objectives agreed before measurement; permissions and data handling approved. |
| B1 | Reconcile scope/identity/evidence from admitted input through all six BOMs | Backend/scanner owner → QA/domain reviewer | Wrong build/version/estate and incomplete receipts never produce false complete/verified paths. |
| B2 | Review context, policy and verification projections | Domain/backend owner → reviewer independent of change | Original observation unchanged; purpose/uncertainty and exact proof limits agree in API/UI/export. |
| B3 | Execute authority/privacy/raw-evidence/hostile-input negative matrix | Security + component owner → independent security reviewer | Critical unauthorized paths refuse; no sensitive output or isolation regression. |
| B4 | Fix observed defects in small changes with explicit reproductions | Component owner → different code reviewer | Affected isolated/integrated tests pass with the adverse case retained. |
| C1 | Rehearse interruption, duplicate delivery and UNKNOWN reconciliation | Worker/database owner → QA/site reviewer | Durable state/progress remains honest; no unsafe automatic replay or claim bypass. |
| C2 | Measure representative query/parser/browser/resource behavior | Performance/component owners → QA/site reviewer | Paired measurements with same conditions; limits/cleanup/fairness hold and semantics unchanged. |
| C3 | Correct existing form/error/accessibility/estate-race behavior | Frontend owner → QA + representative operator | Critical journey succeeds in relevant empty/populated/denied/stale/degraded states. |
| C4 | Refactor only demonstrated high-risk duplication/complexity | Component lead → different maintainer | Contract-preserving small patch and affected caller regressions, no framework rewrite. |
| D1 | Verify critical test execution, skips, dependency inputs and current required results | QA/release owner → technical reviewer | Exact candidate evidence; remaining required CI failure resolved by its owner, not waived. |
| D2 | Prepare reviewed immutable full operator package | Release owner → security/site approver | Registry digests and trusted signature/inventory verified; unsigned preflight not substituted. |
| D3 | Rehearse install, populated-data 0105 upgrade and failed-rollout recovery | Site/database operator → different witness | Data/history/access/compatibility checks retained; no lossy truncation for downgrade. |
| E1 | Execute agreed independent security scope and remediate/retest findings | External assessor + engineering owners → authorized independent review | Actual signed report/retests with limitations, exact candidate and scope binding. |
| E2 | Exercise all nine operating duties and site capacity/recovery/browser objectives | Named primary/backup operators → different reviewers | Real current exercises and accepted measured results; no automatic SLA claim. |
| E3 | Execute bounded six-BOM payments/customer workflow | Bank technical/data owners → different customer decision owner | Current proof/fingerprint, exclusions and separate technical/customer acceptance. |
| F1 | Re-evaluate mandatory release/readiness evidence | Release/service owner → designated approval authority | No mandatory missing/failing proof; exact decision and support boundary retained. |
| F2 | Maintain revalidation and incident/defect follow-up | Service/component owners → periodic independent review | Expired/changed evidence invalidates current claim; new releases are reassessed. |

## 8.4 What to do first, without waiting for new features

For the next planning cycle:

1. Pick a single current journey and record exactly what is supported/refused.
2. Ask the user/CI owner for the actual remaining failing lane, commit and logs;
   track its resolution separately. Do not infer the cause from this pack.
3. Reproduce the current journey, including estate B and dependency failure.
4. Select the highest-impact observed correctness/security/recovery issue; retain
   its regression before changing code.
5. Baseline one representative PostgreSQL workload and one operator/browser task.
6. Assign external assessor procurement, operating owners and site/customer evidence
   to real people in parallel.
7. Review the evidence and choose the next bounded improvement, not another feature.

Work-in-progress should be limited by the team's actual review/testing capacity.
No fixed number of engineers or days is assumed here. A one-person change queue
still needs an eligible different reviewer for independent decisions.

## 8.5 Acceptance matrix for the whole journey

Use the same fixture/estate/release identities across API, storage and browser.
Do not satisfy different steps with unrelated favorable runs.

| Scenario | Required observation | Promotion implication |
|---|---|---|
| Allowed normal source workflow | Durable job/receipts, exact identities, honest six-BOM relations and permitted proof | Necessary happy path, not sufficient alone |
| Denied/foreign/anonymous/machine-reviewer path | No unauthorized data/effect; documented refusal | Any reproduced violation blocks |
| Missing receipt, partial parser, unobserved expected target | Explicit incomplete/unknown coverage; no false safe/verified result | Required coverage remains blocked |
| Invalid/stale/revoked supplier or policy evidence | Quarantine/refusal/current-gate invalidation according to contract | Old valid signature/acceptance cannot override |
| Interrupted mutation or duplicate delivery | Reconciled immutable history/fences; no unsafe duplicate action | Unresolved outcome remains visible/blocking where required |
| Database/Redis/worker fault | Measured approved recovery, known lost work and honest state | Beyond-objective or missing proof blocks site claim |
| Stale browser/estate change/replay gap | Old scope cleared; authoritative reread and explicit gap/failure | Cross-estate exposure/false success blocks |
| Reported action with old/empty rescan | Not VERIFIED; original predicate requirements enforced | No ticket-as-proof shortcut |
| Changed release/topology/procedure after acceptance | Current evidence re-evaluated; historical record preserved | Old approval does not automatically promote changed build |

## 8.6 Quality ledger, not a readiness percentage

Maintain a simple table in the existing issue/evidence workflow:

| Item | Meaningful status |
|---|---|
| Observed defect | Open → reproduced → fix reviewed → affected regressions passed → accepted for exact release |
| Missing test/proof | Not executed → executed with result → independently reviewed; FAIL/SKIP stay explicit |
| External evidence | Requested → supplied → authenticity/scope/freshness reviewed → accepted or rejected |
| Performance/accuracy objective | Agreed before run → measured → compared → accepted only for actual scope |
| Release decision | Blocked until prerequisites; then explicit signed/reviewed decision under the actual policy |

These are planning labels, not newly implemented API enums or a new issue-tracker
schema. Existing product/gate statuses retain their precise meanings.

Useful counts include unresolved stop-the-line defects, unexecuted critical cases,
reviewed fresh evidence and passed measured objectives. Do not aggregate them
into “90% ready”: one mandatory security/recovery failure can block promotion.

## 8.7 Stop, recover and review

Stop promotion if authority/isolation fails, secrets leak, evidence is corrupted,
false PASS/VERIFIED appears, recovery loses required acknowledged state, a required
lane fails or a mandatory external review is missing/rejected.

Use the approved incident/change procedure; preserve restricted evidence and
reconcile any external effect. Revert a compatible binary only when safe. If schema
or evidence history cannot safely downgrade, use approved forward recovery/restore.
No SQL status rewrite, record deletion or lossy 0105 downgrade is a valid shortcut.

## 8.8 Definition of done for this program

- No new customer-facing feature/scope was required.
- Material observed defects are fixed with retained regressions and different review.
- The supported journey works under normal, denied, partial, stale and degraded conditions.
- Measurements substantiate the agreed resource/user/accuracy/recovery envelope.
- The exact full package and migration/recovery path are verifiable.
- Real operating/security/customer evidence satisfies the required current gates.
- The accepted scope, limitations, ownership and requalification triggers are explicit.

If the last external conditions are not supplied, report **engineering improvements
complete for the stated scope; bank production acceptance still blocked**. That is
an honest useful result, not a reason to invent features or approval.
