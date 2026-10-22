# 1. Establish the baseline and prioritize quality

[Pack index](README.md) · [Next: correctness and six BOMs](02-correctness-and-six-bom-quality.md)

## 1.1 What is already valuable

The reviewed implementation contains controls worth strengthening rather than
rebuilding. These are source-level observations, not a new bank-site acceptance:

| Existing foundation | Where to verify it | Quality objective |
|---|---|---|
| Current execution authority and controlled local-source isolation | `services/worker/worker/core/queued_authority.py`, `controlled_source.py`, `static_scan_isolation.py`; controlled-execution runbook | Every allowed and refused path honors the same current contract. |
| Exact-estate observations, history and evidence | API assurance modules and estate/history tests | No cross-estate leak, unowned proof or silent empty-success substitution. |
| Independent expected-target coverage | Existing assurance coverage register | Discovered findings cannot redefine the expected denominator. |
| Six-BOM relationships and context | Existing relationship, applicability and supplier-quarantine workflows | Explain identity and provenance without inventing deployment, invocation or certification. |
| Owner/change/verification loop | Existing operator/remediation workflows | Reported completion never substitutes for an exact later proof. |
| Frontend engineering checks | Typecheck, Vitest, build/toolchain; estate-race tests | The browser reliably preserves those backend meanings. |
| CI and package controls | Active discovered test lanes, PostgreSQL 15/16, six-image build-only checks and operator tooling | Required execution and exact release evidence—not only configured YAML. |
| Launch Preview records | Independent-report/retest, nine-duty ownership, bounded pilot | Real people and external evidence must fulfill the records. |

Use [current status](../CURRENT-IMPLEMENTATION-STATUS.md) for the baseline and
[bank guides 46–58](../bank-environment/README.md) for detailed contracts.

## 1.2 What remains unknown is not automatically broken

Separate these cases before opening tickets:

1. **Observed defect:** reproducible code/user behavior violates the agreed
   contract. Retain input, exact revision and expected/actual behavior.
2. **Missing regression:** the control may work, but a critical negative path
   lacks a repeatable test. Add proof, not a claim that exploitation occurred.
3. **Unqualified environment:** code passes locally but the intended database,
   isolation runtime, browser or operator procedure has not been exercised.
4. **Missing external input:** assessor work, customer samples, bank approval,
   signing authority or credentials have not been supplied. Assign an external
   owner; do not fabricate a passing fixture to close it.
5. **Unsupported scope:** a collector/profile is deliberately refused. Keep it
   refused. Supporting it would be feature expansion outside this program.
6. **Historical evidence:** an earlier run is useful context, not a fresh result.

For example, the user's remaining CI failure has no specified lane/run here.
Record it as **reported unresolved** until the user supplies/resolves the actual
result; do not invent its root cause or bypass it.

## 1.3 Define the product-quality unit

Do not use “all services started” as the unit of success. Use one real journey:

> An authorized user selects the correct estate, submits a permitted bounded
> source release, receives durable attributable evidence and honest six-BOM
> relationships, assigns a real finding, obtains separate change approval,
> reports the action, collects a later exact-site observation and understands the
> verification result through the existing console and retained report.

Additional supplier/hardware/deployment and approved endpoint receipts keep
separate provenance. They do not turn local-source collection into live estate
coverage. The production journey and a broader development demonstration must
have separate acceptance records.

## 1.4 Ten improvement themes, in priority order

Priority below is a recommendation, not a list of confirmed defects.

| ID | Theme | Why it precedes more features | Main guide |
|---|---|---|---|
| Q01 | Contract and scope consistency | A product cannot be trusted if one screen/export interprets a result differently. | 2, 5 |
| Q02 | Evidence and identity accuracy | Incorrect joins or coverage claims send the bank to the wrong remediation. | 2 |
| Q03 | Authorization/privacy/isolation proof | One cross-estate or secret-leak path can invalidate many successful functions. | 3 |
| Q04 | Durable execution and honest recovery | Acknowledged work must not disappear or be repeated unsafely. | 4 |
| Q05 | Measured capacity and resource bounds | Predictable limits are more useful than unsupported throughput claims. | 4 |
| Q06 | Operator usability and accessibility | Existing controls fail operationally if users cannot interpret or safely complete them. | 5 |
| Q07 | Trustworthy regression/CI evidence | Test quantity cannot compensate for skipped or order-dependent critical behavior. | 6 |
| Q08 | Maintainable code/dependencies and exact release | Small verified changes reduce reintroduction, upgrade and supply-chain risk. | 6 |
| Q09 | Demonstrated support/security/site capability | Policies and Preview records are not staffed operations or independent assessment. | 7 |
| Q10 | Customer validation and continued requalification | One accepted build/scope does not approve the next release indefinitely. | 7–9 |

Treat observed cross-estate exposure, secret leakage, evidence corruption,
false VERIFIED/PASS and unsafe duplicate effects as stop-the-line conditions.
Readability/performance improvements must never weaken those boundaries.

## 1.5 Create one quality ledger, using existing tools

Use the team's existing issue tracker and controlled evidence store; no new
backlog service/dashboard is needed. Every work item should contain:

- theme ID; observed defect, missing proof or external acceptance classification;
- affected existing journey, supported profile and user/business impact;
- exact baseline commit, environment, data class and reproduction reference;
- expected contract, actual result and uncertainty;
- accountable engineering/operator/customer owner and different reviewer;
- bounded change, explicit non-goals and regression/acceptance checks;
- evidence location, result, rollback/forward-recovery plan and recheck triggers.

Do not paste raw customer source, credentials, private keys or sensitive logs in
public issues. A restricted evidence reference is enough for the public summary.

## 1.6 Baseline capture procedure

1. Freeze an exact candidate revision and dependency/container inputs.
2. Read the supported profile and list intentionally unavailable surfaces.
3. Register independent expected targets and actual permission/freshness windows.
4. Identify the intended PostgreSQL/Redis/runtime/browser environment; do not
   silently replace it with SQLite/mocks for acceptance.
5. Execute the chosen journey with permitted non-production inputs and retain
   the failures as well as successes.
6. Repeat with estate B, anonymous/denied identities, stale authority and a failed
   dependency. Confirm expected refusals and uncertainty, not just happy paths.
7. Capture latency/resource/error and user-task measurements before optimizing.
8. Open only evidence-backed work items; assign unknowns their own validation tasks.
9. Have a different reviewer agree the starting limitations and release blockers.

This guide does not execute these steps. Existing historical test totals must
not be copied into the new baseline's result column.

## 1.7 Avoid ineffective “improvements”

| Temptation | Why it weakens quality | Better action |
|---|---|---|
| Add another risk score | Hides the reason the existing answer is uncertain. | Explain the current evidence, purpose and missing scope. |
| Mark all absent findings safe | Confuses non-observation with absence. | Reconcile registered targets and parser/collection outcomes. |
| Increase timeout/retry globally | Hides resource defects and may duplicate effects. | Measure the failure, bound attempts and preserve authority/fences. |
| Rewrite all services | Expands regression and release scope. | Refactor only an identified risky path behind contract tests. |
| Disable failing tests | Removes the evidence needed to diagnose the defect. | Fix the behavior, or document and enforce an explicitly optional limitation. |
| Add a generic “production ready” badge | Conflates source, tests, site evidence and approval. | Use exact release/site/scope acceptance and current blockers. |

**Exit for this stage:** one agreed scope, one honest baseline, an owner/reviewer
for each material gap and an ordered quality backlog. No new feature commitment.
