# Improve the existing product — no feature expansion

**Prepared:** 2026-10-22 UTC
**Repository baseline:** `bfc42df0` on `arena/bb4b80dd-cryproscan`; the preceding
implementation review is against `698beb38`. The intervening commit is docs-only.
**Audience:** product owner, engineering, QA, security, operators and bank reviewers.
**Status:** recommended improvement program, not completed work or release approval.

## Implementation has started

The first bounded changes and exact before/after results are tracked in
[implementation status](IMPLEMENTATION-STATUS.md) and the
[dated engineering record](../readiness-evidence/quality-increment-2026-10-22.md).
They strengthen existing source coverage and remove known remote font bootstrap
references. The [second increment](../readiness-evidence/quality-package-identity-2026-10-22.md)
keeps unresolved package versions out of exact SBOM/cascade/crypto paths, including
legacy current reads. The [third increment](../readiness-evidence/quality-authority-privacy-2026-10-22.md)
strengthens role-store failure refusal and selected public probe/log privacy;
all accumulated changes are prepared for the user-requested source PR push.
They do not mark this whole program or bank qualification complete.

## The recommendation in one sentence

**Stop expanding the product's surface; make one supported evidence-to-remediation
workflow correct, secure, predictable, understandable, recoverable and independently
verifiable on the intended bank deployment.**

This is not a request for more scanners, pages, BOM types, integrations, AI,
services or a replacement architecture. Improve the implementation and operating
quality of what already exists. Adding regression tests, correcting a confusing
label, removing duplicated validation or rehearsing restore is quality work—not
a new customer-facing feature.

## What this pack does, and does not, claim

The repository already has substantial controls: current authority, exact-estate
history, bounded execution, evidence hashes, typed six-BOM relationships, review
workflows and explicit uncertainty. These must be preserved and exercised, not
replaced by a simplistic rewrite. A recommendation to test a failure mode is
**not an assertion that the current code contains that defect**.

Four labels are used throughout:

| Label | Meaning |
|---|---|
| **Present in source** | A code path/configuration/manual exists at the reviewed baseline. |
| **Retained evidence** | An earlier execution has its own commit, environment, result and limitations. It is not a current run. |
| **Recommended check/change** | Work to investigate or improve; not completed by writing these guides. |
| **External acceptance** | Real site/customer/provider/independent-review work that repository code cannot self-certify. |

The user reports one remaining workflow failure and will resolve it separately.
Its lane/run is unspecified; this session cannot independently read Actions
results. This pack neither repairs nor waives it. No workflows or application
code are changed, no CI is dispatched, and no new site tests are claimed.

## Read in order

| # | Guide | Practical result |
|---|---|---|
| 1 | [Baseline and priorities](01-baseline-and-priorities.md) | Separate demonstrated engineering, unknowns, quality risks and external blockers. |
| 2 | [Correctness and six-BOM quality](02-correctness-and-six-bom-quality.md) | Trace every answer to exact input, identity, scope, evidence and limitations. |
| 3 | [Security, privacy and isolation](03-security-privacy-and-isolation.md) | Exercise existing controls under denied, revoked, hostile-input and cross-estate conditions. |
| 4 | [Reliability, performance and recovery](04-reliability-performance-and-recovery.md) | Measure the supported workload, bound resources and prove recovery without hiding lost work. |
| 5 | [User workflow and frontend quality](05-user-workflow-and-frontend-quality.md) | Complete the same operator journey safely in empty, populated, denied, stale and degraded states. |
| 6 | [Testing, maintainability and release](06-testing-maintainability-and-release.md) | Trust the tests, simplify risky code, produce an exact repeatable release and preserve history. |
| 7 | [Operations and bank qualification](07-operations-and-bank-qualification.md) | Turn existing policies/Preview records into demonstrated human/site capability. |
| 8 | [Execution roadmap and acceptance](08-execution-roadmap-and-acceptance.md) | Follow a dependency-ordered backlog with owners and evidence-based exit decisions. |
| 9 | [Worked example and review templates](09-worked-example-and-review-templates.md) | Rehearse the whole loop and record quality work without inventing evidence. |

## The end-to-end quality chain

```text
Agreed supported workflow + independent expected-target register
  → approved exact-estate authority + permitted input
  → bounded durable job + isolated parser + honest partial progress
  → immutable observations + attributed identities + explicit uncertainty
  → distinct SBOM / CBOM / NBOM / TechBOM / HBOM / VBOM relationships
  → applicable finding + accountable owner + separate approved change
  → reported completion + later exact-condition proof
  → consistent browser / API / export interpretation
  → signed reviewed release + install / upgrade / recovery rehearsal
  → independent security review + actual operating exercises
  → bounded customer acceptance + ongoing revalidation
```

Failure in an early link blocks downstream claims. For example, a fast page
cannot make an unobserved target safe; a valid signature cannot make a supplier
assertion independent; an earlier test pass cannot approve a changed release.

## Scope freeze: improve depth, not breadth

**In scope:** existing-workflow bug fixes, negative/contract/integration tests,
query/index tuning justified by measurement, timeouts and resource bounds,
configuration consistency, dependency maintenance, accessibility, understandable
errors, removal of unsafe examples, package verification, operator practice and
retained independent evidence.

**Out of scope:** additional collector adapters, new ecosystems or threat feeds,
new analytics/risk scores, extra dashboards, autonomous remediation, new deployment
topologies, architectural rewrites, and promoting Preview to GA without evidence.
Do not re-enable a refused route to make a walkthrough look complete.

The reviewed controlled production profile remains
`kubernetes-external-services/local-source-v1`. Live TLS/SSH/cloud/runtime and
other unqualified acquisition remain refused there. Existing externally obtained
receipts can be reviewed only under their actual metadata/intake contract.
No recommendation here expands that support boundary.

## How to measure improvement

Do not publish a new “bank-ready percentage.” Track a release-bound ledger:

- each critical journey: executed / failed / blocked / not tested;
- each material defect: impact, accountable owner, reproduction and verified fix;
- each evidence path: provenance, fresh registered coverage and unresolved links;
- each resource objective: agreed workload, measurement and recovery result;
- each external requirement: current accepted evidence or explicit blocker.

The historical **6 PASS / 1 FAIL / 3 SKIP** readiness record is not a score for
this program. Completion is a reviewed decision for an exact release, site and
scope, not an average of unrelated test counts.

## Related authorities

- [Current implementation status](../CURRENT-IMPLEMENTATION-STATUS.md)
- [CI/product-build contract](../CI-WORKFLOW-AND-PRODUCT-BUILD-PLAN.md)
- [Production-readiness gate](../../PRODUCTION-READINESS.md)
- [Operator package/install/upgrade/recover](../runbooks/operator-install-upgrade-recover.md)
- [Launch assurance handoff](../runbooks/launch-assurance-handoff.md)

Start with guide 1. Execute the roadmap in guide 8. Use guide 9 for the evidence
record. Writing or checking off a template alone closes nothing.
