# 9. Worked quality walkthrough and editable review templates

[Pack index](README.md) · [Previous: execution roadmap](08-execution-roadmap-and-acceptance.md)

## 9.1 Fictional scenario—no claimed execution

A bank wants to understand and verify a source-level crypto change in **one
payments application/release**. The team improves the current workflow rather
than adds another scanner or dashboard.

Everything below is an illustrative procedure. No bank, source input, customer,
credential, scan, finding, approval, successful proof or test result is supplied
by this example. Actual IDs must come from existing authorized records; do not
paste the labels here into the API as fabricated identities/evidence.

The controlled collection profile remains local-source/v1. Any endpoint,
hardware, supplier or deployment evidence has its own legitimate source/review;
this walkthrough does not authorize live collection or make imported statements
independent observations.

## 9.2 End-to-end walkthrough

### Step 1 — Freeze one supported purpose

Agree: one source target, one application/release and one applicable condition.
Record exclusions—other applications, whole-bank coverage, runtime invocation,
all network nodes, HSM certification and commercial rollout are not proven.
Record the exact candidate release and approved site/configuration identity.

**Quality question:** can an operator tell this scope from the existing console,
API and report? If not, correct existing wording/projection; do not add a scope product.

### Step 2 — Register what should exist independently of findings

The bank's custodian supplies expected SOURCE, ENDPOINT, DEPLOYMENT, HARDWARE and
SUPPLIER targets with owner, method/permission and freshness. The register's own
completeness may honestly remain PARTIAL.

**Negative rehearsal:** omit an expected target from collection. Coverage must
retain it as not observed according to its actual state. A smaller output list
must not shrink the denominator.

### Step 3 — Bind release, SBOM and declared relationships

Use actual artifact digest and **separate SBOM document checksum**, exact package
version and existing system/deployment identity. Preserve whether each was measured,
declared or independently reviewed. Hardware/firmware and supplier origin evidence
retain their own provenance and validity.

**Negative rehearsal:** supply a same-name package with a different version, a
wrong-build supplier statement and an expired relationship. None can silently
complete the trace. A valid supplier signature cannot fix a wrong build.

### Step 4 — Admit and observe bounded source work

Use the current principal/estate, policy and permission. Retain the durable job,
original-file digest and completed parser receipts. Verify the admitted bound
and actual source identity rather than a staging directory name.

**Negative rehearsal:** a revoked approval, disallowed path or resource-limit
refusal must not become a successful empty scan. Interrupt work only in an
approved disposable environment, then reconcile durable state rather than retry blindly.

### Step 5 — Check the six complementary evidence paths

| Layer | What this walkthrough may support | Remaining limitation to retain |
|---|---|---|
| SBOM | Exact release-to-SBOM-to-versioned-package binding | Not independent deployment/runtime invocation |
| CBOM | Actual source algorithm/purpose/site and parser evidence | Not all possible runtime crypto use |
| NBOM | Existing legitimate exact endpoint receipt and its reviewed context | Not live collection by the refused adapter or all traffic paths |
| TechBOM | Explicit existing application/deployment/artifact relations | Declared relation stays declared; no name-based runtime dependency |
| HBOM | Exact supplied hardware/firmware/mode metadata with provenance | Not automatic attestation/certification |
| VBOM | Bound supplier/product/build statement with verified origin/review | Not independent truth, assessor result or whole-vendor assurance |

If a layer's required evidence is missing, keep the gap. Do not invent a positive
row to make the six-BOM demonstration symmetrical.

### Step 6 — Review applicability before prescribing change

Have the authorized reviewer inspect actual purpose/configuration, not just an
algorithm name. An MD5 cache checksum has a different implication from a production
security-integrity use. A context conflict or hardcoded-key concern remains an
investigation. Original observation and policy evidence are retained unchanged.

**Quality improvement:** correct an inconsistent current label/export or retain
a parser regression based on the reviewed input. No new analytics engine is needed.

### Step 7 — Assign an owner and approve an exact condition

Create the existing task/change with actual owner, target/site/purpose, proposed
replacement, expiry, evidence and current revision. A different eligible human
reviews the exact predicate. The owner performs the separately authorized change
and records real completion time/reference.

**Negative rehearsal:** self-approval, stale revision, wrong estate and API-key
human-review attempts must be refused. A closed ticket is still not proof of a fix.

### Step 8 — Collect a later valid observation

The rescan must begin after the reported action, belong to the same target and
carry a changed original-file checksum with eligible completed receipts. For the
current source predicate, expected replacement, exact original site/purpose and
PASS are required. Retain the computed condition proof and limitations.

**Negative rehearsal:** use the original scan, a pre-action scan, an empty scan,
missing receipts and a moved/deleted site. They must not verify by absence. If a
legitimate refactor moves the site, it does not meet this narrow predicate; leave
that proof inconclusive and use a separately authorized review process. Do not
weaken the verifier or build a new predicate as part of this quality-only walkthrough.

### Step 9 — Check API/browser/export agreement

Find the same actual job, finding, task/change and proof in existing views.
Verify consistent scope, freshness, completion/verification meaning and exclusions.
Exercise keyboard use, denied access, estate switch, interrupted mutation and
stale/degraded backend; no prior-estate data or false safe fallback may appear.

**Quality result:** record user interpretation errors and correct existing form,
text or state behavior. Faster task completion is accepted only if decisions remain correct.

### Step 10 — Rehearse delivery and operations

Verify the exact complete operator package, externally trusted attestation,
coordinated 0105 compatibility and approved install/recovery. Exercise the relevant
site workload and all required operating duties with real humans and different review.
Actual independent security results/retests must bind the agreed candidate/scope.

**Negative rehearsal:** tamper with an approved test package, remove required
metadata, use the wrong public trust key or attempt a lossy migration downgrade.
Refuse unsafe promotion; preserve original evidence rather than patch its verdict.

### Step 11 — Make the bounded acceptance decision

The technical owner reviews current evidence; a different customer owner decides
bounded acceptance. Required current gate categories still apply. A changed source,
release, policy, signer, scope or expired evidence invalidates current acceptance
as defined by the existing workflow; historical acceptance remains in history.

No acceptance is issued by following this text. If real evidence is missing, the
outcome is BLOCKED/INCONCLUSIVE for that requirement, not a fictional pass.

## 9.3 Template A — quality work item

Copy into the existing tracker. These planning fields are not an API payload.
Leave missing facts NOT_SUPPLIED/NOT_TESTED; do not create fake IDs or hashes.

```text
Title:
Theme: Q01–Q10 from guide 1
Type: observed defect / missing proof / external acceptance
Supported workflow/profile:
Baseline revision and actual environment:
Impact and affected audience:
Reproduction / restricted evidence reference:
Expected existing contract:
Observed actual result (or NOT_TESTED):
Known limitations / not asserted:
Accountable owner:
Different reviewer:
Bounded change / explicit non-goals:
Regression and acceptance checks:
Required external dependencies:
Secret/privacy handling:
Rollback or forward-recovery plan:
Result and exact candidate (NOT_TESTED until executed):
Review decision / reference / date:
Revalidation triggers:
```

## 9.4 Template B — executed test/measurement record

```text
Record state: NOT_EXECUTED
Purpose and requirement being tested:
Exact source/image/configuration/profile identities:
Environment, database/runtime/browser versions:
Authorized scope / permission / impact limits:
Fixture/input/evidence identities and provenance:
Agreed objective / expected result (defined before execution):
Actual UTC start/end:
Operator:
Procedure/command and controlled output location:
Actual counts/metrics/errors/timeouts/lost acknowledged IDs:
Result: NOT_TESTED / PASS / FAIL / INCONCLUSIVE / BLOCKED
Scope and limitations; unexecuted subcases:
Original artifact digest(s), custody and retention:
Different reviewer and actual review decision:
Follow-up item and recheck trigger:
```

A reported PASS is usable only if actual evidence, scope and review satisfy the
real contract. No default result in this template establishes qualification.

## 9.5 Template C — release quality/acceptance review

| Question | Answer before actual review |
|---|---|
| Exact intended revision/images/package/configuration identified? | NOT_REVIEWED |
| Supported scope and deliberately refused features unchanged? | NOT_REVIEWED |
| Material defects fixed with isolated/integrated negative regressions? | NOT_REVIEWED |
| Required CI results actually completed for this revision? | NOT_REVIEWED |
| Six-BOM scope/provenance/coverage and proof meanings consistent? | NOT_REVIEWED |
| Real browser/user/accessibility and measured resource envelope accepted? | NOT_REVIEWED |
| Package/signature, 0105 migration and failure/recovery rehearsed? | NOT_REVIEWED |
| Actual independent security report/findings/retests accepted? | NOT_REVIEWED |
| Nine operating duties and applicable site/provider requirements demonstrated? | NOT_REVIEWED |
| Separate technical/customer decision and current evidence fingerprint retained? | NOT_REVIEWED |
| All mandatory current gate evidence supplied and reviewed? | NOT_REVIEWED |
| Requalification triggers, limitations and service ownership agreed? | NOT_REVIEWED |

Do not average these answers. A missing mandatory requirement blocks its
promotion/approval regardless of how many other rows passed. This template is not
a replacement for the actual readiness gate or the customer/legal decision.
