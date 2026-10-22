# 2. Improve correctness, evidence and all six BOMs

[Pack index](README.md) · [Previous: baseline](01-baseline-and-priorities.md) ·
[Next: security](03-security-privacy-and-isolation.md)

## 2.1 Objective: make existing answers defensible

The most important quality improvement is not finding more things. It is making
an existing answer reproducible: **which bytes, which release, which estate,
which time, which method, which interpretation and what remains unobserved?**

The existing implementation already separates observations, reviewed assertions
and later proofs. Recommended work is to exercise this consistently across
storage, read models, UI, exports and the customer journey—not introduce a second
identity or evidence system.

## 2.2 Input to evidence: the correctness chain

| Stage | Preserve/check | Failure that must stay visible |
|---|---|---|
| Scope | Independent register revision, target identity, permission and expected method | Not attempted, blocked or unsupported target; unknown register completeness |
| Input | Source identity, original-file digest, artifact digest, distinct SBOM document hash | Missing/changed bytes, ambiguous version, disallowed path or oversized input |
| Execution | Current principal/estate, admitted policy/approval, job/attempt/stage and times | Revoked authority, failure, interruption, partial work, UNKNOWN external outcome |
| Observation | Original algorithm/mode/size/purpose/location and parser receipts | Unknown purpose, incomplete receipts, unsupported syntax, refused material |
| Normalization | Versioned deterministic mapping, attributable deduplication and retained originals | Ambiguous identity or lost provenance; matching names are insufficient |
| Relationships | Allowed typed endpoints, exact owner, supporting evidence, validity and separate review | Missing/retracted/expired edge; declared relation is not observed runtime use |
| Presentation | Same scoped meaning in API, browser and retained export | Stale snapshot, inaccessible source proof or unavailable dependency |

### A concrete failure to test, not a claim of a current bug

A scan attempts ten independently registered source targets. Eight complete, one
is denied and one has an unsupported input. The view must not say “100% complete”
because eight scan outputs were returned. It should reconcile the ten expected
targets with actual current states and limitations. If one observation later
expires, freshness changes; the original successful run is not erased.

Use the [expected-estate ledger](../bank-environment/48-expected-estate-coverage-ledger.md).
Its target states are OBSERVED, STALE, BLOCKED, UNSUPPORTED and NOT_ATTEMPTED;
register completeness itself is a separate owner assertion.

## 2.3 Improvement checklist for each BOM

| BOM | Improve the existing quality of | Required negative checks | Acceptance evidence |
|---|---|---|---|
| **SBOM** | Exact artifact-to-document binding, resolved component versions, package identities, bounded dependency parsing and unresolved counts | Same package name/different version; stale binding; wrong artifact; malformed/nested input; missing version | Trace exact release artifact → separately hashed SBOM → exact versioned package. No package/deployment claim from name alone. |
| **CBOM** | Correct algorithm, purpose, mode/size, location, policy and original-file receipts | Crypto import without use; nonsecurity checksum; unknown mode; incomplete source; moved/deleted site; hardcoded-key evidence with “test” context | Reproduce the observation from retained bytes; contextual review does not mutate original evidence or invent invocation. |
| **NBOM** | Exact endpoint/port/SNI/STARTTLS, method, observation time and successful phase receipt | Open port without TLS result; wrong virtual host; partial probe; stale receipt; static binary socket symbol | Clearly distinguish observed network result from declared/static capability; only the exact observed endpoint can support its approved predicate. |
| **TechBOM** | Application/system → deployment → artifact identity and typed attributable links | Same-name applications; different estate/build; declared deployment; expired/retracted relationship | Trace a relation's origin and reviewer. Missing linkage stays unresolved; a declaration does not become independently verified deployment/runtime dependency. |
| **HBOM** | Exact hardware/product/firmware/operating-mode metadata and source of each field | Model string without firmware; unknown module mode; supplier claim presented as attestation | Retain what was declared, observed or unknown. No hardware-backed/certified claim from a product label. |
| **VBOM** | Supplier/product/version/build identity, signed origin, expiry, quarantine and separate review | Wrong customer/build; expired/revoked signer; malformed payload; valid signature over incorrect assertions | Origin and payload integrity are separate from factual truth, independence and certification. Invalid evidence remains quarantined/refused. |

The six BOMs are complementary, not six interchangeable exports of the same
truth. Vulnerability findings are additional assessments; they do not replace
VBOM or SBOM. The [existing six-BOM contract](../bank-environment/49-six-bom-evidence-paths.md)
keeps `deployed_verified`, `invocation_verified` and `runtime_verified` false
where the evidence does not independently establish those facts.

## 2.4 Source receipts and completeness

The scanner schema carries `file_observation_receipts`,
`file_receipts_complete` and `file_receipts_scope`. The default scope is
PRIMARY_DISCOVERED_SOURCE_FILES_ONLY and completeness defaults false.

Improve/verify consumers so that:

1. Missing legacy fields do not default to a complete estate.
2. An empty receipt list does not establish successful parsing.
3. File hashes refer to the admitted original file, not a temporary staging name.
4. Parser receipts remain linked to the exact completed job and source evidence.
5. A primary-file completeness claim does not extend to imports, dependencies,
   binaries, deployment, runtime or unregistered bank systems.
6. Truncation/resource refusal is visible, not normalized away by a summary count.

Do not relax receipt requirements to make a remediation example turn green.

## 2.5 Improve accuracy with reviewed data, not more rule counts

Use the existing [customer-reviewed accuracy workflow](../bank-environment/50-customer-reviewed-accuracy-workflow.md):

1. Agree what a reviewable unit is for each existing source class; record both
   positive and negative units, not only findings emitted by the scanner.
2. Freeze authorized source material, byte hashes, scope and review instructions.
3. Independently review labels; distinguish absence, uncertainty and unavailable
   evidence. Adjudicate disagreement rather than silently choose a favorable label.
4. Report per-class confusion counts and unreviewed/blind-spot counts. Undefined
   rates stay undefined; never substitute 100% for a zero denominator.
5. Correct the specific parser/normalizer/context defect and retain a regression.
6. Evaluate a held-out partition collected under the approved workflow. Do not
   tune on it, pool away poor classes or reuse a pre-review run as a fresh repeat.
7. Recheck on a later build and compare the same denominators and source classes.

Precision and recall, when labels and denominators actually support them:

- precision = true positives / (true positives + false positives);
- recall = true positives / (true positives + false negatives).

A finding-only review cannot establish recall. Synthetic fixtures establish
regression behavior, not customer-estate accuracy. No target percentage is
predeclared here; the customer and technical reviewer must agree a meaningful
class-specific acceptance threshold before seeing the result.

## 2.6 Improve interpretation without falsifying observations

Use the existing [purpose/applicability contract](../bank-environment/51-purpose-and-applicability-assessments.md).
A nonsecurity MD5 checksum should not automatically receive the same migration
recommendation as production security-integrity use. But a contextual assertion
must not overwrite the original signing/authentication observation or hide an
independent hardcoded-key concern.

Similarly:

- RSA certificate signatures are not automatically negotiated key exchange.
- A package version in a declared affected range is not proof of exploitability.
- A FIPS label is not exact module/version/mode validation.
- A supplier signature is not independent assessor evidence.

The current bounded package-range lane has explicit semantics; do not expand
unsupported ecosystem/version-range meaning by guessing during normalization.
Fix misleading projection/wording within existing surfaces instead.

## 2.7 Preserve condition-level remediation meaning

The existing [verification workflow](../bank-environment/54-independent-remediation-verification.md)
requires an approved predicate, reported action and a later exact observation.
Its source predicate is intentionally narrow: same target, original file/site
and purpose, changed source hash, expected observed replacement and explicit PASS.
A moved/deleted site or empty scan does not satisfy that predicate.

Recommended regression matrix:

| Case | Required interpretation |
|---|---|
| Ticket completed, no later scan | Reported complete; not verified |
| Rescan began before the action | Ineligible proof |
| Later scan is empty/partial or lacks the original-file receipt | Inconclusive, never clean-by-absence |
| Approved replacement observed exactly with adequate evidence | Only the approved condition may verify |
| Old condition reappears | Preserve earlier proof and expose current regression |
| Policy/approval/proof revision changes during review | Conflict/stale authority; read current history, do not silently overwrite |

## 2.8 Exit criteria

A different reviewer can reconstruct the selected workflow from actual retained
IDs and bytes; all six BOMs disclose provenance and unresolved paths; coverage
reconciles to an independently registered scope; original evidence is immutable;
negative cases cannot produce false PASS/VERIFIED. The API, browser and export
must agree on those meanings. Missing external truth stays a named limitation.


## 2.8 Implemented bounded package-identity correction

The [second quality increment](../readiness-evidence/quality-package-identity-2026-10-22.md)
reproduced known unresolved build variables, wildcard version segments and
interval versions being treated as exact package identities. The existing helper
now keeps these unknown after PURL decoding. CycloneDX/SPDX import/binding,
current legacy relationship review/trace and cascade identity/count projections
use that correction without modifying original documents or approved history.
A valid supplier signature does not resolve an unknown package version.

Concrete coordinate labels/encoding/qualifiers remain supported; artifact bytes,
deployment, invocation and independent truth retain their own evidence burdens.
This is not a full Package URL/range parser, new version resolver, complete
six-BOM matrix or independent bank accuracy qualification. Actual results and
open review/site work are in the [implementation ledger](IMPLEMENTATION-STATUS.md).
