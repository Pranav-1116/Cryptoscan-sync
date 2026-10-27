# Precommitted OCI truth review — engineering evidence, 2026-10-26

## Scope and decision

**Scoped engineering validation PASS; independent customer/physical/bank acceptance NOT established.** The new workflow executed an independently constructed fixture expectation, proposal, separate assigned test-user approval, original local capture/intake and exact reconciliation. It does not establish genuine customer source authority or organizational independence from synthetic test identities.

[Guide 84](../bank-environment/84-precommitted-customer-image-truth.md) · [API](../api-reference/oci-truth-review.md) · [operator runbook](../runbooks/oci-truth-review.md).

No actual bank image, authoritative bank estate register, real Windows/customer container/application/physical-HSM return or bank-acceptance statement was supplied. No provider/customer endpoint was contacted, production setting changed, credential/private key requested or workflow dispatched. Production admission remains closed. The six external requirements are mapped explicitly in Guide 84 rather than reported as completed.

## Publication source and regression

The tested publication candidate is published `209ddeb0cb513344b9caa711581d656b84966e5d` plus this scoped change, assembled in a separate source snapshot. It retains the previously published Windows/TLS/OCI/estate/HSM code even where those files are missing or modified in the user's pending local baseline. Unrelated local edits/deletions are preserved and excluded, not restored or bulk-committed.

| Gate | Result |
|---|---|
| Publication candidate: all shared models, all inventory tests, original OCI HTTP, foundation HTTP, new truth HTTP | **1,779 passed / 22 skipped / 7 warnings**, 102.92 seconds |
| Same candidate on newly owned disposable PostgreSQL: existing OCI and new truth contracts/races | **27 passed / 6 warnings**, 41.33 seconds |
| Early new truth HTTP focus, before additive missing-input case | **21 passed / 6 warnings**, 14.57 seconds; final broad gate covers the final source |
| Two new model/Draft schemas | Exact model/schema equality included in broad gate |
| Lint/format, environment consistency, original-return/model/schema/witness consistency, local doc links and staged-source integrity | Checked before publication |

Gates overlap; do not sum them. The new broad cases include **22 truth HTTP cases and 12 shared truth schema/validation cases**. PostgreSQL adds ten truth cases to the existing seventeen OCI cases. No frontend, dependency manifest, database schema/migration or new service changed. Full-repository/frontend/HA/performance/SLA/physical qualification were not rerun or claimed.

The 22 skips are existing explicit gates: ten optional actual-hybrid provider cases, ten actual Windows platform/session/interface cases, one opt-in owned native namespace execution case and one missing optional PyOpenSSL adapter. None is a qualification PASS. Existing deprecation/model-shadow and deliberate malformed-fixture serialization warnings remain. The PostgreSQL helper's runtime-directory fallback warning does not skip database execution.

## New controls actually executed

- Exact authorized target and target-record binding; all approved input IDs/kinds/paths appear once in original order.
- Nonempty bounded full typed expectations and source commitments, with strict revisions and no runtime-use/customer-verified claim fields accepted.
- Proposal before handoff; assigned different current selected-estate reviewer; proposer/unassigned administrator/foreign reviewer refusal.
- Write-once proposal/approval; pending truth blocks handoff rather than allowing review after seeing capture.
- Current reviewer authority revalidation, reviewer distinct from actual evidence uploader, approval timestamp before retained handoff.
- Original job/authorization/return and truth proposal/approval hash-chain revalidation; changed rows refuse.
- Exact full typed fact multiset comparison, not merely count/package name; changed version produces explicit missing/unexpected counts.
- Wrong source digest prevents comparison and leaves missing/unexpected counts unknown.
- Missing source receipts preserve unknown observed/missing counts and `asset_absence_proven=false`.
- No plan, unapproved plan, missing return, revoked reviewer authority and identity/order conflicts are explicit blockers.
- Proposal/approval audit failures roll back their transitions.

## PostgreSQL races actually executed

[New PostgreSQL tests](../../services/api/tests/unit/test_oci_truth_postgres.py) exercise:

- duplicate approval: exactly one 200 and one 409, one approval audit entry;
- concurrent approval/handoff: handoff either waits for approval or refuses pending review; successful handoff audit sequence follows approval;
- separate review, immutable records, uploader separation, current reviewer demotion, partial-input unknowns and audit rollback.

The same run also repeats the existing actual PostgreSQL duplicate-intake, revoke/update/cancel races and row-lock timeout checks. The target mutex serializes the new review/handoff operations. Reviewer eligibility checks use the existing current user/membership records; technical account separation is not proof of distinct people or independent organizations.

The [owned PostgreSQL helper](oci-truth-review-2026-10-26/run-owned-postgres.py) creates a new local server and per-case disposable databases, never consumes a customer DB URL, and stops/removes only its own temporary data. [Cleanup](oci-truth-review-2026-10-26/postgres-cleanup.txt) completed.

## Public synthetic witness

[Expected truth](oci-truth-review-2026-10-26/public-witness/expected-truth.json), [assigned-user approval](oci-truth-review-2026-10-26/public-witness/review.json), [original bound return](oci-truth-review-2026-10-26/public-witness/original-return.json) and [comparison](oci-truth-review-2026-10-26/public-witness/comparison.json) were retained from the actual HTTP/CLI workflow.

The expected source bytes and typed facts were constructed from independent **fixture constants**, not copied from scanner predictions: one known `openssl` package record, declared Debian OS/version and a tiny synthetic ELF-magic file. This is independent fixture construction, **not independently certified customer truth or a real cryptographic library**. User IDs, source references, `system-a`/`prod` labels, paths and source windows are synthetic/ephemeral test scope. No tokens, credentials, private keys or real bank data are retained.

The comparison matches three selected inputs and verifies technical actor separation. It deliberately keeps false for customer independent truth, source authenticity, organizational independence, whole image/estate completeness, bank production acceptance and production execution qualification. Runtime use remains unknown. These flags cannot be promoted by a perfect local match.

## Retained integrity and reproduction

[Publication log](oci-truth-review-2026-10-26/publication-tests.txt) / [JUnit](oci-truth-review-2026-10-26/publication-tests.xml), [PostgreSQL log](oci-truth-review-2026-10-26/postgres-tests.txt) / [JUnit](oci-truth-review-2026-10-26/postgres-tests.xml), [static checks](oci-truth-review-2026-10-26/static-checks.txt), [test environment](oci-truth-review-2026-10-26/test-environment.txt) and [integrity manifest](oci-truth-review-2026-10-26/evidence-manifest.json) identify exercised source/artifact commitments. SHA256 is unsigned integrity, not authenticity, protected custody or independent acceptance.

With approved dependencies and all repository service/shared roots plus `services/api/tests/unit` on `PYTHONPATH`:

```bash
python -m pytest shared/shared_models/tests services/inventory/tests \
  services/api/tests/unit/test_oci_collection_api.py \
  services/api/tests/unit/test_collection_foundation.py \
  services/api/tests/unit/test_oci_truth_api.py -q
python docs/readiness-evidence/oci-truth-review-2026-10-26/run-owned-postgres.py
```

`CRYPTOSCAN_OCI_TRUTH_WITNESS_DIR` optionally retains four public synthetic witness files from the positive test. It is a test-artifact mechanism, not a signer, customer capture endpoint or permission to export bank data.

## Remaining actual external acceptance

Use the authorized operator paths and required original returns in [Guide 84](../bank-environment/84-precommitted-customer-image-truth.md). No software-only comparison can create missing authoritative customer inventories, real devices/platforms, independently trusted reviewers or bank release authority. Those remain unproven until actual scoped evidence, trust/custody and review are supplied. No production-enable endpoint or automatic observed HSM/deployment relationship was added.
