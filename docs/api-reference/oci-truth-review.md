# OCI precommitted truth API

Extends `/api/v1/collection/oci` under its existing session, selected-estate, residency, streaming body-limit, duplicate-JSON and no-store boundaries. No image is read or executed by these routes. The existing unqualified-production boundary still refuses controlled-production use.

| Endpoint | Input / result | Authority |
|---|---|---|
| `POST /jobs/{id}/truth` | `OciTruthProposal` -> PROPOSED record, 201 | current durable human `assurance.manage` |
| `POST /jobs/{id}/truth/approve` | `OciTruthDecision` -> APPROVED record | assigned different current human `assurance.review` |
| `GET /jobs/{id}/truth` | verified proposal/approval history | selected-estate read |
| `GET /jobs/{id}/truth/reconciliation` | source/record reconciliation against original retained return, or explicit blocker | selected-estate read |

[Proposal schema](../../shared/shared_models/shared_models/schemas/oci-truth-proposal-v1.schema.json) · [decision schema](../../shared/shared_models/shared_models/schemas/oci-truth-decision-v1.schema.json).

## Proposal

- `expected_job_revision`: strict integer 1; only READY, pre-handoff jobs.
- `target_sha256`, `target_record_sha256`: exact original target and authorized revision commitments from the job.
- `reviewer_user_id`: actual provisioned current selected-estate reviewer ID, different from proposer. Do not fabricate an ID.
- `source_reference`: bounded public reference to the independently obtained expected source.
- `expected`: every approved input in order, 1–16 entries, each with original typed `source: ImageInput`, `expected_content_sha256` and 1–1000 full typed `HostFact` expectations. Total expected facts ≤1000; duplicate source identities/paths refuse.

Facts must match their source kind and the existing metadata-only constraints. `runtime_use=OBSERVED`, invented input kinds, customer-verification flags, empty expectations and booleans used as revisions refuse. Unknown extra fields are forbidden. JSON Schema checks structural shape; Python validators and the workflow additionally enforce relational scope/order, exact authorization and identity separation.

## Approval and handoff

`OciTruthDecision` contains strict `expected_revision=1`, public `evidence_ref` and a 20–500-character reason. The assigned current reviewer, not the proposer or an unassigned administrator, approves the sole proposal. A third party's role alone cannot replace the assignment. Approval is write-once and requires the same exact job still READY with current authorization.

A declared truth plan blocks `/jobs/{id}/handoff` until approved by a currently eligible reviewer. The existing target mutex serializes approval/handoff. Legacy jobs without a declared plan retain their original capture behavior, **but their truth reconciliation is explicitly blocked**, never accepted by default.

## Reconciliation

The read verifies complete bounded truth, job, target and original-return histories using the existing hash links. It checks exact proposal/approval commitments, assigned/proposed/approved actors, current reviewer permission/membership, approval-before-handoff time and reviewer distinctness from the actual evidence uploader. It then calls the pure `compare_image_truth` function; no filesystem/network/collector operation occurs.

Verdicts:

- `BLOCKED_NO_PRECOMMITTED_TRUTH`
- `BLOCKED_TRUTH_NOT_APPROVED`
- `BLOCKED_NO_ORIGINAL_RETURN`
- `BLOCKED_REVIEWER_NO_LONGER_AUTHORIZED`
- `BLOCKED_REVIEW_IDENTITY_OR_PRECOMMIT_ORDER`
- `BLOCKED_EXPECTED_TRUTH_MISMATCH_OR_GAPS`
- `MATCHED_SEPARATELY_REVIEWED_METADATA`

Corrupted hashes, changed authorization/denominator bindings or malformed retained records refuse with 409 rather than returning a matched verdict. Out-of-estate records return 404; missing current write permission returns 403; bad typed input returns 422. Historical original evidence remains available after reviewer demotion/revocation even when qualification is blocked.

Each compared input reports receipt status, expected/observed record counts, source-match/comparison flags, exact multiset match, missing/unexpected counts, and `asset_absence_proven=false`. Unavailable receipts have `observed_records=null`; incomparable sources have missing/unexpected counts `null`, not zero. Full typed facts are compared by canonical multiset, not just count or package name.

`identity_separation_verified` can be true only for the technical actor separation checks. Even for a metadata match, the response retains false for customer independent truth, organizational independence, source authenticity, whole image/estate completeness, bank production acceptance and production execution qualification. Runtime use remains unknown. The response is not CycloneDX, a device attestation, a trusted producer signature or an independent certification.

See [Guide 84](../bank-environment/84-precommitted-customer-image-truth.md), [operator steps](../runbooks/oci-truth-review.md) and [validation](../readiness-evidence/oci-truth-review-2026-10-26.md).
