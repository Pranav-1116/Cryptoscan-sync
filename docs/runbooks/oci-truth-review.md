# Operator runbook — pre-capture customer-image expected truth

This is the next step after [OCI job intake](oci-job-intake.md). It implements scoped precommit/review/reconciliation, not genuine external evidence or bank acceptance by itself. Read [Guide 84](../bank-environment/84-precommitted-customer-image-truth.md) and [the API](../api-reference/oci-truth-review.md).

## 1. Assign actual scope and humans

Use an existing authorized exact-estate OCI target and READY revision-1 job. Agree the selected inputs and independent expected source **before collection**. Provision a real, different reviewer with current `assurance.review` authority and selected-estate membership. Obtain that actual user's ID through existing approved administration; do not invent IDs or share authentication tokens in chat.

The bank must establish that the source/register and reviewer are genuinely authoritative/independent. Two accounts alone do not establish two people or independent organizations. This software checks account/session/assignment separation, not corporate/legal independence.

## 2. Build expectations independently

For every input in the exact original target order, provide:

- its original `ImageInput` ID/kind/path;
- SHA256 of the **original expected metadata file bytes**;
- the expected full typed facts;
- a public approved source/build-register reference.

Obtain these from the customer's independently controlled build/package/source inventory, not from a first collector run relabeled as independent truth. Preserve authoritative release/image commitments and original source provenance under the bank's evidence policy. A supplier statement or build SBOM may be declared/imported evidence, not automatically observed full-image truth.

Only selected metadata is covered: package DB records, public certificate/TLS configuration, OS declarations and binary magic. Expected facts cannot assert runtime use, physical hardware, live endpoints or complete image coverage. Large/unsupported/unavailable inputs must remain gaps; do not silently remove them to obtain a match. Arbitrary language dependencies, unpackaged files and loaded production code need their own authorized evidence.

Use the [proposal schema](../../shared/shared_models/shared_models/schemas/oci-truth-proposal-v1.schema.json). Copy `target_sha256` and `target_record_sha256` from the exact READY job. Set `reviewer_user_id` to the assigned real user and `expected_job_revision=1`.

## 3. Precommit and review before handoff

Using the existing authenticated approved client:

1. `POST /api/v1/collection/oci/jobs/{job-id}/truth` with the expected-truth proposal.
2. A **different assigned reviewer** inspects source commitments, expected facts, scope and original source authority.
3. That reviewer calls `POST .../truth/approve` with revision 1, a public decision reference and an actual review reason.
4. Retain the immutable proposal/approval and its exact hashes.

The declared plan blocks handoff while unapproved. Neither the proposer nor an unassigned privileged administrator may approve it. Once approved, neither proposal nor approval is editable. If the expected truth was wrong, preserve that record and use a separately authorized new target revision/job—not an after-the-fact replacement hiding a failed result.

## 4. Capture and intake the original return

Follow the existing [bound capture workflow](oci-job-intake.md): explicit handoff, ordinary-user local CLI, agreed target/binding hashes, original `OciJobReturn`, and atomic intake. No image execution, daemon access, remote registry pull or credentials/private keys are required here.

Keep the reviewer different from the actual evidence uploader too. Approval must precede the retained handoff issue time. Adding truth after observing the returned facts is refused. A reviewer who later loses current permission/membership cannot continue qualifying the evidence, although the historical original return remains readable.

## 5. Compare, retain and interpret correctly

`GET /api/v1/collection/oci/jobs/{job-id}/truth/reconciliation` compares the preserved expectation and the original retained return without accessing images or rescanning.

Review each input, not just the top-level verdict:

- source hash mismatch: no record comparison; missing/unexpected counts stay unknown;
- unavailable/failed receipt: no absence conclusion and observed count stays unknown;
- records differ: exact missing/unexpected multiset counts remain explicit;
- all selected sources and full typed fact multisets match: scoped metadata match only.

`MATCHED_SEPARATELY_REVIEWED_METADATA` is **not** `INDEPENDENT_CUSTOMER_TRUTH_CERTIFIED`, `ESTATE_COMPLETE`, `USES_HSM` or `BANK_PRODUCTION_ACCEPTED`. All broader acceptance/completeness/authenticity flags stay false; runtime use remains unknown. Do not convert OS/config declarations into effective runtime observations.

Retain the original plan, review, return, comparison, approved release, authoritative source records and real organizational review/custody evidence through the bank's approved evidence system. Do not publish bank images/configs, keys, credentials, session tokens or sensitive internal inventory in a public PR. Public witnesses in this repository are synthetic only.

## 6. Execute the other external gates separately

The [Guide 84 matrix](../bank-environment/84-precommitted-customer-image-truth.md#remaining-requested-proofs-existing-paths-and-required-original-returns) identifies existing Windows, estate, container, HSM-operation and independent-review tools. Their original authorized operator returns and bank acceptance are still required. No account approval, nonce, metadata match, signature or public fixture can manufacture those physical/customer outcomes. There is no new production-enable endpoint.
