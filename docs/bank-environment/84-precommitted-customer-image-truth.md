# 84. Precommitted, separately reviewed customer-image metadata truth

## What this builds — and what cannot be manufactured

The [OCI intake](83-tenant-scoped-oci-job-intake.md) preserved an authorized original return but did not establish independently expected metadata. This increment adds a pre-capture expected-truth register, a separately assigned current human reviewer, immutable approval and exact source/record reconciliation over that original return.

**It does not produce genuine customer evidence, authoritative bank estate completeness, native Windows/customer-container/application/physical-HSM execution, organizational independence or bank production acceptance inside a Linux development sandbox.** None of those original operator returns or customer-specific authority records was supplied for this run. The tests use synthetic identities/images and do not turn their `prod` scope label into customer production evidence. Production admission remains closed.

## Built path

```text
Exact authorized OCI target -> READY job
  -> expected source hashes + typed facts for every approved input
  -> assigned different current estate reviewer approves write-once plan
  -> handoff (a declared plan blocks handoff until separately approved)
  -> ordinary-user offline original capture and atomic intake
  -> exact expected-vs-original source commitments and fact multisets
  -> scoped matched/mismatch result, with all global acceptance flags false
```

[Typed contract](../../shared/shared_models/shared_models/oci_truth.py) · [existing-store workflow](../../services/api/api/assurance/oci_truth.py) · [HTTP router](../../services/api/api/routers/oci_collection.py) · [API contract](../api-reference/oci-truth-review.md) · [operator runbook](../runbooks/oci-truth-review.md) · [retained validation](../readiness-evidence/oci-truth-review-2026-10-26.md).

No new scanner, service, database, migration, dashboard or generic execution interface is introduced. Existing standalone capture, six-view materialization and native/HSM/estate qualification paths remain unchanged. New truth records use the existing hash-linked assurance/audit store.

### Scope, identity and timing

- Propose only for the exact authorized **READY revision-1 job**, before handoff. Every target input appears exactly once in its original order with its exact kind/path, expected source SHA256 and nonempty typed expected facts.
- The plan binds both the canonical target and its exact authorization-record digest. Omitting an inconvenient input, reordering/reassigning sources or copying truth onto another authorization refuses.
- `assurance.manage` proposes; the assigned human needs current `assurance.review` permission and selected-estate membership. The proposer cannot be the reviewer; an unassigned superadministrator cannot substitute for the assigned reviewer.
- The proposal/approval is write-once. A declared but unapproved plan blocks handoff. Target locking serializes approval/handoff and duplicate approvals.
- Comparison requires approval before the retained handoff's issue time. The reviewer must differ from the evidence uploader, and must still have current review authority. Demotion does not delete original evidence, but blocks its current qualification result.
- An authorization or metadata match does not prove organizational independence. Two accounts can belong to one person; a legitimate reviewer can receive false source information.

### What a match actually means

`MATCHED_SEPARATELY_REVIEWED_METADATA` means:

1. selected-estate user/session identity and approval separation checks passed;
2. immutable precommit, authorization, original handoff/return and record hashes revalidate;
3. every approved source receipt parsed and matched its precommitted byte digest;
4. its **full typed fact multiset**, including duplicate counts, matched the expectation.

A changed source prevents record comparison. A missing/failed receipt has unknown observed/missing counts, not zero and not absence. Unexpected and missing records remain explicit. An old capture cannot acquire a post-hoc reviewed plan.

`identity_separation_verified=true` is only technical account/actor separation. `customer_independent_truth_verified`, `organizational_independence_verified`, `source_authenticity_verified`, `whole_image_software_complete`, `whole_estate_complete`, `bank_production_accepted` and `production_execution_qualified` remain **false**, even after a perfect selected metadata match. Runtime use remains `UNKNOWN`.

This is not a whole-image completeness certificate: approved package databases, ELF/PE magic, OS declarations, public certificates and literal TLS configuration do not cover arbitrary source/language dependencies, loaded production code or every image file. None of these records creates an operational `USES_HSM`, actual deployment, observed network session or physical hardware edge.

## Remaining requested proofs: existing paths and required original returns

The previously published tools below are already on GitHub. Some are intentionally absent/modified in the user's pending local baseline; this increment does not restore or publish those unrelated changes.

| Requested outcome | Existing executable path | Still needed from authorized operators / independent authority |
|---|---|---|
| Independent customer-image truth | New precommit/review API + existing `capture_oci_job_evidence.py` | Original approved customer return; independent build/source inventory and source commitments; real reviewer authority and assessment, not scanner-derived expected facts |
| Authoritative estate completeness | [Signed asset × six-surface reconciliation](https://github.com/ZKChainForge/CryproScan/blob/209ddeb0cb513344b9caa711581d656b84966e5d/scripts/reconcile_software_estate.py) | Bank-authorized denominator, actual sources across all six software surfaces per asset, justified exceptions and independent register/producer trust. A signed incomplete register is still incomplete |
| Genuine Windows evidence | Existing `capture_native_qualification.py` and [native qualification packet](https://github.com/ZKChainForge/CryproScan/blob/209ddeb0cb513344b9caa711581d656b84966e5d/docs/bank-environment/67-native-quotes-and-independent-qualification.md) | Original actual Windows target/plan/snapshot and independently expected native interface truth; Linux, Wine or an asserted platform name cannot substitute |
| Actual customer-container qualification | Existing image/runtime candidates and [owned fixture boundaries](https://github.com/ZKChainForge/CryproScan/blob/209ddeb0cb513344b9caa711581d656b84966e5d/docs/bank-environment/82-native-container-and-external-proof-paths.md) | Customer-approved platform/workload identity, original controls/denial/cancellation/cleanup results and independent review. A local namespace fixture does not qualify customer Docker/Kubernetes |
| Customer application / physical HSM | [Approved operation capture](https://github.com/ZKChainForge/CryproScan/blob/209ddeb0cb513344b9caa711581d656b84966e5d/scripts/capture_approved_hsm_operation.py) and operation-v2 verifier | Authorized original operation, public-key/signature and correlated app/provider records; independently established physical-device/provider custody. Software signatures and KMS attributes alone are insufficient |
| Bank production acceptance | Existing `verify_independent_host_qualification.py` / reviewer policy | Actual assessor/bank-acceptor decisions and signatures over the exact release, scope and original artifacts, independently provisioned trust/custody and agreed release controls. Signature validity alone is not organizational independence or production activation |

These are distinct gates. The new image-truth match does not satisfy the other five. Software cannot create authoritative customer scope, physical devices, independent people or legal/operational bank acceptance by setting a flag.

## Bank acceptance is not an automatic switch

There is deliberately no endpoint to set `production_accepted=true` or bypass the existing controlled-production boundary. A local test result, matching hash, public challenge, additional account or signed checkbox does not turn an unqualified adapter into a production executor. Actual operator returns must be reviewed within the agreed customer's scope and release process.

Use approved transfer/intake channels for customer evidence. Do not send credentials/private keys, post sensitive bank images/configs to chat or a public PR, or replace original source commitments with unacknowledged redacted bytes. Only synthetic public engineering witnesses are retained here.
