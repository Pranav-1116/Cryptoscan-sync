# Operator packet — actual hybrid, signed operation correlation, software truth

[Scope/limits](../bank-environment/81-actual-hybrid-operation-and-software-truth.md) · [Contracts/API](../api-reference/hybrid-operation-software-evidence.md) · [Local engineering evidence](../readiness-evidence/hybrid-operation-software-2026-10-25.md).

**Public evidence only. Do not send credentials, private keys, session secrets or TLS key logs.** The local proofs do not qualify your endpoint, HSM, application, Windows host, container fleet or production release. Use existing assigned-operator approvals and secure evidence return; don't broaden collection or change customer systems for this packet.

## A. One approved actual-hybrid TLS session

1. Agree the exact numeric address/port, canonical SNI, TLS 1.3, X25519MLKEM768, independently reviewed public peer DER SHA-256, environment, authorization window, byte budget and retention. Obtain the full reviewed `TargetSpec` and canonical SHA-256, not only a manifest hash. Keep original approval/target as evidence. IPv4 example URI:

   ```text
   tls-hybrid://<numeric-address>:<port>/sni/service.example/version/TLSv1.3/group/X25519MLKEM768/peer/sha256/<64-lowercase-hex-public-pin>
   ```

   Kind `NETWORK_TLS13_HYBRID`, method `network`, operation `OBSERVE_APPROVED_TLS_SESSION`; no credential reference. IPv6 must use brackets. **Do not use documentation placeholders as runnable approved targets.**
2. In a separate reviewed operator environment, install the optional pinned provider if approved:

   ```bash
   python -m pip install -r requirements-hybrid-tls.txt
   ```

   This is not permission to upgrade a customer environment or declare dependencies/FIPS qualified. No base workflow/dependency change is required. SDK >=26.4.0, embedded OpenSSL >=3.5; the retained engineering witness exercised the exact pinned versions on Linux only.
3. Use an ordinary account, a private working directory and a new output path:

   ```bash
   python scripts/collect_tls_session.py \
     --target approved-hybrid-target.json \
     --approved-target-sha256 "$REVIEWED_TARGET_SHA256" \
     --acknowledge-active-tls --include-hybrid \
     --output hybrid-snapshot.json
   ```

   The provider offers its default groups; only observed 4588 on the pinned completed session is positive. Classical fallback is a gap, not retried. Unsupported provider refuses before TCP. Approval errors/output collisions refuse. Exit zero means a snapshot was written, **not that every receipt succeeded**: inspect PARSED/status/reason and preserve failures. Never change an expected pin/group to make a result pass without a new review.
4. Return the original target, reviewed digest, snapshot and normal operator/source context via existing secure intake. Authorized existing host approval/intake and `/tls-session/cyclonedx-1.6` apply. Intake does not authenticate producer execution or preserve the full target by itself; retain it separately. Export is stored-only, official-schema gated, and does not reconnect. No API network job is newly admitted.

Raw public ServerHello includes correlation-sensitive random/session-ID/public share material; handle it under approved retention even though it is not a private key. One session says nothing about all groups/versions or application/PQC readiness.

## B. Application/provider operation public packet

This profile verifies **Ed25519 only**, using a public operation key and two distinct pre-enrolled public logger keys. It does not wrap arbitrary existing vendor log formats and does not itself call an HSM. Unsupported RSA/ECDSA/provider audit exports remain unverified; do not relabel them.

### Before operating

- Obtain approval for the exact application ID, provider key ID, operation ID, mechanism, fresh 32-byte public nonce and bounded time window. Approve an explicit signing action through the existing operator procedure; never sign arbitrary application/customer data for this check.
- Separately enroll/review the **application-log**, **provider-log**, and **operation** public Ed25519 keys. All three must differ. Public raw 32-byte keys are canonical base64 (44 characters); no private/public-key bundle or credentials.
- Build `OperationApproval` using `operation-approval-v1.schema.json`: `approval_id`, `application_id`, `provider_key_id`, `operation_id`, `nonce_hex`, three public-key fields, `mechanism=ED25519`, offset-aware `not_before`/`expires_at`, `reviewer_reference`.
- Have the reviewer freeze the canonical model hash. Hashing alone does not authenticate the reviewer or enroll a root. Do not derive trust roots from the evidence under test.

The existing canonical helpers define exactly what to sign/hash:

```python
from shared_models.operation_evidence import OperationApproval, operation_message
from shared_models.tpm_quote_verification import canonical, sha
approval = OperationApproval.model_validate(public_approved_object)
reviewed_approval_sha256 = sha(approval)  # reviewer separately freezes/approves this
message = operation_message(approval)   # exact domain-separated public challenge
```

Have the **already authorized** application/provider process perform that operation. Return the signature and two separately signed canonical `OperationLog` statements. Required events are `APPLICATION_OPERATION_COMPLETED` and `PROVIDER_SIGN_COMPLETED`; both bind approval hash, app/key/operation IDs, ED25519, SUCCESS, timestamp, SHA-256 of the exact message and SHA-256 of the raw 64-byte operation signature. Each log signature covers `canonical(statement)` after typed model validation, not arbitrary raw JSON formatting. All signatures are canonical base64 (88 characters). No signing code/private key is part of this packet.

### Verify retained public evidence

Run on Linux with a private, owned `0700` state directory and a new private output. Use one durable state directory per verifier authority; don't create fresh directories to bypass replay detection.

```bash
mkdir -m 700 operation-verifier-state
python scripts/verify_operation_evidence.py \
  --approval reviewed-operation-approval.json \
  --approved-sha256 "$REVIEWED_OPERATION_APPROVAL_SHA256" \
  --evidence signed-public-operation-evidence.json \
  --state-dir operation-verifier-state \
  --output operation-verification.json
```

- `0`: cryptographic signature + correlated signed claims verified; original accepted report retained in local replay ledger.
- `64`: refused scope/hash/window/signature/replay/state/output. No provider action occurred in this verifier. Existing outputs are never overwritten. A refused/crashed output can be empty; it is **not** a valid result. Do not delete an accepted ledger entry to retry; recover/review its retained public report and any interrupted publication.

A positive result is **IMPORTED_SIGNED_CLAIMS**, not attested application execution, organizational independence or physical HSM. Capture real provider-native audit/custody evidence and obtain independent review separately. If all signatures came from an operator software fixture, label it as such. The shipped local proof is explicitly software-only. Existing SUBMITTED `sign_challenge_ok=true` and legacy `sign_challenge=OK` cannot satisfy this verifier.

## C. Agree every package-database input, then reconcile

The `software-truth-plan-v1.schema.json` register requires manifest SHA-256, reviewer reference and one row per approved dpkg/APK/RPM input with exact input ID/kind, independent source commitment, and expected package names/versions. Every approved package input must appear; duplicate counts cannot be silently collapsed. Unsupported/ambiguous identities remain blocked. No empty-register proof of a clean host.

Define expected truth through independent maintained records/read-only approved tools and review **before comparison**. Do not populate the expected list from the snapshot merely to obtain a green result. This profile does not cover language packages, unpackaged/loaded code, images or firmware.

```bash
python scripts/reconcile_software_truth.py \
  --plan reviewed-software-truth-plan.json \
  --approved-plan-sha256 "$REVIEWED_PLAN_SHA256" \
  --snapshot retained-host-snapshot.json \
  --output software-truth-reconciliation.json
```

- `0`: every agreed package-record multiset and committed source matches a PARSED receipt.
- `2`: valid comparison, missing/unexpected/version/source/status gaps; retain the blocked report.
- `64`: invalid scope/reviewed hash/model/output; no rescan or package-manager execution.

Version `null` means unknown metadata, not an inferred version. Source hash and review reference do not authenticate the register or reviewer. Global inventory completeness, runtime crypto/application use, native qualification and production admission stay false/UNKNOWN even on a perfect package match.

## D. Actual Windows/container returns — still required

Use the already assigned operator workflow, pinned source/truth, original native artifacts and separate assessor/bank decisions, not this Linux witness as a replacement:

- [Assigned operator workflow](../bank-environment/68-assigned-operator-qualification-workflow.md).
- [Windows bounded metadata/preflight](../bank-environment/76-bounded-windows-metadata-and-operator-preflight.md).
- [Verified OCI content/runtime and remaining gates](../bank-environment/78-verified-oci-content-and-runtime-candidate.md).

Native Windows means actual supported Windows execution/ACL/buffer/handle/resource negatives plus independently expected truth. Container qualification needs actual approved images/layers/package truth and independently bound runtime identity/cgroup/image/limits, not a synthetic image fixture. Preserve unsupported/failing cases; no blanket PASS or credential request. Existing production admission remains closed pending applicable independent execution/review gates.
