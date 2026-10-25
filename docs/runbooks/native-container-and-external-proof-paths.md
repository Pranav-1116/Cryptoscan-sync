# Operator packet — native container and external proof paths

[Guide82 and exact boundaries](../bank-environment/82-native-container-and-external-proof-paths.md) · [Contracts](../api-reference/native-container-and-external-proof-paths.md) · [Validation](../readiness-evidence/native-container-external-proof-2026-10-25.md).

**Do not send credentials or private keys.** Run external operations only in an already authorized account/lab, with assigned operators and independent expected truth. No action here is blanket bank/HSM/Windows/container qualification. Do not install a privileged runtime, change customer deployment permissions or dispatch CI to make a packet pass.

## A. Real owned rootless namespace-container fixture

This is a disposable **ordinary-user Linux x86_64** fixture, not a customer image or general arbitrary-code runner. gcc with static libc, unshare, mount, `/usr/sbin/chroot`, pidfd support and permitted unprivileged namespaces must already exist. Unsupported/native-control failure is refusal, not PASS. No Docker/Podman daemon is used.

First describe and review the exact predefined plan, including C/runner source hashes and resource/expected-truth constraints:

```bash
python scripts/qualify_owned_namespace_container.py --describe-plan > namespace-plan.json
```

The reviewer freezes `plan_sha256` from that public object. Review before executing; do not compute-and-approve an unreviewed changed plan automatically. Then use a new private output:

```bash
python scripts/qualify_owned_namespace_container.py \
  --approved-plan-sha256 "$REVIEWED_NAMESPACE_PLAN_SHA256" \
  --acknowledge-owned-container \
  --output namespace-result.json
```

Exit0 means this specific real fixture passed native control, OCI/package-truth, cancellation and cleanup checks. Exit64 refuses scope/platform/control/truth/output; an empty reserved output is **not** a result. Existing outputs are never overwritten. The runner creates/cleans only its own temporary directory under the user's home, with no customer rootfs/command parameter. No generated executable, private key or full dataset belongs in Git.

Review both normal and held/cancellation runs, namespace IDs, expected byte match, executable inode, denied operations and memory/FD negative results. CPU limit is configured, not an executed CPU-exhaustion test. No independent reviewer acceptance, Docker/Kubernetes/customer release, Windows or production admission follows automatically.

To exercise the same actual native test locally rather than count a skip:

```bash
CRYPTOSCAN_RUN_OWNED_NAMESPACE_TEST=1 python -m pytest \
  services/inventory/tests/test_owned_namespace_container.py -q
```

Without explicit opt-in the actual native case skips; that is not qualification success. Do not loosen expected values/privileges after a failure.

## B. HSM-common public operation-v2 verification

Keep the prior public application/provider log workflow, but use v2 for these exact operation mechanisms:

```text
RSA_PKCS1_SHA256       RSA2048–8192/e65537, PKCS#1 v1.5
RSA_PSS_SHA256         RSA2048–8192/e65537, MGF1 SHA256, salt exactly32bytes
ECDSA_P256_SHA256      secp256r1 only, DER-encoded signature
```

[OperationApprovalV2](../../shared/shared_models/shared_models/schemas/operation-approval-v2.schema.json) requires the original IDs/nonce/window/reviewer reference and distinct application/provider **Ed25519 public logger roots**. `operation_public_key` is canonical base64 of **public SubjectPublicKeyInfo DER**, not a private DER/PEM bundle; `operation_public_key_sha256` hashes the decoded public DER bytes. The public operation key must match the mechanism. A public-key hash alone does not enroll or authenticate its owner.

The application/provider must sign the canonical typed log statements for the **same actual operation**, not reports assembled from unrelated successful probes. `operation_message(approval)` binds the whole approved object. Log events/message/signature hashes, mechanism, approval/app/key/operation/time and both logger signatures are required. Existing v1 Ed25519 remains unchanged; do not relabel its packet as v2.

The existing verifier dispatches on the approved schema version:

```bash
python scripts/verify_operation_evidence.py \
  --approval reviewed-operation-v2.json \
  --approved-sha256 "$REVIEWED_OPERATION_APPROVAL_SHA256" \
  --evidence signed-public-operation-v2.json \
  --state-dir operation-verifier-state \
  --output operation-result.json
```

Use an existing durable owned0700 Linux state directory and new output. Exit0 verifies the operation signature and correlated **signed claims**;64 refuses. It does not attest application execution, actual HSM custody or independent organizations. State must not be reset to bypass replay; retain original public evidence and recover/review an accepted result after interrupted publication.

## C. Optional single-attempt AWS KMS capture

This performs a real authorized **signing action** when run in the operator's SDK environment. It is not executed against a real provider by the shipped local tests. AWS KMS capture is currently the only new live capture profile; other vendor mechanisms remain external public verification inputs, not silently supported SDK capture.

Before running:

1. Approve the exact immutable KMS key ARN (not alias or MRK-format key), matching region, operation/message/nonce, public key fingerprint, mechanism, window and retention. An operator probe is not permission to sign customer data.
2. Wrap the v2 approval in `HsmOperationRequest` with `schema_version=cryptoscan.hsm-operation-request/v1`, `provider=aws_kms`, `region` and `approval`. Freeze the **canonical typed request SHA256** after review, not the raw JSON file hash.
3. Use the existing approved SDK environment/credential mechanism. Never paste access keys/PINs/tokens into request files, command flags or chat. SDK credential resolution stays operator-controlled; this does not qualify that mechanism or provider network path.
4. Create one owned0700 durable attempt-state directory for this authority; don't create another to retry a consumed approval.

```bash
python scripts/capture_approved_hsm_operation.py \
  --request reviewed-hsm-request.json \
  --approved-request-sha256 "$REVIEWED_HSM_REQUEST_SHA256" \
  --state-dir hsm-operation-state \
  --acknowledge-provider-sign \
  --output public-hsm-signature-capture.json
```

The command reserves output and attempt marker before SDK work; it uses the exact region endpoint, disables SDK retries, asks DescribeKey for supported mechanisms and performs the approved Sign. It verifies the returned public signature before writing a success result. No private components or raw provider response/error text are returned.

Exit0: this public challenge signature verified. **No customer-app/HSM-use claim.** Exit64: refused/unsupported/provider/signature/state/output failure; the attempt may already be consumed or the provider may already have signed. Inspect the durable state and provider audit under the existing operator incident procedure; obtain a **new** approval if another attempt is justified. Do not blindly retry, delete markers or reuse the request in fresh directories. SDK authentication may make its own credential-provider requests; “one attempt” refers to this authorization/sign operation, not a claim of one total network packet.

Capture result is `OPERATOR_INITIATED_PROVIDER_CHALLENGE_NOT_CUSTOMER_APPLICATION_TRACE`; it contains no manufactured application/provider log signatures. Actual customer proof still needs customer-generated correlated signed logs and original provider audit/identity/hardware/custody evidence. A valid KMS response is not, by itself, proof of a physical HSM model or firmware.

## D. Estate denominator: every registered asset × six surfaces

Create the authoritative scoped asset register **before collection/comparison**, with asset IDs/platform and independently enrolled producer public Ed25519 keys. Obtain organizational authority/exception review separately; a hash is not authenticity. Freeze register hash and release in `SoftwareEstatePlan`, with one scope per asset for all six named surfaces. See [plan schema](../../shared/shared_models/shared_models/schemas/software-estate-plan-v1.schema.json).

- REQUIRED: expected nonempty identity/version/content-hash records, expected original source SHA256, scope reason.
- NOT_APPLICABLE: explicit reviewed rationale/commitment and no records. All-N/A assets refuse. Genuine empty-surface proofs are not implemented by an empty list; keep those units unresolved or use separately reviewed applicable evidence.
- Source capture must distinguish installed/runtime measurements from declarations. A language lockfile or signed assertion is not runtime evidence just because its file is hashed.

Actual assigned producers return signed `EstateSurfaceStatement` objects, binding plan/release/asset/surface/source/time/status/records. Packet does not supply its own trust keys. Store original public source bytes under their lowercase64-hex SHA filenames in the artifact directory. Statements cover canonical typed JSON. FAILED/UNAVAILABLE/DECLARED_ONLY cannot satisfy a measured unit or assert zero software.

```bash
python scripts/reconcile_software_estate.py \
  --plan reviewed-estate-plan.json \
  --approved-plan-sha256 "$REVIEWED_ESTATE_PLAN_SHA256" \
  --packet signed-estate-returns.json \
  --artifacts original-public-software-sources \
  --output estate-reconciliation.json
```

Exit0 matches all REQUIRED signed reported record sets against the agreed register. Exit2 writes a blocked gap report;64 refuses invalid scope/signature/source/window/output. The command never scans or invokes package tools. Read limits: plan/packet4MiB each, each source2MiB, aggregate sources16MiB; model scope at most20 assets/120 units and20,000 expected records. Oversized scope must not be truncated and called complete.

Inspect required/matched/N/A counts and every unit. Missing/non-measured observed counts are null, not package absence. Generic source semantics/producer truth and authoritative estate coverage are **not** verified; `whole_estate_software_complete` remains false even on an exact signed match. Stronger supported package/OCI parsers and independent review remain necessary. No BOM observation or `USES_HSM` edge is manufactured from this supporting report.

## E. Actual Windows/operator acceptance still required

Use the [existing bounded Windows qualification packet](windows-bounded-qualification-packet.md) on an ordinary-user **actual supported Windows host**, with the original independently prepared expected truth, reviewed source lock and frozen preflight. Run `capture_native_qualification.py --category windows` there—not on Linux/Wine or by relabeling a snapshot. Source-lock file SHA256 in that packet is distinct from the canonical typed request hashes above.

Return the original public target/plan/preflight/source binding/native snapshot and approved adverse/resource/ACL/handle results through the [assigned operator workflow](../bank-environment/68-assigned-operator-qualification-workflow.md); preserve failures. Separate assessor and bank acceptance remain required; signatures authenticate approved-key statements, not corporate independence or unforgeable native execution. Never send credentials/private keys. This repository checkout cannot supply customer Windows/hardware access or manufacture those returns.
