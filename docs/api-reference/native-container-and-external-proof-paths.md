# Native container / operation-v2 / estate proof contracts

[Guide82](../bank-environment/82-native-container-and-external-proof-paths.md) · [Operator packet](../runbooks/native-container-and-external-proof-paths.md).

These are operator qualification/verification entry points, **not new HTTP dispatch, production admission, services, databases or BOM exporters**. Existing tenant/RBAC/custody/official-CycloneDX behavior is unchanged. Supporting signed claims are not automatically OBSERVED collector facts or graph relationships.

## Operation-v2 schemas

- [operation-approval-v2](../../shared/shared_models/shared_models/schemas/operation-approval-v2.schema.json).
- [operation-evidence-v2](../../shared/shared_models/shared_models/schemas/operation-evidence-v2.schema.json).
- [hsm-operation-request-v1](../../shared/shared_models/shared_models/schemas/hsm-operation-request-v1.schema.json).

`OperationApprovalV2` retains the v1 IDs/nonce/window/reviewer/log-root fields and changes:

| Field | Meaning |
|---|---|
| `schema_version` | `cryptoscan.operation-approval/v2` |
| `mechanism` | RSA_PKCS1_SHA256 / RSA_PSS_SHA256 / ECDSA_P256_SHA256 |
| `operation_public_key` | Canonical base64 **public SPKI DER**, <=3072 decoded bytes; private DER/alternate encoding refused |
| `operation_public_key_sha256` | Exact SHA256 of decoded public DER |

RSA2048–8192/e65537; PSS MGF1/SHA256 with32-byte salt; ECDSA P-256 only. Application/provider log roots remain distinct canonical32-byte Ed25519 public keys. V2 operation signatures are bounded canonical base64, max1024 raw bytes; logger signatures remain64 raw bytes. Canonical public key, algorithm/type/curve, exact signature and both correlated logger statements are checked. Existing challenge helper binds the entire approval SHA, including its version, public roots and window.

`verify_operation_evidence.py` dispatches from the **approved approval version**, never an evidence-selected root. V1 schemas/defaults are byte-for-byte unchanged. Unknown version/mechanism, malformed/private keys, wrong fingerprint, operation/nonce/approval/log/signature/algorithm/time and replay/output errors refuse. Positive v2 reports still say IMPORTED_SIGNED_CLAIMS, not attested execution or HSM hardware proof.

### AWS request/capture

`HsmOperationRequest`: `schema_version=cryptoscan.hsm-operation-request/v1`, `provider=aws_kms`, `region`, `approval` (v2). The provider key must be an immutable UUID-format AWS KMS ARN for the same region; aliases/MRK/custom endpoint fields and credentials are unsupported. Approval/schema/hash/window validation and output reservation happen before SDK work.

Existing `AwsKmsBackend` accepts an optional injected client and approved signing algorithm. Legacy calls keep their original algorithm-selection behavior. New capture requires the approved algorithm in DescribeKey's list and refuses a changed returned algorithm. Sign is RAW over the fixed approved challenge, not an arbitrary message. SDK retries are disabled and returned signature must verify against the independently pinned public key.

Capture result:

```json
{
  "schema_version": "cryptoscan.hsm-operation-capture/v1",
  "operation_signature_verified": true,
  "capture_basis": "OPERATOR_INITIATED_PROVIDER_CHALLENGE_NOT_CUSTOMER_APPLICATION_TRACE",
  "application_provider_logs_correlated": false,
  "application_execution_attested": false,
  "hardware_backing_verified": false,
  "application_uses_physical_hsm": "UNKNOWN",
  "production_execution_qualified": false
}
```

Excerpt omits public signature/hashes/mechanism, not a complete object. The Linux private local attempt ledger is reserved before SDK work and remains consumed on crash/failure; a completed public result is retained separately for recovery. This is one verifier-authority state, not distributed idempotency, a guarantee of provider-side completion, general credentials qualification or physical custody. Errors do not emit provider exception text. The captured signature alone does not satisfy the two signed customer/provider logs required by operation-v2.

## Estate schemas and semantics

- [estate-asset-register-v1](../../shared/shared_models/shared_models/schemas/estate-asset-register-v1.schema.json).
- [software-estate-plan-v1](../../shared/shared_models/shared_models/schemas/software-estate-plan-v1.schema.json).
- [software-estate-packet-v1](../../shared/shared_models/shared_models/schemas/software-estate-packet-v1.schema.json).

The plan embeds `asset_register` and its canonical typed SHA256; exact asset IDs/platform/producer pins come from that frozen register. Release, window and reviewer reference are also bound. Every asset must have exactly one scope for each of six surfaces: os_packages, language_dependencies, unpackaged_binaries, loaded_code, container_images, firmware. Missing/duplicate/cross-asset scope fails model validation. Required scopes need nonempty expected records; explicit N/A units cannot carry records; all-N/A assets refuse.

A record consists of `identity`, nullable `version` and nullable `content_sha256`; unknown fields/versions stay unknown, not inferred. Exact multiset comparison retains duplicates. Source commitments pin original nonempty bytes, not their authenticity. Plan max20 assets/120 units/20,000 aggregate expected records; packet max120 signed returns. CLI plan/packet read limits are4MiB, sources2MiB each/16MiB combined, with no truncation-to-complete behavior.

Each producer-signed statement binds plan/release/asset/surface/source/time/status/records. Producer root is taken only from the reviewed register. Valid statuses: MEASURED with nonempty records, or FAILED/UNAVAILABLE/DECLARED_ONLY with no measured records. Missing/non-measured returns have `observed_records=null` and cannot qualify. Repeated returns, wrong root/signature, source tampering/missing/extra artifacts, cross-plan/release/asset and future/expired data refuse.

Positive report is `MATCHED_AGREED_SIGNED_REGISTER`, not a standard SBOM or measured estate inventory. It exposes total/required/matched/N/A units and **always** keeps:

```json
{
  "source_basis": "IMPORTED_SIGNED_CLAIMS",
  "producer_measurement_truth_independently_verified": false,
  "asset_register_authoritativeness_verified": false,
  "whole_estate_software_complete": false,
  "production_execution_qualified": false,
  "materialized_without_collection": true
}
```

The generic verifier checks source byte commitments and signed reported records; it does **not** parse every arbitrary source format or authenticate organizational ownership. Signed lockfiles must not be relabeled runtime use. Supported existing package/OCI parsing and independent expected-truth review provide stronger evidence where available. No observation/edge/BOM completeness is manufactured from these supporting reports. Exit0 matched register;2 valid blocked report;64 invalid/refused. No scanning or package-manager execution. The CLI opens only referenced digest filenames; unrelated directory entries are not enumerated or treated as measured inventory. The pure verifier rejects extra entries in its supplied artifact mapping.

## Actual owned namespace fixture result

`scripts/qualify_owned_namespace_container.py` requires a pre-reviewed plan SHA and explicit owned-container acknowledgement. It only builds/executes its known temporary fixture; no arbitrary rootfs/command/customer target is accepted. `--describe-plan` is non-executing and not approval/PASS.

Result `cryptoscan.owned-namespace-container-result/v1` retains the original typed product HostSnapshot and plan plus their canonical commitments, image/binary hashes, normal and held native observations, cancellation and cleanup result. Product OCI metadata is still the same virtual verified-content fact; physical fixture execution is a separate local-engineering report, not a promoted product fact or Docker image binding.

Normal/held child must be PID1 in namespaces different from the host, run the owned executable inode, read the expected rootfs database and pass denied-outside/read-only/capability/NNP/socket/mount/memory/FD checks. Cancellation uses pidfds after ancestry recheck and requires the owned child to be reaped. Output is bounded; a missing tool, permission/native mismatch, failed control/truth, unexpected timeout or cleanup error refuses instead of PASS. Existing outputs are not overwritten.

`actual_native_namespace_execution=true` is scoped to the executed owned Linux fixture. The result explicitly keeps independent expected-truth review, Docker/Kubernetes/customer container/Windows qualification and production admission false. No existing Windows/container server allowlist is changed. This is not a full arbitrary-code sandbox certificate or an attested execution report.
