# Hybrid TLS / operation correlation / software truth contracts

[Implementation and boundaries](../bank-environment/81-actual-hybrid-operation-and-software-truth.md) · [Operator packet](../runbooks/hybrid-operation-software-evidence.md).

## Additive TLS fact and existing stored API

New host input/fact discriminator: `NETWORK_TLS13_HYBRID`. Resource:

```text
tls-hybrid://<numeric-IP>:<port>/sni/<canonical-name>/version/TLSv1.3/group/X25519MLKEM768/peer/sha256/<64-lowercase-hex-public-pin>
```

`TlsHybridFact` extends the existing selected-group/session fact with:

| Field | Required value/meaning |
|---|---|
| `purpose` | `PINNED_COMPLETED_X25519_MLKEM768_SESSION` |
| `selected_group_id`, `key_exchange_group` | `4588`, `X25519MLKEM768` |
| `group_classification` | `REGISTERED_HYBRID_GROUP_SELECTED`; interpretation, not implementation certification |
| `hybrid_session_completed` | `true`: enforced locally by collector; remains an imported producer claim on intake |
| `tls_provider` | `PYOPENSSL_CRYPTOGRAPHY_OPENSSL` |
| `openssl_version`, `pyopenssl_version`, `cryptography_version` | Bounded stable version strings; OpenSSL >=3.5 generation, not measured execution |
| `provider_identity_basis` | `SELF_REPORTED_LIBRARY_VERSION_NOT_MEASURED_EXECUTION` |

Existing raw final hello/hash, exact endpoint/version/cipher/certificate pin, source/budget commitments, inherited false verification flags and UNKNOWN operational use remain. The new subtype also requires a 1,120-byte server share; old selected-group fact shapes/defaults are unchanged. New receipt reason `TLS_REQUIRED_GROUP_NOT_SELECTED` permits only `UNAVAILABLE`; it does not emit a hybrid fact or prove endpoint PQC absence.

No new network HTTP dispatch exists. The explicit optional-provider wrapper/CLI is operator-run. Offline collectors/bare collection cannot activate it; API network-job authorization remains blocked. Existing standalone host approval/intake can receive the new typed snapshot as IMPORTED evidence, under the same tenant/RBAC/custody controls. It does not authenticate native execution or the original full target by hashing it.

Existing route remains:

```http
GET /api/v1/host-evidence/approvals/{approval_id}/tls-session/cyclonedx-1.6
```

No live probes or new scan/evidence rows. Original receipt/custody is checked on every read; successful export is audited; official pinned CycloneDX 1.6 schema must validate before return. Changed custody returns 409; foreign tenant/unselected administrator 404; forced schema failure 503 without success audit. An all-failure snapshot cannot export successful TLS evidence.

The protocol component includes existing selected-group properties and additional `cryptoscan:hybrid_session_completed`, `cryptoscan:tls_provider`, provider-version and `cryptoscan:provider_identity_basis` properties. Composition stays incomplete; no inferred app/HSM dependency. The existing UI recognizes the strict subtype, rejects promoted/malformed metadata, and labels a completed hybrid session separately from readiness/application/HSM proof.

Schema changes to the five existing roots are additive: discriminator, fact union/definition, receipt reason only. A retained reversal proof exactly reproduces baseline `7b06710118fa5efd14bad223e543176544df15bd`, preserving all old fact definitions/defaults.

## Public operation proof (offline supporting artifact)

Schemas:

- [OperationApproval](../../shared/shared_models/shared_models/schemas/operation-approval-v1.schema.json)
- [OperationEvidence](../../shared/shared_models/shared_models/schemas/operation-evidence-v1.schema.json)

`OperationApproval` pins all three distinct public Ed25519 keys, public nonce, IDs, mechanism, offset-aware time window and reviewer reference. `operation_message(approval)` domain-separates and hashes the **whole approval**, binding roots/window/scope. `OperationEvidence` contains exactly the 64-byte operation signature and two signed typed statements. No private key, credential, alternate root, opaque provider response or arbitrary extra field is accepted.

Both logs must have matching approval/message/signature digests and application/provider-key/operation IDs, `ED25519`, `SUCCESS`, event appropriate to that logger and times within approval and verification time. Both approved logger signatures and the approved operation signature must verify. Public key base64 length44 decodes32; signature base64 length88 decodes64, with canonical encoding checked. SDK/provider access is not performed.

Positive result (`cryptoscan.operation-verification/v1`):

```json
{
  "operation_signature_verified": true,
  "application_provider_logs_correlated": true,
  "source_basis": "IMPORTED_SIGNED_CLAIMS",
  "relationship": "APPLICATION_REPORTED_MATCHING_PROVIDER_SIGNATURE",
  "application_execution_attested": false,
  "signer_organizational_independence_verified": false,
  "hardware_backing_verified": false,
  "application_uses_physical_hsm": "UNKNOWN",
  "whole_application_crypto_coverage_verified": false,
  "production_execution_qualified": false
}
```

This excerpt omits IDs/timestamps/hashes, not a standalone complete output. The pure verifier is deterministic/repeatable for fixed time; `verify_operation_evidence.py` adds a local private atomic one-use approval ledger and no-overwrite output. It is not distributed replay prevention, authenticated root enrollment or attestation. Reports are supporting qualification artifacts, not automatic API evidence, BOM components or `USES_HSM` edges. Only Ed25519 is implemented; other mechanisms/vendor formats remain unsupported.

## Expected package-record scope (offline supporting artifact)

[SoftwareTruthPlan schema](../../shared/shared_models/shared_models/schemas/software-truth-plan-v1.schema.json) pins:

- `manifest_sha256`, `reviewer_reference` and explicit operator-supplied/not-authenticated truth basis.
- Unique input IDs, each with `DPKG_STATUS`, `APK_INSTALLED` or `RPM_SQLITE`, expected committed content SHA-256 and nonempty name/version record list.
- At most100 input rows and1,000 aggregate expected records; normal snapshot limits still apply.

Every approved package input must be included, even if it failed. Exact source kind/manifest/denominator mismatches refuse. Reconciliation compares multisets (including duplicate counts), receipt status and source commitments without touching original sources. Missing/extra/version/status/hash gaps block; failure never becomes absence. Failed inputs have `observed_records=null`, `record_comparison_performed=false`, and no missing/unexpected record assertions. Deltas are computed only for PARSED sources matching the independently committed hash.

A successful `cryptoscan.software-truth-reconciliation/v1` says `MATCHED_AGREED_PACKAGE_RECORD_SET` and scoped record coverage true. It **always** keeps whole-host software completeness, independent reviewer identity and production execution false, with application crypto use UNKNOWN and named unassessed surfaces. It does not replace existing incomplete SBOM export or authenticate independently supplied truth by hashing it.

`reconcile_software_truth.py` input caps: reviewed plan1MiB, retained snapshot1.5MB; unknown fields and outputs that already exist refuse. It performs no collection/package-manager command. Exit0 matched;2 valid blocked comparison;64 invalid/refused. No new service/database/API admission or dashboard is introduced.

## Legacy HSM compatibility warning

Existing HSM results now explicitly include:

- `key_residence_basis=PROVIDER_METADATA_CLAIM_NOT_ATTESTATION`.
- `sign_challenge_basis=NONEMPTY_RESPONSE_NOT_SIGNATURE_VERIFICATION`.
- False `operation_signature_verified`, `hardware_backing_verified`, `application_execution_attested`; `application_uses_physical_hsm=UNKNOWN`.
- Per-call fresh challenge hash when the signature receipt is attempted.

Old `hardware_backed`/`sign_challenge=OK` fields retain compatibility meaning, not proof. Pre-scrub exposure detection discards exposed attributes/stops signing, reports critical exposure and UNDETERMINED residence; SDK error details are withheld. Existing UI no longer says a response proves in-boundary use. SUBMITTED or LIVE provider metadata alone cannot satisfy the new public operation verifier.
