# Windows TPM device-info candidate input

No new execution endpoint, database table or service. Extend the existing approved offline host input contract with:

```text
kind: WINDOWS_TPM_DEVICE_INFO
path: windows-tpm://local/device-info
```

Only the exact local OS-selected metadata resource is supported. No alternate device ID, trailing slash, escaped alias, wildcard, query, remote target or TPM command is accepted. This names an OS metadata slot, not a uniquely authenticated physical TPM.

## Fact and receipt

One parsed receipt contains a strict `WindowsTpmFact`:

- `kind: WINDOWS_TPM_METADATA`, `purpose: OS_REPORTED_TPM_METADATA`.
- `interface: WINDOWS_TBS_DEVICE_INFO`, `identity_key: windows-tpm:local:device-info`, `hardware_type: TPM`.
- `api_structure_version: 1`, `tpm_specification: 1.2|2.0` (strings, not algorithm/software versions).
- `capture_basis: OS_REPORTED_NOT_ATTESTED_OR_INVOKED`, `local_basis: OBSERVED` for the returned OS metadata only.
- Algorithm/runtime/operation/PQC UNKNOWN; software name/version/key size null; capabilities false; policy NOT_EVALUATED.
- `interface_sha256` reconstructs canonical selected structure/specification JSON and must equal receipt `content_sha256`; scoped kind/platform and single-fact cardinality are validated independently.

No manufacturer/model/firmware/serial, attestation, physical-versus-virtual, crypto capability or key-use fields are accepted. Reserved output DWORDs are intentionally ignored and are not part of the selected commitment. Hashes are integrity references, not host/device authenticity or TPM quotes.

## Refusal and native boundary

One System32 `tbs.dll!Tbsi_GetDeviceInfo` call writes a caller-owned fixed 16-byte output structure; no native ownership transfer/context/key/command API. Reserve caller-buffer bytes before the call, then selected JSON before positive emission. Internal native work/allocation/cancellation/latency are not qualified by this byte budget.

TPM-not-found/missing library/export/service errors become UNAVAILABLE, not physical absence. Unknown output layout/specification becomes UNSUPPORTED/INVALID_FORMAT; exhausted limits become BUDGET_EXCEEDED. Wrong platform, elevation, expiry and unsupported resource refuse. No failure emits positive hardware/crypto facts or means NO_ASSET/NO_CRYPTO.

The pinned SDK says output structure version 1; structure-page wording disagrees. This candidate accepts only the header's returned layout 1 and does not guess/force version 2. Actual Windows qualification must resolve this; portable seams do not prove native compatibility.

## Existing integrations and admission

Existing approval/intake/stored snapshot/CBOM inspection preserve tenant/RBAC, original integrity and normal export auditing. Reads never query TBS again. CBOM has **zero crypto components from this fact**, not proof no cryptography exists. UI labels specification as OS reported and refuses unsupported/promoted claims.

The fact is classified for HBOM and TechBOM only. Existing `hardware_metadata` coverage includes the input; it measures approved-input parse outcomes, never complete hardware/estate coverage. No application↔device/key relationship, supplier, network or package fact is invented. Universal Windows authorization remains 409/future capability; this does not make Windows jobs production-admissible.

Five public v1 schemas add the input/fact union without changing old fact defaults. Update pinned consumers. Native expected-truth allowlists add the new scalar fields while retaining mandatory existing OS/SCM review; no acceptance/signature is fabricated.

See [guide 75](../bank-environment/75-phase-three-windows-tpm-device-info-candidate.md) for the operator-owned packet, SDK discrepancy and pinned references. No credentials or private keys should be sent in chat or public evidence.
