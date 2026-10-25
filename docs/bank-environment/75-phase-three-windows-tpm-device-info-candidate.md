# 75. Phase 3 — Windows TPM device-info candidate

## Continue, do not rebuild

The foundation, bounded Linux work, Windows OS/SCM, public certificates, exact process/modules and CNG registration candidates already exist. This increment fills the next Windows hardware-metadata gap using the same approved offline collection, evidence custody, normalization and UI contracts. It does not create a second universal collector architecture or skip to a claim that every phase is finished.

**New input:**

```text
kind: WINDOWS_TPM_DEVICE_INFO
path: windows-tpm://local/device-info
```

This exact resource means the TPM selected/reported by the local Windows OS API. It is not a device-enumeration interface, remote target, hardware serial number, stable physical identity or permission to run TPM commands. No aliases, query strings, alternate device indexes, trailing slash or wildcard are accepted.

Example input (not authorization to run it):

```json
{
  "input_id": "reviewed-windows-tpm-version",
  "kind": "WINDOWS_TPM_DEVICE_INFO",
  "path": "windows-tpm://local/device-info"
}
```

## Native read boundary

- Ordinary-user/platform/expiry/per-input/total byte/fact guards remain. No administrator/debug privilege, shell/PowerShell, remote credentials or escalation fallback.
- Fixed System32 `tbs.dll` loading with explicit WINAPI prototype: `Tbsi_GetDeviceInfo(UINT32 Size, PVOID Info)`, returning a uint32 `TBS_RESULT`, **not BOOL or GetLastError**.
- One zero-initialized caller-owned output structure containing exactly four uint32 values (16 bytes). Reserve that caller-buffer budget before loading/calling the API, then charge selected JSON bytes before emission.
- Accept only success, supported output structure version and known TPM-version constants. `TPM_VERSION_12` maps to the string `1.2`; `TPM_VERSION_20` maps to `2.0`. Do not call version 1 “TPM 1.0.”
- Missing TPM report, missing library/export, stopped/disabled service, unknown result, unknown structure/version and exhausted budget refuse positive facts. Missing OS metadata is **not physical hardware absence**.
- No TBS context or native result-buffer ownership is transferred. No context creation, command submission/cancellation, PCR read, quote, owner-auth retrieval, key enumeration, key creation/use, firmware operation or mutation API is exposed.
- The remaining interface/revision DWORDs are deliberately **not interpreted or emitted**. They are not manufacturer, firmware, physical-versus-emulated or hardware-key-origin claims.

### Important SDK/documentation disagreement

The pinned SDK header marks `TPM_DEVICE_INFO.structVersion` as **1 for now** and marks the function's `Info` as output. The pinned API structure page instead describes setting `structVersion` to `TPM_VERSION_20` using context-like wording. This candidate follows the fixed output prototype/header, initializes the output buffer to zero and accepts returned structure version **1 only**; a different layout/version refuses instead of being guessed or forced.

This discrepancy must be resolved by independent real-Windows/version/architecture qualification before production admission. Portable fixtures witness the selected contract, **not** actual Windows output. No native success is manufactured to settle the disagreement.

The fixed caller buffer does not prove bounded internal OS activity/allocation or native-call latency. Independent native isolation, cancellation and lifecycle evidence remain required.

## Typed fact and source commitment

One parsed input produces one separate `WindowsTpmFact`:

| Field | Meaning |
|---|---|
| `kind` | `WINDOWS_TPM_METADATA` |
| `purpose` / `interface` | `OS_REPORTED_TPM_METADATA` / `WINDOWS_TBS_DEVICE_INFO` |
| `hardware_type` | TPM metadata category, not physical-device attestation |
| `api_structure_version` | Supported reported output layout: 1 |
| `tpm_specification` | OS-reported `1.2` or `2.0` |
| `identity_key` | `windows-tpm:local:device-info`, a metadata slot requiring surrounding host/target scope |
| `capture_basis` | `OS_REPORTED_NOT_ATTESTED_OR_INVOKED` |
| `interface_sha256` | Deterministic selected-metadata commitment, not a quote/firmware/image/host-authenticity hash |

Algorithm/runtime/operation/PQC use remain UNKNOWN, key size/software name/software version null, capabilities false and policy NOT_EVALUATED. There is no manufacturer/model/firmware/serial field in this fact. Unknown fields are refused.

Selected JSON includes only structure version and TPM specification. Model validation reconstructs its digest, and snapshot validation requires the digest to equal the receipt content commitment and the fact to match the approved kind/scope/platform. Ignored DWORDs are not part of the selected-metadata commitment; it is not a hash of all native memory.

Existing v1 fact defaults remain unchanged because this is a new union member. Five published JSON Schemas extend input/fact types; old pinned clients need updating. Qualification expected-field allowlists recognize the new scalar fields without removing OS/SCM requirements from existing Windows native review. Missing approval/native truth remains a gap.

## Existing product integration and six-BOM contribution

The existing host approval → one-use intake → original snapshot/manifest custody → authorized inspection/export path stores IMPORTED transport with local OBSERVED OS metadata claims. Stored reads never call TBS again. Normal CBOM export auditing remains intact. The existing UI shows “OS reported; not attestation, firmware or key use.” No new service, table, dashboard or execution/upload endpoint is introduced.

| BOM | Contribution / limit |
|---|---|
| HBOM | Narrow OS-reported TPM specification metadata classification; no complete hardware inventory or physical identity |
| TechBOM | Same scoped metadata reference; no application↔TPM/HSM/key relationship |
| SBOM | No package/library/version/artifact inventory inferred |
| CBOM | No algorithm/key/capability/use component; TPM version is not a crypto operation |
| NBOM | No listener, endpoint, session or TLS inference |
| VBOM | No manufacturer/supplier inference from this API |

The existing `hardware_metadata` coverage bucket includes the new input, still with approved-input parsing as its denominator. Windows universal authorization and production materialization remain blocked. Domain classification does not imply a complete Windows HBOM/export or all-six-BOM coverage.

## Operator-owned native packet

Do not send credentials or private keys. Operators select a previously approved ordinary-user Windows fixture; the code never creates a TPM/device/key to manufacture evidence.

1. Independently review the exact fixture's expected OS-reported specification and supported output layout before measuring. Keep the default OS-selected TPM scope explicit; do not claim a physical identity from it.
2. Add the exact input and scalar expected `WINDOWS_TPM_METADATA`, `tpm_specification`, `api_structure_version`, false capabilities and UNKNOWN-use assertions to the reviewed target/plan.
3. Run the existing candidate fixture runner on actual Windows:
   ```powershell
   python scripts/qualify_host_profile.py --target reviewed-windows-target.json --expectations reviewed-windows-plan.json --windows-candidate --output new-tpm-fixture-result.json
   ```
4. For the existing signed/custodied native-evidence packet, retain the required OS/SCM inputs **and** this new input; use a fresh approved source lock and independent review in guides 67–68. Prior scoped acceptance does not qualify this interface automatically.
5. Optional native test:
   ```powershell
   $env:CRYPTOSCAN_WINDOWS_TPM_RESOURCE = "windows-tpm://local/device-info"
   python -m pytest services/inventory/tests/test_windows_tpm.py::test_native_operator_selected_device_info -q
   ```
   Missing actual Windows or explicit reviewed resource is SKIP, never native PASS. Missing TPM metadata fails/refuses rather than becoming “no hardware.”
6. Independently exercise actual supported OS/architectures, SDK-layout discrepancy, TPM 1.2/2.0/default virtualized environments, service/missing/permission failures, token refusal, budget/expiry, native lifecycle/latency and isolated cancellation. Do not mutate a customer deployment for negative fixtures.

## Remaining phase gates

[Local readiness and retained test artifacts](../readiness-evidence/windows-tpm-device-info-candidate-2026-10-25.md) separate portable/native/database/UI evidence. No real Windows TPM was contacted during this implementation.

Phase 3 still needs broader reviewed CAPI/CNG surfaces, negotiated TLS/listener attribution, firmware/hardware identity where justified, real native execution/isolation/cancellation and independent acceptance. This increment is not the later full HSM/hardware phase, Windows production clearance or all-ten-phase completion. Continue to containers → network → cloud → HSM/hardware → vendor → correlation → hardening only with their respective implementation/admission contracts; do not force BOMs from unsupported inputs.

## Pinned references

- [Tbsi_GetDeviceInfo size/output/result contract](https://github.com/MicrosoftDocs/sdk-api/blob/0797841e74f7d55cba99a08948b601604799ef07/sdk-api-src/content/tbs/nf-tbs-tbsi_getdeviceinfo.md).
- [API structure page, including the version wording discrepancy](https://github.com/MicrosoftDocs/sdk-api/blob/0797841e74f7d55cba99a08948b601604799ef07/sdk-api-src/content/tbs/ns-tbs-tpm_device_info.md).
- [SDK header layout, constants and output prototype](https://github.com/microsoft/win32metadata/blob/71033001b4479c6566546b68d32276e70a8d68b9/generation/WinSDK/RecompiledIdlHeaders/shared/tbs.h).
- [Fixed TBS status definitions](https://github.com/mingw-w64/mingw-w64/blob/99144bb19f57a51f7ed82c5c9c1457647565c36b/mingw-w64-headers/include/winerror.h).
