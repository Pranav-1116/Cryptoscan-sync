# 74. Phase 3 — Windows CNG registration candidate

## Position in the build

Continue the existing foundation → Linux → Windows engineering sequence. This increment adds a bounded **CNG provider-registration metadata** reader, not a complete CryptoAPI collector or Windows production admission. Earlier OS/SCM, public-certificate and exact-process/module candidates remain separate evidence surfaces. Containers, network, cloud, HSM/hardware, vendor, correlation and hardening remain later universal-adapter phases; existing standalone features do not imply their admission.

Collectors emit facts; the central platform projects evidence. In particular:

```text
A provider registers the label AES
    ≠ a tested AES implementation/capability
    ≠ an application opened that provider
    ≠ an application performed AES
    ≠ a particular mode/key size
    ≠ production traffic or hardware-backed key use
```

No Windows host, account, keys or customer deployment was contacted for the local validation reported here.

## Exact supported input

```text
kind: WINDOWS_CNG_REGISTRATION
path: windows-cng://local/microsoft-primitive/{cipher|hash}-registration
```

Examples (input shapes, not bank authorization):

```json
[
  {
    "input_id": "reviewed-cipher-registration",
    "kind": "WINDOWS_CNG_REGISTRATION",
    "path": "windows-cng://local/microsoft-primitive/cipher-registration"
  },
  {
    "input_id": "reviewed-hash-registration",
    "kind": "WINDOWS_CNG_REGISTRATION",
    "path": "windows-cng://local/microsoft-primitive/hash-registration"
  }
]
```

The fixed provider is `Microsoft Primitive Provider`. Only the explicit user-mode cipher or hash interface is queried. Each input must be independently approved. There is no remote authority, wildcard, custom provider name, kernel-mode selector, key-storage/signature/Schannel interface, query string, encoded alias, global provider enumeration or automatic scope expansion. Unsupported names/interfaces refuse; they are not silently substituted.

## Native operation and buffer ownership

1. Existing ordinary-user, platform, approved expiry, per-input/total byte and fact guards apply. No root/administrator/debug privilege or remote credential is requested.
2. Load `bcrypt.dll` with System32-only loading and explicit WINAPI prototypes. DWORD/ULONG and NTSTATUS widths are fixed; UTF-16 uses 16-bit units rather than the Linux size of `wchar_t`.
3. Call `BCryptQueryProviderRegistration(fixed_name, CRYPT_UM, exact_interface, &size, NULL)`. The final argument is **NULL**, not the address of a null pointer. This is the documented size-query form, not the auto-allocation form. Only `STATUS_BUFFER_TOO_SMALL` is accepted for this step.
4. Refuse an undersized, over-65,536-byte or over-budget required size before allocating the result block or making the data call. The caller owns a bounded Python buffer. Pass the address of its **non-null** pointer for the second query; the initial size is its capacity.
5. Accept only `STATUS_SUCCESS` for the data call. Changed size/`STATUS_BUFFER_TOO_SMALL` refuses without retry. Other NTSTATUS errors remain denied/missing/unavailable gaps, never asset absence. `GetLastError` and generic boolean success are not used for CNG status interpretation.
6. Refuse a replaced result pointer or returned length outside the caller block. Before every nested structure, pointer-array or UTF-16 read, validate its alignment, count and complete span within the reported block. Null, unaligned, overflow-count, out-of-range, unterminated and malformed UTF-16 paths refuse before unbounded traversal.
7. Require one selected user-mode interface, no returned kernel-mode registration and 1–64 unique canonical ASCII function labels of 1–64 characters. Sort labels deterministically; ambiguous case-insensitive duplicates refuse. Native image/alias fields are not dereferenced or emitted.

No native buffer ownership is transferred in the supported API forms: there is no `BCryptFreeBuffer` or provider/key handle to close. Python owns and releases its buffer on all exits. The candidate does not use auto-allocation, global enumeration, `BCryptOpenAlgorithmProvider`, `BCryptGetProperty`, `NCryptOpenKey`, key enumeration, encryption/signing, registration mutation or target-image loading.

This does **not** prove zero internal OS allocation, zero internal provider activity or bounded native-call latency. Size queries and native calls still need real Windows lifecycle, architecture, cancellation/isolation and independent security qualification. A bounded caller buffer is not a whole-process RSS or wall-clock guarantee. Unexpected pointer replacement is refused; the candidate does not guess ownership and free an untrusted replacement address.

## Evidence contract

One parsed input emits one separate `WindowsCngFact`:

| Field | Meaning |
|---|---|
| `kind` | `WINDOWS_CNG_REGISTRATION` |
| `local_basis` | OBSERVED registration metadata claim, not implementation/use proof |
| `purpose` | `PROVIDER_REGISTRATION_METADATA` |
| `provider_name` / `registration_mode` | Fixed queried name / USER |
| `registration_interface` | Exactly approved `cipher` or `hash` |
| `registered_functions` | Bounded sorted registration labels, not normalized algorithm-use findings |
| `registration_flags` | Raw uint32 registration flags, not a security/policy assessment |
| `identity_key` | `microsoft-primitive:user:<interface>`; local metadata slot, requiring surrounding host/target scope |
| `capture_basis` | `REGISTERED_NOT_OPENED_OR_INVOKED` |
| `interface_sha256` | SHA-256 of deterministic selected metadata, not a DLL/artifact/signature/host-authenticity hash |

Algorithm, runtime use, operation use and PQC assessment remain UNKNOWN. Key size/software name/software version remain null, capabilities false and policy NOT_EVALUATED. An `AES` label does not populate `algorithm: AES`.

The deterministic selected JSON covers fixed provider/mode, selected interface, flags and sorted labels. The model reconstructs its hash; snapshot validation requires it to equal the receipt content digest and match the approved interface/platform. Changed labels, flags, scope or commitments cannot preserve a valid unchanged receipt. The retained original is the typed snapshot/manifest and its metadata/digests, not a raw pointer graph, registry hive or provider image.

Existing scoped host approval → intake → snapshot/CBOM inspection retains **IMPORTED** transport and local metadata claims. Stored reads do not invoke CNG again; normal CBOM export audit behavior remains. Cross-estate/private-read controls and changed-original integrity refusal remain intact. No new service, database table, dashboard, upload/execution endpoint or remote worker is introduced.

The evidence UI displays the queried provider/interface and registered labels with “registration only; capability/use UNKNOWN.” It refuses promoted crypto/software/use claims and malformed label lists. Five public JSON Schemas extend the input enum and new fact union. Existing HostFact, RuntimeFact and WindowsImageFact shapes/defaults remain unchanged; old pinned clients must update to understand this new kind.

The existing `crypto_configuration` coverage surface includes provider-registration configuration metadata. Its denominator is **approved input parses**, not configured application crypto, negotiated TLS, working algorithms or estate coverage. No new coverage surface/version or manufactured percentage is added. Universal Windows collection/materialization remains unadmitted.

## Six-BOM boundary

| BOM | What this input supports |
|---|---|
| SBOM | No installed software/package/version/license/artifact inventory inferred from provider registration. |
| CBOM | **No crypto component from this metadata-only input.** Registration labels are not capability, use, key-size or application findings. Separate certificate/configuration evidence remains separate. |
| NBOM | No listener, TLS protocol/cipher/session, SNI or certificate binding inferred. |
| HBOM | No TPM/HSM identity, firmware, hardware-backed key or application–hardware relationship inferred. |
| VBOM | A fixed provider name does not authenticate a publisher/vendor, contract or supplier declaration. |
| TechBOM | One scoped registration-metadata observation can contribute; no application/service dependency or globally attested provider asset is manufactured. |

These limits are deliberate: a BOM is a projection of evidence, not a way to fill unsupported columns.

## Operator-owned native fixture

Operators run the packet. **Do not send credentials or private keys.**

1. Choose an authorized ordinary-user Windows fixture and independently review the exact provider/interface and complete expected sorted function-label set, flags and UNKNOWN boundaries **before** collecting. Do not derive expected truth by copying the candidate's result after execution.
2. Add the exact input to the reviewed Windows target/manifest. Expected truth may assert scalar fields and the bounded canonical `registered_functions` list. Arbitrary nested/list assertions remain refused; only this new flat 1–64-label field is added to the old scalar assertion contract.
3. Run the existing candidate fixture tool:
   ```powershell
   python scripts/qualify_host_profile.py --target reviewed-windows-target.json --expectations reviewed-windows-plan.json --windows-candidate --output new-cng-fixture-result.json
   ```
   A scoped fixture result is not bank approval or Windows production qualification.
4. For the existing native-evidence/signature workflow, retain required OS/SCM inputs **and** the new registration input in the exact pre-approved plan. Prior OS/SCM/certificate/module-only acceptance does not qualify this new interface. Use a fresh approved release/source lock and the independent review workflow in guides 67–68; this increment generates no approval/signature.
5. Optional native test, with an independently approved existing registration:
   ```powershell
   $env:CRYPTOSCAN_WINDOWS_CNG_RESOURCE = "windows-cng://local/microsoft-primitive/cipher-registration"
   python -m pytest services/inventory/tests/test_windows_cng.py::test_native_operator_reviewed_registration -q
   ```
   Missing actual Windows or missing explicit resource is SKIP, not native PASS. The test does not install/register a provider or create a key.
6. Independently exercise cipher/hash registrations on supported Windows versions/architectures, real permission/missing cases, registry churn/size growth, malformed-interface defenses, memory/lifecycle bounds, native latency and isolated cancellation. Do not mutate a customer deployment to manufacture negative fixtures.

[Local readiness and retained artifacts](../readiness-evidence/windows-cng-registration-candidate-2026-10-25.md) separate portable ABI seams, SQL custody and frontend validation from actual Windows skips. Remaining Phase 3 work includes broader reviewed CNG/legacy CAPI surfaces, TLS/listener attribution, TPM/firmware, real native denial/lifecycle/isolation/cancellation evidence and independent acceptance. Windows universal authorization remains blocked; all ten phases/all six Windows BOMs are not complete.

## Pinned references

- [BCryptQueryProviderRegistration parameter, ownership and status semantics](https://github.com/MicrosoftDocs/sdk-api/blob/0797841e74f7d55cba99a08948b601604799ef07/sdk-api-src/content/bcrypt/nf-bcrypt-bcryptqueryproviderregistration.md).
- [Provider name, CRYPT_UM/interface constants and fixed structure/prototype definitions](https://github.com/mingw-w64/mingw-w64/blob/99144bb19f57a51f7ed82c5c9c1457647565c36b/mingw-w64-headers/include/bcrypt.h).

Documentation and portable fixtures are engineering references, not native or bank observation evidence.
