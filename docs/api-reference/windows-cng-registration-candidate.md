# Windows CNG registration candidate input

No new execution endpoint. Extend the existing explicitly approved offline host contract:

```text
kind: WINDOWS_CNG_REGISTRATION
path: windows-cng://local/microsoft-primitive/{cipher|hash}-registration
```

Only the fixed `Microsoft Primitive Provider`, user mode and the selected cipher/hash registration interface are supported. No global discovery, arbitrary provider, remote host, kernel/key-storage/Schannel/signature interface, encoded alias, query string or wildcard scope is accepted.

## Fact and receipt

One parsed receipt has one new `WindowsCngFact` with:

- `provider_name: Microsoft Primitive Provider`, `registration_mode: USER`, approved `registration_interface: cipher|hash`.
- `registered_functions`: 1–64 sorted unique ASCII labels, each 1–64 characters; case-insensitive ambiguity refuses. `registration_flags` retains raw uint32 flags, not policy conclusions.
- `identity_key: microsoft-primitive:user:<interface>`; this needs surrounding host/target/evidence scope and is not a globally attested asset.
- `purpose: PROVIDER_REGISTRATION_METADATA`, `interface: WINDOWS_CNG_REGISTRATION_QUERY`, `capture_basis: REGISTERED_NOT_OPENED_OR_INVOKED`.
- `algorithm`, `runtime_use`, `operation_use`, `pqc_assessment`: UNKNOWN; software name/version/key size null, capabilities false, policy NOT_EVALUATED.
- `interface_sha256`: deterministic selected metadata commitment. The fact reconstructs it; snapshot validation requires equality with receipt `content_sha256`, exact interface and Windows platform.

OBSERVED local basis means registration metadata was returned by the interface, **not working crypto capability or application/production use**. Imported snapshots retain IMPORTED transport and do not authenticate the host/provider publisher. A crypto label such as AES creates no CBOM crypto component. Only TechBOM metadata-domain contribution is classified; no vendor/software/network/hardware relationship is inferred.

Failed/denied/missing/changed/malformed/unsupported/over-budget acquisition emits no positive fact/content digest and never means NO_ASSET or NO_CRYPTO. Byte counts reserve caller buffers and selected JSON, not all native OS allocation or process RSS.

## Acquisition/ownership

The System32 bcrypt query uses fixed-width prototypes and NTSTATUS interpretation. First call uses `ppBuffer == NULL` for sizing. Refuse over-budget/over-65,536-byte required lengths; second call supplies a caller-owned non-null buffer. No auto-allocation form or BCryptFreeBuffer/provider/key handle is used. Pointer replacement, changed size, unexpected interface/kernel return and every out-of-range/null/unaligned nested read refuse; native calls do not retry indefinitely.

No provider/algorithm/key opening, crypto operation, global provider enumeration, registration mutation or target-image load is exposed. Internal OS activity/allocation and native-call timeout/isolation still need real Windows qualification.

## Existing product integration

Existing host approval → intake → stored inspection/CBOM export keeps tenant/RBAC/custody checks and normal export auditing. Reads do not invoke CNG. The existing host UI displays labels as registration only and refuses promoted software/use/capability claims.

The existing `crypto_configuration` coverage bucket includes provider-registration configuration metadata, not effective application or negotiated TLS configuration. Percentages, if later projected from an admitted envelope, describe approved-input parsing only. Universal Windows authorization remains 409/future capability.

Five public v1 schemas add the input/fact union without changing existing fact defaults. Older pinned clients need updating; runtime scope/commitment checks remain mandatory. Native expected-truth allowlists add this fact and permit only the bounded canonical `registered_functions` list alongside existing scalar assertions; arbitrary nested/list assertions remain unsupported.

See [guide 74](../bank-environment/74-phase-three-windows-cng-registration-candidate.md) for operator-owned native fixture steps, pinned API references, six-BOM limits and remaining gates. No credentials/private keys are needed in chat.
