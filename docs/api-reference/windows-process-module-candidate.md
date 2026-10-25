# Windows process/module candidate contract

No new execution endpoint. New opt-in input on the existing offline host contract:

```text
WINDOWS_PROCESS_MODULES
windows-process://<positive uint32 PID>/created/<positive uint64 decimal FILETIME>/modules
```

The creation FILETIME segment and fact field `creation_filetime` are canonical decimal **strings**, not JSON numbers. Exact one-process incarnation scope is required; no remote/self/wildcard enumeration, leading zeros, aliases or automatic PID refresh.

## Parsed receipt

- One `WINDOWS_PROCESS_IMAGE` plus 1–256 unique `WINDOWS_MODULE` facts, all carrying the approved PID/creation string.
- Separate `WindowsImageFact` union member; old HostFact/RuntimeFact fields/defaults remain unchanged.
- `interface: WINDOWS_PROCESS_TOOLHELP`; `capture_basis: REPEATED_MATCHING_METADATA_NOT_INVOCATION`.
- `image_path`: literal local drive path. Modules additionally have `module_name`, matching the path basename. Conservative fixed-buffer/ambiguity/path checks refuse unsupported paths. Drive-letter syntax is not physical-locality or link-resolution proof; image files are not opened.
- `identity_key`: incarnation label, plus hash of literal path text for a module; **not file-content or globally attested identity**.
- `interface_sha256`: selected metadata commitment, reconstructed from process path and sorted module name/path pairs with PID and string FILETIME. Every fact must match that commitment and the receipt's `content_sha256`.
- All algorithm/runtime/operation/PQC assertions remain UNKNOWN, software version/name/key size null, capabilities false, policy NOT_EVALUATED. Module rows may include executable images and do not prove crypto capability or invocation.

Failed reads have no positive facts or content digest. Denied, missing, changed, cross-bitness, malformed, truncated, duplicate, over-budget or unavailable results never become asset absence. Caller-buffer byte charging is not a bound on native OS allocation/latency or a traffic measurement.

## Native and transport boundaries

The native reader requests only query-limited information plus SYNCHRONIZE for a zero-time liveness check. It checks one held process incarnation/image before and after two exact-PID module snapshots. System32-only loading, fixed-width prototypes, bounded tables, no indefinite retries and `finally` cleanup apply. No target-image execution, memory dump, VM_READ, escalation, private-key interface or remote path is exposed.

Matching sampled tables are not atomic or continuous observations; Toolhelp omissions and native qualification gaps remain explicit. Actual Windows is required for acquisition. The optional reviewed fixture environment variable is `CRYPTOSCAN_WINDOWS_PROCESS_RESOURCE`; absent OS/fixture skips the native test.

Existing tenant-scoped host approval/intake retains original snapshots as IMPORTED local metadata claims. Stored inspection/export never recollects; normal CBOM export auditing remains. This input creates **no CBOM crypto components**, even for crypto-named modules. Module-path domain classification does not implement a complete Windows SBOM/graph or admit universal Windows execution. `/api/v1/collection/targets/{id}/authorize` remains blocked for Windows.

Five public JSON Schemas extend the input enum and relevant fact unions. Runtime canonical-resource/commitment checks remain mandatory; old pinned clients must update. Expected-truth qualification allowlists and existing evidence UI recognize the fields without changing production/native qualification flags.

See [guide 73](../bank-environment/73-phase-three-windows-process-module-candidate.md) for native operator steps, all six BOM boundaries and remaining gates. Do not send credentials or private keys.
