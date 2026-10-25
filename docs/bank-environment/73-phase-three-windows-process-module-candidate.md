# 73. Phase 3 — exact Windows process/module candidate

## What this increment builds

Continue the existing universal collection foundation and Linux work, rather than introduce another scanner or six independent inventories. This increment adds a **candidate Windows process-image and loader-module metadata reader** to the existing approved offline host path. It is not Windows production admission or completion of all ten phases.

```text
kind: WINDOWS_PROCESS_MODULES
path: windows-process://{positive-uint32-PID}/created/{positive-uint64-decimal-FILETIME}/modules
```

The URI binds one explicitly approved local process **incarnation**, not just a reusable PID. Creation FILETIME is a decimal **string**, never a JavaScript number, Unix timestamp or formatted date. For example, `133800000000000001` exceeds JavaScript's exact integer range. This synthetic example is not an actual bank process:

```json
{
  "input_id": "reviewed-payment-process",
  "kind": "WINDOWS_PROCESS_MODULES",
  "path": "windows-process://71/created/133800000000000001/modules"
}
```

Replace both identifiers using independently reviewed fixture truth **before** approving the scope. Leading zeros, PID zero/self aliases, wildcards, remote hosts, encoded aliases, queries, extra segments and out-of-range integers refuse. The collector does not discover a PID or refresh a stale creation timestamp automatically.

## Read boundary and refusal rules

1. Existing approval, platform, ordinary-user, expiry and byte/fact limits apply. No escalation, debug privilege, remote login or credentials are added.
2. Load fixed `kernel32.dll` from System32 with explicit WINAPI prototypes, 32-bit DWORDs, pointer-width handles and fixed 16-bit UTF-16 buffers. The portable ABI fixture checks the running pointer width; it is not a real cross-architecture test.
3. Open only the exact PID with `PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE` (`0x00101000`). SYNCHRONIZE is used solely for `WaitForSingleObject(handle, 0)`, not a blocking wait. No `VM_READ`, `ALL_ACCESS`, process-memory read, shell command or target-image execution/load is exposed.
4. Check handle-bound creation FILETIME, exit status, zero-time handle liveness and full process-image path. Exit code 259 alone is insufficient: a process can terminate with that code. A signaled handle refuses even if its exit code is 259.
5. Read two exact-PID Toolhelp snapshots using only `TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32` (`0x18`); compare sorted selected name/path rows. No system-wide process/thread/heap enumeration flags are used.
6. Recheck the held process handle and image path after the two tables. Changed creation, liveness, path or table refuses `INVALID / INPUT_CHANGED`. These checks witness matching sampled metadata, **not atomicity or continuous execution**.
7. Permit 1–256 unique module paths and one process-image fact. Only `ERROR_NO_MORE_FILES` ends successful enumeration. Missing/denied/cross-bitness/unknown API errors are gaps. `ERROR_BAD_LENGTH` refuses as changed input; unlike the SDK retry recommendation, this bounded candidate does not retry indefinitely.
8. Caller-buffer charges are reserved before native calls; conservative per-row charges and selected JSON bytes consume existing limits. Snapshot and process handles close in `finally`; an explicit close failure refuses positive output. Native allocations inside Toolhelp and native API elapsed time are **not** bounded by this Python byte budget.

Only literal local drive paths are supported. UNC/device paths, alternate streams, wildcard/invalid components, dot components, trailing dot/space, duplicates and malformed UTF-16 refuse. Fixed Toolhelp paths of 259 or more characters refuse conservatively rather than assert an untruncated identity. Drive-letter syntax does not attest physical locality or resolve mapped drives, junctions or links; the reader does not open those image files. Long-path/native architecture coverage remains a gate. Toolhelp does not report every possible mapping (for example, data-file loads); this is not complete library or memory inventory.

## Facts, identity and custody

A parsed input emits one new `WindowsImageFact(kind="WINDOWS_PROCESS_IMAGE")` and 1–256 `WindowsImageFact(kind="WINDOWS_MODULE")` values. A module-table row can include the executable; **WINDOWS_MODULE does not classify a file as a DLL**.

- The process identity label is `pid:<PID>:created:<FILETIME>`.
- A module adds `:path-sha256:<digest-of-literal-path-text>` within that incarnation. This digest is **not a file-content hash**, publisher signature, canonical global software identity, version or executable authenticity claim.
- Host/approved input/evidence scope remains necessary around these local labels. Different hosts must not be collapsed merely because labels match.
- `interface = WINDOWS_PROCESS_TOOLHELP`; `capture_basis = REPEATED_MATCHING_METADATA_NOT_INVOCATION`.
- `algorithm`, `runtime_use`, `operation_use` and `pqc_assessment` remain UNKNOWN; key size/software name/software version remain null, capabilities false, policy NOT_EVALUATED.
- One deterministic selected-metadata JSON commitment covers PID, string FILETIME, process path and sorted module name/path pairs. Intake reconstructs that commitment from the facts and requires every interface digest to equal it and the receipt content digest. It does not hash target files or process memory.
- Selected native JSON is transient acquisition data; the retained original is the typed snapshot and its manifest/facts/digests, not a raw Toolhelp memory dump. Native addresses/handles/base sizes are not emitted.

The existing tenant-scoped approval → intake → stored snapshot → inspection/export flow retains **IMPORTED** transport and local OBSERVED claims without attesting the host or executing the collector again. Ordinary CBOM export auditing remains. Existing HostFact/RuntimeFact defaults are unchanged: the new fact is a separate union member. Five public schemas add the kind/union, and older pinned clients need updating. Runtime resource, table and commitment checks are stricter than generic JSON Schema validation.

The existing evidence UI displays exact string FILETIME/PID/path and the non-invocation limitation. No new dashboard, service, table, scanner endpoint or automatic upload is introduced. Windows universal job authorization stays blocked.

## Honest six-BOM consequences

| Projection | Contribution / boundary |
|---|---|
| SBOM | Module-path metadata is classified for future evidence projections; no package version, license, purl, artifact hash, full Windows software BOM or operational dependency is invented. The Linux software exporter is not repurposed as a Windows exporter. |
| CBOM | **None from this input.** Even a module named `libcrypto.dll` has algorithm/use UNKNOWN and creates no crypto component. Existing public-certificate facts are separate evidence. |
| NBOM | No listener, connection, TLS negotiation or service ownership inferred. |
| HBOM | No TPM, firmware, hardware identity, HSM relationship or key origin inferred. |
| VBOM | File/module names do not establish a supplier or publisher. |
| TechBOM | Scoped process/image metadata can contribute; co-existence does not establish a service, hardware or crypto-operation relationship. |

Collector facts remain the source for central projections. This does **not** materialize all six Windows BOMs or turn module rows into an attested process-to-library graph. Universal Windows execution/materialization is still unqualified.

## Operator-owned native packet

Operators run the packet; no credentials or private keys should be sent in chat or put in public evidence.

1. On an authorized ordinary-user Windows fixture, independently identify one already-running process, its exact creation FILETIME, expected image path and complete expected module name/path set. Obtain approval before measuring; do not copy the candidate's output into expected truth after the fact. Process restarts require a newly reviewed incarnation/scope.
2. Add this exact input to the reviewed target/manifest and include one process-image and all expected module facts in the fixture plan. Expected FILETIME values must be JSON strings. Retain required OS/SCM inputs in a combined Windows native-acceptance packet; an old OS/SCM-only result does not qualify this new interface.
3. Run the existing candidate fixture tool as an ordinary native user:
   ```powershell
   python scripts/qualify_host_profile.py --target reviewed-windows-target.json --expectations reviewed-windows-plan.json --windows-candidate --output new-module-fixture-result.json
   ```
4. Use the existing source-lock/native capture and independent review workflow in guides 67–68 with a fresh approved release lock. The expected-field allowlists now recognize the new fact fields. No signature or acceptance is generated by this increment.
5. Optional real-OS test:
   ```powershell
   $env:CRYPTOSCAN_WINDOWS_PROCESS_RESOURCE = "windows-process://<approved-PID>/created/<approved-FILETIME>/modules"
   python -m pytest services/inventory/tests/test_windows_images.py::test_native_operator_selected_process_image_fixture -q
   ```
   Replace placeholders; they are deliberately invalid as written. The test never starts a process to manufacture a fixture. Missing actual Windows or missing reviewed resource is SKIP, not native PASS.
6. Independently test access denied/protected targets, exited/stale PID including exit 259, churn, cross-bitness/architecture, long paths, Unicode, count/byte exhaustion, native handle lifecycle, allocation/latency, isolation/cancellation and expiry. Do not mutate customer deployments to simulate these conditions.

## Qualification and phase order

[Local readiness and retained test artifacts](../readiness-evidence/windows-process-module-candidate-2026-10-25.md) distinguish portable native seams, SQL custody, frontend regression and actual native skips. No Windows host was contacted in this implementation environment.

Phase 1 foundation and bounded Phase 2 Linux work are reused; external acceptance remains open. Phase 3 now has OS/uninstall/file/SCM, public-certificate and process/module candidates, **not a qualified complete Windows collector**. Remaining Windows gates include real native execution/security review, CNG/CAPI provider metadata, TLS/listener attribution, TPM/firmware and independent isolation/cancellation evidence. Containers → network → cloud → HSM/hardware → vendor → correlation → hardening remain the ordered universal build; existing standalone features do not imply those adapters are admitted.

## Pinned API references

- [Toolhelp flags, cross-bitness, limitations and snapshot CloseHandle ownership](https://github.com/MicrosoftDocs/sdk-api/blob/0797841e74f7d55cba99a08948b601604799ef07/sdk-api-src/content/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot.md).
- [MODULEENTRY32W fields](https://github.com/MicrosoftDocs/sdk-api/blob/0797841e74f7d55cba99a08948b601604799ef07/sdk-api-src/content/tlhelp32/ns-tlhelp32-moduleentry32w.md) and [fixed header layout/prototypes](https://github.com/mingw-w64/mingw-w64/blob/99144bb19f57a51f7ed82c5c9c1457647565c36b/mingw-w64-headers/include/tlhelp32.h).
- [WaitForSingleObject rights and zero-time semantics](https://github.com/MicrosoftDocs/sdk-api/blob/0797841e74f7d55cba99a08948b601604799ef07/sdk-api-src/content/synchapi/nf-synchapi-waitforsingleobject.md).

References and portable fixtures are engineering inputs, not real Windows or bank qualification evidence.
