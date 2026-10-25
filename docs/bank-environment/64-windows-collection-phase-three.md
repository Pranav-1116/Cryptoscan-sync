# Phase 3 — Windows candidate implementation and native acceptance gates

**2026-10-24 · Started after the scoped Linux runtime implementation**

[Linux scope/remaining qualification](63-linux-collection-phase-two.md) ·
[Execution report](../readiness-evidence/linux-runtime-windows-candidate-2026-10-24.md)

## Implemented now, not a completed Windows phase

The existing safe local file/uninstall-registry infrastructure now has a named
local service candidate using Windows Service Control Manager (SCM), a typed
`SERVICE` observation, an explicit offline Windows adapter and CLI opt-in.
**Linux cannot run or qualify Windows APIs.** Portable parser/layout checks and
the native test that skips here are reported separately; qualification flags
stay false. Universal registry authorization still rejects Windows targets.

| Surface | Implementation | Current evidence boundary |
|---|---|---|
| Approved local regular public-cert/config/PE-header files | Existing metadata collector, ordinary-user/reparse/path checks | Native Windows file/reparse witness still skips here; header presence is not Authenticode or runtime use |
| Approved HKLM uninstall branches | Existing fixed-size allowlisted DisplayName/DisplayVersion reads; no uninstall commands | Native registry/denial/view fixtures still needed |
| Named local service status **new** | `WINDOWS_SERVICE`, `windows-service://EventLog` → SCM state and conditionally valid PID | Portable fixed-width structure/state tests; native ordinary-user EventLog/nonexistent witness skipped on Linux |
| Windows target-spec adapter **new** | `OfflineWindowsCollector`, explicit `--windows-candidate` | Requires actual `sys.platform == win32`, matching manifest/method and time window; not a production/remote worker |
| Certificate stores, CNG/CAPI provider enumeration, TLS listeners, loaded modules, TPM/firmware | Not added in this candidate | Remain implementation/native gates, not replaced by a package list or Linux emulation |

## Least privilege and bounded native interface

- Exact local SCM name only; canonical URI rejects separators, remote hosts,
  arbitrary paths and option/command syntax. No service enumeration or discovery.
- `OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT)` and
  `OpenServiceW(..., SERVICE_QUERY_STATUS)` only. No ALL_ACCESS, start/stop,
  config changes, service executable paths, credentials, remote SCM, PowerShell,
  shell or service-binary execution.
- Explicit native function prototypes/handle-width types; nine 32-bit DWORD
  fields (36-byte `SERVICE_STATUS_PROCESS`); two fixed buffers are reserved in
  the existing charged-byte budget before querying. Output projection also
  consumes that budget; no unbounded output/native allocation.
- Both status queries must agree on state/PID; changed values fail instead of
  fabricating a stable service. PID is exported only in RUNNING,
  CONTINUE_PENDING, PAUSE_PENDING or PAUSED, the documented valid states; zero
  is unknown. There is no PID-start/binary/module edge or algorithm inference.
- Manager/service handles close in `finally`. Denial, nonexistent service,
  unknown state and other native errors cannot emit positive facts.
- The native SCM call does not yet have an independently enforced wall-clock
  deadline/cancellation worker. That is a production gate, not hidden behind
  a claim that fixed-size buffers guarantee bounded elapsed time.

SCM fact commitment covers the allowlisted fixed status fields; receipt commitment
covers the canonical fact projection. Metadata stays IMPORTED at intake, local
OBSERVED only for the queried interface; algorithm, operational crypto/PQC use
remain UNKNOWN. Service state is not a security grade or uptime SLA.

## Candidate execution (on a reviewed ordinary-user Windows fixture only)

Example manifest input, inside an otherwise exact reviewed Windows target spec:

```json
{"input_id":"eventlog-status","kind":"WINDOWS_SERVICE","path":"windows-service://EventLog"}
```

```powershell
python scripts/collect_host.py --target-spec reviewed-windows-target.json --windows-candidate --output new-snapshot.json
```

The option is an explicit acknowledgement of candidate status, not permission to
bypass scope, elevation or native platform checks. Without it, target-spec CLI
uses the Linux adapter and refuses Windows. It performs no upload. Existing
legacy `--manifest` handling remains separate; the new opt-in is valid only with
`--target-spec`. No credentials, Windows VM or bank host was contacted here.

## Native gate checklist before enabling registry jobs

1. Run as actual non-administrator Windows user; separately prove elevated-token
   refusal. Retain OS/build/architecture, account/session and expected truth.
2. Test actual EventLog plus a controlled running/stopped fixture, transient
   states, invalid PID states, nonexistent service, service-specific query
   denial, SCM denial, state changes and handle cleanup. Do not manufacture a
   denial by merely mocking `sys.platform` or an API return value.
3. Exercise ordinary/reparse/hardlink/UNC/device/ADS/ambiguous file paths and
   fixed-size registry reads (both intended views, missing values, oversize/type
   refusal, denied keys). Native file tests must not be reported as passed when
   symlink privileges or the Windows runner are absent.
4. Implement and independently fixture the remaining Windows interfaces above.
   Public certificate-store enumeration must never extract private material;
   native provider/library presence cannot be called an observed key operation.
5. Demonstrate exact bank/estate/system authorization, window expiry/revocation,
   limits and immutable original-evidence projections on native Windows receipts.
6. Complete signed release/identity, isolated execution/cancellation, native
   security review and independent bank acceptance before changing the hardcoded
   Windows authorization or production-execution gates.

Current code intentionally **does not** meet that full checklist. Phase 3 has
begun with a bounded read-only candidate, not a Windows-ready release or a claim
that the Linux host is a Windows witness.

## Next implemented increment

[Guide 65](65-signed-collector-isolation-and-native-gates.md) adds the fixed local
`WINDOWS_OS_RELEASE` registry declaration and executable expected-truth native
fixture runner, alongside signing-key and Linux isolation controls. Native Windows
OS/SCM execution still requires an actual Windows ordinary-user fixture; no
production authorization gate is changed.

## Subsequent candidate increment

[Guide 72](72-phase-three-windows-public-certificate-candidate.md) adds exact local public-certificate-store lookup with SHA-1 locator plus required SHA-256 binding, no private-key APIs or store-wide enumeration request. This does not complete the native checklist or enable universal Windows job authorization.
