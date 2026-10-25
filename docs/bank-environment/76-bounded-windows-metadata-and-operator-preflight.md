# 76. Bounded Windows metadata and operator preflight

## Delivered increment, not a qualification shortcut

This continues Phase 3 using the existing ordinary-user collector, approved host intake, stored originals, shared projections and console. It adds no service, table, dashboard, remote dispatcher or execution endpoint. Existing certificate/process/CNG/TPM work is reused, not rebuilt.

Three implementation gaps are narrowed:

1. **Legacy CryptoAPI default-provider selection metadata.**
2. **Five additional CNG registration interfaces.**
3. **Windows IPv4/IPv6 TCP listener-table metadata.**

The existing native qualification CLI now has a **preflight-only** mode binding the independently reviewed target/expected-truth/source identifiers before native acquisition. This does not assign/contact people, authenticate an approval or execute Windows. Actual operators still use the assigned-human workflow in [guide 68](68-assigned-operator-qualification-workflow.md).

## 1. Exact legacy CryptoAPI resource

```text
kind: WINDOWS_CAPI_DEFAULT_PROVIDER
path: windows-capi://local/current-user/{rsa-full|rsa-signature|dss|dss-dh|rsa-aes}/default-provider
```

The alternatives are literal supported selectors, not wildcard syntax. Mappings are PROV_RSA_FULL=1, RSA_SIG=2, DSS=3, DSS_DH=13 and RSA_AES=24. Only `CRYPT_USER_DEFAULT=2`, NULL reserved and fixed System32 `advapi32.dll!CryptGetDefaultProviderW` are exposed. There is no explicit machine-context retry/fallback, provider enumeration, `CryptAcquireContext`, key operation or default-provider mutation.

The reader uses explicit uint32 lengths, BOOL/GetLastError semantics and UTF-16LE uint16 storage. Query sizes are **bytes**, not platform-dependent `wchar_t` counts. Each of two samples makes a NULL size query and bounded caller-buffer read. At most 512 name bytes per sample; missing/odd/oversized/growing/unterminated/embedded-NUL/malformed/unsupported labels refuse. Selected labels support 1–255 bounded ASCII characters; unsupported/localized labels are not guessed. Changed samples refuse; equal samples do not prove atomic or continuous configuration.

`WINDOWS_CAPI_DEFAULT_PROVIDER` retains exact provider type/context/name and selected-metadata commitment. OBSERVED means the selection API returned that label. It does not prove the CSP was opened, is authentic/usable, supports an algorithm, holds keys or was used by an application. The provider name is not an authenticated vendor/software release. The API is deprecated; it is collected for legacy metadata, not recommended for new application cryptography.

## 2. Extended CNG registration scope

The existing fixed-provider/user-mode contract now supports seven exact interfaces:

| URI suffix before `-registration` | Native interface |
|---|---:|
| `cipher` | 1 |
| `hash` | 2 |
| `asymmetric-encryption` | 3 |
| `secret-agreement` | 4 |
| `signature` | 5 |
| `rng` | 6 |
| `key-derivation` | 7 |

Full prefix remains `windows-cng://local/microsoft-primitive/`. Existing bounded caller-owned storage, NTSTATUS, nested-pointer validation, canonical labels and source commitments apply unchanged. No arbitrary/global provider, kernel, key-storage or Schannel interface is admitted. No provider/algorithm/key is opened; registration labels such as RSA/ECDSA/RNG are not normalized crypto capabilities, invocations or PQC assessments.

Existing cipher/hash URIs, facts, defaults and commitments remain unchanged. Pinned v1 consumers must update for the additive interface enum/input/fact unions; older client support is not inferred.

## 3. Exact TCP table resource

```text
kind: WINDOWS_TCP_LISTENERS
path: windows-sockets://local/{ipv4|ipv6}/tcp-listeners
```

An operator approves **the local address-family listener table**, not an individual port, process, remote endpoint or active probe. No CIDR/remote target, UDP, established-connection, owning-module table or socket/process opening is exposed. This can reveal confidential local addresses/ports/PIDs and requires approved custody.

System32 `iphlpapi.dll!GetExtendedTcpTable` uses Windows AF_INET=2 / AF_INET6=23 and TCP_TABLE_OWNER_PID_LISTENER=3, reserved zero. Linux's AF_INET6 constant must not be substituted. Return value is the direct uint32 error code, not BOOL/GetLastError.

Each of two samples reserves a DWORD size variable, NULL-queries required bytes, refuses over 65,536 bytes before allocation, then reads a caller-owned buffer. At most 256 rows; validate fixed-width IPv4/IPv6 ABI, row spans/count/state, network-order low-WORD port, canonical addresses/scopes and unique ordered rows. Higher port DWORD bits are unspecified and ignored. Size growth, non-listener rows, malformed fields, duplicate rows or changed canonical samples refuse rather than returning a partial positive. Native activity/allocation/latency is not proved bounded by caller-buffer accounting.

One strict `WINDOWS_TCP_LISTENER_TABLE` fact retains family, count and canonical rows (`address`, `port`, `owning_pid`, `scope_id`). It reconstructs its selected-metadata digest and binds it to the approved family and receipt. Empty successful samples retain a **table observation with zero rows**, not NO_ASSET/NO_NETWORK. A count is not complete-host coverage. Two equal samples are not atomic or continuously monitored truth.

An owning PID is only an OS table value. There is no process creation time, stable process incarnation, socket handle, executable identity, service relationship or application→endpoint edge. A matching PID in a separate module snapshot cannot justify a join. No TLS handshake/certificate/protocol, remote reachability, firewall state, effective service health or crypto operation is inferred.

The existing UI shows bounded selection/table labels, the first ten TCP rows with explicit unverified-PID/TLS wording and truncation notice. Full rows remain in the authorized stored snapshot. Reads never call Windows again.

## 4. Six-BOM contribution and fail-closed controls

| Evidence | Legitimate classification | Not established |
|---|---|---|
| CAPI default selection | TechBOM metadata | Algorithm/software/vendor/key use; no new CBOM component |
| Extended CNG registration | TechBOM metadata | Working implementation/capability/invocation/PQC use |
| TCP table capture | NBOM + TechBOM metadata references | TLS, process identity/use, network completeness or live reachability |
| Existing TPM device info | HBOM + TechBOM metadata references | Firmware, physical identity, quote or key use |

SBOM/CBOM/NBOM/HBOM/VBOM/TechBOM remain projections of stored evidence, not six independent scans. A TCP table is one observation/reference; its count of rows is **not** the BOM observation count. Zero CBOM components from selection/registration/listener facts never means no cryptography.

Wrong platform, elevation, expiry, missing/denied/error/malformed/changed/over-budget inputs produce explicit gaps, not absence. Per-input/native-buffer/selected-JSON/total/fact guards remain. Snapshots refuse changed source commitments, wrong kind/platform/scope, duplicate facts and promoted use/capability claims. Byte budgets do not provide native-call interruption or internal OS/RSS limits.

Universal Windows, container, network, cloud, HSM/hardware and vendor authorizations remain refused as future capabilities under the current admission contract. A positive preflight/native review does not automatically change those controls.

## 5. Operator-owned preflight and native run

Detailed steps: [Windows bounded qualification packet](../runbooks/windows-bounded-qualification-packet.md).

- Actual assigned operators/reviewers agree target, approved time, fixture state, expected truth, source identifier and negative-case procedures **before measurement**. Do not derive the expected plan from this collector's result.
- Retain mandatory OS and named-SCM inputs in a Windows packet. Add only reviewed existing resources. For TCP, independently specify exact canonical rows/count and false TLS/process-identity claims; for CAPI/CNG, exact type/context/name or interface/labels; for TPM, layout/specification.
- `--preflight-only` checks the packet and writes a strict `PREFLIGHT_ONLY_AWAITING_REAL_WINDOWS_OPERATOR` artifact. No native/elevation query or dispatch. `native_execution_performed`, `independent_approval_verified`, production clearance and container admission are false.
- `--preflight-packet` binds that retained packet to the current target/plan/source identifiers before a native run. Changed commitments/refused packets are not silently regenerated. Existing invocations without this option remain backward-compatible, but are not evidence that this expanded packet was preflighted.
- A source-lock file is shape/path/digest checked for this packet. It is still an **operator-supplied source identifier**, not proof that collection ran from those files. External signatures/verified staging and independent worker checks remain separate.
- Real Windows/version/architecture/token/ACL/service/API availability/lifecycle/isolation/cancellation are required. A Linux preflight or portable ABI fixture is never native PASS. Do not create keys/devices, elevate, install certificates or mutate a customer deployment to manufacture success.

## 6. Remaining gates and phase order

There are no actual assigned operator identities, approved real-Windows fixtures/original returns or new independent decisions supplied in this engineering session. **The operator run is ready to be handed off, not executed or approved.** No automatic notification/SSH/WinRM/channel was invented.

Native TPM SDK/documentation layout discrepancy, real API compatibility/failure behavior, native lifecycle/internal work/latency/isolation/cancellation and independent review remain open. Firmware/hardware identity and application/crypto/TLS-use relationships require justified evidence, not labels or PID proximity. The implementation does not claim every possible Windows provider/hardware surface is complete.

Do not skip these missing prerequisites and label the container phase complete. Phase 4 remains the next ordered universal adapter: bounded offline OCI/image digest/platform/layer inputs, safe archive/link/decompression handling, typed package/config/base-image evidence using existing utilities and the same custody pipeline. No container adapter or later production capability was enabled in this increment.

See [retained local validation](../readiness-evidence/windows-bounded-metadata-2026-10-25.md).

## Pinned native references

- [CryptGetDefaultProviderW contract and byte lengths](https://github.com/MicrosoftDocs/sdk-api/blob/0797841e74f7d55cba99a08948b601604799ef07/sdk-api-src/content/wincrypt/nf-wincrypt-cryptgetdefaultproviderw.md).
- [CAPI constants and WINAPI declaration](https://github.com/mingw-w64/mingw-w64/blob/99144bb19f57a51f7ed82c5c9c1457647565c36b/mingw-w64-headers/include/wincrypt.h).
- [Seven CNG interface constants](https://github.com/mingw-w64/mingw-w64/blob/99144bb19f57a51f7ed82c5c9c1457647565c36b/mingw-w64-headers/include/bcrypt.h).
- [GetExtendedTcpTable direct-return contract and NULL size query](https://github.com/MicrosoftDocs/sdk-api/blob/0797841e74f7d55cba99a08948b601604799ef07/sdk-api-src/content/iphlpapi/nf-iphlpapi-getextendedtcptable.md).
- [TCP owner-PID row/table layout, class and state constants](https://github.com/mingw-w64/mingw-w64/blob/99144bb19f57a51f7ed82c5c9c1457647565c36b/mingw-w64-headers/include/iprtrmib.h).
