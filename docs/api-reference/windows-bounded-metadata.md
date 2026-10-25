# Bounded Windows CAPI and TCP-table candidate contracts

No new API route/service/table. Use existing approved host manifest → intake → immutable original custody → authorized snapshot/CBOM inspection. Reads/export never call the OS again. Universal Windows authorization remains 409/future capability; preflight cannot grant it.

## Inputs

| Kind | Exact resource |
|---|---|
| `WINDOWS_CAPI_DEFAULT_PROVIDER` | `windows-capi://local/current-user/{rsa-full|rsa-signature|dss|dss-dh|rsa-aes}/default-provider` |
| `WINDOWS_TCP_LISTENERS` | `windows-sockets://local/{ipv4|ipv6}/tcp-listeners` |

Alternatives identify separate explicitly approved inputs. No aliases/query/wildcards/remote scopes. CAPI supports only current-user default-selection metadata, not provider/key acquisition. TCP scope approves the complete bounded local family **listener table**, not an endpoint probe, established connections or UDP. [CNG contract](windows-cng-registration-candidate.md) now supports seven exact registration interfaces, with the same provider/user-mode/buffer/pointer guards.

## Strict facts and source binding

Both new fact types fix algorithm/runtime/operation/PQC to UNKNOWN, software name/version/key size null, policy NOT_EVALUATED, capabilities false and local basis OBSERVED **only for returned OS metadata**. Extra/promoted fields refuse.

`WINDOWS_CAPI_DEFAULT_PROVIDER`:

- `purpose: DEFAULT_PROVIDER_SELECTION_METADATA`, `interface: WINDOWS_CAPI_DEFAULT_PROVIDER_QUERY`.
- `provider_context: CURRENT_USER`, numeric type 1/2/3/13/24, bounded ASCII `provider_name`.
- `identity_key: windows-capi:current-user:<type>:default-provider`.
- `capture_basis: DEFAULT_SELECTION_NOT_OPENED_OR_INVOKED`.
- Selected commitment covers context/type/name. Labels do not authenticate a vendor, installed release, usable crypto implementation or key use.

`WINDOWS_TCP_LISTENER_TABLE`:

- `purpose: OS_TCP_LISTENER_TABLE_METADATA`, `interface: WINDOWS_IP_HELPER_TCP_TABLE`.
- `address_family: ipv4|ipv6`, `listener_count: 0..256`, canonical unique sorted `listeners` rows with only `address`, `port`, `owning_pid`, `scope_id`.
- `identity_key: windows-tcp-table:<family>:owner-pid-listener`.
- `capture_basis: REPEATED_TABLE_NOT_PROCESS_IDENTITY_OR_TLS`.
- `process_identity_verified`, `tls_observed`, `asset_absence_proven`: false.
- Selected commitment covers family and rows, not padding/remote-address fields/native allocation. Empty rows remain a table observation, not absence or complete network coverage.

Each fact reconstructs `interface_sha256`; snapshot validation matches receipt `content_sha256`, exact input/family/type/platform and one-fact cardinality. Surrounding host/target scope is required: metadata identities are not globally attested assets. Hashes do not authenticate the producer or prove atomic acquisition.

## Native/refusal boundary

CAPI: fixed System32 `CryptGetDefaultProviderW`, NULL reserved, CRYPT_USER_DEFAULT, BOOL/GetLastError, byte-sized UTF-16 uint16 buffer ≤512 bytes, two size/read samples. No context/provider/key opening or mutation. Deprecated API availability remains a real-Windows gate.

TCP: fixed System32 `GetExtendedTcpTable`, direct uint32 error, Windows AF=2/23, OWNER_PID_LISTENER=3, reserved zero. Two size/read samples, caller block ≤65,536 bytes/sample, fixed 24-/56-byte rows, bounded count/spans/LISTEN state and network-order low-WORD port. No socket/process opening or network traffic.

Missing/denied/unknown/malformed/changed/over-budget/expired/elevated/wrong-platform input is a gap with no positive facts/content digest. No truncation-to-success or fallback scope. Caller-buffer/JSON budgets are not native internal allocation/RSS/latency/cancellation guarantees. Stable samples are not atomic or continuous monitoring. A reported PID does not provide creation time or a process↔listener/application-use relationship.

## Shared projections and display

CAPI/CNG metadata contributes TechBOM; TCP table metadata contributes NBOM + TechBOM. Neither produces CBOM crypto components or inferred SBOM/HBOM/VBOM/use relationships. The eight-surface coverage schema remains stable: CAPI maps to `crypto_configuration`, TCP to `network_listeners`. Table observations and endpoint rows are different counts. No complete six-BOM inventory is inferred.

Existing tenant/RBAC, tamper refusal and export audit remain. UI validates bounded fields/promotions and shows at most ten table rows per fact with explicit unverified-PID/TLS labeling. Full metadata remains in the authorized snapshot.

## Preflight artifact and compatibility

Existing `capture_native_qualification.py` adds `--preflight-only`, `--approved-source-lock-sha256`, `--preflight-packet`. See the [operator runbook](../runbooks/windows-bounded-qualification-packet.md).

New strict public artifact: `cryptoscan.windows-qualification-preflight/v1`, schema `windows-qualification-preflight-v1.schema.json`. It binds target/plan/source identifiers and ordered input IDs, status `PREFLIGHT_ONLY_AWAITING_REAL_WINDOWS_OPERATOR`; native execution, independent approval, production qualification and container admission are false. It is **not NativeEvidence**, does not satisfy the native index and sends no notifications. It checks the same read's source bytes for digest/shape, not measured execution from those files.

Five existing public v1 schemas extend input/fact/CNG-interface unions without changing old defaults; update pinned consumers. Expected-truth assertions permit only the existing bounded registration-label list and the new bounded canonical flat TCP row list in addition to scalars. Other nested/list assertions remain refused. Do not substitute a model-derived fixture for independently agreed operator truth.

[Guide 76](../bank-environment/76-bounded-windows-metadata-and-operator-preflight.md) contains pinned native references, scope and remaining gates. Native Windows, source approval, lifecycle/isolation/cancellation, independent review and bank/deployment acceptance remain pending; later phases are not automatically admitted.
