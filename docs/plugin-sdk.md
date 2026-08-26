# Plugin SDK

CryptoScan discovers cryptography through **plugins**. A plugin never writes
policy and never mutates customer infrastructure.

## Lifecycle

1. `validate_configuration()`
2. `authenticate()` (no-op for filesystem / git)
3. `discover(target)` → scanner-native objects (`RawFinding` today)
4. `normalize(raw)` → `CryptoObservation` dicts
5. `collect_evidence(observations)` → hashed records (worker stage)
6. `health_check()`

The worker pipeline is the only orchestrator. Plugins must be side-effect
free except for reading the target.

## Contract

Implement `scanner.core.plugin.DiscoveryPlugin`:

| Field / method | Meaning |
|---|---|
| `plugin_id` | Stable id: `static-{java,python,js,csharp,go,php,ruby,rust,kotlin,config}-scanner` |
| `plugin_version` | Semver string stamped on evidence |
| `capabilities()` | `source_code`, `java`, `filesystem`, … |
| `discover(target)` | Read-only collection |
| `normalize(raw)` | Map to `CryptoObservation.to_dict()` |

Canonical observation fields live in
`shared_models.observation.CryptoObservation`. Downstream services consume
that shape, not `Cipher.getInstance` regex groups.

## Errors

- Raise on configuration that would be unsafe (path escape, live cloud
  without opt-in).
- Swallow per-file parse errors and record them; never abort the estate scan.
- Live cloud / network plugins stay **off** unless the operator sets `live`.

## Version compatibility

`plugin_version` is stored on every evidence row. Policy and CBOM must not
assume a scanner version. Adding a plugin must not require editing
`PipelineRunner` if it is registered in `scanner.core.plugin.registry`.

## Testing

Ship unit tests that:

- ignore crypto mentioned only in comments
- resolve local string constants
- leave unrelated files unscanned after a parse error
- emit a `CryptoObservation` with `collector` + `collector_version`
