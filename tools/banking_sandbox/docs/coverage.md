# Scenario and execution coverage

Representation is not product acceptance. The 35 difficult cases and failure cases have bank-scoped subjects and independent hidden expectations. Only the explicitly measured static/live/input-validation paths count as execution.

## 35 required difficult cases

| # | Scenario | Evaluation path |
|---|---|---|
| 1 | `shared-library-20-apps` | Linked fixture + hidden expectation; external actual facts required for full product acceptance |
| 2 | `application-multiple-versions` | Linked fixture + hidden expectation; external actual facts required for full product acceptance |
| 3 | `shared-ip-multiple-services` | Linked fixture + hidden expectation; external actual facts required for full product acceptance |
| 4 | `lb-tls-termination` | Linked fixture + hidden expectation; external actual facts required for full product acceptance |
| 5 | `internal-reencryption` | Linked fixture + hidden expectation; external actual facts required for full product acceptance |
| 6 | `mesh-mtls` | Linked fixture + hidden expectation; external actual facts required for full product acceptance |
| 7 | `application-encryption-over-tls` | Linked fixture + hidden expectation; external actual facts required for full product acceptance |
| 8 | `hsm-backed-rsa` | Linked fixture + hidden expectation; external actual facts required for full product acceptance |
| 9 | `kms-backed-aes` | Linked fixture + hidden expectation; external actual facts required for full product acceptance |
| 10 | `certificate-vs-application-algorithm` | Linked fixture + hidden expectation; external actual facts required for full product acceptance |
| 11 | `sbom-vs-runtime-provider` | Linked fixture + hidden expectation; external actual facts required for full product acceptance |
| 12 | `installed-unused-library` | Linked fixture + hidden expectation; external actual facts required for full product acceptance |
| 13 | `configured-not-negotiated` | Linked fixture + hidden expectation; external actual facts required for full product acceptance |
| 14 | `weak-supported-not-negotiated` | Linked fixture + hidden expectation; external actual facts required for full product acceptance |
| 15 | `strong-negotiated-weak-enabled` | Linked fixture + hidden expectation; external actual facts required for full product acceptance |
| 16 | `vendor-only-no-independent-proof` | Linked fixture + hidden expectation; external actual facts required for full product acceptance |
| 17 | `runtime-missing-sbom` | Linked fixture + hidden expectation; external actual facts required for full product acceptance |
| 18 | `network-without-source` | Linked fixture + hidden expectation; external actual facts required for full product acceptance |
| 19 | `source-without-runtime` | Linked fixture + hidden expectation; external actual facts required for full product acceptance |
| 20 | `multiple-endpoint-certificates` | Linked fixture + hidden expectation; external actual facts required for full product acceptance |
| 21 | `expired-unused-certificate` | Linked fixture + hidden expectation; external actual facts required for full product acceptance |
| 22 | `rotation-stale-inventory` | Linked fixture + hidden expectation; external actual facts required for full product acceptance |
| 23 | `primary-dr-difference` | Linked fixture + hidden expectation; external actual facts required for full product acceptance |
| 24 | `dev-production-difference` | Linked fixture + hidden expectation; external actual facts required for full product acceptance |
| 25 | `controlled-crypto-drift` | Linked fixture + hidden expectation; external actual facts required for full product acceptance |
| 26 | `unknown-implementation` | Linked fixture + hidden expectation; external actual facts required for full product acceptance |
| 27 | `custom-wrapper` | Linked fixture + hidden expectation; external actual facts required for full product acceptance |
| 28 | `dynamic-native-library` | Linked fixture + hidden expectation; external actual facts required for full product acceptance |
| 29 | `image-sbom-mismatch` | Linked fixture + hidden expectation; external actual facts required for full product acceptance |
| 30 | `sidecar-tls-not-application` | Linked fixture + hidden expectation; external actual facts required for full product acceptance |
| 31 | `hsm-signing-source-invisible` | Linked fixture + hidden expectation; external actual facts required for full product acceptance |
| 32 | `kms-api-encryption` | Linked fixture + hidden expectation; external actual facts required for full product acceptance |
| 33 | `legacy-network-only` | Linked fixture + hidden expectation; external actual facts required for full product acceptance |
| 34 | `appliance-config-only` | Linked fixture + hidden expectation; external actual facts required for full product acceptance |
| 35 | `partial-passive-sensor` | Linked fixture + hidden expectation; external actual facts required for full product acceptance |

## Fifteen test modes

| Mode | Implemented execution scope |
|---|---|
| `discovery` | FIXTURES_AND_EXTERNAL_RESULT_VALIDATOR_ONLY |
| `static` | NORMAL_COLLECTOR_AVAILABLE |
| `runtime` | ISOLATED_VM_SAMPLE_AVAILABLE |
| `network` | ISOLATED_VM_SAMPLE_AVAILABLE |
| `sbom` | ACTUAL_INPUT_VALIDATION_AVAILABLE |
| `cbom` | ACTUAL_INPUT_VALIDATION_AVAILABLE |
| `cross-correlation` | FIXTURES_AND_EXTERNAL_RESULT_VALIDATOR_ONLY |
| `evidence-integrity` | ACTUAL_INPUT_VALIDATION_AVAILABLE |
| `drift` | CONTROLLED_FIXTURE_MUTATION_AVAILABLE |
| `pqc` | FIXTURES_AND_EXTERNAL_RESULT_VALIDATOR_ONLY |
| `performance` | BENCHMARK_AVAILABLE |
| `scale` | BENCHMARK_AVAILABLE |
| `failure-recovery` | CONTROLLED_FIXTURE_MUTATION_AVAILABLE |
| `partial-visibility` | FIXTURES_AND_EXTERNAL_RESULT_VALIDATOR_ONLY |
| `conflict-resolution` | FIXTURES_AND_EXTERNAL_RESULT_VALIDATOR_ONLY |

The network/runtime entries mean the **narrow no-NIC VM sample**, not the complete generated portfolio. BOM entries mean actual schema/input validation, not proven use of every production importer or correlation service.

## Source ecosystems

('Python', '.py'), ('Java', '.java'), ('Kotlin', '.kt'), ('C', '.c'), ('C++', '.cpp'), ('C#', '.cs'), ('Go', '.go'), ('Rust', '.rs'), ('JavaScript', '.js'), ('TypeScript', '.ts'), ('PHP', '.php'), ('Ruby', '.rb'), ('COBOL-like', '.cbl'), ('.NET-config', '.config').

## Static semantic scenarios

- `direct-aes`
- `explicit-aes256-gcm`
- `config-key-size`
- `rsa-generation`
- `rsa-pss`
- `ecdsa`
- `ecdh`
- `hkdf`
- `hmac`
- `sha256`
- `sha1`
- `md5`
- `wrapper`
- `helper`
- `config-selection`
- `environment-selection`
- `database-selection`
- `dependency-only`
- `dead-code`
- `unreachable-code`
- `test-only`
- `production-code`
- `misleading-name`
- `native-library`
- `provider-switch`
- `negative-lookalike`

Python templates provide the detailed semantic variants. Other ecosystems have direct API/configuration examples; **not every scenario is compiled and executed in all 14 ecosystems**. Source fixtures are never run by the static harness. Dead/test/dependency/config examples are independently modeled as static evidence, not runtime proof. Actual family detection misses are reported, not repaired by changing expected truth to match output.

## Failure declarations

- `unavailable-host`
- `connection-refused`
- `timeout`
- `expired-authorization`
- `invalid-certificate`
- `malformed-sbom`
- `malformed-cbom`
- `corrupted-evidence`
- `duplicate-asset`
- `stale-inventory`
- `missing-package`
- `hsm-unavailable`
- `kms-unavailable`
- `database-timeout`
- `redis-failure`
- `collector-crash`
- `partial-network-visibility`
- `network-route-failure`
- `kubernetes-api-unavailable`

Actual executed checks: malformed SBOM, malformed CBOM, corrupted evidence, missing materialized source/runtime cases, denied socket/oracle access, plus the isolated VM refused-service sample. Other failures remain declared, with PARTIAL/FAILED/UNKNOWN expectations and no inference of NO CRYPTO. This distinction is an explicit remaining limitation, not a completion claim.
