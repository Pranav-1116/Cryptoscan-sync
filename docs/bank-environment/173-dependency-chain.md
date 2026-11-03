# The dependency chain, twenty-six points

`cryptoscan.cbom-dependency-guide/1` · generated 2026-11-03T06:26:36Z · **26 pass · 0 partial · 0 fail** · 77 probes

**26/26 points of the chain are present in the built projection.**

```
BUSINESS SYSTEM → APPLICATION → RELEASE → PROCESS / CONTAINER
    → CRYPTO PROVIDER → CRYPTO OPERATION → ALGORITHM → KEY METADATA
    → HSM / KMS → CERTIFICATE / NETWORK → HARDWARE → VENDOR
```

26 of 26 points of the dependency chain are present in the built projection, across 77 probes; 47 assets and 65 evidenced edges

## The levels, as the estate holds them

| level | nodes |
|---|---|
| system | 1 |
| application | 1 |
| release | 3 |
| process | 7 |
| provider | 2 |
| operation | 3 |
| algorithm | 10 |
| key | 2 |
| key_provider | 3 |
| certificate | 1 |
| endpoint | 3 |
| vendor | 2 |
| hardware | 5 |

## The chain from the application

**Payments API: down 3 release → 6 process → 2 provider → 3 operation → 10 algorithm → 2 key → 3 key_provider → 1 certificate → 2 endpoint; up 1 system**

- **release** — `payments-api-4.2.0.jar`, `payments-api:4.2.0`, `payments-api 4.2.0`
- **process** — `payments-api-deploy`, `prod-cluster`, `payments`, `payments-api-7d9f4c-x2m8p`
- **provider** — `libcrypto.so.3`, `OpenSSL 3.0.11`
- **operation** — `OP-ENCRYPT-002`, `OP-SIGN-001`, `OP-STATIC-003`
- **algorithm** — `AES-256`, `DES-ECB`, `RSA-2048`, `SHA-256`
- **key** — `KEY-REF-4401`, `KEY-REF-4402`
- **key_provider** — `HSM-001`, `KMS-01`, `TPM-01`
- **certificate** — `CERT-001`
- **endpoint** — `lb-01:443`, `payments.bank.example:443`

## HOP 1..N

**2 hop(s): payments.bank.example:443 → lb-01:443 (TLS1.3/TLS_AES_256_GCM_SHA384) → lb-01:443 → payments-api (TLS1.2/ECDHE-RSA-AES128-GCM-SHA256)**

| hop | from | to | mode | TLS | suite | class |
|---|---|---|---|---|---|---|
| 1 | payments.bank.example:443 | lb-01:443 | FORWARDS_TO | TLS1.3 | TLS_AES_256_GCM_SHA384 | CONFIGURED |
| 2 | lb-01:443 | payments-api | ROUTES_TO | TLS1.2 | ECDHE-RSA-AES128-GCM-SHA256 | CONFIGURED |

## Capability, and usage

**OpenSSL 3.0.11: 3 capability(ies), 3 observed use(s) from 2 layer(s), 1 listed and never used, 1 used without being listed**

- capability: AES-256, RSA-2048, SHA-256
- usage: AES-256, DES-ECB, RSA-2048
- listed and never used: SHA-256

## Disagreement

**2 dependency conflict(s): 1 LAYER, 1 VERSION**

- `VERSION` OpenSSL 3.0.11: sbom=3.0.11, process-map=3.0.13, agent-inventory=3.0.11
- `LAYER` payments-api[1821]: STATIC_OBSERVED=DES-ECB, RUNTIME_OBSERVED=AES-256/RSA-2048

## What moved

**1 changed, 0 added, 0 removed**

- `CRYPTO_DEPENDENCY_CHANGED` OP-SIGN-001 USES_ALGORITHM: RSA-2048 → RSA-3072 (before `EVID-95004`, after `EVID-95004`, detected 2026-11-03T08:30:00Z)

## The PQC blocker is the path

**RSA-2048: 10 blocker(s) on the chain — ALGORITHM, CERTIFICATE, FIRMWARE, HSM, KEY_REFERENCE, LOAD_BALANCER, NETWORK_ENDPOINT, TPM, VENDOR_PRODUCT**

| kind | name | relation | why it blocks |
|---|---|---|---|
| ALGORITHM | RSA-2048 | — | the algorithm itself is quantum-sensitive |
| HSM | HSM-001 | BACKED_BY | a migration that moves this algorithm has to change this device, its firmware or its key store |
| KEY_REFERENCE | KEY-REF-4401 | USES_KEY | the key has to be re-issued and every consumer of the reference re-pointed |
| TPM | TPM-01 | USES_TPM | a migration that moves this algorithm has to change this device, its firmware or its key store |
| NETWORK_ENDPOINT | payments.bank.example:443 | EXPOSES | this listener negotiates the suite, and a listener is the hop a client actually meets |
| CERTIFICATE | CERT-001 | PRESENTS | the certificate carries the key exchange and the signature that a migration has to replace |
| NETWORK_ENDPOINT | lb-01:443 | FORWARDS_TO | this listener negotiates the suite, and a listener is the hop a client actually meets |
| LOAD_BALANCER | LB-01 | LISTENS_ON | a migration that moves this algorithm has to change this device, its firmware or its key store |
| FIRMWARE | BIG-IP 17.1.1 | RUNS_FIRMWARE | the firmware has to support ML-KEM before the device can negotiate it |
| VENDOR_PRODUCT | BIG-IP i5800 | HAS_MODEL | the product's crypto is the vendor's to change, not the bank's |

## What the count means

**12 crypto asset(s) discovered; 12/70 application(s) inspected (17.1%); the count is what was discovered, not what exists**

| Row | Question | Verdict | Probes |
|---|---|---|---|
| `CBOM-01` | an application reaches its crypto by use, not by containment | **PASS** | 3, 0 failing |
| `CBOM-02` | an SBOM becomes a CBOM through capability and evidence, never a preset edge | **PASS** | 3, 0 failing |
| `CBOM-03` | a source hit is a dependency at STATIC_OBSERVED and never a runtime use | **PASS** | 4, 0 failing |
| `CBOM-04` | a runtime observation names the process, the provider and the parameters | **PASS** | 3, 0 failing |
| `CBOM-05` | the provider is a node, so a library advisory maps to assets | **PASS** | 3, 0 failing |
| `CBOM-06` | the operation is a node with its parameters, not a cipher name | **PASS** | 3, 0 failing |
| `CBOM-07` | a key reaches the graph as metadata and never as material | **PASS** | 3, 0 failing |
| `CBOM-08` | an HSM that supports RSA is not an application that uses the HSM | **PASS** | 3, 0 failing |
| `CBOM-09` | a KMS answer is one of four states and the strongest one is named | **PASS** | 3, 0 failing |
| `CBOM-10` | the certificate chain is a listener dependency, not the application's crypto | **PASS** | 3, 0 failing |
| `CBOM-11` | the negotiated crypto is NETWORK_OBSERVED at the listener | **PASS** | 3, 0 failing |
| `CBOM-12` | a multi-hop path is HOP 1..N, never one collapsed dependency | **PASS** | 3, 0 failing |
| `CBOM-13` | USES_HSM, USES_TPM, BACKED_BY, PROTECTED_BY and RUNS_ON carry evidence | **PASS** | 2, 0 failing |
| `CBOM-14` | a vendor firmware advisory maps back to the assets that depend on it | **PASS** | 3, 0 failing |
| `CBOM-15` | an algorithm reaches an image through the library it lives in | **PASS** | 3, 0 failing |
| `CBOM-16` | existence in an image is not a load, and the Kubernetes path is walkable | **PASS** | 2, 0 failing |
| `CBOM-17` | the deployment topology joins the hardware estate | **PASS** | 3, 0 failing |
| `CBOM-18` | which business systems depend on RSA-2048 is a query, not a spreadsheet | **PASS** | 3, 0 failing |
| `CBOM-19` | every dependency edge carries its record, and a collector where one exists | **PASS** | 3, 0 failing |
| `CBOM-20` | capability and usage are two sets and never one | **PASS** | 3, 0 failing |
| `CBOM-21` | a disagreement about a dependency is the finding, with every source kept | **PASS** | 3, 0 failing |
| `CBOM-22` | a dependency that moved is a change with evidence on both sides | **PASS** | 3, 0 failing |
| `CBOM-23` | a dependency that stops being observed is superseded, not deleted | **PASS** | 3, 0 failing |
| `CBOM-24` | a count is reported against what was inspected, never against the bank | **PASS** | 3, 0 failing |
| `CBOM-25` | the PQC blocker is a path through the graph, not a property of the algorithm | **PASS** | 3, 0 failing |
| `CBOM-26` | the whole chain joins the Digital Twin's canonical estate graph | **PASS** | 3, 0 failing |

## `CBOM-01` — PASS

*an application reaches its crypto by use, not by containment* (guide 173, the chain)

- **PASS** `application-to-provider-is-evidenced` — Payments API → provider: ['libcrypto.so.3', 'OpenSSL 3.0.11']
- **PASS** `the-use-is-an-operation-not-an-edge-to-a-cipher` — operations ['OP-ENCRYPT-002', 'OP-SIGN-001', 'OP-STATIC-003']; no application USES_CRYPTO RSA-2048 edge
- **PASS** `the-chain-starts-at-the-business-system` — Payments System: down 1 application → 3 release → 6 process → 2 provider → 3 operation → 10 algorithm → 2 key → 3 key_provider → 1 certificate → 2 endpoint; up nothing

## `CBOM-02` — PASS

*an SBOM becomes a CBOM through capability and evidence, never a preset edge* (guide 173, the chain)

- **PASS** `provider-lists-its-capabilities-at-CAPABILITY` — 3 SUPPORTS edge(s) at ['CAPABILITY']
- **PASS** `provider-implements-algorithms-at-an-evidenced-class` — classes ['OBSERVED']
- **PASS** `no-provider-USES-AES-edge-exists` — no provider USES_* edge; a provider implements, it does not use

## `CBOM-03` — PASS

*a source hit is a dependency at STATIC_OBSERVED and never a runtime use* (guide 173, the chain)

- **PASS** `three-static-edges-file-then-call-then-algorithm` — source-analysis edges: DECLARES, INVOKES, LOADS, RUNS_APPLICATION, USES_ALGORITHM, USES_ALGORITHM, USES_CRYPTO
- **PASS** `every-static-edge-is-STATIC_OBSERVED` — classes ['STATIC_OBSERVED']
- **PASS** `STATIC_OBSERVED-is-not-PROVEN` — PROVEN = ['CONFIGURED', 'NETWORK_OBSERVED', 'OBSERVED', 'RUNTIME_OBSERVED']; STATIC_OBSERVED excluded
- **PASS** `the-file-carries-api-and-line` — SOURCE file node beside the crypto call, with api and line 214

## `CBOM-04` — PASS

*a runtime observation names the process, the provider and the parameters* (guide 173, the chain)

- **PASS** `the-operation-hangs-off-the-process` — 2 RUNTIME_OBSERVED INVOKES edge(s)
- **PASS** `the-process-loads-the-provider` — payments-api[1821] LOADS OpenSSL at RUNTIME_OBSERVED
- **PASS** `the-operation-names-its-parameters` — SIGN / RSA-2048 / 2048 / PSS / SHA-256

## `CBOM-05` — PASS

*the provider is a node, so a library advisory maps to assets* (guide 173, the chain)

- **PASS** `provider-and-algorithm-are-different-kinds` — CRYPTO_PROVIDER vs ALGORITHM
- **PASS** `the-provider-carries-a-family-and-a-version` — family OPENSSL, version 3.0.11
- **PASS** `the-provider-is-reachable-from-the-application` — up from the provider: ['system', 'application', 'process']

## `CBOM-06` — PASS

*the operation is a node with its parameters, not a cipher name* (guide 173, the chain)

- **PASS** `signature-names-seven-of-nine-fields` — present ['operation', 'algorithm', 'key_size', 'padding', 'hash', 'purpose', 'provider']; mode and curve do not apply to RSA signing
- **PASS** `a-block-cipher-without-a-mode-is-refused` — AES with no mode → BLOCK_CIPHER_WITHOUT_MODE
- **PASS** `an-unknown-verb-is-refused` — 'USES_CRYPTO' is not an operation → UNKNOWN_OPERATION

## `CBOM-07` — PASS

*a key reaches the graph as metadata and never as material* (guide 173, keys)

- **PASS** `the-key-carries-reference-size-purpose-and-holder` — pkcs11:token=bank;id=4401 / RSA-2048 / SIGNING / HSM-001
- **PASS** `key-material-is-refused` — private_key field → KEY_MATERIAL_REFUSED
- **PASS** `no-asset-holds-a-private-key` — no attribute anywhere contains a private-key marker

## `CBOM-08` — PASS

*an HSM that supports RSA is not an application that uses the HSM* (guide 173, keys)

- **PASS** `the-capability-is-VENDOR_DECLARED` — HSM-001 SUPPORTS ['RSA-2048'] at VENDOR_DECLARED
- **PASS** `the-use-is-an-operation-BACKED_BY-the-HSM` — 1 BACKED_BY edge(s) at RUNTIME_OBSERVED
- **PASS** `the-two-claims-are-separate-edges` — SUPPORTS on the HSM, BACKED_BY on the operation

## `CBOM-09` — PASS

*a KMS answer is one of four states and the strongest one is named* (guide 173, keys)

- **PASS** `the-four-states-are-distinct` — SUPPORTED / CONFIGURED / REFERENCED / ACTUALLY_USED
- **PASS** `the-kms-in-this-estate-is-configured-not-used` — KMS-01: 2 answer(s), strongest CONFIGURED — CONFIGURED
- **PASS** `an-HSM-backed-operation-is-the-only-ACTUALLY_USED-answer` — HSM-001: 3 answer(s), strongest ACTUALLY_USED — SUPPORTED, ACTUALLY_USED

## `CBOM-10` — PASS

*the certificate chain is a listener dependency, not the application's crypto* (guide 173, network)

- **PASS** `only-a-listener-presents-the-certificate` — PRESENTS from ['payments.bank.example:443']
- **PASS** `the-application-holds-no-certificate-edge` — no PRESENTS or USES_CERTIFICATE from Payments API
- **PASS** `the-application-usage-set-excludes-the-certificate-algorithm` — ECDSA belongs to CERT-001's key, not to the provider's observed uses

## `CBOM-11` — PASS

*the negotiated crypto is NETWORK_OBSERVED at the listener* (guide 173, network)

- **PASS** `the-handshake-is-the-only-source` — 2 NEGOTIATES edge(s), basis ['tls-handshake']
- **PASS** `the-suite-is-decomposed-into-three-assets` — bulk, mac and kex as three crypto assets
- **PASS** `the-endpoint-reaches-the-application` — 1 suite(s) negotiated, 0 supported but never negotiated, 3 crypto asset(s) behind the session, 1 used inside a process

## `CBOM-12` — PASS

*a multi-hop path is HOP 1..N, never one collapsed dependency* (guide 173, network)

- **PASS** `the-hops-are-numbered-in-order` — 2 hop(s): HOP 1 payments.bank.example:443 → lb-01:443 (FORWARDS_TO), HOP 2 lb-01:443 → payments-api (ROUTES_TO)
- **PASS** `each-hop-carries-its-own-class` — classes ['CONFIGURED', 'CONFIGURED']
- **PASS** `a-hop-with-no-facts-is-refused` — a hop with no target → HOP_WITHOUT_FACTS

## `CBOM-13` — PASS

*USES_HSM, USES_TPM, BACKED_BY, PROTECTED_BY and RUNS_ON carry evidence* (guide 173, hardware)

- **PASS** `every-hardware-relation-in-the-spec-is-present` — present ['BACKED_BY', 'PROTECTED_BY', 'RUNS_ON', 'USES_KMS', 'USES_TPM']
- **PASS** `each-carries-an-evidence-id` — every one of them has an evidence id

## `CBOM-14` — PASS

*a vendor firmware advisory maps back to the assets that depend on it* (guide 173, hardware)

- **PASS** `the-device-is-supplied-by-the-vendor` — LB-01 SUPPLIED_BY F5
- **PASS** `the-device-names-its-firmware-version` — BIG-IP 17.1.1 as a node with a version
- **PASS** `the-vulnerability-reaches-a-listener-and-an-application` — up from the firmware: ['endpoint']

## `CBOM-15` — PASS

*an algorithm reaches an image through the library it lives in* (guide 173, build)

- **PASS** `the-library-implements-the-algorithm` — libcrypto.so.3 IMPLEMENTS the algorithms, and the package LINKS the library
- **PASS** `the-package-reaches-the-image-and-the-image-the-application` — image SHIPS package; artifact PACKAGED_AS image; application RELEASED_AS release
- **PASS** `the-library-is-a-node-not-an-attribute` — libcrypto.so.3 is a CRYPTO_LIBRARY

## `CBOM-16` — PASS

*existence in an image is not a load, and the Kubernetes path is walkable* (guide 173, build)

- **PASS** `the-kubernetes-path-has-six-relations` — image → container → pod → process → application
- **PASS** `the-image-edge-is-imported-and-the-load-is-runtime` — 'exists in the image' at IMPORTED, 'loaded' at RUNTIME_OBSERVED

## `CBOM-17` — PASS

*the deployment topology joins the hardware estate* (guide 173, build)

- **PASS** `every-topology-relation-is-present` — present ['MEMBER_OF_CLUSTER', 'RUNS_IN', 'RUNS_ON', 'SCHEDULED_ON', 'SCHEDULES']
- **PASS** `the-cluster-and-node-are-nodes` — CLUSTER prod-cluster and KUBERNETES_NODE node-07
- **PASS** `the-node-sits-on-a-physical-host` — node-07 RUNS_ON srv-k8s-07

## `CBOM-18` — PASS

*which business systems depend on RSA-2048 is a query, not a spreadsheet* (guide 173, queries)

- **PASS** `the-system-is-named-through-an-evidenced-path` — 1 business system(s) depend on RSA-2048 through 1 application(s)
- **PASS** `the-path-is-printed-with-its-classes` — Payments API → payments-api[1821] → OpenSSL 3.0.11 → RSA-2048
- **PASS** `the-strict-answer-excludes-static-only-paths` — strict answer: no application reaches RSA-2048

## `CBOM-19` — PASS

*every dependency edge carries its record, and a collector where one exists* (guide 173, evidence)

- **PASS** `no-dependency-edge-is-missing-a-required-field` — 58 of 58 complete
- **PASS** `a-collector-is-named-where-a-record-exists` — 22 edge(s) name a collector: ['PROC-PROBE-01', 'TLS-SENSOR-04']
- **PASS** `the-nine-fields-are-declared` — EDGE_FIELDS = ['source', 'target', 'relationship', 'basis', 'confidence', 'evidence_id', 'evidence_type', 'observed_at', 'first_seen', 'last_seen']

## `CBOM-20` — PASS

*capability and usage are two sets and never one* (guide 173, evidence)

- **PASS** `capability-is-what-the-provider-lists` — capability ['AES-256', 'RSA-2048', 'SHA-256']
- **PASS** `usage-is-what-was-observed` — usage ['AES-256', 'DES-ECB', 'RSA-2048']
- **PASS** `the-difference-is-reported-not-resolved` — listed and never used: ['SHA-256']

## `CBOM-21` — PASS

*a disagreement about a dependency is the finding, with every source kept* (guide 173, conflict)

- **PASS** `the-version-disagreement-is-found` — 2 dependency conflict(s): 1 LAYER, 1 VERSION
- **PASS** `every-source-is-preserved` — values ['3.0.11', '3.0.13'] from ['sbom', 'process-map', 'agent-inventory']
- **PASS** `the-static-and-runtime-layers-also-disagree` — the process invoked AES-256-GCM at runtime and DES-ECB statically

## `CBOM-22` — PASS

*a dependency that moved is a change with evidence on both sides* (guide 173, temporal)

- **PASS** `the-signature-move-is-detected` — RSA-2048 → RSA-3072
- **PASS** `both-evidence-ids-are-kept` — before EVID-95004, after EVID-95004, at 2026-11-03T08:30:00Z
- **PASS** `the-same-estate-compared-with-itself-shows-nothing` — no change when nothing moved

## `CBOM-23` — PASS

*a dependency that stops being observed is superseded, not deleted* (guide 173, temporal)

- **PASS** `the-lifecycle-states-are-derived-per-edge` — counts {'ACTIVE': 14, 'CHANGED': 3, 'FIRST_SEEN': 1, 'UNKNOWN': 47}
- **PASS** `the-old-edge-is-reported-not-silently-dropped` — 4 network change(s): 4 EDGE_SUPERSEDED
- **PASS** `the-six-word-vocabulary-is-reachable` — vocabulary seen: ['ACTIVE', 'CHANGED', 'FIRST_SEEN', 'SUPERSEDED', 'UNKNOWN']

## `CBOM-24` — PASS

*a count is reported against what was inspected, never against the bank* (guide 173, honesty)

- **PASS** `twelve-of-seventy-is-partial-and-not-quotable` — 12 crypto asset(s) discovered; 12/70 application(s) inspected (17.1%); the count is what was discovered, not what exists
- **PASS** `the-network-denominator-reconciles` — expected 70 endpoint(s): observed 12, unavailable 40, unknown 18, permission denied 0 — coverage PARTIAL
- **PASS** `a-consumer-that-claims-more-is-refused` — network coverage PARTIAL propagates to cbom PARTIAL, twin PARTIAL; 1 laundered

## `CBOM-25` — PASS

*the PQC blocker is a path through the graph, not a property of the algorithm* (guide 173, pqc)

- **PASS** `the-blockers-are-named-per-hop` — RSA-2048: 10 blocker(s) on the chain — ALGORITHM, CERTIFICATE, FIRMWARE, HSM, KEY_REFERENCE, LOAD_BALANCER, NETWORK_ENDPOINT, TPM, VENDOR_PRODUCT
- **PASS** `the-algorithm-itself-is-labelled-separately` — RSA-2048 is quantum-sensitive, and that is one blocker of several
- **PASS** `a-listener-blocker-names-the-suite-it-negotiates` — the listener blocker carries the suites it negotiates

## `CBOM-26` — PASS

*the whole chain joins the Digital Twin's canonical estate graph* (guide 173, twin)

- **PASS** `the-twin-reads-every-edge-of-this-projection` — 65 edge(s) into the twin, 65 in the BOM
- **PASS** `the-twin-names-the-system-and-the-application` — systems ['Payments System'], one of 1 applications
- **PASS** `the-twin-carries-the-keys-and-the-tls` — keys ['HSM-001', 'KEY-REF-4401', 'KEY-REF-4402', 'KMS-01'], 2 TLS edge(s)

## What this does not prove

- the fixture is the bank's own path: every shape is real, the rows are not
- the provider's operation list is what a runtime probe saw once; a second sample could add an operation and no sample can remove one
- a static hit names a file, an API and a line; it never proves the branch ran
- the key record is a reference and its metadata: nothing here proves which key produced a signature, and nothing here would hold the key if it could
- the KMS answer is the strongest single answer in the estate, not the strongest answer per application
- coverage is arithmetic on what the collectors reported; it cannot see an application that was never scanned
