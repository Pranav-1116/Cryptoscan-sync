# The chain, closed: six questions under the twenty-six points

`cryptoscan.cbom-chain-closure/1` · generated 2026-11-03T07:35:44Z · **6 pass · 0 partial · 0 fail** · 18 probes

6 of 6 questions close on the built projection, across 18 probes; 64 assets and 85 claims

| Row | Question | Verdict | Probes |
|---|---|---|---|
| `CLOSE-01` | every dependency edge carries the fields the review names, the collector included | **PASS** | 3, 0 failing |
| `CLOSE-02` | a capability listed by a source is a question, and only an evidence class answers it | **PASS** | 3, 0 failing |
| `CLOSE-03` | application, certificate, network and platform crypto are counted apart | **PASS** | 3, 0 failing |
| `CLOSE-04` | the transport path ends at an operation, a key and the device that holds it | **PASS** | 3, 0 failing |
| `CLOSE-05` | a PQC requirement is answered against each device's own capability list | **PASS** | 3, 0 failing |
| `CLOSE-06` | the assembled graph is one projection and names the families it reaches | **PASS** | 3, 0 failing |

## The edge's record

**73 dependency edge(s): 73 carry all six structural fields, 4 carry all 12; 34 name a collector; short on collector 34/73, collector_version 34/73, observed_at 41/73, first_seen 18/73, last_seen 18/73**

| field | carried by |
|---|---|
| `source` | 73/73 |
| `target` | 73/73 |
| `relationship` | 73/73 |
| `basis` | 73/73 |
| `confidence` | 73/73 |
| `evidence_id` | 73/73 |
| `evidence_type` | 73/73 |
| `collector` | 34/73 |
| `collector_version` | 34/73 |
| `observed_at` | 41/73 |
| `first_seen` | 18/73 |
| `last_seen` | 18/73 |

## The SBOM join

**OpenSSL 3.0.11: 6 capability(ies) as the source lists them; 2 corroborated by runtime or network evidence, 0 static only, 0 configured only, 4 with nothing behind them; 1 use not on the list**

| capability | algorithms | classes | verdict |
|---|---|---|---|
| OpenSSL 3.0.11:SHA-256 | SHA-256 | — | LISTED_ONLY |
| OpenSSL 3.0.11:ECDSA-P256 | ECDSA-P256 | — | LISTED_ONLY |
| OpenSSL 3.0.11:AES-128 | AES-128 | — | LISTED_ONLY |
| OpenSSL 3.0.11:RSA-2048 | RSA-2048 | RUNTIME_OBSERVED | CORROBORATED |
| OpenSSL 3.0.11:AES-256 | AES-256 | RUNTIME_OBSERVED | CORROBORATED |
| OpenSSL 3.0.11:AES-192 | AES-192 | — | LISTED_ONLY |

## Four domains, never summed

**application: 3 algorithm(s) from 14 node(s); certificate: 2 from 5; network: 5 from 5; platform: 5 node(s); 1 domain pair(s) share an algorithm**

| domain | nodes | algorithms |
|---|---|---|
| APPLICATION | 14 | AES-256, DES-ECB, RSA-2048 |
| PLATFORM | 5 | — |
| CERTIFICATE | 5 | ECDSA-P256, RSA-2048 |
| NETWORK | 5 | AES-256-GCM, ECDHE-RSA-AES128-GCM-SHA256, SHA-384, TLS_AES_256_GCM_SHA384, X25519 |

## The path, down to the operation

**3 hop(s): payments.bank.example:443 → lb-01:443 (TLS1.3/TLS_AES_256_GCM_SHA384) → lb-01:443 → payments-api (TLS1.2/ECDHE-RSA-AES128-GCM-SHA256) → payments-api → OpenSSL 3.0.11 (SIGN/RSA-2048) → SIGN → KEY-REF-4401 → HSM-001**

| hop | from | to | mode | TLS | suite | class |
|---|---|---|---|---|---|---|
| 1 | payments.bank.example:443 | lb-01:443 | FORWARDS_TO | TLS1.3 | TLS_AES_256_GCM_SHA384 | CONFIGURED |
| 2 | lb-01:443 | payments-api | ROUTES_TO | TLS1.2 | ECDHE-RSA-AES128-GCM-SHA256 | CONFIGURED |
| 3 | payments-api | OpenSSL 3.0.11 | SIGN | — | RSA-2048 | RUNTIME_OBSERVED |

the key behind it: `KEY-REF-4401` held by `HSM-001`

## PQC, in the device's own words

**RSA-2048: 7 device(s) on the migration path; 1 advertise a required PQC algorithm, 1 publish a capability list without one, 5 publish none at all**

| device | kind | readiness | supports |
|---|---|---|---|
| lb-01:443 | NETWORK_ENDPOINT | UNKNOWN | — |
| HSM-001 | HSM | READY | HSM-001:ML-KEM-768, ML-KEM-768, RSA-2048 |
| payments.bank.example:443 | NETWORK_ENDPOINT | UNKNOWN | — |
| LB-01 | LOAD_BALANCER | UNKNOWN | — |
| BIG-IP 17.1.1 | FIRMWARE | BLOCKED | BIG-IP 17.1.1:AES-256-GCM |
| BIG-IP i5800 | VENDOR_PRODUCT | UNKNOWN | — |
| TPM-01 | TPM | UNKNOWN | — |

## One graph

**64 node(s) of 37 kind(s), 85 edge(s) over 46 relation(s); families present: KUBERNETES (7), HARDWARE (4), NETWORK (2), VENDOR (3), KEY_STORE (4), SUPPLY_CHAIN (5); source CANONICAL_ESTATE, one store**

| family | kinds present |
|---|---|
| KUBERNETES | CLUSTER, CONTAINER, DEPLOYMENT, KUBERNETES_NODE, NAMESPACE, POD, SERVICE |
| HARDWARE | FIRMWARE, KUBERNETES_NODE, PHYSICAL_SERVER, TPM |
| NETWORK | LOAD_BALANCER, NETWORK_ENDPOINT |
| VENDOR | VENDOR, VENDOR_PRODUCT, VULNERABILITY |
| KEY_STORE | HSM, KEY_REFERENCE, KMS, TPM |
| SUPPLY_CHAIN | ARTIFACT, CRYPTO_LIBRARY, IMAGE, PACKAGE, RELEASE |

## `CLOSE-01` — PASS

*every dependency edge carries the fields the review names, the collector included*

- **PASS** `the-review-fields-are-all-declared` — 9 review field(s), 12 audited; missing none
- **PASS** `the-collector-is-counted-not-assumed` — collector on 34/73 edge(s), collector_version on 34/73
- **PASS** `a-field-nobody-supplied-is-a-shortfall` — shortfalls ['collector 34/73', 'collector_version 34/73']; 4/73 carry all 12

## `CLOSE-02` — PASS

*a capability listed by a source is a question, and only an evidence class answers it*

- **PASS** `a-verdict-and-its-classes-agree` — 6 capability(ies), verdicts {'CORROBORATED': 2, 'CONFIGURED_ONLY': 0, 'STATIC_ONLY': 0, 'LISTED_ONLY': 4}; listed with no class: ['OpenSSL 3.0.11:SHA-256', 'OpenSSL 3.0.11:ECDSA-P256', 'OpenSSL 3.0.11:AES-128', 'OpenSSL 3.0.11:AES-192']
- **PASS** `a-listed-and-unused-capability-stays-listed` — listed only ['OpenSSL 3.0.11:SHA-256', 'OpenSSL 3.0.11:ECDSA-P256', 'OpenSSL 3.0.11:AES-128', 'OpenSSL 3.0.11:AES-192']; corroborated ['OpenSSL 3.0.11:RSA-2048', 'OpenSSL 3.0.11:AES-256']
- **PASS** `the-usage-that-was-never-listed-is-still-reported` — used but not listed: ['DES-ECB']

## `CLOSE-03` — PASS

*application, certificate, network and platform crypto are counted apart*

- **PASS** `the-four-domains-exist` — domains ['APPLICATION', 'CERTIFICATE', 'NETWORK', 'PLATFORM'], nodes [14, 5, 5, 5]
- **PASS** `a-certificate-algorithm-is-not-an-application-use` — certificate ['ECDSA-P256', 'RSA-2048'], application ['AES-256', 'DES-ECB', 'RSA-2048']
- **PASS** `an-overlap-is-reported-and-never-summed` — 1 pair(s) share an algorithm {'APPLICATION+CERTIFICATE': ['RSA-2048']}; naive total 10 vs union 9

## `CLOSE-04` — PASS

*the transport path ends at an operation, a key and the device that holds it*

- **PASS** `the-transport-hops-stay-hops` — 3 hop(s); payments.bank.example:443 → lb-01:443, lb-01:443 → payments-api, payments-api → OpenSSL 3.0.11
- **PASS** `the-terminal-hop-is-the-operation-with-its-parameters` — HOP 3 payments-api → OpenSSL 3.0.11 (SIGN / RSA-2048/SHA-256)
- **PASS** `the-key-and-the-hsm-hang-off-that-hop` — key KEY-REF-4401 held by HSM-001

## `CLOSE-05` — PASS

*a PQC requirement is answered against each device's own capability list*

- **PASS** `the-three-readiness-answers-are-distinguished` — 7 device(s): {'READY': 1, 'BLOCKED': 1, 'UNKNOWN': 5}; required ['ML-KEM-768', 'ML-KEM-1024', 'X25519MLKEM768', 'ML-DSA-65']
- **PASS** `the-firmware-publishes-a-list-without-ml-kem` — BIG-IP 17.1.1: BLOCKED — supports ['BIG-IP 17.1.1:AES-256-GCM']
- **PASS** `a-device-that-published-no-list-is-UNKNOWN-not-READY` — ready ['HSM-001'], unknown ['lb-01:443', 'payments.bank.example:443', 'LB-01', 'BIG-IP i5800', 'TPM-01']

## `CLOSE-06` — PASS

*the assembled graph is one projection and names the families it reaches*

- **PASS** `every-family-is-reached` — 64 node(s) of 37 kind(s), 85 edge(s) over 46 relation(s); families present: KUBERNETES (7), HARDWARE (4), NETWORK (2), VENDOR (3), KEY_STORE (4), SUPPLY_CHAIN (5); source CANONICAL_ESTATE, one store
- **PASS** `the-graph-reads-the-canonical-estate-and-no-second-store` — canonical CANONICAL_ESTATE, second store False; 73 edge(s) of 85 claim(s)
- **PASS** `the-domains-and-levels-travel-with-the-graph` — levels {'system': 1, 'application': 1, 'release': 3, 'process': 7, 'provider': 3, 'operation': 3, 'algorithm': 22, 'key': 2, 'key_provider': 3, 'certificate': 5, 'endpoint': 3, 'vendor': 2, 'hardware': 5}; domain pairs ['APPLICATION+CERTIFICATE']

## What this does not prove

- the estate is guide 173's fixture, extended: every shape is real, the rows are not
- a collector is named only where an evidence record exists; an edge with none is reported short and never borrows its neighbour's
- the domains classify algorithms by who cites them, so an algorithm cited by nobody appears in no domain rather than in all four
- the terminal hop is the first runtime operation reached from the landing workload; a workload that invokes three operations shows one and the chain query shows all
- a PQC readiness answer is the device's own published list, which is a claim and not a test: READY means it says it can, and nobody has run it
- the graph is one projection of the canonical estate; it proves there is no second store here and not that no other team keeps one
