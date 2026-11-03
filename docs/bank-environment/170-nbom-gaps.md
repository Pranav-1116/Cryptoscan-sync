# The rest of the NBOM review

`cryptoscan.cbom-nbom-gaps-guide/1` · generated 2026-11-03T06:04:35.189319+00:00 · **11 pass · 0 partial · 0 fail** · 45 probes

Guide 169 answered the twenty-two points at the level of relations. Read back,
nine things were still thin — ids, routes, the fourth state of a listener, the
runtime comparison, evidence on a network edge, exposure, the vendor's
capability, history and per-segment coverage — and each is now a shape, not a
promise.

```
ids            NET-ENDPOINT-001 / TECH-EP-001 / NETWORK_ENDPOINT-9281
routes         listener → hop → hop → application, with every TLS boundary
policy         CONFIGURED beside SUPPORTED, NEGOTIATED and OBSERVED
comparison     network set, runtime set, intersection, difference
evidence       record{collector, hash} → EVIDENCE node → EVIDENCED_BY edge
exposure       what a session negotiated, counted apart from a capability
history        FIRST_SEEN / ACTIVE / CHANGED / SUPERSEDED / REMOVED / UNKNOWN
segments       the weakest segment decides the whole
```

6 network endpoint(s), 26 evidenced edge(s), 2 TLS boundary mode(s) in use, 6 proven route(s); 0 claim(s) refused

## The review's ids

| kind | node | id |
|---|---|---|
| `APPLICATION` | Payments API | `APPLICATION-001` |
| `BUSINESS_SYSTEM` | Payments System | `SYSTEM-001` |
| `NETWORK_ENDPOINT` | api-gw-01:8443 | `NET-ENDPOINT-001` |
| `NETWORK_ENDPOINT` | lb-01:443 | `NET-ENDPOINT-002` |
| `NETWORK_ENDPOINT` | payments-api:8443 | `NET-ENDPOINT-003` |
| `SERVICE` | payments-api | `SERVICE-001` |

## Routes

**api-gw-01:8443** — 1 proven, 0 declared
- api-gw-01:8443 → payments-api:8443 → Payments API (no TLS boundary)
**lb-01:443** — 1 proven, 0 declared
- lb-01:443 → api-gw-01:8443 → payments-api:8443 → Payments API (RE_ENCRYPTS; ECDHE-RSA-AES128-GCM-SHA256)
**payments-api:8443** — 1 proven, 0 declared
- payments-api:8443 → Payments API (no TLS boundary)
**payments.bank.example:443** — 1 proven, 0 declared
- payments.bank.example:443 → payments-api → Payments API (no TLS boundary)
**waf-01:443** — 1 proven, 0 declared
- waf-01:443 → waf-01:8080 → lb-01:443 → api-gw-01:8443 → payments-api:8443 → Payments API (TERMINATES_TLS, RE_ENCRYPTS; TLS_AES_256_GCM_SHA384, ECDHE-RSA-AES128-GCM-SHA256)
**waf-01:8080** — 1 proven, 0 declared
- waf-01:8080 → lb-01:443 → api-gw-01:8443 → payments-api:8443 → Payments API (RE_ENCRYPTS; ECDHE-RSA-AES128-GCM-SHA256)

## Policy findings

| endpoint | findings |
|---|---|
| api-gw-01:8443 | NO_POLICY_RECORDED |
| lb-01:443 | NO_POLICY_RECORDED |
| payments-api:8443 | NO_POLICY_RECORDED |
| payments.bank.example:443 | BELOW_CONFIGURED_FLOOR, SUITE_NOT_IN_POLICY, TLS_DOWNGRADED |
| waf-01:443 | NO_POLICY_RECORDED |
| waf-01:8080 | NO_POLICY_RECORDED |

**Runtime vs network** — 5 on the wire, 1 in the process, 0 in both

- on the wire: TLS_AES_256_GCM_SHA384, AES-256-GCM, ECDSA-P256, SHA-384, X25519
- in the process: AES-128-CBC
- in both: none

**Exposure** — 1 endpoint(s) negotiate quantum-sensitive cryptography: payments.bank.example:443 (ECDSA-P256, X25519)

**Coverage** — expected 500 endpoint(s): observed 420, unavailable 50, unknown 30, permission denied 0 — coverage PARTIAL

**By segment** — 3 segment(s), overall PARTIAL: BRANCH COMPLETE, CARDHOLDER PARTIAL, EDGE COMPLETE

| Row | Question | Verdict | Probes |
|---|---|---|---|
| `ids` | do the review's ids exist beside the graph's ids | **PASS** | 4, 0 failing |
| `paths` | is the network a set of edges or a set of routes | **PASS** | 5, 0 failing |
| `policy` | is CONFIGURED a state of its own | **PASS** | 5, 0 failing |
| `runtime-vs-network` | is the two-observation comparison an operation | **PASS** | 4, 0 failing |
| `evidence` | does an edge name the collector behind it | **PASS** | 5, 0 failing |
| `exposure` | is quantum exposure measured or mentioned | **PASS** | 4, 0 failing |
| `vendor-capability` | does the vendor join the crypto view | **PASS** | 3, 0 failing |
| `timeline` | does an edge have a history | **PASS** | 3, 0 failing |
| `segments` | does one healthy segment hide one sick one | **PASS** | 4, 0 failing |
| `tunnel` | is a tunnel a path or a record | **PASS** | 4, 0 failing |
| `vocabulary` | does the graph carry what the second read needed | **PASS** | 4, 0 failing |

## `ids` — PASS

*do the review's ids exist beside the graph's ids* (review nbom 1)

- **PASS** `the-review-s-id-scheme-exists-per-kind` — APPLICATION, CERTIFICATE, CERTIFICATE-AUTHORITY, CIPHER-SUITE, CRYPTO-ASSET, CRYPTO-LIBRARY, EVIDENCE, IPSEC-TUNNEL, NET-ENDPOINT, NETWORK-SEGMENT, PROCESS, SERVICE, SYSTEM, VENDOR-PRODUCT, VPN-GATEWAY
- **PASS** `three-id-families-name-one-node-and-only-one-is-for-keying` — TECH-EP-004 (graph), NET-ENDPOINT-004 (view), NETWORK_ENDPOINT-5437 (content)
- **PASS** `numbering-is-per-kind-so-a-service-never-collides-with-an-application` — one prefix per kind, numbered from 001
- **PASS** `the-ids-are-stable-for-a-stable-estate` — a second build over the same estate assigns the same ids

## `paths` — PASS

*is the network a set of edges or a set of routes* (review nbom 3, 15)

- **PASS** `a-route-is-a-sequence-of-edges-from-a-listener-to-an-application` — waf-01:443 → waf-01:8080 → lb-01:443 → api-gw-01:8443 → payments-api:8443 → Payments API (TERMINATES_TLS, RE_ENCRYPTS; TLS_AES_256_GCM_SHA384, ECDHE-RSA-AES128-GCM-SHA256)
- **PASS** `the-route-carries-every-tls-boundary-on-it` — modes ['TERMINATES_TLS', 'RE_ENCRYPTS']
- **PASS** `each-boundary-names-the-suite-that-crossed-it` — suites ['TLS_AES_256_GCM_SHA384', 'ECDHE-RSA-AES128-GCM-SHA256']
- **PASS** `a-route-that-depends-on-one-declared-hop-is-reported-declared` — proven 0, declared 1, weakest IMPORTED
- **PASS** `a-tunnel-that-is-down-is-not-a-route` — 0 route(s) from dr-site-to-payments: 0 proven, 0 declared

## `policy` — PASS

*is CONFIGURED a state of its own* (review nbom 6)

- **PASS** `a-policy-is-a-fourth-state-beside-supported-negotiated-and-observed` — min TLS1.3, suites [TLS_AES_256_GCM_SHA384], client_auth NONE
- **PASS** `a-session-below-the-policy-is-a-finding-not-a-success` — policy TLS1.3, negotiated TLS1.2 → BELOW_CONFIGURED_FLOOR
- **PASS** `a-suite-outside-the-policy-is-its-own-finding` — ECDHE-RSA-AES128-GCM-SHA256 is not on the configured list
- **PASS** `a-listener-with-no-policy-says-so-rather-than-assuming-one` — waf-01:443 → NO_POLICY_RECORDED
- **PASS** `a-policy-that-accepts-nothing-is-refused` — min TLS1.3 > max TLS1.2 → TLS_POLICY_INVERTED

## `runtime-vs-network` — PASS

*is the two-observation comparison an operation* (review nbom 7)

- **PASS** `the-wire-and-the-process-are-two-observations` — 5 on the wire, 1 in the process, 0 in both
- **PASS** `the-difference-is-reported-as-a-difference` — network only ['AES-256-GCM', 'ECDSA-P256', 'SHA-384', 'TLS_AES_256_GCM_SHA384', 'X25519'], runtime only ['AES-128-CBC']
- **PASS** `the-intersection-is-computed-not-assumed` — 0 asset(s) in both
- **PASS** `the-honest-caveat-travels-with-the-answer` — not_proven names the listener/process split

## `evidence` — PASS

*does an edge name the collector behind it* (review nbom 16)

- **PASS** `a-record-needs-a-collector` — no collector → EVIDENCE_WITHOUT_COLLECTOR
- **PASS** `a-record-needs-a-hash` — no hash → EVIDENCE_WITHOUT_HASH
- **PASS** `the-record-is-a-node-an-edge-can-point-at` — EVID-92841 is a node, lb-01:443 EVIDENCED_BY it
- **PASS** `an-edge-names-its-collector-and-its-evidence-class` — 4 edge(s) resolve a collector, e.g. LB-CONFIG-01 (CONFIGURED)
- **PASS** `every-edge-still-carries-the-nine-fields` — 26 edge(s), 9 field(s) each

## `exposure` — PASS

*is quantum exposure measured or mentioned* (review nbom 5)

- **PASS** `what-a-session-negotiated-is-what-is-exposed` — ECDSA-P256, X25519
- **PASS** `a-capability-that-was-never-negotiated-is-not-counted` — AES-128-GCM is supported, not negotiated, and is not counted
- **PASS** `the-exposure-statement-names-the-endpoint-and-the-algorithms` — 1 endpoint(s) negotiate quantum-sensitive cryptography: payments.bank.example:443 (ECDSA-P256, X25519)
- **PASS** `the-migration-judgement-is-left-to-the-engine-that-owns-it` — not_proven hands the verdict to the PQC engine

## `vendor-capability` — PASS

*does the vendor join the crypto view* (review nbom 19)

- **PASS** `a-product-declares-a-capability-at-the-class-a-datasheet-deserves` — F5 BIG-IP i5800 SUPPORTS TLS 1.3 termination (VENDOR_DECLARED)
- **PASS** `vbom-is-joined-to-cbom-through-the-capability` — VENDOR_PRODUCT → SUPPORTS → CRYPTO_CAPABILITY
- **PASS** `a-product-cannot-claim-an-operation-its-device-performed` — VENDOR_PRODUCT PERFORMS CRYPTO_CAPABILITY → TYPE_MISMATCH

## `timeline` — PASS

*does an edge have a history* (review nbom 17)

- **PASS** `every-edge-has-a-state-and-a-first-and-last-seen` — 26 edge(s) with history; no previous projection was supplied
- **PASS** `an-edge-with-timestamps-is-active-not-unknown` — 5 ACTIVE, 21 UNKNOWN
- **PASS** `the-history-can-be-joined-to-a-drift-feed` — the same projection against itself produces no changes

## `segments` — PASS

*does one healthy segment hide one sick one* (review nbom 21)

- **PASS** `coverage-is-reported-per-segment-not-only-in-total` — 3 segment(s), overall PARTIAL: BRANCH COMPLETE, CARDHOLDER PARTIAL, EDGE COMPLETE
- **PASS** `the-weakest-segment-decides-the-whole` — EDGE COMPLETE, CARDHOLDER PARTIAL, overall PARTIAL
- **PASS** `the-weakest-segment-is-named` — weakest segment: ['CARDHOLDER']
- **PASS** `the-total-coverage-is-not-rounded-by-the-healthy-segments` — expected 500 endpoint(s): observed 420, unavailable 50, unknown 30, permission denied 0 — coverage PARTIAL

## `tunnel` — PASS

*is a tunnel a path or a record* (review nbom 14)

- **PASS** `a-tunnel-records-its-state` — tunnel states: {'branch-to-payments': 'UP', 'dr-site-to-payments': 'DOWN'}
- **PASS** `a-state-this-model-does-not-know-is-refused` — DEGRADED → UNKNOWN_TUNNEL_STATUS
- **PASS** `a-pre-shared-key-is-material-and-is-refused` — psk → KEY_MATERIAL_REFUSED
- **PASS** `a-down-tunnel-tunnels-nowhere-that-matters` — the UP tunnel is a route; the DOWN tunnel is not

## `vocabulary` — PASS

*does the graph carry what the second read needed* (review nbom 22)

- **PASS** `the-relations-the-second-read-leans-on-are-in-the-graph` — HOLDS_CERTIFICATE, EVIDENCED_BY, SUPPORTS, RUNS_APPLICATION
- **PASS** `a-network-asset-can-be-evidenced-like-a-device` — EVIDENCED_BY starts at NETWORK_ENDPOINT
- **PASS** `a-vendor-product-can-support-a-capability` — SUPPORTS starts at VENDOR_PRODUCT
- **PASS** `a-process-is-a-level-in-the-chain-the-review-draws` — 1 service → 1 process → 1 application → 1 system → 6 crypto

## What this does not prove

- the fixture is the review's own path: the shapes are real, the rows are not
- a policy finding compares what was configured with what was observed once; a session that rolled back to a lower version after this capture is not in it
- a route is the shortest evidenced chain, not the only one: an estate with a mesh has as many routes as it has policies
- exposure counts algorithms a session negotiated, and a capability is not counted twice — but nothing here decides which one must be migrated first
- a segment's denominator comes from a CMDB the platform does not own, so the weakest segment is only as honest as that list
- a down tunnel is excluded from routes and still counted in the graph: unavailable is not absent
