# The review, point by point

`cryptoscan.cbom-nbom-depth-guide/1` · generated 2026-11-03T06:13:08.908860+00:00 · **6 pass · 0 partial · 0 fail** · 51 probes

**22 of 22 points of the review are present in the
built projection**, and five dependencies under them were still missing — one of
them a defect that had been losing an answer since guide 169.

```
sections   a block a builder returns now reaches the projection  (point 9)
certificate endpoint → certificate → key → algorithm → issuer → root  (point 4)
operation   application → INVOKES → operation → key, HSM, algorithm  (point 8)
at rest     in transit ≠ at rest, and neither implies the other  (point 9)
coverage    the worse verdict wins downstream, laundering refused  (point 21)
```

10 network endpoint(s), 63 evidenced edge(s), 3 TLS boundary mode(s) in use, 9 proven route(s); 1 claim(s) refused

## The twenty-two points, read off the build

| # | point | present | what the projection says |
|---|---|---|---|
| 1 | network endpoint has a stable identity beyond ip port | yes | NET-ENDPOINT ids per kind beside TECH-EP and the content id — NET-ENDPOINT-007, APPLICATION-001, SYSTEM-001 |
| 2 | endpoint reaches a service through a named basis | yes | payments.bank.example:443 → payments-api on sni-header — payments.bank.example:443 ROUTES_TO payments-api on sni-header |
| 3 | the three tls modes are three graphs | yes | TERMINATES_TLS, RE_ENCRYPTS and PASSTHROUGH in one estate — PASSTHROUGH 1, RE_ENCRYPTS 1, TERMINATES_TLS 1 |
| 4 | the certificate chain is five edges to a root | yes | certificate → key → algorithm, signature, issuer → root — 2 certificate(s) presented on 1 endpoint(s); 2 reach a root, 0 finding(s): none |
| 5 | a cipher suite is decomposed not an opaque asset | yes | kex, auth, bulk and mac as four crypto assets — suite roles ['auth', 'bulk', 'kex', 'mac'] |
| 6 | supported configured negotiated and observed stay apart | yes | SUPPORTS, tls_policy, NEGOTIATES and the evidence class — policy TLS1.3-TLS1.3, 2 supported, 1 negotiated |
| 7 | the process and its runtime crypto are reachable | yes | application → RUNS_APPLICATION → process → USES_CRYPTO — 5 on the wire, 1 in the process, 0 in both |
| 8 | an application invokes an operation a provider performs | yes | application → INVOKES → operation → key, HSM, algorithm — 2 crypto operation(s), 1 in an HSM/KMS, 2 finding(s) |
| 9 | a database is encrypted in transit and at rest separately | yes | two blocks, two findings, one database — 1 database(s) with a crypto record; 1 finding(s): AT_REST_UNENCRYPTED |
| 10 | the sidecar does the tls not the application | yes | PROXY_FOR from the sidecar, AUTHENTICATES from the mesh — envoy-sidecar PROXY_FOR Payments API; MESH-01 AUTHENTICATES it |
| 11 | the gateway routes to the application with evidence | yes | ROUTES_TO carrying a basis, a port and an evidence id — payments-api:8443 ROUTES_TO Payments API on api-gateway-config |
| 12 | the waf protects and terminates separately | yes | PROTECTS the application, TERMINATES_TLS to the next hop — WAF-01 PROTECTS Payments API; waf-01:443 TERMINATES_TLS waf-01:8081 |
| 13 | ssh is kex host key cipher and mac | yes | four NEGOTIATES edges with a role each — ssh roles ['cipher', 'host-key', 'kex', 'mac'] |
| 14 | the tunnel carries encryption integrity and a dh group | yes | IKEv2, AES-256, SHA-256, DH-19, and the zone it joins — branch-to-payments: IKEv2, UP |
| 15 | the projection is a graph not a list | yes | vertices, edges and adjacency from one build — 59 vertex/vertices, 63 edge(s) |
| 16 | every edge carries its nine fields and its collector | yes | EDGE_FIELDS on every claim, collector where one is known — 63 edge(s) with 9 field(s); 8 name a collector |
| 17 | a relationship has a lifecycle | yes | FIRST_SEEN, ACTIVE, CHANGED, SUPERSEDED, REMOVED, UNKNOWN — 63 edge(s) with a state: ACTIVE 8, UNKNOWN 55 |
| 18 | the digital twin reads the same graph | yes | who connects to whom, with which TLS and certificate — 63 edge(s) into the twin — one graph, read as the network projection rather than stored as a second database |
| 19 | the device has a vendor product and a firmware | yes | LB-01 → HAS_MODEL → product → SUPPLIED_BY → vendor — LB-01 HAS_MODEL F5 BIG-IP i5800, SUPPLIED_BY F5, RUNS_FIRMWARE 17.1.1 |
| 20 | the device runs on hardware | yes | LB-01 → RUNS_ON → Hardware-9281 — LB-01 RUNS_ON Hardware-9281 (Mumbai-DC2, R12) |
| 21 | coverage propagates and never improves downstream | yes | PARTIAL inherited by every consumer, and laundering refused — network coverage PARTIAL propagates to cbom PARTIAL; 1 laundered |
| 22 | the whole chain exists end to end | yes | system → application → process → service → endpoint → waf → lb → gateway → mesh → database → hsm → crypto → vendor — 1 service → 2 process → 1 application → 1 system → 3 device → 1 database → 2 keys → 7 crypto → 3 vendor |

## The certificate chain, reached from the endpoint

**2 certificate(s) presented on 1 endpoint(s); 2 reach a root, 0 finding(s): none**

- `delivers` → `CERTIFICATE` CERT-001 (CONFIGURED)
- `SIGNED_WITH` → `ALGORITHM` ECDSA-SHA256 (NETWORK_OBSERVED)
- `CONTAINS_KEY` → `PUBLIC_KEY` PK-CERT-001 (NETWORK_OBSERVED)
- `ISSUED_BY` → `CERTIFICATE_AUTHORITY` Bank Issuing CA (NETWORK_OBSERVED)
- `USES_ALGORITHM` → `ALGORITHM` ECDSA P-256 (NETWORK_OBSERVED)
- `SIGNED_BY` → `CERTIFICATE_AUTHORITY` Bank Root CA (NETWORK_OBSERVED)

## The operations the application invokes

**2 crypto operation(s), 1 in an HSM/KMS, 2 finding(s)**

| operation | what | key | provider | runs in |
|---|---|---|---|---|
| OP-ENCRYPT-002 | ENCRYPT | — | — | APPLICATION |
| OP-SIGN-001 | SIGN | KEY-REF-8271 | HSM-001 | HSM |

## In transit, at rest

**1 database(s) with a crypto record; 1 finding(s): AT_REST_UNENCRYPTED**

- `AT_REST_UNENCRYPTED` — DB-01: the database is encrypted in transit and not at rest — two different dependencies, one of them missing

## Coverage, downstream

**network coverage PARTIAL propagates to cbom_network_evidence PARTIAL, digital_twin_network PARTIAL; 1 laundered**

- cbom_network_evidence: PARTIAL
- digital_twin_network: PARTIAL
- `COVERAGE_LAUNDERED` on digital_twin_network — claimed COMPLETE, inherited PARTIAL

| Row | Question | Verdict | Probes |
|---|---|---|---|
| `audit` | is each of the twenty-two points present in the built projection | **PASS** | 22, 0 failing |
| `sections` | does a fact a builder returns reach the projection | **PASS** | 4, 0 failing |
| `certificate-depth` | is point 4 a chain or a picture of one | **PASS** | 6, 0 failing |
| `operations` | is point 8 a level in the graph or a verb in a report | **PASS** | 8, 0 failing |
| `at-rest` | is point 9 two dependencies or one | **PASS** | 5, 0 failing |
| `coverage-propagation` | does point 21 propagate or merely echo | **PASS** | 6, 0 failing |

## `audit` — PASS

*is each of the twenty-two points present in the built projection* (guide 172, 1–22)

- **PASS** `01-network-endpoint-has-a-stable-identity-beyond-ip-port` — NET-ENDPOINT ids per kind beside TECH-EP and the content id — NET-ENDPOINT-007, APPLICATION-001, SYSTEM-001
- **PASS** `02-endpoint-reaches-a-service-through-a-named-basis` — payments.bank.example:443 → payments-api on sni-header — payments.bank.example:443 ROUTES_TO payments-api on sni-header
- **PASS** `03-the-three-tls-modes-are-three-graphs` — TERMINATES_TLS, RE_ENCRYPTS and PASSTHROUGH in one estate — PASSTHROUGH 1, RE_ENCRYPTS 1, TERMINATES_TLS 1
- **PASS** `04-the-certificate-chain-is-five-edges-to-a-root` — certificate → key → algorithm, signature, issuer → root — 2 certificate(s) presented on 1 endpoint(s); 2 reach a root, 0 finding(s): none
- **PASS** `05-a-cipher-suite-is-decomposed-not-an-opaque-asset` — kex, auth, bulk and mac as four crypto assets — suite roles ['auth', 'bulk', 'kex', 'mac']
- **PASS** `06-supported-configured-negotiated-and-observed-stay-apart` — SUPPORTS, tls_policy, NEGOTIATES and the evidence class — policy TLS1.3-TLS1.3, 2 supported, 1 negotiated
- **PASS** `07-the-process-and-its-runtime-crypto-are-reachable` — application → RUNS_APPLICATION → process → USES_CRYPTO — 5 on the wire, 1 in the process, 0 in both
- **PASS** `08-an-application-invokes-an-operation-a-provider-performs` — application → INVOKES → operation → key, HSM, algorithm — 2 crypto operation(s), 1 in an HSM/KMS, 2 finding(s)
- **PASS** `09-a-database-is-encrypted-in-transit-and-at-rest-separately` — two blocks, two findings, one database — 1 database(s) with a crypto record; 1 finding(s): AT_REST_UNENCRYPTED
- **PASS** `10-the-sidecar-does-the-tls-not-the-application` — PROXY_FOR from the sidecar, AUTHENTICATES from the mesh — envoy-sidecar PROXY_FOR Payments API; MESH-01 AUTHENTICATES it
- **PASS** `11-the-gateway-routes-to-the-application-with-evidence` — ROUTES_TO carrying a basis, a port and an evidence id — payments-api:8443 ROUTES_TO Payments API on api-gateway-config
- **PASS** `12-the-waf-protects-and-terminates-separately` — PROTECTS the application, TERMINATES_TLS to the next hop — WAF-01 PROTECTS Payments API; waf-01:443 TERMINATES_TLS waf-01:8081
- **PASS** `13-ssh-is-kex-host-key-cipher-and-mac` — four NEGOTIATES edges with a role each — ssh roles ['cipher', 'host-key', 'kex', 'mac']
- **PASS** `14-the-tunnel-carries-encryption-integrity-and-a-dh-group` — IKEv2, AES-256, SHA-256, DH-19, and the zone it joins — branch-to-payments: IKEv2, UP
- **PASS** `15-the-projection-is-a-graph-not-a-list` — vertices, edges and adjacency from one build — 59 vertex/vertices, 63 edge(s)
- **PASS** `16-every-edge-carries-its-nine-fields-and-its-collector` — EDGE_FIELDS on every claim, collector where one is known — 63 edge(s) with 9 field(s); 8 name a collector
- **PASS** `17-a-relationship-has-a-lifecycle` — FIRST_SEEN, ACTIVE, CHANGED, SUPERSEDED, REMOVED, UNKNOWN — 63 edge(s) with a state: ACTIVE 8, UNKNOWN 55
- **PASS** `18-the-digital-twin-reads-the-same-graph` — who connects to whom, with which TLS and certificate — 63 edge(s) into the twin — one graph, read as the network projection rather than stored as a second database
- **PASS** `19-the-device-has-a-vendor-product-and-a-firmware` — LB-01 → HAS_MODEL → product → SUPPLIED_BY → vendor — LB-01 HAS_MODEL F5 BIG-IP i5800, SUPPLIED_BY F5, RUNS_FIRMWARE 17.1.1
- **PASS** `20-the-device-runs-on-hardware` — LB-01 → RUNS_ON → Hardware-9281 — LB-01 RUNS_ON Hardware-9281 (Mumbai-DC2, R12)
- **PASS** `21-coverage-propagates-and-never-improves-downstream` — PARTIAL inherited by every consumer, and laundering refused — network coverage PARTIAL propagates to cbom PARTIAL; 1 laundered
- **PASS** `22-the-whole-chain-exists-end-to-end` — system → application → process → service → endpoint → waf → lb → gateway → mesh → database → hsm → crypto → vendor — 1 service → 2 process → 1 application → 1 system → 3 device → 1 database → 2 keys → 7 crypto → 3 vendor

## `sections` — PASS

*does a fact a builder returns reach the projection* (guide 172, 9, 21)

- **PASS** `a-builder-s-block-survives-estate` — sections: ['database_crypto']
- **PASS** `the-projection-carries-the-section-it-was-given` — 1 database(s) in the built NBOM
- **PASS** `two-parts-of-the-same-section-merge-instead-of-replacing` — merged: ['DB-02', 'DB-03']
- **PASS** `a-bom-that-dropped-its-sections-would-lose-point-9` — 1 database(s) with a crypto record; 1 finding(s): AT_REST_UNENCRYPTED

## `certificate-depth` — PASS

*is point 4 a chain or a picture of one* (guide 172, 4)

- **PASS** `a-named-certificate-on-a-listener-is-an-edge` — waf-01:443 PRESENTS CERT-001 on tls-handshake
- **PASS** `the-depth-is-reached-from-the-endpoint-not-stored-beside-it` — CERTIFICATE → ALGORITHM → PUBLIC_KEY → CERTIFICATE_AUTHORITY → ALGORITHM → CERTIFICATE_AUTHORITY
- **PASS** `the-chain-says-whether-it-reaches-a-root` — rooted: 2 of 2
- **PASS** `a-weak-key-and-a-broken-hash-are-named-by-size` — RSA-1024 + SHA1 + an intermediate as the last link
- **PASS** `a-certificate-the-estate-does-not-hold-is-a-finding-not-a-skip` — tls.certificate = CERT-999 with no node → CERTIFICATE_UNRESOLVED
- **PASS** `every-link-carries-its-own-evidence-class` — 6 link(s), each with a class

## `operations` — PASS

*is point 8 a level in the graph or a verb in a report* (guide 172, 8)

- **PASS** `an-operation-is-a-node-with-an-id-of-its-own` — TECH-OP-001 … beside TECH-HSM-001 and TECH-KREF-001
- **PASS** `an-application-invokes-it-rather-than-using-crypto` — Payments API INVOKES OP-SIGN-001
- **PASS** `the-operation-names-its-key-its-provider-and-its-algorithm` — SIGN on RSA-2048 with KEY-REF-8271 in HSM-001
- **PASS** `an-operation-with-no-key-is-a-finding` — OPERATION_WITHOUT_KEY on 1 operation(s)
- **PASS** `an-operation-done-in-the-application-is-a-different-claim` — OP-ENCRYPT-002 runs in the application, not the HSM
- **PASS** `no-key-material-is-accepted-only-metadata` — private_key → KEY_MATERIAL_REFUSED
- **PASS** `uses-crypto-is-not-an-operation` — USE_CRYPTO → UNKNOWN_CRYPTO_OPERATION
- **PASS** `an-application-is-not-a-key-provider` — provider = an application → NOT_A_KEY_PROVIDER

## `at-rest` — PASS

*is point 9 two dependencies or one* (guide 172, 9)

- **PASS** `in-transit-and-at-rest-are-two-blocks-on-one-database` — DB-01: in_transit TLS1.3, at_rest disabled, distinct
- **PASS** `a-database-encrypted-on-the-wire-and-not-on-disk-says-so` — AT_REST_UNENCRYPTED with in_transit True
- **PASS** `nothing-read-about-at-rest-is-not-the-same-as-no-encryption` — no tde block → TDE_NOT_RECORDED, not AT_REST_UNENCRYPTED
- **PASS** `a-database-with-no-tls-on-its-listener-is-its-own-finding` — no tls parameters → TLS_NOT_OBSERVED
- **PASS** `the-same-algorithm-on-both-sides-is-one-decision-applied-twice` — TLS suite = TDE algorithm → AT_REST_MIRRORS_TRANSIT

## `coverage-propagation` — PASS

*does point 21 propagate or merely echo* (guide 172, 21)

- **PASS** `the-coverage-verdict-travels-with-its-denominator` — expected 500 endpoint(s): observed 420, unavailable 50, unknown 30, permission denied 0 — coverage PARTIAL
- **PASS** `a-downstream-view-inherits-the-worse-of-its-claim-and-the-network` — network coverage PARTIAL propagates to cbom PARTIAL, twin PARTIAL
- **PASS** `a-cbom-cannot-claim-complete-over-a-partial-network` — 2 COVERAGE_LAUNDERED
- **PASS** `a-consumer-that-knows-less-keeps-its-own-answer` — UNKNOWN is worse than PARTIAL and is not improved by it
- **PASS** `the-weakest-segment-decides-the-network-it-does-not-average-away` — 3 segment(s), overall PARTIAL: BRANCH COMPLETE, CARDHOLDER PARTIAL, EDGE COMPLETE
- **PASS** `a-verdict-that-is-not-a-verdict-is-refused` — MOSTLY → UNKNOWN_COVERAGE_VERDICT

## What this does not prove

- the fixture is the bank's own path: every shape is real, the rows are not
- a certificate chain is what the estate holds and the handshake presented; revocation and expiry state are separate questions this does not answer
- a weak key is named by size against a floor, not scored: the risk judgement belongs to the assurance engine, and nothing here calls a finding an exploit
- a crypto operation names a key reference and a provider; it never proves the key that produced a signature, and it never holds key material
- coverage propagation is arithmetic on verdicts, not a second measurement: it cannot see an endpoint the network never saw
- point 21's downstream consumers are named by the caller; nothing here knows which reports actually read this projection
