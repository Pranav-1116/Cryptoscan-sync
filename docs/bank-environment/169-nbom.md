# The network is a graph

`cryptoscan.cbom-nbom-guide/1` · generated 2026-11-03T06:04:34.983782+00:00 · **18 pass · 0 partial · 0 fail** · 81 probes

The NBOM review's twenty-two points, answered by putting the network into the
graph the rest of the estate lives in. An address is a location, the backend is a
claim with a named basis, and TLS termination is a topology.

```
endpoint → service      ROUTES_TO          from SNI, DNS, ingress, gateway config
endpoint → suite        NEGOTIATES         a handshake, or a capture of one
endpoint → suite        SUPPORTS           what the listener would accept
suite → crypto          USES_CRYPTO        bulk, mac, kex, auth — four assets
l1 → l2                 TERMINATES_TLS     TLS ends here, plaintext onwards
l1 → l2                 RE_ENCRYPTS        TLS again, possibly weaker
l1 → l2                 PASSTHROUGH        the handshake crosses untouched
proxy → application     PROXY_FOR          the TLS belongs to the proxy
```

10 network endpoint(s), 74 evidenced edge(s), 3 TLS boundary mode(s) in use, 2 proven route(s); 0 claim(s) refused

## What the projection holds

| kind | rows |
|---|---|
| `ALGORITHM` | 2 |
| `API_GATEWAY` | 1 |
| `APPLICATION` | 2 |
| `BUSINESS_SYSTEM` | 1 |
| `CERTIFICATE` | 3 |
| `CERTIFICATE_AUTHORITY` | 2 |
| `CIPHER_SUITE` | 3 |
| `CRYPTO_ASSET` | 14 |
| `CRYPTO_CAPABILITY` | 3 |
| `CRYPTO_LIBRARY` | 1 |
| `DATABASE` | 1 |
| `FIRMWARE` | 5 |
| `HOST` | 1 |
| `HSM` | 1 |
| `IPSEC_TUNNEL` | 1 |
| `KEY_REFERENCE` | 1 |
| `LOAD_BALANCER` | 1 |
| `NETWORK_ENDPOINT` | 10 |
| `NETWORK_SEGMENT` | 1 |
| `PHYSICAL_SERVER` | 1 |
| `PROCESS` | 2 |
| `PUBLIC_KEY` | 1 |
| `SERVICE` | 2 |
| `SERVICE_MESH` | 1 |
| `SSH_SERVICE` | 1 |
| `VENDOR` | 5 |
| `VENDOR_PRODUCT` | 5 |
| `VPN_GATEWAY` | 2 |
| `WAF` | 1 |

**Negotiated crypto** — 1 suite(s) negotiated, 2 supported but never negotiated, 4 crypto asset(s) behind the session, 1 used inside a process

| suite | state |
|---|---|
| `TLS_AES_256_GCM_SHA384` | negotiated |
| `TLS_CHACHA20_POLY1305_SHA256` | supported only |
| `TLS_AES_128_GCM_SHA256` | supported only |

**The chain from the endpoint** — 1 service → 2 process → 1 application → 1 system → 4 device → 1 database → 2 keys → 8 crypto → 8 vendor

**Coverage** — expected 500 endpoint(s): observed 420, unavailable 50, unknown 30, permission denied 0 — coverage PARTIAL

| lifecycle state | edges |
|---|---|
| `ACTIVE` | 14 |
| `FIRST_SEEN` | 1 |
| `UNKNOWN` | 59 |

| Row | Question | Verdict | Probes |
|---|---|---|---|
| `endpoint-identity` | is an address an identity, or a location | **PASS** | 5, 0 failing |
| `routing-evidence` | what ties an endpoint to the application behind it | **PASS** | 4, 0 failing |
| `tls-boundaries` | is TLS termination a topology or a flag | **PASS** | 6, 0 failing |
| `certificate-chain` | does a certificate dependency go deeper than its name | **PASS** | 5, 0 failing |
| `negotiated-crypto` | which cryptography did the session actually use | **PASS** | 5, 0 failing |
| `runtime` | does a network observation prove the application's crypto | **PASS** | 4, 0 failing |
| `keys` | does the HSM dependency carry keys or metadata | **PASS** | 4, 0 failing |
| `database` | is DB TLS the same dependency as DB TDE | **PASS** | 4, 0 failing |
| `mesh` | does the sidecar do the TLS, or the application | **PASS** | 5, 0 failing |
| `gateway-waf` | do the boxes in the path say how they are in the path | **PASS** | 4, 0 failing |
| `ssh` | is SSH a port or a set of negotiated algorithms | **PASS** | 3, 0 failing |
| `vpn` | does the IPsec dependency reach the zone and the algorithms | **PASS** | 4, 0 failing |
| `topology` | is the network a list of endpoints or a graph | **PASS** | 4, 0 failing |
| `lifecycle` | does a relationship have a life | **PASS** | 5, 0 failing |
| `twin` | is NBOM a projection of the twin or a second database | **PASS** | 4, 0 failing |
| `vendor-hardware` | does the network join VBOM and HBOM | **PASS** | 5, 0 failing |
| `coverage` | does coverage propagate, or does it get rounded to healthy | **PASS** | 5, 0 failing |
| `spine` | does the biggest missing chain exist end to end | **PASS** | 5, 0 failing |

## `endpoint-identity` — PASS

*is an address an identity, or a location* (review nbom 1–2)

- **PASS** `an-endpoint-is-host-and-port-and-an-address-alone-is-refused` — 10.10.10.20 with no port → ENDPOINT_WITHOUT_HOST_OR_PORT
- **PASS** `one-address-hosts-two-virtual-hosts-as-two-endpoints` — 10.10.10.20 carries 3 listener(s), two of them virtual hosts with their own SNI and their own service
- **PASS** `each-endpoint-reaches-its-own-service-not-the-first-one` — payments.bank.example:443 → payments-api, auth.bank.example:443 → auth-api
- **PASS** `the-chain-reads-endpoint-service-process-application-system` — 1 service → 2 process → 1 application → 1 system → 4 device → 1 database → 2 keys → 8 crypto → 8 vendor
- **PASS** `a-stable-id-survives-renumbering-a-readable-one-does-not` — TECH-EP-007 reads; NETWORK_ENDPOINT-5437 holds

## `routing-evidence` — PASS

*what ties an endpoint to the application behind it* (review nbom 2, 16)

- **PASS** `a-name-match-is-refused-as-a-routing-basis` — name-match → ROUTING_BASIS_NOT_EVIDENCE
- **PASS** `every-basis-the-review-names-is-a-basis-the-model-knows` — 8 of 8 routing bases are classified
- **PASS** `the-routing-edge-carries-its-record` — ROUTES_TO payments.bank.example:443 → payments-api (sni-header, NETWORK_OBSERVED, port 443)
- **PASS** `no-edge-in-the-projection-is-missing-its-record` — 74 edge(s), 0 incomplete

## `tls-boundaries` — PASS

*is TLS termination a topology or a flag* (review nbom 3, 12)

- **PASS** `the-three-modes-are-three-relations` — TERMINATES_TLS, RE_ENCRYPTS, PASSTHROUGH
- **PASS** `each-mode-in-the-estate-is-counted-separately` — tls modes: {'PASSTHROUGH': 1, 'RE_ENCRYPTS': 1, 'TERMINATES_TLS': 1}
- **PASS** `termination-with-a-tls-upstream-is-refused-as-a-re-encryption` — TERMINATE with a TLS backend → TERMINATION_WITH_TLS_UPSTREAM
- **PASS** `re-encryption-without-upstream-tls-is-refused` — RE_ENCRYPT onto a plaintext backend → RE_ENCRYPT_WITHOUT_UPSTREAM_TLS
- **PASS** `a-passthrough-may-not-present-a-certificate` — PASSTHROUGH with a certificate → PASSTHROUGH_WITH_CERTIFICATE
- **PASS** `a-waf-that-terminates-tls-is-a-hop-and-a-protection-edge` — WAF-01 PROTECTS Payments API, waf-01:443 TERMINATES_TLS waf-01:8080

## `certificate-chain` — PASS

*does a certificate dependency go deeper than its name* (review nbom 4)

- **PASS** `the-certificate-chain-is-five-edges-not-one-row` — CONTAINS_KEY, USES_ALGORITHM, SIGNED_WITH, ISSUED_BY, SIGNED_BY
- **PASS** `the-curve-and-the-key-size-live-on-the-algorithm-node` — ECDSA P-256: curve P-256, 256 bits
- **PASS** `the-signature-algorithm-is-its-own-dependency` — CERT-001 SIGNED_WITH ECDSA-SHA256
- **PASS** `the-chain-reaches-the-root` — Intermediate CA SIGNED_BY Root CA
- **PASS** `the-endpoint-presents-the-certificate-it-was-observed-with` — waf-01:443 PRESENTS CERT-001

## `negotiated-crypto` — PASS

*which cryptography did the session actually use* (review nbom 5–6)

- **PASS** `a-cipher-suite-is-decomposed-into-four-crypto-dependencies` — TLS_AES_256_GCM_SHA384 → bulk, mac, kex, auth
- **PASS** `one-suite-was-negotiated-out-of-three-supported` — negotiated ['TLS_AES_256_GCM_SHA384'], supported only 2
- **PASS** `AES-128-is-supported-and-never-reported-as-used` — AES-128-GCM is supported-only; AES-128-CBC appears only from the process
- **PASS** `a-capability-list-cannot-claim-what-was-negotiated` — capability-list → CLAIM_WEAKER_THAN_RELATION_REQUIRES
- **PASS** `a-configuration-file-cannot-claim-a-session` — config-parse → NEGOTIATION_NEEDS_A_HANDSHAKE

## `runtime` — PASS

*does a network observation prove the application's crypto* (review nbom 7)

- **PASS** `the-process-is-a-node-between-the-application-and-its-library` — payments-api[1821] LOADS OpenSSL 3.0.13
- **PASS** `a-runtime-observation-is-its-own-class` — 3 edge(s) RUNTIME_OBSERVED, 6 edge(s) NETWORK_OBSERVED
- **PASS** `the-network-cipher-and-the-internal-cipher-are-not-the-same-fact` — 443/TLS is AES-256-GCM; the process encrypts with AES-128-CBC
- **PASS** `a-runtime-claim-cannot-be-made-from-a-configuration-file` — config-parse on a RUNTIME_OBSERVED asset → EVIDENCE_CLASS_MISMATCH

## `keys` — PASS

*does the HSM dependency carry keys or metadata* (review nbom 8)

- **PASS** `an-application-reaches-its-hsm-through-an-operation` — Payments API USES_HSM HSM-001 (operation SIGN)
- **PASS** `the-key-is-a-reference-with-metadata-and-nothing-else` — KEY-REF-8271: ref, purpose SIGN, RSA-2048, ACTIVE
- **PASS** `key-material-is-refused-by-name` — private_key → KEY_MATERIAL_REFUSED
- **PASS** `a-pem-in-a-fact-is-refused-too` — a PEM body → KEY_MATERIAL_REFUSED

## `database` — PASS

*is DB TLS the same dependency as DB TDE* (review nbom 9)

- **PASS** `the-application-reaches-the-database-and-its-port` — Payments API STORES_IN DB-01, DB-01 LISTENS_ON db-01:5432
- **PASS** `the-database-session-negotiates-a-suite` — db-01:5432 NEGOTIATES TLS_AES_256_GCM_SHA384
- **PASS** `tls-in-transit-and-tde-at-rest-are-two-dependencies` — in transit TLS1.3 / AES-256-GCM; at rest AES-256-XTS
- **PASS** `the-two-are-not-merged-into-one-encrypted-flag` — TLS_AES_256_GCM_SHA384 ≠ AES-256-XTS

## `mesh` — PASS

*does the sidecar do the TLS, or the application* (review nbom 10)

- **PASS** `the-sidecar-proxies-the-application` — envoy-sidecar PROXY_FOR Payments API
- **PASS** `the-mesh-authenticates-what-it-proxies` — MESH-01 AUTHENTICATES Payments API (mTLS, bank.internal)
- **PASS** `the-mtls-certificate-belongs-to-the-proxy-not-the-application` — envoy-sidecar USES_CERTIFICATE CERT-MESH-001; the application holds none
- **PASS** `the-trust-domain-travels-with-the-edge` — trust_domain=bank.internal on PROXY_FOR
- **PASS** `who-terminated-the-handshake-is-a-question-with-an-answer` — 1 certificate holder(s) on 1 endpoint(s); 1 application(s) are proxied

## `gateway-waf` — PASS

*do the boxes in the path say how they are in the path* (review nbom 11–12)

- **PASS** `the-gateway-routes-to-the-application-with-its-own-config-as-evidence` — API-GW-01 ROUTES_TO Payments API via api-gateway-config
- **PASS** `the-waf-protects-what-it-fronts` — WAF-01 PROTECTS Payments API
- **PASS** `the-chain-from-the-internet-reaches-the-application-in-order` — waf terminate → lb re-encrypt → mesh passthrough
- **PASS** `every-listener-names-the-device-that-owns-it` — WAF-01, LB-01 and API-GW-01 each LISTENS_ON their own port

## `ssh` — PASS

*is SSH a port or a set of negotiated algorithms* (review nbom 13)

- **PASS** `ssh-is-four-negotiated-parameters-not-a-version` — X25519, Ed25519, ChaCha20-Poly1305, HMAC-SHA2-256
- **PASS** `the-ssh-service-listens-on-a-port-and-runs-on-a-host` — sshd@srv-payments-01 LISTENS_ON :22 and RUNS_ON srv-payments-01
- **PASS** `the-ssh-parameters-are-network observations-not-capability-claims` — banner-read parameters are NETWORK_OBSERVED

## `vpn` — PASS

*does the IPsec dependency reach the zone and the algorithms* (review nbom 14)

- **PASS** `the-tunnel-negotiates-encryption-integrity-and-a-dh-group` — negotiated ['AES-256', 'CERT-VPN-001', 'DH-Group-19', 'SHA-256']
- **PASS** `what-the-gateway-would-accept-is-kept-apart-from-what-it-uses` — supported ['AES-128 proposal', 'SHA-1 proposal'], negotiated ['AES-256', 'CERT-VPN-001', 'DH-Group-19', 'SHA-256']
- **PASS** `the-tunnel-ends-in-a-network-zone` — branch-to-payments TUNNELS_TO Payment Network
- **PASS** `the-tunnel-reads-its-ike-version-from-the-tunnel-not-from-prose` — IKEv2

## `topology` — PASS

*is the network a list of endpoints or a graph* (review nbom 15–16)

- **PASS** `the-projection-is-a-graph-not-a-list` — 72 node(s), 74 edge(s)
- **PASS** `every-network-edge-carries-a-port-and-a-protocol` — 25 of 25 network edge(s) name a port
- **PASS** `the-adjacency-can-be-walked-from-the-internet-inward` — Payments API → DB-01 and Payments API → HSM-001
- **PASS** `the-edge-record-carries-the-fields-the-review-names` — 9 field(s) on each of 74 edge(s)

## `lifecycle` — PASS

*does a relationship have a life* (review nbom 17)

- **PASS** `an-edge-seen-once-and-an-edge-seen-twice-are-different-states` — lifecycle: 14 ACTIVE, 1 FIRST_SEEN, 59 UNKNOWN
- **PASS** `an-edge-with-no-timestamps-is-unknown-not-active` — 59 edge(s) UNKNOWN
- **PASS** `an-edge-that-moved-is-superseded-not-removed-and-added` — 1 network change(s): 1 EDGE_SUPERSEDED
- **PASS** `the-superseded-edge-names-both-targets` — LB/SNI edge: payments-api → payments-api-v2
- **PASS** `every-change-carries-its-crypto-impact` — 1 event(s), each with a crypto impact block

## `twin` — PASS

*is NBOM a projection of the twin or a second database* (review nbom 18)

- **PASS** `the-twin-knows-who-connects-to-whom-and-how` — 72 pair(s), 37 relationship/protocol combination(s)
- **PASS** `the-twin-carries-certificates-keys-and-applications` — 4 certificate edge(s), keys ['HSM-001', 'KEY-REF-8271']
- **PASS** `a-projection-cannot-be-its-own-source` — NBOM as input → PROJECTION_AS_SOURCE
- **PASS** `a-techbom-cannot-build-an-nbom-either` — TechBOM as estate → ValueError

## `vendor-hardware` — PASS

*does the network join VBOM and HBOM* (review nbom 19–20)

- **PASS** `a-load-balancer-has-a-vendor-a-product-and-a-firmware` — LB-01 → F5 BIG-IP i5800 → firmware 17.1.1 → F5
- **PASS** `the-vendor-chain-reaches-the-vendor-node` — VENDOR F5 in the estate
- **PASS** `a-network-device-sits-on-hardware` — LB-01 RUNS_ON SRV-PAY-01
- **PASS** `the-endpoint-reaches-the-device-that-owns-it` — LB-01 LISTENS_ON lb-01:443
- **PASS** `a-device-kind-the-model-does-not-build-is-refused` — ROUTER → NOT_A_NETWORK_DEVICE

## `coverage` — PASS

*does coverage propagate, or does it get rounded to healthy* (review nbom 21)

- **PASS** `coverage-is-reported-with-its-denominator` — expected 500 endpoint(s): observed 420, unavailable 50, unknown 30, permission denied 0 — coverage PARTIAL
- **PASS** `an-unavailable-endpoint-makes-the-verdict-partial` — PARTIAL with 50 unavailable and 30 unknown
- **PASS** `partial-propagates-to-every-view-that-reads-the-projection` — nbom, cbom network evidence and the twin all PARTIAL
- **PASS** `coverage-that-does-not-add-up-is-refused` — 80 + 40 out of 100 → COVERAGE_DOES_NOT_RECONCILE
- **PASS** `an-unavailable-endpoint-is-not-dropped-from-the-denominator` — 420 observed + 50 unavailable + 30 unknown = 500 expected

## `spine` — PASS

*does the biggest missing chain exist end to end* (review nbom 22)

- **PASS** `the-review-s-whole-vocabulary-exists` — 10 of 10 relations exist
- **PASS** `the-chain-reaches-the-business-system-the-database-and-the-keys` — 1 service → 2 process → 1 application → 1 system → 4 device → 1 database → 2 keys → 8 crypto → 8 vendor
- **PASS** `the-chain-also-reaches-the-crypto-behind-the-session` — 8 crypto node(s) behind the endpoint
- **PASS** `every-layer-of-the-review-s-stack-is-a-kind-in-one-graph` — 14 layers, one ASSET_TYPES tuple
- **PASS** `no-edge-in-the-graph-was-drawn-without-a-basis` — 74 edge(s), each with a basis

## What this does not prove

- the fixture is the review's own example estate, not a bank's collector output: the shapes are real, the rows are not
- a routing edge is only as good as its basis: an SNI value ties a name to a listener, and this model does not resolve DNS itself
- supported, negotiated and used are separated as relations, but a suite's negotiation is one observation, and a session that was never captured leaves only the policy behind it
- the sidecar is modelled as a process because that is what presents the certificate; a mesh that terminates outside a sidecar needs its own collector
- coverage is only as honest as the denominator, which comes from a CMDB the platform does not own
- a tunnel's parameters are read from configuration unless a status poll supplied them, and the two are told apart by evidence class
