# The security control integration layer

`cryptoscan.security-controls-guide/1` · generated 2026-11-03T11:52:02Z · **14 pass · 0 partial · 0 fail** · 47 probes

**14 of 14 points hold across 47 probes: 9 collectors over 9 control types, 31 vendor dialects, 16 assets and 5 evidence-carrying claims, 5 redaction(s), 6 refusal(s)**

> CryptoScan integrates with the bank's existing network and security controls to build an evidence-backed cryptographic and security estate model.

```
vendor adapter → common contract → normalized evidence → canonical identity → twin
      ↑                  ↑                    ↑                  ↑            ↑
  dialect row       six read verbs      EVID- per fact      KIND:name:env   TechBOM
```

## The contract

| | |
|---|---|
| contract | `cryptoscan.security-controls/1` |
| verbs | `collect_configuration`, `collect_crypto_metadata`, `collect_relationships`, `collect_security_events`, `discover_assets`, `health` |
| vendor dialects | 31 |
| implemented controls | `API_GATEWAY`, `FIREWALL`, `IDS`, `IPS`, `LOAD_BALANCER`, `RATE_LIMIT`, `SIEM`, `VPN`, `WAF` |
| deferred to existing collectors | `HSM`, `KMS`, `NETWORK`, `PKI` |

## The fleet that was read

| Adapter | Control | Vendor | Configured | Facts | Refusals | Redactions |
|---|---|---|---|---|---|---|
| `firewall.fortigate` | FIREWALL | Fortinet | API_GET, CLI_SHOW | CONFIGURED 8 | 17 | 18 |
| `ids.suricata` | IDS | OISF | LIST, PCAP_READ, READ_CONFIG_FILE, TAIL_EVENTS | CONFIGURED 1, OBSERVED 1 | 8 | 8 |
| `ips.suricata_inline` | IPS | OISF | LIST, READ_CONFIG_FILE, TAIL_EVENTS | CONFIGURED 1, OBSERVED 2 | 0 | 0 |
| `waf.modsecurity` | WAF | OWASP | READ_CONFIG_FILE, TAIL_EVENTS | CONFIGURED 2, OBSERVED 1 | 0 | 0 |
| `load_balancer.f5` | LOAD_BALANCER | F5 | API_GET | CONFIGURED 2 | 0 | 0 |
| `api_gateway.kong` | API_GATEWAY | Kong | API_GET | CONFIGURED 5 | 0 | 5 |
| `rate_limit.gateway` | RATE_LIMIT | (the API gateway's own limiter) | API_GET | CONFIGURED 2 | 0 | 0 |
| `vpn.strongswan` | VPN | strongX509 / strongSwan | CLI_SHOW, READ_CONFIG_FILE, SHOW | CONFIGURED 1 | 0 | 0 |
| `siem.splunk` | SIEM | Splunk | API_GET, QUERY, SIEM_QUERY | CONFIGURED 1, OBSERVED 1 | 0 | 0 |

## What landed in the Digital Twin

| | |
|---|---|
| assets | 16 |
| evidence-carrying claims | 5 |
| asset kinds | `API_GATEWAY` 1, `APPLICATION` 2, `CERTIFICATE` 1, `FIREWALL` 1, `IDS` 1, `IPS` 1, `LOAD_BALANCER` 1, `NETWORK_SEGMENT` 3, `RATE_LIMIT` 2, `SECURITY_APPLIANCE` 1, `VPN_GATEWAY` 1, `WAF` 1 |
| relations | `INSPECTS` 1, `PROTECTS` 1, `ROUTES_TO` 2, `USES_CERTIFICATE` 1 |
| refusals | 6 (`EDGE_TO_UNDECLARED_ASSET`, `NO_LEGAL_RELATION`, `RELATIONSHIP_WITHOUT_EVIDENCE`, `UNDECLARED_EVENT_KIND`, `UNKNOWN_REF`, `UNKNOWN_RELATION`) |

## The rate-limit audit

| State | Findings |
|---|---|
| `NOT_CONFIGURED` | 1 |
| `WITHIN_LIMIT` | 0 |
| `OVER_LIMIT` | 1 |
| `POLICY_NOT_ATTACHED` | 1 |
| `UNKNOWN` | 0 |

| Finding | State | Configured | Observed | Facts |
|---|---|---|---|---|
| `REPORTS-API` | NOT_CONFIGURED | —/—s | 40 | OBSERVED |
| `PAYMENTS-API` | OVER_LIMIT | 100.0/60.0s | 900 | CONFIGURED + OBSERVED |
| `LIMIT-ORPHAN` | POLICY_NOT_ATTACHED | 50/60s | — | CONFIGURED |

Refused observations:

- `OBSERVATION_WITHOUT_EVIDENCE` — LEGACY-API: a request volume with no evidence id is a number nobody can point at; it is refused, not counted

## An alert becomes a crypto question

> What cryptographic assets and critical systems are involved in this network security event?

```
10.20.3.4 → host:APP-PAY-01 → process:java:payments → api:PAYMENTS-API → library:OpenSSL → hsm:HSM-PAY-01
```

| Hop | From | Resolved to | Evidence | Fact |
|---|---|---|---|---|
| `host` | `10.20.3.4` | `APP-PAY-01` | `EVID-ASSET-0001` | CONFIGURED |
| `process` | `APP-PAY-01` | `java:payments` | `EVID-RUNTIME-0001` | RUNTIME_OBSERVED |
| `api` | `java:payments` | `PAYMENTS-API` | `EVID-API-0001` | CONFIGURED |
| `library` | `PAYMENTS-API` | `OpenSSL` | `EVID-RUNTIME-0002` | RUNTIME_OBSERVED |
| `hsm` | `OpenSSL` | `HSM-PAY-01` | `EVID-KEY-0001` | CONFIGURED |

Crypto reached:

- `CRYPTO_LIBRARY` OpenSSL 3.0.13 — `EVID-RUNTIME-0002`
- `HSM` HSM-PAY-01 (key `pin-key-1`) — `EVID-KEY-0001`

Gaps the correlation named rather than guessed:

- `NO_HOST_FOR_ADDRESS` — 10.99.99.99: no inventory declares this address, so the event lands on an unknown host
- `NO_LIBRARY_FOR_API` — PAYMENTS-API: the API is known and no runtime observation records the crypto library it loaded

## What the redaction guard refused

| Path | Field | Reason |
|---|---|---|
| `password` | `password` | PROHIBITED_FIELD |
| `comment` | `comment` | PEM_PRIVATE_KEY |
| `psk` | `psk` | PROHIBITED_FIELD |
| `authorization` | `authorization` | PROHIBITED_FIELD |
| `api_secret` | `api_secret` | PROHIBITED_FIELD |

*The value is never recorded — only the fact that it was refused.*

| Row | Section | Question | Verdict | Probes |
|---|---|---|---|---|
| `SC-01` | contract | the collector contract is six verbs and no write | **PASS** | 4, 0 failing |
| `SC-02` | adapters | a vendor is a dialect row, not a new architecture | **PASS** | 4, 0 failing |
| `SC-03` | privacy | no prohibited value survives a collection cycle | **PASS** | 5, 0 failing |
| `SC-04` | facts | configured, observed and runtime-observed never merge | **PASS** | 4, 0 failing |
| `SC-05` | evidence | every relationship carries the evidence that states it | **PASS** | 4, 0 failing |
| `SC-06` | digital-twin | the projection lands in the TechBOM, typed | **PASS** | 4, 0 failing |
| `SC-07` | rate-limit | an API with traffic and no policy is a finding | **PASS** | 2, 0 failing |
| `SC-08` | rate-limit | a breach prints the configured limit beside the observed volume | **PASS** | 2, 0 failing |
| `SC-09` | rate-limit | a policy attached to nothing is distinguishable from a limit | **PASS** | 2, 0 failing |
| `SC-10` | correlation | an IDS event reaches the crypto it touches | **PASS** | 3, 0 failing |
| `SC-11` | correlation | a hop nobody collected is a named gap | **PASS** | 3, 0 failing |
| `SC-12` | normalization | each control type normalizes what its device reports | **PASS** | 5, 0 failing |
| `SC-13` | siem | an event keeps the reference that makes it auditable | **PASS** | 2, 0 failing |
| `SC-14` | fleet | nine controls, one contract, one report | **PASS** | 3, 0 failing |

## `SC-01` — PASS

*the collector contract is six verbs and no write* (guide 181, contract)

- **PASS** `the-contract-has-exactly-six-verbs` — collect_configuration, collect_crypto_metadata, collect_relationships, collect_security_events, discover_assets, health
- **PASS** `no-adapter-declares-a-write` — 31 adapters, 0 write operations
- **PASS** `every-declared-operation-is-on-the-read-allow-list` — allow-list of 17 read operations: API_GET, CLI_SHOW, EXPORT_CONFIG, GET, KMIP_QUERY, LIST, …
- **PASS** `a-mutating-adapter-is-refused-at-registration` — PUSH_POLICY → NOT_READ_ONLY, before anything connects

## `SC-02` — PASS

*a vendor is a dialect row, not a new architecture* (guide 181, adapters)

- **PASS** `every-control-type-is-implemented-or-named-as-deferred` — 9 implemented, 4 deferred to an existing collector
- **PASS** `the-implemented-controls-carry-their-collection-table` — API_GATEWAY, FIREWALL, IDS, IPS, LOAD_BALANCER, RATE_LIMIT, SIEM, VPN, WAF
- **PASS** `every-dialect-declares-a-read-only-capability-surface` — 31 dialects across 9 control types
- **PASS** `an-unknown-vendor-is-refused-with-the-list-of-dialects` — UNKNOWN_VENDOR: netgear is not a firewall dialect this integration speaks; add a row to vendors.py (checkpoint, fortigate, gen

## `SC-03` — PASS

*no prohibited value survives a collection cycle* (guide 181, privacy)

- **PASS** `the-fixtures-actually-plant-secrets` — 6 of 8 sentinels are really in the recorded feeds (a guard that is never exercised proves nothing)
- **PASS** `no-planted-secret-appears-anywhere-in-the-report` — 6 sentinels planted, 0 survived in 53 KiB of report
- **PASS** `the-redactions-are-recorded-by-field-and-path` — 5 redaction record(s): api_secret, authorization, comment, password, psk
- **PASS** `a-private-key-is-caught-by-shape-under-an-innocent-name` — PEM, card-number and authorization shapes all → [REDACTED]
- **PASS** `no-http-body-or-payload-reaches-an-event` — payload/body fields are dropped before normalization

## `SC-04` — PASS

*configured, observed and runtime-observed never merge* (guide 181, facts)

- **PASS** `a-config-row-is-configured-only` — configuration rows: CONFIGURED
- **PASS** `an-event-is-observed-only` — event rows: OBSERVED
- **PASS** `a-loaded-library-is-runtime-observed-and-a-config-hop-is-not` — library RUNTIME_OBSERVED, api CONFIGURED
- **PASS** `three-records-stay-three-buckets` — CONFIGURED 1 · OBSERVED 1 · RUNTIME_OBSERVED 1

## `SC-05` — PASS

*every relationship carries the evidence that states it* (guide 181, evidence)

- **PASS** `every-asset-crypto-row-event-and-claim-has-an-evidence-id` — 47 evidence record(s) retained
- **PASS** `evidence-ids-are-deterministic-across-two-reads` — 5 claims on the second read, 5 on the first
- **PASS** `a-claim-with-no-evidence-is-refused-by-name` — INSPECTS INTERNET → RELATIONSHIP_WITHOUT_EVIDENCE
- **PASS** `a-vendor-cannot-name-a-relation-of-its-own` — FW-EDGE-01 ALLOWS PAYMENTS-SEG → UNKNOWN_RELATION (the model has no ALLOWS)

## `SC-06` — PASS

*the projection lands in the TechBOM, typed* (guide 181, digital-twin)

- **PASS** `the-graph-builds-with-no-refusals-of-its-own` — 16 assets · 5 claims · {'INSPECTS': 1, 'PROTECTS': 1, 'ROUTES_TO': 2, 'USES_CERTIFICATE': 1}
- **PASS** `the-asset-kinds-are-the-models-own` — API_GATEWAY 1, APPLICATION 2, CERTIFICATE 1, FIREWALL 1, IDS 1, IPS 1, LOAD_BALANCER 1, NETWORK_SEGMENT 3, RATE_LIMIT 2, SECURITY_APPLIANCE 1, VPN_GATEWAY 1, WAF 1
- **PASS** `a-pairing-no-relation-permits-is-refused-by-name` — FW-EDGE-01 PRESENTS PAYMENTS-SEG: PRESENTS starts at NETWORK_ENDPOINT, LOAD_BALANCER, API_GATEWAY, WAF, SERVICE_MESH, DATABASE, not FI
- **PASS** `an-edge-to-an-undeclared-node-is-refused-not-created` — SHADOW-SEG → UNKNOWN_REF; the node is not invented

## `SC-07` — PASS

*an API with traffic and no policy is a finding* (guide 181, rate-limit)

- **PASS** `the-not-configured-api-is-named` — 1 NOT_CONFIGURED: REPORTS-API
- **PASS** `it-carries-the-observation-and-no-configuration` — facts [OBSERVED], policy None

## `SC-08` — PASS

*a breach prints the configured limit beside the observed volume* (guide 181, rate-limit)

- **PASS** `the-over-limit-row-keeps-both-numbers` — PAYMENTS-API: configured 100/60s, observed 900/60s
- **PASS** `it-carries-both-evidence-classes-and-neither-verdict` — facts [CONFIGURED, OBSERVED] with two evidence ids

## `SC-09` — PASS

*a policy attached to nothing is distinguishable from a limit* (guide 181, rate-limit)

- **PASS** `the-orphan-policy-is-named` — 1 POLICY_NOT_ATTACHED: LIMIT-ORPHAN
- **PASS** `an-observation-with-no-evidence-is-refused-not-counted` — LEGACY-API → OBSERVATION_WITHOUT_EVIDENCE, excluded from the counts

## `SC-10` — PASS

*an IDS event reaches the crypto it touches* (guide 181, correlation)

- **PASS** `the-path-runs-address→host→process→api→library→hsm` — APP-PAY-01 → java:payments → PAYMENTS-API → OpenSSL → HSM-PAY-01
- **PASS** `it-names-the-crypto-assets-and-the-critical-systems` — CRYPTO_LIBRARY=OpenSSL, HSM=HSM-PAY-01, API=PAYMENTS-API, HOST=APP-PAY-01
- **PASS** `the-question-is-the-one-the-specification-asks` — What cryptographic assets and critical systems are involved in this network security event?

## `SC-11` — PASS

*a hop nobody collected is a named gap* (guide 181, correlation)

- **PASS** `an-address-no-inventory-declares-stops-the-path` — 10.99.99.99: no inventory declares this address, so the event lands on an unknown host
- **PASS** `two-hosts-behind-one-address-is-ambiguous-not-first-row` — 10.20.3.4 → APP-PAY-01, APP-PAY-02; not decided by row order
- **PASS** `the-path-stops-where-the-runtime-inventory-does` — PAYMENTS-API: the API is known and no runtime observation records the crypto library it lo

## `SC-12` — PASS

*each control type normalizes what its device reports* (guide 181, normalization)

- **PASS** `a-fortigate-accept-becomes-an-allow-and-a-deny-stays-a-deny` — FW-001=ALLOW tcp/HTTPS, FW-002=DENY tcp/SSH, FW-003=ALLOW tcp/HTTPS
- **PASS** `a-vip-flattens-to-its-pool-members-with-both-evidence-ids` — 10.30.2.11:8443, 10.30.2.12:8443
- **PASS** `an-ips-block-is-a-block-and-an-alert-is-not` — 2 events, 1 block(s)
- **PASS** `the-gateway-reports-mtls-and-plaintext-routes-without-a-secret` — mtls ['payments'], plaintext ['reports'], api secret redacted
- **PASS** `a-tunnel-below-the-crypto-floor-is-reported-not-fixed` — hq-dr:IKEv1+legacy-algorithm+dh-group-1024+no-pfs

## `SC-13` — PASS

*an event keeps the reference that makes it auditable* (guide 181, siem)

- **PASS** `a-notable-carries-its-incident-and-search-ids` — INC-77 / corr-17 / sid_1
- **PASS** `the-siem-collector-declares-that-it-writes-nothing-back` — write_to_the_siem, suppress_a_correlation, run_a_response_action, read_raw_log_content

## `SC-14` — PASS

*nine controls, one contract, one report* (guide 181, fleet)

- **PASS** `nine-collectors-answer-the-same-six-questions` — 9 collectors · API_GATEWAY, FIREWALL, IDS, IPS, LOAD_BALANCER, RATE_LIMIT, SIEM, VPN, WAF
- **PASS** `every-device-answered-and-each-says-what-it-read` — 9 health records, all reachable, all declaring read operations
- **PASS** `the-refusals-are-data-and-the-run-still-succeeds` — 6 refusal(s), 0 exceptions raised

## What this does not prove

- the feeds are recorded fixtures, not live devices: the read-only client for each dialect is described in vendors.py and not implemented here
- HSM, KMS, PKI and the passive network path are named as deferred: they already have read-only collectors elsewhere in the platform and this layer correlates them rather than re-collecting them
- correlation resolves only as far as the inventories reach; an unresolved hop is reported, and it stays unresolved until the platform collects that layer
- nothing is persisted: findings and evidence are documents, and a table for them is a separate guide that must not become a second source of truth
