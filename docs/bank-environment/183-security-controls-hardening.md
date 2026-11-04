# Security control integration — live harness (guides 182–183)

> CryptoScan integrates with the bank's existing network and security controls to build an evidence-backed cryptographic and security estate model.

**16 pass · 0 partial · 0 fail** over 69 probes (69 passed, 0 failed).

| | point | question | verdict | probes |
|---|---|---|---|---|
| L-01 | Transport | can the integration be made to write, or to read over plaintext? | **PASS** | 4/4 |
| L-02 | Drivers | does every read control have a driver, and is an unknown dialect named? | **PASS** | 3/3 |
| L-03 | Live read | does a read that failed look like a read that failed? | **PASS** | 4/4 |
| L-04 | Evidence store | can the evidence tell an edit from a retry, and a delete from a gap? | **PASS** | 6/6 |
| L-05 | Facades | are HSM, KMS, PKI and NETWORK in the layer without a second architecture? | **PASS** | 4/4 |
| L-06 | Prohibited values | does key material or a request body survive a cycle? | **PASS** | 5/5 |
| L-07 | Rate limit windows | does the audit use the limiter's arithmetic, not its own? | **PASS** | 4/4 |
| L-08 | Comparability | is a breach claimed only when the windows are the same interval? | **PASS** | 2/2 |
| L-09 | Observation states | are NOT_CONFIGURED, UNKNOWN and OVER_LIMIT kept apart? | **PASS** | 4/4 |
| L-10 | Resolver | does correlation come from the estate, and does it know when it is old? | **PASS** | 4/4 |
| L-11 | Evidence API | is a finding stored as evidence, tenant-scoped and citable? | **PASS** | 4/4 |
| L-12 | Redaction precision | does the guard redact the card numbers and not the evidence? | **PASS** | 4/4 |
| L-13 | Read-only at the socket | is the method allowlist enforced where the bytes leave? | **PASS** | 4/4 |
| L-14 | Evidence identity | is an evidence id stable, revision-aware and readable after a rule change? | **PASS** | 5/5 |
| L-15 | Failure taxonomy | does every failure have a name, on health, in the summary and for the console? | **PASS** | 6/6 |
| L-16 | Scale | is collection incremental, coverage per-device and memory bounded? | **PASS** | 6/6 |

## L-01 — Transport

*can the integration be made to write, or to read over plaintext?*

- [PASS] no write verb reaches the device — refused DELETE, PATCH, POST, PUT
- [PASS] plaintext base_url is refused — TLS_REQUIRED
- [PASS] verify=False is refused — TLS_VERIFICATION_REQUIRED
- [PASS] a credential never prints itself — repr is redacted

## L-02 — Drivers

*does every read control have a driver, and is an unknown dialect named?*

- [PASS] every registered dialect constructs — 9 dialect(s): api_gateway.kong, firewall.checkpoint, firewall.fortigate, firewall.paloalto, ids.suricata, ips.suricata_inline, load_balancer.f5, load_balancer.nginx, siem.splunk
- [PASS] an unimplemented dialect is refused by name — NO_LIVE_DRIVER
- [PASS] every driver declares endpoints or a log tail — endpoints per dialect

## L-03 — Live read

*does a read that failed look like a read that failed?*

- [PASS] an unreachable device is a state, not an empty success — BAD_RESPONSE
- [PASS] the failed sections are named — 5 section(s) failed
- [PASS] a partially answered device says PARTIAL_READ — PARTIAL_READ, 4 section(s) failed
- [PASS] the snapshot carries the transport it used — read_only: true

## L-04 — Evidence store

*can the evidence tell an edit from a retry, and a delete from a gap?*

- [PASS] a retry does not advance the chain — sequence 1, duplicate
- [PASS] an intact chain verifies — 2 record(s)
- [PASS] an edited body is found — ['BODY_ALTERED']
- [PASS] a deleted record is found — ['SEQUENCE_GAP', 'CHAIN_BROKEN']
- [PASS] retention leaves a tombstone — 1 removed, tombstone written
- [PASS] a tenant name cannot escape the store root — ../ refused

## L-05 — Facades

*are HSM, KMS, PKI and NETWORK in the layer without a second architecture?*

- [PASS] the four facade controls are implemented — HSM, KMS, NETWORK, PKI
- [PASS] each names the module it delegates to — HSM → cbom.hsm_pkcs11.assess_hsm_deep, cbom.hsm_pkcs11.detect_vendor; KMS → cbom.kms_collectors.key_records_from_kms, cbom.kms_collectors.posture, cbom.usage_evidence.key_metadata; NETWORK → cbom.nbom_graph.endpoint, cbom.nbom_graph.estate; PKI → cbom.certificate_chain.certificate, cbom.certificate_chain.chain
- [PASS] a facade has no vendor dialect of its own — FACADE_HAS_NO_VENDOR for all four
- [PASS] nothing is deferred any more — deferred: []

## L-06 — Prohibited values

*does key material or a request body survive a cycle?*

- [PASS] HSM key material does not survive — material and password refused
- [PASS] a network payload does not survive — body and header dropped by name
- [PASS] the drop is recorded, not silent — ['authorization', 'raw_body']
- [PASS] KMS keys are metadata only — 3 asset(s)
- [PASS] PKI emits only the model's own relations — ISSUED_BY, SIGNED_BY

## L-07 — Rate limit windows

*does the audit use the limiter's arithmetic, not its own?*

- [PASS] a sliding window permits N in any rolling window — 100 over 60s
- [PASS] a fixed counter permits a boundary burst — at most 2 aligned window(s) touched, so a boundary burst of 100 per window is possible and is not a breach
- [PASS] an aligned window does not get the burst — 100 over one closed window
- [PASS] an unknown window model is refused — refused

## L-08 — Comparability

*is a breach claimed only when the windows are the same interval?*

- [PASS] a mismatched window model is INCOMPARABLE_WINDOW — 1 incomparable, 0 over limit
- [PASS] a fragment of a window is not a rate — 30s sample under a 60s policy

## L-09 — Observation states

*are NOT_CONFIGURED, UNKNOWN and OVER_LIMIT kept apart?*

- [PASS] traffic with no policy is NOT_CONFIGURED — OPEN-API → NOT_CONFIGURED
- [PASS] an aligned counter over the limit is OVER_LIMIT — 140 over 100 in one closed window
- [PASS] an unavailable source is reported, not treated as zero — OBSERVATION_SOURCE_UNAVAILABLE
- [PASS] the report says what was not measured — 2 API(s) had a measured rate; 0 attached API(s) had no observation at all — a limit nobody measured is not a limit that held

## L-10 — Resolver

*does correlation come from the estate, and does it know when it is old?*

- [PASS] the whole path resolves from the inventory — APP-PAY-01 → java:payments → PAYMENTS-API → OpenSSL 3.0.13 → HSM-PAY-01
- [PASS] a stale hop is named, not used as proof — 1 stale hop(s)
- [PASS] strict mode stops where the evidence stops — path ends at PAYMENTS-API
- [PASS] an empty inventory is unresolved, not a pass — answerable: false

## L-11 — Evidence API

*is a finding stored as evidence, tenant-scoped and citable?*

- [PASS] the write and read routes exist — /security-controls/findings, /security-controls/health, /security-controls/snapshots, /security-controls/verify
- [PASS] both tables exist and carry tenant_id — security_control_snapshots, security_control_findings
- [PASS] a finding cannot exist without evidence ids — FINDING_WITHOUT_EVIDENCE
- [PASS] a user token is not a collector — user_token_not_accepted

## L-12 — Redaction precision

*does the guard redact the card numbers and not the evidence?*

- [PASS] legitimate numeric fields survive — 12 field(s), 0 false positive(s)
- [PASS] four real card numbers are still caught — Visa, Mastercard, Amex (15), Discover
- [PASS] a Luhn-valid number in no issuer range is not a card — not a PAN
- [PASS] the allowlist is published for review — 87 field(s) allowlisted

## L-13 — Read-only at the socket

*is the method allowlist enforced where the bytes leave?*

- [PASS] all four write verbs are refused — 4/4 refused
- [PASS] no refused write reached the client — 0 request(s) sent
- [PASS] GET and HEAD do reach the client — GET, HEAD
- [PASS] the allowlist is the whole method set — GET, HEAD

## L-14 — Evidence identity

*is an evidence id stable, revision-aware and readable after a rule change?*

- [PASS] an unchanged fact keeps its id — two reads, one id
- [PASS] a bumped config revision moves the id — version 42 → 43
- [PASS] every id carries its digest scheme — v1
- [PASS] a legacy id is named, not misread — v0
- [PASS] a citation re-verifies months later — recomputed match

## L-15 — Failure taxonomy

*does every failure have a name, on health, in the summary and for the console?*

- [PASS] three of five sections is PARTIAL_READ with named failures — 1/5 sections
- [PASS] health carries the state and its meaning — UNREACHABLE, retryable
- [PASS] a refused credential is AUTH_FAILED, not unreachable — rotate the collector credential and re-r
- [PASS] the projection summary carries coverage, not just counts — 1 of 3 control(s) were read; 2 could not be read; the rows from the remaining controls are not evidence of their state
- [PASS] a dialect with no driver is UNSUPPORTED_DIALECT — ABSENT
- [PASS] every state says what to do about it — 9 states

## L-16 — Scale

*is collection incremental, coverage per-device and memory bounded?*

- [PASS] an unchanged section is not re-read — rules, zones
- [PASS] the snapshot stays complete: unchanged rows are merged back — 2 section(s) present
- [PASS] a changed section is read again — rules changed, zones did not
- [PASS] coverage is per device, not per estate — FW-01 2/5, FW-02 0/5
- [PASS] a section past the cap is truncated and says so — 40 read, 10 kept
- [PASS] the snapshot ceiling is published — 4194304 bytes

## What this harness does not prove

* that a real device answers these endpoints: every read is through a recorded transport, so the *dialects* are exercised and the devices are not;
* that a PostgreSQL deployment applies the row-level policy in revision 0133 — the harness checks the tables and their columns, and the RBAC/RLS behaviour is covered by the database suite;
* that a rate-limit policy is the bank's policy: the numbers are the device's, and the policies are read from the device's own configuration.
