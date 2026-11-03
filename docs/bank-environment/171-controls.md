# The controls in front of the estate

`cryptoscan.cbom-controls-guide/1` · generated 2026-11-03T06:06:06.987729+00:00 · **9 pass · 0 partial · 0 fail** · 53 probes

The NBOM answered what the estate is. This is what stands in front of it, and
the question is not whether a control exists but what it can stop. An IPS in the
path can drop a packet; an IDS on a tap can only say what it saw. A firewall rule
that matches is a policy, not a packet. A rate limit is a number and a
behaviour, and it is the behaviour that fails. A request the platform did not
send is recorded with a collector and a hash, so silence is not mistaken for
coverage.

```
ids      an IDS alerts, an IPS blocks — two kinds, two ids, one graph
ips      inline is a hop on the route; a tap is a copy beside it
inspect  INSPECTED_INLINE / TAP_ONLY / NOT_INSPECTED / FAIL_OPEN_INLINE
firewall rules in order, first match wins, default action decides the rest
limit    limit + window + scope + on_exceed + fail_open, as one policy node
probe    allowlist → method → budget → concurrency → backoff → interval
```

4 network endpoint(s), 18 evidenced edge(s), 0 TLS boundary mode(s) in use, 4 proven route(s); 0 claim(s) refused

## The sensors

| sensor | kind | mode | inspects | blocks | fail-open |
|---|---|---|---|---|---|
| ids-01 | `IDS` | TAP | CARDHOLDER, auth-api:9443 | no | no |
| ips-01 | `IPS` | INLINE | CARDHOLDER, payments-api:8443 | yes | no |
| ips-dr-01 | `IPS` | TAP | CARDHOLDER, payments-api:8443 | no | no |

## Inspection, per route

**1 route(s) from waf-01:443: 1 cross a control that can block, 0 do not**

| route | verdict | blocking | tap-only |
|---|---|---|---|
| waf-01:443 → ips-01 → api-gw-01:8443 → payments-api:8443 → Payments API | INSPECTED_INLINE | ips-01 | ips-dr-01 |

**Sensor findings**

- `IPS_NOT_INLINE` on ips-dr-01 — an IPS deployed off the path detects and never blocks; the prevention it was bought for is not deployed

## The firewall

- **allowed** — fw-01 rule 1 allows TCP:8443 to 10.10.1.5 — a matching rule, not an observed packet
- **default** — no rule matched; fw-01 falls to its default deny

## Rate limits

**4 rate-limit finding(s) on 1 policy row(s): LIMIT_FAIL_OPEN, LIMIT_NOT_ENFORCED, NO_LIMIT_RECORDED**

- `LIMIT_FAIL_OPEN` — rl-payments-edge: when the limiter cannot decide, traffic passes
- `LIMIT_NOT_ENFORCED` — rl-payments-edge: traffic above the limit was never refused
- `NO_LIMIT_RECORDED` — api-gw-01:8443: the endpoint is reachable through a device and no limit was read for it
- `NO_LIMIT_RECORDED` — payments-api:8443: the endpoint is reachable through a device and no limit was read for it

| Row | Question | Verdict | Probes |
|---|---|---|---|
| `sensors` | is an IDS a firewall with a different sticker | **PASS** | 8, 0 failing |
| `in-path` | does traffic actually pass through the control | **PASS** | 4, 0 failing |
| `inspection` | is inspection a property of the estate or of a route | **PASS** | 5, 0 failing |
| `firewall` | is a rule set evaluated or asserted | **PASS** | 6, 0 failing |
| `rate-limit` | is a limit a policy or a paragraph | **PASS** | 6, 0 failing |
| `rate-limit-gap` | does one healthy segment hide one sick one | **PASS** | 5, 0 failing |
| `probe-gate` | is a request sent or is it decided | **PASS** | 9, 0 failing |
| `probe-ledger` | is a request not sent a silence or a record | **PASS** | 5, 0 failing |
| `vocabulary` | does the graph carry the controls it reports | **PASS** | 5, 0 failing |

## `sensors` — PASS

*is an IDS a firewall with a different sticker* (guide 171, ids, ips)

- **PASS** `an-ids-and-an-ips-are-two-kinds-not-one-appliance` — IDS and IPS are asset kinds beside SECURITY_APPLIANCE
- **PASS** `a-sensor-is-in-the-path-or-it-sees-a-copy` — ips-01 INLINE, ids-01 TAP, ips-dr-01 TAP
- **PASS** `only-a-sensor-that-is-both-an-ips-and-inline-is-blocking` — ips-01 blocks; ids-01 and the DR IPS — deployed as a tap — observe
- **PASS** `the-sensors-have-their-own-ids-per-kind` — TECH-IDS-001, TECH-IPS-001 (inline), TECH-IPS-002 (the tap)
- **PASS** `an-ids-that-claims-to-block-is-refused` — IDS with blocks=True → IDS_CANNOT_BLOCK
- **PASS** `a-tap-cannot-drop-a-packet-it-never-carried` — IPS in TAP mode with blocks=True → SENSOR_CANNOT_BLOCK_OFF_PATH
- **PASS** `an-inline-sensor-with-nothing-behind-it-is-an-outage` — inline IPS with no downstream → INLINE_WITHOUT_DOWNSTREAM
- **PASS** `only-an-ips-may-protect-in-the-type-table` — PROTECTS starts at IPS, WAF, FIREWALL, SERVICE_MESH — never at IDS

## `in-path` — PASS

*does traffic actually pass through the control* (guide 171, ips)

- **PASS** `an-inline-ips-is-a-hop-on-the-route` — waf-01:443 → ips-01 → api-gw-01:8443 → payments-api:8443 → Payments API
- **PASS** `a-tap-is-not-a-hop-on-any-route` — ids-01 appears in no path: a tap receives a copy
- **PASS** `inspecting-a-node-is-not-forwarding-to-it` — INSPECTS exists as a relation and is deliberately absent from PATH_RELATIONS
- **PASS** `an-ips-deployed-as-a-tap-is-reported-rather-than-drawn` — IPS in TAP mode → IPS_NOT_INLINE

## `inspection` — PASS

*is inspection a property of the estate or of a route* (guide 171, ips, ids)

- **PASS** `a-route-that-crosses-a-blocking-control-is-inspected-inline` — 1 route(s) from waf-01:443: 1 cross a control that can block, 0 do not
- **PASS** `a-route-watched-only-from-a-tap-is-tap-only` — auth-api:9443 → Auth API → TAP_ONLY via ids-01
- **PASS** `a-route-nothing-sees-says-not-inspected` — 1 route(s) cross no blocking control
- **PASS** `a-blocking-control-is-named-on-the-route-it-guards` — blocking: ['ips-01']
- **PASS** `an-inline-control-deployed-fail-open-gives-up-its-own-verdict` — inline IPS with fail_open → FAIL_OPEN_INLINE, inspected False

## `firewall` — PASS

*is a rule set evaluated or asserted* (guide 171, firewall)

- **PASS** `a-rule-that-matches-is-evaluated-in-order` — fw-01 rule 1 allows TCP:8443 to 10.10.1.5 — a matching rule, not an observed packet
- **PASS** `a-deny-rule-ahead-of-the-default-is-its-own-match` — fw-01 rule 2 denies TCP:22 to 10.10.1.5 — a matching rule, not an observed packet
- **PASS** `an-unmatched-flow-falls-to-the-default-action` — no rule matched; fw-01 falls to its default deny
- **PASS** `a-matching-rule-is-configured-and-never-network-observed` — CONFIGURED, and the caveat — only a capture says what happened — travels with the answer
- **PASS** `a-rule-that-names-no-service-is-refused` — a rule with no port → RULE_WITHOUT_SERVICE
- **PASS** `a-firewall-carries-its-vendor-chain-like-any-other-device` — fw-01 HAS_MODEL Palo Alto PA-5220, SUPPLIED_BY Palo Alto

## `rate-limit` — PASS

*is a limit a policy or a paragraph* (guide 171, ratelimit)

- **PASS** `a-limit-is-a-number-a-window-and-a-scope` — 100 per 1s per CLIENT
- **PASS** `the-behaviour-at-the-edge-is-part-of-the-policy` — 429 by configuration, pass-through when the limiter fails
- **PASS** `a-policy-is-joined-to-the-device-that-enforces-it` — waf-01:443 ENFORCES rl-payments-edge, rl-payments-edge LIMITS waf-01:443
- **PASS** `a-limit-of-zero-or-a-window-of-zero-is-refused` — 0 per 1s → INVALID_RATE_LIMIT
- **PASS** `a-scope-nobody-has-is-refused` — EVERYONE → UNKNOWN_RATE_SCOPE
- **PASS** `the-policy-is-a-node-with-its-own-id` — TECH-RL-001

## `rate-limit-gap` — PASS

*does one healthy segment hide one sick one* (guide 171, ratelimit)

- **PASS** `a-limiter-deployed-fail-open-passes-what-it-was-meant-to-stop` — fail_open=True → LIMIT_FAIL_OPEN
- **PASS** `traffic-above-the-limit-with-no-refusal-is-not-enforcement` — 250 rps observed, limit 100, 0 refused → LIMIT_NOT_ENFORCED
- **PASS** `an-endpoint-behind-a-device-with-no-limit-read-is-a-finding` — NO_LIMIT_RECORDED on the endpoints behind a device
- **PASS** `a-limit-that-did-refuse-is-not-a-finding` — 250 rps observed, 150 refused → no LIMIT_NOT_ENFORCED
- **PASS** `the-answer-carries-its-evidence-class` — 4 rate-limit finding(s) on 1 policy row(s): LIMIT_FAIL_OPEN, LIMIT_NOT_ENFORCED, NO_LIMIT_RECORDED

## `probe-gate` — PASS

*is a request sent or is it decided* (guide 171, request sending)

- **PASS** `an-allowlist-is-a-list-of-ranges-names-and-addresses` — 10.10.0.0/16 (CIDR), *.bank.example (SUFFIX), 203.0.113.9:443 (HOST)
- **PASS** `a-probe-with-no-allowlist-is-a-scan-of-the-internet` — [] → EMPTY_ALLOWLIST
- **PASS** `an-allowlist-entry-that-does-not-parse-is-refused` — 10.0.0.0/999 → ALLOWLIST_INVALID
- **PASS** `permission-is-decided-before-budget` — an exhausted budget never turns an off-list target into an allowed one
- **PASS** `a-method-that-can-change-state-is-refused` — POST → METHOD_NOT_SAFE
- **PASS** `a-cidr-entry-admits-an-address-and-a-suffix-admits-a-name` — 10.10.1.5 in 10.10.0.0/16; auth.bank.example under *.bank.example
- **PASS** `the-budget-the-concurrency-and-the-backoff-each-stop-a-scan` — budget → concurrency → backoff, each with its own code
- **PASS** `the-interval-between-requests-is-enforced-not-assumed` — 100ms since the last request, floor 250ms → INTERVAL_NOT_ELAPSED
- **PASS** `a-dry-run-decides-and-sends-nothing` — dry_run=True → DRY_RUN

## `probe-ledger` — PASS

*is a request not sent a silence or a record* (guide 171, request sending)

- **PASS** `every-decision-becomes-a-record-including-the-refusals` — 3 decision(s): 1 sent, 2 refused (METHOD_NOT_SAFE 1, TARGET_NOT_ALLOWED 1)
- **PASS** `a-sent-request-is-observed-and-a-refusal-is-configured` — SEND → NETWORK_OBSERVED, refusal → CONFIGURED
- **PASS** `each-record-names-its-collector-and-carries-a-hash` — 3 record(s), collector probe-gate, sha256 each
- **PASS** `a-decision-with-no-collector-or-no-hash-is-refused` — EVIDENCE_WITHOUT_COLLECTOR / EVIDENCE_WITHOUT_HASH
- **PASS** `we-did-not-probe-that-segment-is-a-checkable-fact` — TARGET_NOT_ALLOWED GET 198.51.100.7:443

## `vocabulary` — PASS

*does the graph carry the controls it reports* (guide 171, vocabulary)

- **PASS** `the-three-control-relations-exist-in-the-one-graph` — INSPECTS, ENFORCES, LIMITS
- **PASS** `the-three-control-kinds-are-asset-types-with-prefixes` — IDS, IPS, RATE_LIMIT
- **PASS** `a-control-is-a-level-in-the-chain-the-review-draws` — 1 application → 1 control
- **PASS** `the-projection-reports-the-controls-it-holds` — 3 sensor(s), 4 inspected route view(s)
- **PASS** `nothing-in-this-guide-needed-a-new-projection` — cryptoscan.nbom/1 from CANONICAL_ESTATE

## What this does not prove

- the fixture is the bank's own path: the shapes are real, the rows are not
- an inline control is where the traffic goes, not a rule that fired: a rule that matches is CONFIGURED and only a capture or a probe is NETWORK_OBSERVED
- a tap is evidenced against a node, so TAP_ONLY says the sensor watches a node on the route — not that it captured this request
- a rate-limit finding compares what was configured with one observation; a limiter that failed over after this capture is not in it
- the probe gate is a decision engine: it records what would be sent, and the socket lives outside this module so the check cannot be skipped by a caller that forgets it
- an allowlist that parses is not an authorisation: the signed scope for a scan is a contract with the bank, and this module only enforces the list it is given
