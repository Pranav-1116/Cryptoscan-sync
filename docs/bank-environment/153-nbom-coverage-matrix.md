# NBOM coverage: an observed endpoint is not the network

`cryptoscan.nbom-coverage-guide/1` · generated 2026-11-02T19:01:09.242158+00:00 · **5 pass · 0 partial · 0 fail** · 29 probes

Review item 4: an estate with 10,000 endpoints and 6,500 observed must not produce an NBOM that reads as *the bank's network*. The collection path already refuses to read a timeout as plaintext; this is the same refusal one level up.

```
expected · attempted · observed · failed · unauthorized · excluded
      → unattempted · coverage_pct · status · reasons
      → TOTAL (only when every group is COMPLETE) or FLOOR
```

Review's own numbers: **65.0%** — 6500 of 10000 observed, PARTIAL, 1500 never attempted; claim basis **FLOOR**.

| status | what it means | can a total be quoted? |
|---|---|---|
| `COMPLETE` | every expected endpoint was observed | yes, for that group |
| `PARTIAL` | some were, and the rest are named | no — a floor |
| `FAILED` | probes ran and none negotiated | no: a scan failure |
| `UNAUTHORIZED` | nothing was attempted | no: an authorization gap |
| `UNMEASURED` | no target list | no: 0% and 100% are both wrong |

## The estate network coverage matrix

| Target | Expected | Attempted | Observed | Unattempted | Coverage | Status |
|---|---|---|---|---|---|---|
| External endpoints | 120 | 120 | 118 | 0 | 98.3% | **PARTIAL** |
| Internal LB | 25 | 25 | 25 | 0 | 100.0% | **COMPLETE** |
| API gateways | 40 | 40 | 37 | 0 | 92.5% | **PARTIAL** |
| DB endpoints | 80 | 60 | 54 | 20 | 67.5% | **PARTIAL** |
| HSM network interfaces | 8 | 8 | 8 | 0 | 100.0% | **COMPLETE** |
| VPN gateways | 12 | 10 | 9 | 2 | 75.0% | **PARTIAL** |

251 of 285 expected endpoint(s) observed across 6 target group(s) (88.1%) — partial: 2 group(s) complete, 22 never attempted; any total is a floor on the network, not the network

`FLOOR` — 251 endpoint(s) observed is a floor: the matrix does not cover the whole estate, so the NBOM describes what was observed, not what exists

| Row | Question | Verdict | Probes |
|---|---|---|---|
| `observed_is_not_the_network` | does 6,500 observed endpoints read as a 10,000-endpoint estate? | **PASS** | 6, 0 failing |
| `five_statuses` | is 'not complete' fine-grained enough to act on? | **PASS** | 5, 0 failing |
| `arithmetic_checked` | can a stale target list produce a plausible percentage? | **PASS** | 6, 0 failing |
| `from_probes` | does a stored probe ledger produce an honest coverage row? | **PASS** | 6, 0 failing |
| `document_carries_the_claim` | does the NBOM itself say how much of the network it covers? | **PASS** | 6, 0 failing |

## `observed_is_not_the_network` — PASS

*does 6,500 observed endpoints read as a 10,000-endpoint estate?* (review 4)

- **PASS** `the-review-s-numbers-produce-65-percent` — 6500 of 10000 (65.0%)
- **PASS** `the-status-is-partial-not-complete` — PARTIAL
- **PASS** `the-unattempted-endpoints-are-counted` — 1500 never attempted = 10,000 − 8,000 − 500
- **PASS** `a-partial-estate-yields-a-floor-never-a-total` — 6500 endpoint(s) observed is a floor: the matrix does not cover the whole estate, so the NBOM describes what was observed, not what exists
- **PASS** `only-a-fully-observed-estate-supports-a-total` — 25 endpoint(s) observed, and every expected endpoint was observed
- **PASS** `the-gaps-are-named-in-words-not-only-in-numbers` — 6500 of 10000 expected endpoint(s) observed across 1 target group(s) (65.0%) — partial: 0 group(s) complete, 1500 never attempted, 500 unauthorized, 1000 failed; any total is a floor on the network, not the network

## `five_statuses` — PASS

*is 'not complete' fine-grained enough to act on?* (review 5)

- **PASS** `all-five-statuses-are-reachable-and-distinct` — {"COMPLETE": "COMPLETE", "FAILED": "FAILED", "PARTIAL": "PARTIAL", "UNAUTHORIZED": "UNAUTHORIZED", "UNMEASURED": "UNMEASURED"}
- **PASS** `an-unmeasured-group-is-neither-0-nor-100-percent` — Partner network: no target list, so coverage is unknown — 0% and 100% are both wrong
- **PASS** `probes-that-all-failed-are-a-scan-failure-not-an-empty-network` — DMZ: 0 of 10 observed (0.0%); probes ran and none negotiated — that is a scan failure, not an empty network
- **PASS** `an-unauthorized-group-is-called-an-authorization-gap` — Partner VPN: 0 of 12 observed (0.0%); nothing was attempted because the collector was not authorized for this group
- **PASS** `a-complete-group-says-so-without-a-caveat` — no reasons, because there is no gap

## `arithmetic_checked` — PASS

*can a stale target list produce a plausible percentage?* (review 4)

- **PASS** `an-observation-above-the-target-list-is-refused` — x: 6 observed against 5 expected — the target list is stale, and clamping the percentage would hide that
- **PASS** `a-probe-against-an-uninventoried-endpoint-is-refused` — x: 6 attempted against 5 expected — the scan targeted endpoints nobody inventoried
- **PASS** `an-observation-without-a-probe-is-refused` — x: 2 observed against 1 attempted — an observation needs a probe
- **PASS** `a-negative-or-boolean-count-is-refused` — expected must be a count, not a boolean
- **PASS** `a-row-with-no-target-is-refused` — a coverage row needs a target (which group is being measured)
- **PASS** `the-same-group-twice-is-refused-rather-than-summed` — dmz appears twice in one matrix

## `from_probes` — PASS

*does a stored probe ledger produce an honest coverage row?* (review 4 / 3)

- **PASS** `a-successful-handshake-is-observed` — 2 observed
- **PASS** `a-timeout-is-a-failure-and-never-an-observation` — failed=1, observed=2
- **PASS** `an-unauthorized-probe-is-not-counted-as-attempted` — unauthorized=1, attempted=3
- **PASS** `an-undocumented-status-is-refused-not-bucketed` — status MAYBE is not a documented probe outcome, so it is not counted as observed or failed
- **PASS** `a-declared-endpoint-nobody-probed-is-the-gap` — 1 unattempted: ['f.bank.example:443']
- **PASS** `the-row-is-partial-because-a-declared-endpoint-was-never-probed` — External endpoints: 2 of 5 observed (40.0%); 1 never attempted, 1 unauthorized, 1 failed; 1 declared endpoint(s) were never probed; 1 probe row(s) refused

## `document_carries_the_claim` — PASS

*does the NBOM itself say how much of the network it covers?* (review 4 / 5)

- **PASS** `the-block-travels-with-the-document` — PARTIAL at 88.1% of 285
- **PASS** `the-total-claim-is-a-property-a-reader-cannot-miss` — cryptoscan:network_may_report_total = false
- **PASS** `existing-document-properties-survive` — the estate property is still there
- **PASS** `an-nbom-with-components-and-no-coverage-is-unqualified` — 1 component(s) and no coverage block: the document does not say how much of the network it describes
- **PASS** `an-empty-nbom-claims-nothing-so-it-is-not-lying` — no components and no coverage block, so nothing is claimed
- **PASS** `a-complete-document-may-report-a-total` — coverage COMPLETE at 100.0%; a total may be quoted

## What this does not prove

- the expected count comes from the estate's target list. If nobody inventoried the network to begin with, the matrix is arithmetically correct and still describes the wrong denominator — that is why a group with no targets is UNMEASURED rather than 0%
- coverage is counted per endpoint, not per service behind it. One IP with twelve virtual hosts is one endpoint here and twelve listeners in the NBOM, and neither number is wrong as long as the unit is read
- a probe status vocabulary is a contract. A scanner that starts emitting a new outcome will have its rows refused until the status is mapped, which is deliberate: silently bucketing a new failure mode into 'observed' is the failure this module exists to prevent
- the numbers describe a moment. A run six weeks old is still COMPLETE for the endpoints it probed, so staleness has to be read from the run, not inferred from coverage_pct
- coverage says how much was looked at, never how much cryptography is there. A 100% covered estate with an empty NBOM is a measurement; a 65% estate with 6,500 listeners is a floor
- attaching the block to a document does not enforce it. A reader that ignores cryptoscan:network_may_report_total can still quote a total, which is why qualify() exists for the readers the platform controls
