# NBOM history: snapshots, changes, and NETWORK_CRYPTO_REGRESSION

`cryptoscan.nbom-history-guide/1` · generated 2026-11-02T19:09:26.040391+00:00 · **5 pass · 0 partial · 0 fail** · 31 probes

Review items 18 and 21: the NBOM is point-in-time, and a point has no memory. A normalised snapshot per run, hashed over **state**, makes *nothing changed* cheap to prove and *what changed* cheap to find.

```
OBSERVE → NORMALIZE → HASH → COMPARE → CHANGE?
              state only          complete list → the weakening subset
                                  → NETWORK_CRYPTO_REGRESSION
```

Sample: 4 change(s) across 4 kind(s) between 2026-11-01T00:00:00Z and 2026-11-02T00:00:00Z: CERTIFICATE_CHANGED, CIPHER_SUITE_CHANGED, TLS_VERSION_CHANGED, TRUST_PATH_CHANGED; 1 endpoint(s) unchanged

1 NETWORK_CRYPTO_REGRESSION finding(s), worst HIGH; each names what is not proven

| change kind | reported as |
|---|---|
| `ENDPOINT_ADDED` | a change that needs an owner (`INFO`) |
| `ENDPOINT_REMOVED` | decommissioned *or* stopped answering (`MEDIUM`) |
| `PORT_CHANGED` | one endpoint moving, not a disappearance plus an arrival |
| `TLS_VERSION_CHANGED` | `HIGH` when it goes down, `INFO` when it goes up |
| `CIPHER_SUITE_CHANGED` | `HIGH` when weaker (smaller bulk key or weak class) |
| `CERTIFICATE_CHANGED` | `MEDIUM`: rotations are ordinary, replacements are not |
| `TRUST_PATH_CHANGED` | `MEDIUM`: the anchor moved |
| `SNI_CHANGED`, `ALPN_CHANGED` | `LOW`, because a change is still a change |
| `COLLECTION_STATUS_CHANGED` | `MEDIUM`: a collection gap, not a crypto finding |

| Row | Question | Verdict | Probes |
|---|---|---|---|
| `snapshot_is_a_state` | is a snapshot a state, or a record of one collection run? | **PASS** | 6, 0 failing |
| `the_change_list` | is every kind of network change reported, with its evidence? | **PASS** | 6, 0 failing |
| `downgrade_is_not_any_change` | which changes are weakenings, and which are just changes? | **PASS** | 6, 0 failing |
| `the_finding` | what does a NETWORK_CRYPTO_REGRESSION say, and refuse to say? | **PASS** | 8, 0 failing |
| `history` | does the NBOM keep enough history to answer what changed? | **PASS** | 5, 0 failing |

## `snapshot_is_a_state` — PASS

*is a snapshot a state, or a record of one collection run?* (review 18 / 21)

- **PASS** `the-hash-covers-state-not-the-run` — 0ec0541fe066 for three runs of the same state
- **PASS** `a-different-spelling-of-the-same-endpoint-is-the-same-endpoint` — payments.bank.example:443 from the endpoint form
- **PASS** `re-collecting-the-same-fact-does-not-read-as-a-change` — the two snapshots are identical (2 endpoint(s), same hash), so nothing changed
- **PASS** `two-observations-of-one-endpoint-are-refused-not-merged` — payments.bank.example:443 appears twice in one snapshot: two observations of one endpoint must be merged by the collector, not by the diff
- **PASS** `an-endpoint-with-no-host-cannot-be-identified` — a network endpoint needs a host before it can be identified
- **PASS** `the-evidence-ids-travel-outside-the-digest` — evidence is provenance, not state

## `the_change_list` — PASS

*is every kind of network change reported, with its evidence?* (review 21)

- **PASS** `a-listener-that-moved-port-is-one-change-not-two` — ALPN_CHANGED, CERTIFICATE_CHANGED, ENDPOINT_ADDED, PORT_CHANGED, SNI_CHANGED, TRUST_PATH_CHANGED (one arrival is the genuinely new host)
- **PASS** `a-new-listener-is-named-as-a-change-that-needs-an-owner` — a new listener is a change that needs an owner, not a finding about its cryptography
- **PASS** `a-changed-certificate-and-issuer-are-both-reported` — two facts, because a rotation and a new trust anchor are different
- **PASS** `sni-and-alpn-changes-are-low-severity-but-never-silent` — both kept, both LOW
- **PASS** `every-change-carries-the-evidence-from-both-sides` — before and after evidence ids on every row
- **PASS** `two-identical-snapshots-say-so-instead-of-listing-nothing` — the two snapshots are identical (2 endpoint(s), same hash), so nothing changed

## `downgrade_is_not_any_change` — PASS

*which changes are weakenings, and which are just changes?* (review 18)

- **PASS** `the-review-s-example-downgrades-the-protocol` — the negotiated protocol went from TLS1.3 to TLS1.2
- **PASS** `aes-256-to-aes-128-is-a-downgrade-even-on-the-same-version` — the negotiated suite went from TLS_AES_256_GCM_SHA384 to ECDHE-RSA-AES128-GCM-SHA256 (weaker: smaller key)
- **PASS** `the-hash-in-a-suite-name-is-not-a-key-size` — AES128…SHA256 is a 128-bit bulk cipher
- **PASS** `a-move-into-a-classically-weak-class-is-a-downgrade` — the negotiated suite went from TLS_AES_256_GCM_SHA384 to ECDHE-RSA-AES128-SHA (weaker: SHA1)
- **PASS** `an-upgrade-is-a-change-and-not-a-regression` — TLS1.2 → TLS1.3 produces no finding
- **PASS** `collection-status-loss-is-a-gap-not-a-crypto-finding` — an endpoint that stopped answering is reported as a collection gap

## `the_finding` — PASS

*what does a NETWORK_CRYPTO_REGRESSION say, and refuse to say?* (review 18 / 19)

- **PASS** `the-finding-is-one-row-per-endpoint-not-one-per-symptom` — TLS_VERSION_CHANGED, CIPHER_SUITE_CHANGED, CERTIFICATE_CHANGED, TRUST_PATH_CHANGED
- **PASS** `the-severity-is-the-worst-of-its-signals` — HIGH
- **PASS** `both-sides-of-the-evidence-are-kept` — NET-1 → NET-9
- **PASS** `the-finding-is-timestamped-by-the-observation-that-found-it` — 2026-11-02T00:00:00Z
- **PASS** `affected-systems-travel-when-the-mapping-exists` — Payments API, Payments System
- **PASS** `the-finding-states-what-it-does-not-prove` — payments.bank.example:443 weakened between the two snapshots: TLS_VERSION_CHANGED, CIPHER_SUITE_CHANGED, CERTIFICATE_CHANGED, TRUST_PATH_CHANGED. This is a reason to investigate, not a conclusion
- **PASS** `nothing-here-calls-it-an-attack` — a downgrade is a reason to investigate
- **PASS** `the-next-action-is-specific-to-the-signal` — confirm the protocol policy on the terminating device and whether the weaker version was intended

## `history` — PASS

*does the NBOM keep enough history to answer what changed?* (review 21)

- **PASS** `a-timeline-compares-each-consecutive-pair` — 4 snapshot(s), 3 period(s), 2 with changes; 1 NETWORK_CRYPTO_REGRESSION finding(s)
- **PASS** `a-period-with-no-change-is-marked-identical` — day 2 → day 3 changed nothing
- **PASS** `regressions-are-counted-across-the-history` — 1 finding(s), worst HIGH
- **PASS** `a-restoration-is-not-silently-a-regression` — day 3 → day 4 recovered the protocol and produced no finding
- **PASS** `the-summary-says-whether-anything-moved-the-wrong-way` — 2 change(s) across 2 kind(s) between 2026-11-01T00:00:00Z and 2026-11-02T00:00:00Z: CIPHER_SUITE_CHANGED, TLS_VERSION_CHANGED; 0 endpoint(s) unchanged; 1 NETWORK_CRYPTO_REGRESSION finding(s), worst HIGH; each names what is not proven

## What this does not prove

- a snapshot is what the collector saw. An endpoint that was not probed is absent from both snapshots, so its absence is not a change — the coverage matrix from guide 153 says whether the two runs are comparable
- the digest covers negotiated state, not the endpoint's capability set. A device that started offering TLS 1.0 while still negotiating TLS 1.3 produces no change here until something enumerates it (guide 154)
- a certificate change is reported as a change with medium severity, because rotations are ordinary. The finding says to confirm it with the PKI owner rather than deciding that it is suspicious
- affected systems come from a mapping somebody supplied. Without it the finding names the endpoint and nothing else, which is the honest bound
- two snapshots do not make a baseline. A change between the first two runs of a new collector is as likely to be collector configuration as device configuration
- the severity ladder is a heuristic over protocol order, bulk key size and a list of weak suite tokens. It is deliberately explainable rather than scored, so a reviewer can disagree with one row without distrusting the rest
