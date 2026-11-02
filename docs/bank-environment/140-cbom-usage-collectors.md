# The collectors that make the usage profile mean something

`cryptoscan.cbom-usage-collectors-guide/1` · generated 2026-11-02T17:46:21.801503+00:00 · **5 pass · 0 partial · 0 fail** · 27 probes

Guide 139 built the evidence model and said what it could not do: nothing fed it. This artifact measures the collectors — pure projections from rows the platform already stores.

1. **Network** — a completed handshake becomes algorithm facts (`TLS_AES_256_GCM_SHA384` → AES-256-GCM bulk + SHA-384 hash), a certificate record that proves no application operation, and one hop attributed to the endpoint that terminated it. An unprobed endpoint produces a refusal, not an absence.
2. **Static** — a stored finding with its evidence row is an observation; without one it is refused, because an inventory entry is not a record that something was seen.
3. **Runtime** — an operation needs its name, its algorithm, an evidence id and a timestamp before it counts.
4. **Profiles** — collected evidence becomes one profile per algorithm, with the layers that observed it, every evidence id, and the layers that have **no collector at all** named explicitly so `NOT_OBSERVED` cannot be read as `not used`.

| Row | Question | Verdict | Probes |
|---|---|---|---|
| `cipher_suites` | can a negotiated suite be read as algorithm facts? | **PASS** | 5, 0 failing |
| `network_source` | does the network scanner's own output become CBOM evidence? | **PASS** | 6, 0 failing |
| `static_source` | does a stored finding carry the evidence that makes it one? | **PASS** | 4, 0 failing |
| `runtime_source` | does a runtime row have to name the operation to count? | **PASS** | 6, 0 failing |
| `collect_to_profile` | does collected evidence become a CBOM asset's answer? | **PASS** | 6, 0 failing |

## `cipher_suites` — PASS

*can a negotiated suite be read as algorithm facts?* (review 8)

- **PASS** `a-tls13-suite-names-its-bulk-algorithm-and-hash` — {"AES-256-GCM": "BULK", "SHA-384": "HASH"}
- **PASS** `the-bulk-algorithm-carries-its-parameters` — {"key_size": 256, "mode": "GCM"}
- **PASS** `a-tls12-suite-adds-signature-and-key-exchange` — {"AES-128-GCM": "BULK", "ECDHE": "KEY_EXCHANGE", "RSA": "SIGNATURE", "SHA-256": "HASH"}
- **PASS** `an-unknown-suite-invents-nothing` — a suite outside the table produces no fact rather than a guess
- **PASS** `the-longest-token-wins` — CHACHA20_POLY1305 is not mistaken for AES or SHA alone

## `network_source` — PASS

*does the network scanner's own output become CBOM evidence?* (review 8 / 9)

- **PASS** `a-completed-handshake-becomes-network-evidence` — 2 algorithm fact(s) from 1 completed handshake(s)
- **PASS** `an-unprobed-endpoint-observes-nothing` — no handshake completed, so nothing was negotiated
- **PASS** `a-handshake-with-no-suite-is-not-algorithm-evidence` — a completed handshake with no negotiated suite is not evidence of an algorithm
- **PASS** `network-evidence-without-a-run-or-id-is-refused` — an unfalsifiable network fact is not stored
- **PASS** `a-probe-yields-a-certificate-record-that-proves-no-operation` — ECDSA / ECDSA-SHA256 describes the certificate on payments.bank.example:443. A certificate's public key does not prove the application behind it performs that algorithm
- **PASS** `a-probe-yields-one-hop-attributed-to-its-endpoint` — 1 hop(s) with the terminating endpoint named

## `static_source` — PASS

*does a stored finding carry the evidence that makes it one?* (review 5 / 6)

- **PASS** `a-finding-with-its-evidence-row-is-a-static-observation` — 1 static observation(s) from 1 evidence row(s)
- **PASS** `the-findings-parameters-travel-with-it` — {"key_size": 256, "mode": "GCM"}
- **PASS** `a-finding-without-an-evidence-row-is-refused` — the finding has no evidence row, so it is an inventory entry and not an observation
- **PASS** `a-finding-with-no-algorithm-is-refused` — an evidence row with no algorithm names nothing

## `runtime_source` — PASS

*does a runtime row have to name the operation to count?* (review 7 / 21)

- **PASS** `a-recorded-operation-is-runtime-evidence` — 1 recorded crypto operation(s)
- **PASS** `a-runtime-row-without-evidence-id-is-a-claim` — a runtime observation is missing evidence_id
- **PASS** `a-runtime-row-without-observed-at-is-a-claim` — a runtime observation is missing observed_at
- **PASS** `a-runtime-row-without-operation-is-a-claim` — a runtime observation is missing operation
- **PASS** `a-runtime-row-without-algorithm-is-a-claim` — a runtime observation is missing algorithm
- **PASS** `a-process-with-no-operation-is-not-runtime-evidence` — naming a process is not recording an operation

## `collect_to_profile` — PASS

*does collected evidence become a CBOM asset's answer?* (review 4 / 20)

- **PASS** `network-alone-is-high-and-names-the-missing-layers` — 2 algorithm(s) from 2 evidence event(s); nothing has observed config, runtime, static for every asset, which is an absent collector and not an absent algorithm
- **PASS** `three-sources-reach-very-high-with-every-id-kept` — runtime and network both observed this asset, which are independent collection mechanisms
- **PASS** `the-profile-keeps-roles-and-locations` — roles=['BULK'], locations=['payments-api[9182]', 'payments.bank.example:443', 'src/tls.py:12']
- **PASS** `an-sbom-fact-stays-a-candidate-in-the-collected-profile` — AES-256: candidate only; the evidence says it could be used, which is a capability and not an invocation
- **PASS** `the-collect-routes-are-typed-and-mounted` — POST /cbom/usage/collect and GET /cbom/usage/network
- **PASS** `the-network-route-reads-stored-scan-runs` — the network half comes from rows, not from the request body

## What this does not prove

- the network collector reads what the prober negotiated. It cannot see a listener the prober never reached, and an unreached endpoint is refused rather than recorded as absent cryptography
- cipher-suite parsing is a table, not a spec implementation. A suite outside it produces no fact rather than a guess, which means a new suite looks like missing evidence until the table is extended
- the static collector joins stored findings to their evidence rows. If the link is absent the finding is refused, which is correct but means a broken ingestion path shrinks the profile instead of flagging the ingestion
- the runtime collector is fed by whatever records crypto operations. The platform does not yet trace a process, so a runtime row is only as good as the agent that wrote it — the collector's job is to insist on the operation, the id and the time, not to produce them
- profiles are grouped by algorithm name, not by call site: two applications using AES-256-GCM in different ways share one profile unless the caller separates them
- a layer with no collector is reported as unobserved_layers. That is honest, but it is still an absence the console must render as unknown rather than as safe
