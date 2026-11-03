# TechBOM is a projection of evidenced relationships

`cryptoscan.cbom-techbom-guide/1` · generated 2026-11-03T01:27:27.756904+00:00 · **7 pass · 0 partial · 0 fail** · 35 probes

A TechBOM is not `SBOM + CBOM + HBOM + NBOM + VBOM` in one file. It is a graph of typed assets whose every edge is a claim carrying a basis, a confidence class and an evidence id.

```
EVIDENCE  →  CANONICAL ESTATE  →  TECHBOM (a projection)

BUSINESS_SYSTEM → APPLICATION → SERVICE → CONTAINER → IMAGE
                            → PACKAGE → CRYPTO_LIBRARY → CRYPTO_ASSET
APPLICATION → NETWORK_ENDPOINT → LOAD_BALANCER → API_GATEWAY → APPLICATION
ENDPOINT → CERTIFICATE → PUBLIC_KEY → ALGORITHM → CERTIFICATE_AUTHORITY → HSM
APPLICATION → HSM → KEY_REFERENCE
APPLICATION → VENDOR_PRODUCT → VENDOR
SOURCE → BUILD → ARTIFACT → SBOM → IMAGE → DEPLOYMENT → POD → PROCESS
```

34 technology asset(s) across 31 kind(s) and 34 evidenced relationship(s); 9 edge(s) not proven; 0 claim(s) refused

Completeness: **PARTIAL** — PARTIAL: 6 kind(s) complete, 5 short, 2 stated gap(s), 20 unmeasured

| kind | observed | expected | verdict |
|---|---|---|---|
| `ALGORITHM` | 1 | — | UNMEASURED |
| `API_GATEWAY` | 1 | — | UNMEASURED |
| `APPLICATION` | 2 | 2 | COMPLETE |
| `ARTIFACT` | 1 | — | UNMEASURED |
| `BUILD` | 1 | — | UNMEASURED |
| `BUSINESS_SYSTEM` | 1 | 1 | COMPLETE |
| `CERTIFICATE` | 1 | 2 | PARTIAL |
| `CERTIFICATE_AUTHORITY` | 1 | — | UNMEASURED |
| `CONTAINER` | 1 | 2 | PARTIAL |
| `CRYPTO_ASSET` | 3 | 4 | PARTIAL |
| `CRYPTO_LIBRARY` | 1 | — | UNMEASURED |
| `DEPLOYMENT` | 1 | — | UNMEASURED |
| `FIRMWARE` | 1 | — | UNMEASURED |
| `HOST` | 1 | — | UNMEASURED |
| `HSM` | 1 | 2 | PARTIAL |
| `IMAGE` | 1 | — | UNMEASURED |
| `KEY_REFERENCE` | 1 | — | UNMEASURED |
| `LOAD_BALANCER` | 1 | 1 | COMPLETE |
| `NETWORK_ENDPOINT` | 1 | 1 | COMPLETE |
| `PACKAGE` | 1 | 3 | PARTIAL |
| `PHYSICAL_SERVER` | 1 | — | UNMEASURED |
| `POD` | 1 | — | UNMEASURED |
| `PROCESS` | 1 | — | UNMEASURED |
| `PUBLIC_KEY` | 1 | — | UNMEASURED |
| `SBOM` | 1 | — | UNMEASURED |
| `SERVICE` | 1 | 1 | COMPLETE |
| `SOURCE` | 1 | — | UNMEASURED |
| `TPM` | 1 | — | UNMEASURED |
| `VENDOR` | 1 | 1 | COMPLETE |
| `VENDOR_PRODUCT` | 1 | — | UNMEASURED |
| `VM` | 1 | — | UNMEASURED |

Gaps stated by the source:

- `HSM` — 1 HSM collector unavailable (vendor API offline)
- `PACKAGE` — payments-batch container not reachable; its manifest was not collected

| chain | relationships |
|---|---|
| `CERTIFICATE` | 3 |
| `HARDWARE` | 5 |
| `KEYS` | 2 |
| `NETWORK` | 5 |
| `RUNTIME` | 8 |
| `SOFTWARE` | 9 |
| `VENDOR` | 2 |

| confidence | relationships |
|---|---|
| `CONFIGURED` | 18 |
| `IMPORTED` | 6 |
| `OBSERVED` | 7 |
| `VENDOR_DECLARED` | 3 |

| Row | Question | Verdict | Probes |
|---|---|---|---|
| `assets` | is there an explicit asset model with identity that survives? | **PASS** | 5, 0 failing |
| `claims` | is a relationship a claim with a basis, or a proximity guess? | **PASS** | 5, 0 failing |
| `boundaries` | do the layers stay apart instead of standing in for each other? | **PASS** | 5, 0 failing |
| `completeness` | is coverage explicit, with a denominator and a reason per gap? | **PASS** | 5, 0 failing |
| `reconciliation` | does a disagreement survive into the report instead of being lost? | **PASS** | 5, 0 failing |
| `radius_and_time` | can the bom answer what breaks, and what changed? | **PASS** | 5, 0 failing |
| `projection` | is TechBOM a projection, and does it know what it cannot say? | **PASS** | 5, 0 failing |

## `assets` — PASS

*is there an explicit asset model with identity that survives?* (review techbom / 6)

- **PASS** `an-asset-carries-a-stable-key-a-readable-id-and-its-evidence` — TECH-APP-001 · APPLICATION:payments api:production · 2 evidence id(s)
- **PASS** `the-estate-produces-every-layer-of-the-model` — 34 assets across 31 kinds
- **PASS** `an-asset-with-no-evidence-is-refused` — an asset with no evidence id is a claim, not an asset
- **PASS** `two-assets-with-the-same-identity-are-refused-not-merged` — the first description is kept and the second refused
- **PASS** `ids-are-deterministic-for-one-estate-and-not-durable` — same estate, same ids; anything durable keys on `key`

## `claims` — PASS

*is a relationship a claim with a basis, or a proximity guess?* (review techbom / 5 and 22)

- **PASS** `every-relationship-carries-a-basis-a-class-and-an-evidence-id` — 34 claim(s), each with its basis printed
- **PASS** `co-occurrence-is-refused-by-name` — two assets in one scan is proximity, not a relationship
- **PASS** `the-other-proximity-bases-are-refused-too` — same-scan · proximity · name-similarity · assumption
- **PASS** `an-edge-may-not-be-stronger-than-its-evidence` — a vendor datasheet stays VENDOR_DECLARED however it is labelled
- **PASS** `an-inference-must-name-its-rule-so-it-can-be-argued-with` — an unnamed inference is an assumption with better manners

## `boundaries` — PASS

*do the layers stay apart instead of standing in for each other?* (review techbom / 9, 10, 12, 13, 22)

- **PASS** `a-certificate-does-not-prove-the-application-s-crypto` — the algorithm is reached through the key that carries it
- **PASS** `a-network-hop-does-not-reach-into-application-internals` — a container is scheduled on a host; an endpoint is not
- **PASS** `a-runtime-crypto-use-may-not-be-evidenced-by-a-manifest` — RUNTIME_OBSERVED, STATIC_OBSERVED and CERTIFICATE_OBSERVED stay apart
- **PASS** `an-edge-to-an-undeclared-node-is-refused-not-invented` — an edge may only join assets the estate declares
- **PASS** `the-seven-chains-are-modelled-and-distinguishable` — CERTIFICATE, HARDWARE, KEYS, NETWORK, RUNTIME, SOFTWARE, VENDOR

## `completeness` — PASS

*is coverage explicit, with a denominator and a reason per gap?* (review techbom / 16)

- **PASS** `the-overall-verdict-is-partial-and-says-so` — PARTIAL: 6 kind(s) complete, 5 short, 2 stated gap(s), 20 unmeasured
- **PASS** `every-kind-is-measured-against-a-denominator` — HSM 1 / 2, coverage 0.50
- **PASS** `each-gap-carries-the-reason-a-person-would-ask-for` — 1 HSM collector unavailable (vendor API offline) · payments-batch container not reachable; its manifest was not collected
- **PASS** `a-kind-with-no-denominator-is-unmeasured-not-complete` — a count nobody can divide by is not coverage
- **PASS** `an-asset-count-is-never-printed-without-its-relationships-and-verdict` — 34 technology asset(s) across 31 kind(s) and 34 evidenced relationship(s); 9 edge(s) not proven; 0 claim(s) refused

## `reconciliation` — PASS

*does a disagreement survive into the report instead of being lost?* (review techbom / 18)

- **PASS** `four-sources-three-agreeing-is-still-a-conflict` — Payments API openssl version: 2 values across 4 source(s) — kept as a conflict, because choosing one would hide which layer disagrees
- **PASS** `the-conflict-is-left-unresolved-instead-of-picking-a-winner` — observed 3.0.11 · artifact 3.0.13 · vendor 3.0.13 · resolution UNRESOLVED
- **PASS** `agreement-is-reported-and-not-called-verification` — Payments API runtime: OpenJDK 21 from 2 source(s); agreement is not verification
- **PASS** `a-proximity-source-cannot-settle-an-attribute` — a scan-time co-occurrence is not a statement about the attribute
- **PASS** `the-report-says-what-it-cannot-decide` — 2 stated limit(s)

## `radius_and_time` — PASS

*can the bom answer what breaks, and what changed?* (review techbom / 15, 19, 20)

- **PASS** `a-blast-radius-is-proven-for-applications-and-declared-above-them` — the application is proven by config and capture; the business system above it is only an import
- **PASS** `reachability-is-not-the-same-as-impact` — 6 dependent(s), each with its hop count
- **PASS** `a-migration-blocker-is-named-where-it-sits` — a migration that replaces an algorithm on this path has to change this device or its firmware
- **PASS** `a-declared-edge-is-not-counted-as-a-proven-dependency-path` — VENDOR_DECLARED paths land in `possible`, not in `reachable`
- **PASS** `a-version-change-is-a-named-event-with-both-values` — openssl: 3.0.13 → 3.0.11

## `projection` — PASS

*is TechBOM a projection, and does it know what it cannot say?* (review techbom / 17)

- **PASS** `the-document-declares-itself-a-projection` — evidence → canonical estate → TechBOM, never the other way round
- **PASS** `a-techbom-cannot-be-fed-back-in-as-its-own-source` — no second source of truth, by construction
- **PASS** `the-summary-reports-confidence-not-just-a-count` — {"CONFIGURED": 18, "IMPORTED": 6, "OBSERVED": 7, "VENDOR_DECLARED": 3}
- **PASS** `a-bom-that-loses-its-evidence-is-refused-at-the-asset` — the asset model is not the place a fact arrives unbacked
- **PASS** `the-report-states-what-it-does-not-prove` — 5 stated limit(s)

## What this does not prove

- the estate is a fixture, not a bank: every asset and edge here is the shape of the argument, and none of it is an observation of a real network
- an edge is in the graph because a source asserted it. A relationship nobody recorded is missing, and this model does not infer it from proximity
- completeness is only as honest as its denominator, which comes from authorisation and the scan plan, not from this module
- a blast radius is exposure, not impact: whether a dependent system actually breaks is the owner's assessment
- reconciliation preserves a conflict and cannot resolve it — resolution needs a probe at the place the value matters
- readable ids renumber when the estate changes, so only `key` may be used as a durable reference
