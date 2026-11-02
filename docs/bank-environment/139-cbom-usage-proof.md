# What a CBOM asset may claim

`cryptoscan.cbom-usage-proof-guide/1` · generated 2026-11-02T17:42:06.149489+00:00 · **6 pass · 0 partial · 0 fail** · 34 probes

The review's central point is that `AES-256-GCM / confidence HIGH` is eight claims wearing one line. This artifact measures the code that pulls them apart:

1. **Capability is not usage.** A library that supports an algorithm yields candidates, never assets, and a declared fact can never promote itself to an observation.
2. **The layer is named.** static, config, runtime and network are reported per asset with the evidence ids that support each, and confidence follows a stated ladder — imported `LOW`, static `MEDIUM`, runtime or network `HIGH`, runtime *and* network `VERY_HIGH`.
3. **Disagreement is the finding.** Two observing sources that disagree produce a conflict and no asserted value; the imported claim is kept and labelled.
4. **Termination, certificates and HSM are their own answers.** A TLS chain is one relationship per hop; a certificate proves nothing about the application's operations; HSM capability, configured key and recorded operation are three steps.
5. **A partial estate cannot be quoted as a total.** `12 discovered, 62/100 inspected (62%), PARTIAL` — and only `COMPLETE` makes the count a total.

| Row | Question | Verdict | Probes |
|---|---|---|---|
| `evidence_classes` | does every claim carry a class, and can a class lie? | **PASS** | 5, 0 failing |
| `usage_profile` | can an asset say which layer observed it, and why the confidence? | **PASS** | 8, 0 failing |
| `no_false_attribution` | does an SBOM mint crypto assets it cannot prove? | **PASS** | 3, 0 failing |
| `conflicts` | does the CBOM collapse disagreeing sources into one version? | **PASS** | 5, 0 failing |
| `tls_certificates_keys` | is termination, certificate crypto and HSM use kept apart? | **PASS** | 8, 0 failing |
| `coverage_and_api` | does the CBOM state how much of the estate it speaks for? | **PASS** | 5, 0 failing |

## `evidence_classes` — PASS

*does every claim carry a class, and can a class lie?* (review 5 / 21)

- **PASS** `the-nine-classes-are-the-vocabulary` — OBSERVED, STATIC_OBSERVED, RUNTIME_OBSERVED, NETWORK_OBSERVED, CONFIGURED, IMPORTED, VENDOR_DECLARED, INFERRED, UNKNOWN
- **PASS** `an-invented-class-is-refused-not-mapped` — only the closed vocabulary is accepted
- **PASS** `an-observation-without-an-evidence-id-is-refused` — an observation nobody can point at is not evidence
- **PASS** `an-imported-fact-cannot-promote-itself-to-runtime` — runtime claims RUNTIME_OBSERVED, but the event is IMPORTED; it cannot become an observation without independent evidence
- **PASS** `a-layer-implies-its-class` — runtime -> RUNTIME_OBSERVED, sbom -> IMPORTED

## `usage_profile` — PASS

*can an asset say which layer observed it, and why the confidence?* (review 4 / 17)

- **PASS** `sbom-capability-is-low-confidence-and-not-usage` — AES-256-GCM (key_size=256, mode=GCM): candidate only; the evidence says it could be used, which is a capability and not an invocation
- **PASS** `a-static-observation-is-medium-and-observed` — static or configuration evidence places the algorithm here, but nothing watched it run
- **PASS** `a-runtime-observation-is-high-and-carries-its-evidence` — runtime observed the operation
- **PASS** `runtime-and-network-together-are-very-high` — runtime and network both observed this asset, which are independent collection mechanisms
- **PASS** `the-reviews-four-layer-view-is-produced` — {"static": true, "config": true, "runtime": true, "network": true}
- **PASS** `evidence-about-another-algorithm-does-not-count` — a runtime RSA observation says nothing about AES-256-GCM
- **PASS** `no-evidence-is-unknown-not-observed-as-clean` — no evidence has been collected for this asset
- **PASS** `a-profile-of-nothing-is-refused` — an asset needs an algorithm

## `no_false_attribution` — PASS

*does an SBOM mint crypto assets it cannot prove?* (review 6 / 21)

- **PASS** `a-librarys-support-list-becomes-candidates-not-assets` — 5 candidate algorithm(s) from openssl's capability. A library that supports an algorithm is not an application that calls it, so none of these is a usage claim until an observing layer reports the operation
- **PASS** `a-candidate-carries-the-evidence-that-would-promote-it` — STATIC_OBSERVED, RUNTIME_OBSERVED, NETWORK_OBSERVED
- **PASS** `only-new-evidence-promotes-a-candidate-to-usage` — the same asset with a runtime observation is usage; the candidate was not used as evidence

## `conflicts` — PASS

*does the CBOM collapse disagreeing sources into one version?* (review 16)

- **PASS** `every-source-is-kept-including-the-declarations` — IMPORTED, OBSERVED, RUNTIME_OBSERVED, VENDOR_DECLARED
- **PASS** `disagreeing-observers-produce-a-named-conflict` — version has 2 observed values across 2 source(s); the observation layers disagree and the disagreement is the finding
- **PASS** `a-conflicted-field-asserts-no-value` — no single value is asserted: the sources conflict
- **PASS** `agreeing-observers-resolve-to-the-strongest-claim` — 3.0.13 from runtime (RUNTIME_OBSERVED), the strongest available claim
- **PASS** `an-imported-claim-does-not-conflict-with-an-observation` — a declaration is not a second observation

## `tls_certificates_keys` — PASS

*is termination, certificate crypto and HSM use kept apart?* (review 8-13 / 21)

- **PASS** `a-tls-chain-is-three-relationships-not-one-attribute` — 3 TLS relationship(s) across 3 endpoint(s); each hop is attributed to the interface that terminated it, not to the application behind it
- **PASS** `each-hop-is-attributed-to-the-endpoint-that-terminated-it` — attribution is to the observed endpoint
- **PASS** `a-hop-without-evidence-or-endpoint-is-refused` — an unobserved hop is not a relationship
- **PASS** `a-certificate-is-its-own-category-and-proves-no-operation` — ECDSA / ECDSA-SHA256 describes the certificate on payments.bank.example:443. A certificate's public key does not prove the application behind it performs that algorithm
- **PASS** `key-metadata-is-a-reference-and-never-material` — HSM://partition-01/key/PAY-SIGN-001, private_material=NOT STORED
- **PASS** `a-private-key-in-a-cbom-is-an-error` — the record is refused, not sanitised
- **PASS** `hsm-capability-configured-key-and-operation-are-three-answers` — VENDOR_DECLARED -> CONFIGURED -> RUNTIME_OBSERVED as evidence accumulates
- **PASS** `an-hsm-operation-without-evidence-is-refused` — the only evidence of an operation is a record of it

## `coverage_and_api` — PASS

*does the CBOM state how much of the estate it speaks for?* (review 18 / 19)

- **PASS** `a-partial-estate-cannot-quote-its-count-as-a-total` — 12 crypto asset(s) discovered; 62/100 application(s) inspected (62%); the count is what was discovered, not what exists
- **PASS** `the-statement-says-discovered-not-exists` — the count is annotated with its coverage
- **PASS** `only-a-complete-inventory-is-a-total` — COMPLETE is the only quotable state; NONE and UNKNOWN are named
- **PASS** `the-four-routes-exist-and-are-mounted` — POST /cbom/{usage,reconcile,tls-paths,hsm-evidence}
- **PASS** `the-schema-key-survives-the-response-model` — the report's `schema` key is kept by the typed model

## What this does not prove

- the module classifies evidence, it does not collect it. A caller that labels a vendor's PDF as RUNTIME_OBSERVED with an invented evidence id defeats it, which is why the collecting layer must own the class rather than the request body
- confidence is a ladder over classes present, not a probability: two agreeing observations are VERY_HIGH because the mechanisms are independent, not because the answer has been tested against ground truth
- runtime and network evidence do not yet have first-class collectors feeding this profile. The contract, the ladder and the API exist so that they can, and until they do every asset's runtime and network rows are genuinely NOT_OBSERVED
- a TLS hop is attributed to the endpoint that terminated it. Nothing here proves the traffic before and after a terminator is the same connection, which is why the hops stay separate rather than being joined into a path with one verdict
- certificate parsing is the collector's job: this record keeps the fields it is given, and an incomplete certificate is reported as incomplete rather than read as a weaker certificate
- PQC status is deliberately absent. CBOM says what crypto exists; migration priority, quantum risk and the assessment itself belong to the assessment engine, which already has its own vocabulary
