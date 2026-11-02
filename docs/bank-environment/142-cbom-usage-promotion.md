# From "this library can do AES" to "this is an asset"

`cryptoscan.cbom-usage-promotion-guide/1` · generated 2026-11-02T18:31:44.015850+00:00 · **4 pass · 0 partial · 0 fail** · 20 probes

The review's item 6: a library that supports AES must not mint `AES-256 USED`. `cbom.promotion` implements the chain the review asks for — capability → candidate → evidence promotes — and makes the boundary visible in the document:

1. **A candidate is not an asset.** Only an observing class promotes one; everything else is returned as a candidate and deliberately kept out of the CBOM.
2. **Each asset says how strong its evidence is.** `CAPABILITY` < `STATIC`/`CONFIGURED` < `RUNTIME`/`NETWORK` < `VERIFIED` (both independent mechanisms agreed).
3. **The document stays CycloneDX.** Standard fields carry the algorithm; every platform claim is a `cryptoscan:` property, with the evidence ids attached.
4. **An unattributable component is refused**, not promoted quietly.

| Row | Question | Verdict | Probes |
|---|---|---|---|
| `ladder` | does a promotion level mean what it says? | **PASS** | 5, 0 failing |
| `capability_is_not_an_asset` | does an SBOM still mint assets it cannot prove? | **PASS** | 6, 0 failing |
| `the_document` | is the produced CBOM a claim or a capability list? | **PASS** | 6, 0 failing |
| `api_exposure` | can an operator produce a defensible CBOM? | **PASS** | 3, 0 failing |

## `ladder` — PASS

*does a promotion level mean what it says?* (review 13 / 17)

- **PASS** `a-capability-is-the-bottom-of-the-ladder` — IMPORTED and VENDOR_DECLARED both earn CAPABILITY and no more
- **PASS** `static-and-configured-sit-above-capability` — the code or the configuration was seen to select it
- **PASS** `runtime-and-network-together-are-verified` — two independent mechanisms, not one louder one
- **PASS** `the-strongest-class-decides-the-level` — the ladder is a max, not an average
- **PASS** `no-evidence-is-no-level` — an asset with no evidence is not promoted at any level

## `capability_is_not_an_asset` — PASS

*does an SBOM still mint assets it cannot prove?* (review 6 / 13 / 21)

- **PASS** `a-library-with-no-observations-promotes-nothing` — 0 CBOM asset(s) promoted from evidence, 4 candidate(s) left out of the document; a capability is not an invocation
- **PASS** `only-the-observed-algorithm-is-promoted` — 1 CBOM asset(s) promoted from evidence, 3 candidate(s) left out of the document; a capability is not an invocation
- **PASS** `an-imported-event-cannot-promote` — the document that declared the capability is not evidence of use
- **PASS** `a-component-with-no-evidence-id-is-refused` — the component has no evidence id, so its capabilities cannot be attributed to a document
- **PASS** `evidence-for-another-algorithm-promotes-nothing-else` — the matching is by algorithm, not by component
- **PASS** `a-refused-event-does-not-promote` — a runtime claim with no evidence id promotes nothing

## `the_document` — PASS

*is the produced CBOM a claim or a capability list?* (review 6 / 20)

- **PASS** `only-promoted-assets-are-components` — 2 component(s), 2 candidate(s)
- **PASS** `candidates-are-counted-in-metadata-not-written-as-components` — {"cryptoscan:candidates_excluded": "2", "cryptoscan:promoted_assets": "2", "cryptoscan:promotion_schema": "cryptoscan.cbom-promotion/1", "cryptoscan:promotion_statement": "2 CBOM asset(s) promoted from evidence, 2 candidate(s) left out of the document; a capability is not an invocation"}
- **PASS** `a-promoted-asset-is-a-cyclonedx-cryptographic-asset` — crypto/algorithm/aes-256-gcm
- **PASS** `platform-claims-live-in-properties-not-standard-fields` — cryptoscan:confidence, cryptoscan:evidence_id, cryptoscan:observed_classes, cryptoscan:promotion_level, cryptoscan:usage
- **PASS** `the-evidence-that-earned-the-asset-travels-with-it` — ["RUNTIME-1"]
- **PASS** `the-inventory-says-what-the-document-may-be-read-as` — 2 algorithm(s) in the document across 2 promotion level(s); 2 candidate(s) are not in it

## `api_exposure` — PASS

*can an operator produce a defensible CBOM?* (review 6)

- **PASS** `the-promote-route-exists-and-is-typed` — POST /cbom/promote
- **PASS** `the-route-returns-document-inventory-and-refusals` — promotion + inventory + document in one answer
- **PASS** `the-route-uses-the-promotion-module` — one implementation, not a copy in the router

## What this does not prove

- promotion is only as good as the collector that reported the observation. The document says VERIFIED when runtime and network agreed; it cannot say whether both collectors were looking at the same deployment
- the algorithm list a component declares is the caller's. This module refuses an unattributable component, but it cannot verify that openssl really supports every algorithm the SBOM claims
- a candidate that is never promoted stays a candidate forever. That is honest and also a blind spot: an algorithm used in a path no collector watches is invisible in the document rather than present-but-unproven
- the produced document is CycloneDX 1.5 and is not validated against the 1.6 schema here; the platform's own properties are namespaced, but a strict consumer may still reject them
- level is per algorithm, not per call site: two applications sharing one algorithm produce two assets with the same name unless the caller separates them by component
- promotion does not decide migration or risk. A VERIFIED weak algorithm is still weak; that judgement belongs to the assessment and PQC engines, not to this ladder
