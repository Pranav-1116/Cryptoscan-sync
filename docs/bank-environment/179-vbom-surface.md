# The VBOM surface: catalogue, envelope, export and live merge

`cryptoscan.vbom-surface-guide/1` · generated 2026-11-03T11:07:37Z · **13 pass · 0 partial · 0 fail** · 45 probes

**13 of 13 points of surface behaviour hold, across 45 probes; 29 question(s) over 28 section(s), 21 exported component(s) in a document the official schema accepts**

```
payload + collectors → one estate → the graph → { catalogue, answers, CycloneDX }
                                      ↓
                         ok / code / statement, never an exception
```

| Surface | Value |
|---|---|
| questions | 29 |
| sections | 28 |
| surface codes | MISSING_PARAMETER, UNKNOWN_PARAMETER, UNKNOWN_QUESTION |
| exported components | 21 (11 top-level, 10 nested) |
| exporters' dependencies | 6 |
| relation properties | 21 |
| suppliers | 3 |
| schema valid | True |
| live transports | registry, scan |

| Level | Nodes |
|---|---|
| `vendor` | 3 |
| `product` | 3 |
| `release` | 4 |
| `firmware` | 4 |
| `package` | 2 |
| `asset` | 4 |
| `application` | 2 |
| `crypto` | 7 |
| `runtime` | 2 |
| `system` | 2 |

| Applicability | Declaration/deployment pairs |
|---|---|
| `DEPLOYMENT_UNVERIFIED` | 6 |
| `MATCHED` | 4 |
| `VERSION_MISMATCH` | 2 |

| Row | Section | Question | Verdict | Probes |
|---|---|---|---|---|
| `VBS-01` | catalogue | every answer the module has is a question the surface can be asked | **PASS** | 5, 0 failing |
| `VBS-02` | envelope | a question, a refusal and a mistake are three different answers | **PASS** | 4, 0 failing |
| `VBS-03` | refusals | the graph saying no is an answer the API returns as 200 | **PASS** | 3, 0 failing |
| `VBS-04` | assessment | one payload in, one estate and a set of answers out | **PASS** | 4, 0 failing |
| `VBS-05` | export | the vendor graph leaves as CycloneDX 1.6 or it does not leave | **PASS** | 4, 0 failing |
| `VBS-06` | vendor-is-a-supplier | CycloneDX has no vendor type and this does not invent one | **PASS** | 3, 0 failing |
| `VBS-07` | composition | a release belongs to a product, so it is nested in it | **PASS** | 3, 0 failing |
| `VBS-08` | dependencies | dependsOn is an installation contract, not an evidence list | **PASS** | 3, 0 failing |
| `VBS-09` | confidence | the document says how strongly each row is believed | **PASS** | 3, 0 failing |
| `VBS-10` | live | a collector and a vendor payload describe the same estate | **PASS** | 4, 0 failing |
| `VBS-11` | summary | the first three numbers, refusals included | **PASS** | 3, 0 failing |
| `VBS-12` | purity | the surface answers about what it was given and reads nothing else | **PASS** | 3, 0 failing |
| `VBS-13` | http | the surface is reachable, or it is a library nobody calls | **PASS** | 3, 0 failing |

## What was refused while building the graph

- `ASSET_WITHOUT_PRODUCT` — UNMAPPED-HSM: an asset that names no product cannot be attributed to a vendor, and an unattributed asset is a vendor dependency nobody owns

## `VBS-01` — PASS

*every answer the module has is a question the surface can be asked* (guide 179, catalogue)

- **PASS** `the-catalogue-covers-every-public-reader` — 36 public function(s), 29 question(s), 7 documented as not questions
- **PASS** `no-question-is-listed-twice` — 29 row(s)
- **PASS** `every-question-cites-a-section-and-a-sentence` — 28 distinct section(s)
- **PASS** `each-question-says-where-its-answer-comes-from` — argument, payload, projection
- **PASS** `the-required-parameters-come-from-the-signatures` — vendor_products needs a vendor; twin needs nothing

## `VBS-02` — PASS

*a question, a refusal and a mistake are three different answers* (guide 179, envelope)

- **PASS** `an-answered-question-carries-the-readers-own-statement` — the envelope repeats the reader's sentence rather than inventing one
- **PASS** `an-unknown-question-is-refused-with-a-code` — UNKNOWN_QUESTION: which_vendor_is_worst is not a question this surface answers; see the 
- **PASS** `an-unlisted-parameter-is-refused-not-dropped` — UNKNOWN_PARAMETER: vendor is not a parameter of twin; it takes none
- **PASS** `a-missing-required-parameter-is-refused-before-the-reader-runs` — MISSING_PARAMETER: product_releases needs product; product was not given

## `VBS-03` — PASS

*the graph saying no is an answer the API returns as 200* (guide 179, refusals)

- **PASS** `an-unknown-vendor-is-the-modules-code-not-the-surfaces` — UNKNOWN_NODE: Nobody is not a node in this projection
- **PASS** `a-question-with-no-subject-keeps-the-readers-own-code` — NO_QUERY: a software chain starts at a vendor or a product
- **PASS** `the-surface-own-vocabulary-is-three-codes` — MISSING_PARAMETER, UNKNOWN_PARAMETER, UNKNOWN_QUESTION

## `VBS-04` — PASS

*one payload in, one estate and a set of answers out* (guide 179, assessment)

- **PASS** `the-estate-is-assembled-once-and-shared` — 42 asset(s), 55 claim(s), identical across two assessments
- **PASS** `the-default-question-set-is-what-a-graph-can-answer` — 7 of 29 answered without a subject; 8 need one
- **PASS** `an-empty-question-list-answers-nothing` — 0 answers, so a caller that wants only the graph pays for only the graph
- **PASS** `a-called-out-question-is-named-when-it-refuses` — the statement names what was refused, not only what succeeded

## `VBS-05` — PASS

*the vendor graph leaves as CycloneDX 1.6 or it does not leave* (guide 179, export)

- **PASS** `the-official-schema-accepts-the-document` — 21 component(s) (11 top-level, 10 nested), 6 dependency entr(ies), 21 relation propert(ies), 3 supplier(s); schema valid
- **PASS** `every-component-type-is-in-the-formats-vocabulary` — application, device
- **PASS** `the-timestamp-is-the-documents-and-not-the-clock` — 2026-11-03T00:00:00Z
- **PASS** `the-export-is-deterministic` — two calls with the same claims, one document

## `VBS-06` — PASS

*CycloneDX has no vendor type and this does not invent one* (guide 179, vendor-is-a-supplier)

- **PASS** `no-component-is-a-vendor` — 11 top-level component(s), none of them a vendor
- **PASS** `each-product-names-its-supplier` — F5, OpenSSL Project, Thales
- **PASS** `the-vendors-are-listed-in-the-documents-own-metadata` — Thales and 2 more

## `VBS-07` — PASS

*a release belongs to a product, so it is nested in it* (guide 179, composition)

- **PASS** `a-release-is-nested-in-its-product` — payShield 9000 → payShield 9000@9.2
- **PASS** `a-package-is-nested-in-its-release` — OpenSSL@3.0.13 → OpenSSL firmware 3.0.13, pkg:generic/openssl
- **PASS** `a-release-is-not-a-dependency-of-its-product` — 6 dependency entr(ies), none of them a containment

## `VBS-08` — PASS

*dependsOn is an installation contract, not an evidence list* (guide 179, dependencies)

- **PASS** `every-dependency-reference-resolves` — 6 entr(ies), 0 dangling
- **PASS** `a-device-depends-on-its-model-and-its-firmware` — 6 entr(ies) start at a device or an application
- **PASS** `the-relations-that-are-not-needs-travel-as-properties` — 21 relation propert(ies) carry documented-by, declares and supplies

## `VBS-09` — PASS

*the document says how strongly each row is believed* (guide 179, confidence)

- **PASS** `every-applicability-state-is-one-the-module-defines` — DEPLOYMENT_UNVERIFIED, MATCHED, VERSION_MISMATCH
- **PASS** `the-estates-states-are-published-in-metadata` — DEPLOYMENT_UNVERIFIED:6, MATCHED:4, VERSION_MISMATCH:2
- **PASS** `the-supplier-basis-is-on-the-component-it-justifies` — vendor-datasheet, carried next to the supplier it justifies

## `VBS-10` — PASS

*a collector and a vendor payload describe the same estate* (guide 179, live)

- **PASS** `both-transports-are-reported` — registry, scan; 5 row(s)
- **PASS** `a-scanned-package-joins-the-vendor-estate` — 3 package node(s) after the merge
- **PASS** `a-package-the-payload-already-names-is-not-duplicated` — openssl appears once: the release names it and the scan agrees
- **PASS** `a-live-read-never-replaces-a-vendor-declaration` — 3 vendor(s), unchanged by the scan

## `VBS-11` — PASS

*the first three numbers, refusals included* (guide 179, summary)

- **PASS** `the-levels-are-the-graphs-own-counts` — vendor 3, product 3, release 4, firmware 4, package 2, asset 4, application 2, crypto 7, runtime 2, system 2
- **PASS** `the-applicability-states-are-carried-through` — DEPLOYMENT_UNVERIFIED 6, MATCHED 4, VERSION_MISMATCH 2
- **PASS** `the-refusals-are-counted-and-named` — 1 refusal(s) (ASSET_WITHOUT_PRODUCT): UNMAPPED-HSM

## `VBS-12` — PASS

*the surface answers about what it was given and reads nothing else* (guide 179, purity)

- **PASS** `no-database-and-no-session-import` — no engine, no session, no tenant filter
- **PASS** `no-writes-and-no-caches` — nothing is stored between two calls
- **PASS** `the-same-payload-twice-is-the-same-answer` — two assessments, one answer

## `VBS-13` — PASS

*the surface is reachable, or it is a library nobody calls* (guide 179, http)

- **PASS** `the-catalogue-is-a-route` — /cbom/vbom/questions
- **PASS** `every-question-shares-one-answer-route` — one route parametrised by the catalogue, not 29 hand-written handlers
- **PASS** `the-export-and-the-assessment-are-routes` — /answer/{question}, /assess, /export/cyclonedx, /questions, /summary

## What this does not prove

- the payload is a recorded vendor estate: the surface is proven against the shapes a bank files, not against a running procurement system
- the live merge joins a registry and an image scan to the vendor payload; it does not read the API database, which is the cross-links route's job
- a MATCHED applicability state says the vendor's claim lines up with the deployment; it does not say anything exercised the capability
- CycloneDX carries no field for class, basis or applicability, so those travel as cryptoscan: properties that a consumer may ignore
- the API is exercised for routing and for one assessment; full endpoint behaviour is covered by the unit tests, not by this harness
