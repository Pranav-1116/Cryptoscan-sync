# The vendor dependency graph over the live estate

`cryptoscan.vbom-estate-guide/1` · generated 2026-11-03T11:39:40Z · **13 pass · 0 partial · 0 fail** · 42 probes

**13 of 13 points of estate mapping hold, across 42 probes; 34 row(s) mapped over 10 section(s), 3 unmapped by name, 32 node(s) in the graph**

```
stored rows → payload → graph → { answers, summary, CycloneDX, HTTP }
                   ↓
        unmapped rows, by name and by reason
```

| Section | Rows mapped |
|---|---|
| `documents` | 1 |
| `vendors` | 5 |
| `products` | 5 |
| `releases` | 4 |
| `firmware` | 5 |
| `assets` | 5 |
| `packages` | 3 |
| `components` | 3 |
| `applications` | 1 |
| `systems` | 2 |
| `usage` | 0 |
| `network` | 0 |
| `pki` | 0 |

| Level | Nodes |
|---|---|
| `vendor` | 5 |
| `product` | 5 |
| `release` | 4 |
| `firmware` | 5 |
| `package` | 3 |
| `asset` | 5 |
| `application` | 1 |
| `crypto` | 2 |
| `runtime` | 0 |
| `system` | 2 |

| Applicability | Pair(s) |
|---|---|
| `DEPLOYMENT_UNVERIFIED` | 2 |
| `UNKNOWN` | 4 |

| Coverage | Value |
|---|---|
| components | 3 |
| vendor identified | 1 (33.3%) |
| vendor unknown | 1 |
| internal | 1 |
| accounted for | 66.7% |

| Row | Section | Question | Verdict | Probes |
|---|---|---|---|---|
| `VBE-01` | mapping | stored rows become one payload, and the count says which | **PASS** | 3, 0 failing |
| `VBE-02` | vendor→product→version | a versioned vendor row names a release | **PASS** | 3, 0 failing |
| `VBE-03` | vendor→asset | a device keeps the identity, the firmware and the place it is | **PASS** | 3, 0 failing |
| `VBE-04` | declared-capability | a capability is imported with the page that states it | **PASS** | 3, 0 failing |
| `VBE-05` | declared≠observed | a static finding is not an observation | **PASS** | 3, 0 failing |
| `VBE-06` | vendor→system | the rows say what the bank runs and what it would lose | **PASS** | 3, 0 failing |
| `VBE-07` | the-graph | the levels the estate supports, and nothing above them | **PASS** | 3, 0 failing |
| `VBE-08` | answers | every question has one shape, refusals included | **PASS** | 5, 0 failing |
| `VBE-09` | coverage | how much of the software estate has a vendor | **PASS** | 2, 0 failing |
| `VBE-10` | applicability | the answer names the field the estate does not keep | **PASS** | 3, 0 failing |
| `VBE-11` | summary | the first three numbers a reviewer wants | **PASS** | 3, 0 failing |
| `VBE-12` | export | the graph leaves as a CycloneDX document | **PASS** | 4, 0 failing |
| `VBE-13` | http | the graph is reachable, or it is a library nobody calls | **PASS** | 4, 0 failing |

## Rows the mapper refused to place

- `assets` — MYSTERY-01: the row names no model, so the device cannot be attributed to a product and an unattributed device is a vendor dependency nobody owns
- `releases` — Acme Datacrypt@4.2: the capability cites no document, and a capability with no page behind it is a rumour the graph refuses (VENDOR_CLAIM_WITHOUT_DOCUMENT)
- `packages` — no-coordinate: a software row with no coordinate cannot be joined to an SBOM or a runtime trace, which both name components by coordinate

## Sections this mapper does not read

- `usage` — runtime usage needs a process trace or a live probe; the stored crypto findings are static analysis and are not mapped here, so `declared_vs_observed` reports every declared capability as declared and never observed rather than inheriting a runtime claim from a file path
- `network` — an endpoint's load balancer, TLS mode and certificate chain come from the network scan projection and the NBOM, not from this mapper
- `pki` — certificate authority, certificate and endpoint rows come from the PKI projection; a fingerprint without its chain is not a dependency edge
- `firmware` — no firmware rows are mapped: a device's firmware becomes a node from the device's own row, and a vendor firmware document would add the support dates and the security status that row does not carry
- `applications` — the API's `applications` rows are business systems (the System model); the only application node this mapper can justify is the scanned target, and it carries the packages the scan reported

## `VBE-01` — PASS

*stored rows become one payload, and the count says which* (guide 180, mapping)

- **PASS** `the-payload-declares-the-graphs-input-schema` — cryptoscan.vbom-input/1
- **PASS** `every-section-has-a-count-including-the-empty-ones` — documents 1, vendors 5, products 5, releases 4, firmware 5, assets 5, packages 3, components 3, applications 1, systems 2
- **PASS** `the-environment-is-stated-not-assumed` — PRODUCTION (the default when no row says otherwise)

## `VBE-02` — PASS

*a versioned vendor row names a release* (guide 180, vendor→product→version)

- **PASS** `every-versioned-vendor-row-lands-on-a-release` — 4 release(s): Acme Datacrypt@4.2, BIG-IP 9000@17.1, PKI Platform@5.0, payShield 9000@9.2
- **PASS** `the-lifecycle-and-pqc-field-travel-with-it` — SUPPORTED / PQC_READY
- **PASS** `a-vendor-with-no-product-still-becomes-a-vendor` — Dell is a vendor from a device row; no product row was invented for it

## `VBE-03` — PASS

*a device keeps the identity, the firmware and the place it is* (guide 180, vendor→asset)

- **PASS** `the-flags-and-type-choose-the-kind` — CA-01=CERTIFICATE_AUTHORITY, HSM-001=HSM, HSM-002=HSM, LB-001=LOAD_BALANCER, SRV-01=PHYSICAL_SERVER
- **PASS** `firmware-serial-and-location-survive-the-mapping` — 9.2.1, SN-001, dc-1
- **PASS** `a-device-with-no-model-is-unmapped-by-name` — the row names no model, so the device cannot be attributed to a product and an u

## `VBE-04` — PASS

*a capability is imported with the page that states it* (guide 180, declared-capability)

- **PASS** `a-declaration-becomes-a-release-capability` — AES, ML-KEM
- **PASS** `the-document-is-created-once-and-cited-by-id` — VCI-D133296595 ← payShield 9.2 policy
- **PASS** `a-capability-with-no-document-is-unmapped-not-imported` — Acme Datacrypt RSA-2048 refused: the row cites no document

## `VBE-05` — PASS

*a static finding is not an observation* (guide 180, declared≠observed)

- **PASS** `the-stored-crypto-findings-do-not-become-runtime-usage` — 1 stored finding(s), 0 usage row(s)
- **PASS** `the-reason-is-in-the-response` — runtime usage needs a process trace or a live probe; the stored crypto findings are static
- **PASS** `declared-vs-observed-keeps-the-two-apart` — 2 capabilities declared, 0 observed: the vendor's page is not a runtime observation

## `VBE-06` — PASS

*the rows say what the bank runs and what it would lose* (guide 180, vendor→system)

- **PASS** `a-system-row-becomes-a-business-system` — Payments System, Reporting System
- **PASS** `the-scanned-target-is-the-only-application-claimed` — payments-api carries the three packages the scan reported
- **PASS** `a-package-with-no-coordinate-is-unmapped` — no-coordinate: a row that cannot be joined to an SBOM or a trace

## `VBE-07` — PASS

*the levels the estate supports, and nothing above them* (guide 180, the-graph)

- **PASS** `the-levels-are-populated-up-to-what-the-rows-support` — vendor 5, product 5, release 4, firmware 5, package 3, asset 5, application 1, crypto 2, system 2
- **PASS** `the-runtime-level-stays-empty-because-nothing-was-observed` — 0 runtime node(s): a static finding is not a process
- **PASS** `the-graph-refuses-nothing-the-mapper-had-already-rejected` — 0 graph refusal(s), none of them a row the mapper had already reported

## `VBE-08` — PASS

*every question has one shape, refusals included* (guide 180, answers)

- **PASS** `the-catalogue-and-the-module-agree` — 25 question(s), 21 of which need a subject
- **PASS** `the-default-assessment-answers-without-a-subject` — vendor_history, evidence_report, statement_applicability, version_conflicts, twin, coverage
- **PASS** `an-unknown-question-is-refused-with-a-code` — UNKNOWN_QUESTION
- **PASS** `a-missing-subject-is-refused-before-the-reader-runs` — MISSING_PARAMETER
- **PASS** `a-readers-refusal-keeps-the-readers-code` — UNKNOWN_NODE, passed through rather than renamed

## `VBE-09` — PASS

*how much of the software estate has a vendor* (guide 180, coverage)

- **PASS** `three-answers-not-one` — 1 identified, 1 unknown, 1 internal of 3
- **PASS** `an-unknown-vendor-is-a-mapping-gap-and-an-internal-one-is-not` — 33.3% identified, 66.7% accounted for

## `VBE-10` — PASS

*the answer names the field the estate does not keep* (guide 180, applicability)

- **PASS** `a-declaration-reaches-a-deployment` — 6 declaration/deployment pair(s): DEPLOYMENT_UNVERIFIED 2, UNKNOWN 4
- **PASS** `the-missing-field-is-named-not-assumed` — version: NOT_COMPARABLE — the inventory knows a device's firmware, not its product release
- **PASS** `no-pair-claims-MATCHED-on-a-field-nobody-kept` — MATCHED requires a version comparison that passed

## `VBE-11` — PASS

*the first three numbers a reviewer wants* (guide 180, summary)

- **PASS** `the-levels-are-the-graphs-own` — 32 node(s) over 9 level(s)
- **PASS** `the-applicability-states-are-carried-through` — DEPLOYMENT_UNVERIFIED 2, UNKNOWN 4
- **PASS** `the-refusals-are-counted-even-when-there-are-none` — 32 node(s) over 9 level(s); 0 refusal(s); DEPLOYMENT_UNVERIFIED 2, UNKNOWN 4

## `VBE-12` — PASS

*the graph leaves as a CycloneDX document* (guide 180, export)

- **PASS** `only-the-vendor-side-is-exported` — 31 component(s), kinds within the export list
- **PASS** `every-dependency-reference-resolves` — 12 dependency entr(ies), 0 dangling
- **PASS** `the-timestamp-is-the-documents-not-the-clock` — 2026-11-03T00:00:00Z
- **PASS** `the-export-is-deterministic` — two calls, one document

## `VBE-13` — PASS

*the graph is reachable, or it is a library nobody calls* (guide 180, http)

- **PASS** `the-graph-is-a-route` — GET /vbom/dependency
- **PASS** `the-catalogue-is-a-route` — GET /vbom/dependency/questions
- **PASS** `a-vendor-and-an-asset-are-addressable` — /dependency, /dependency/assets/{asset}, /dependency/export, /dependency/questions, /dependency/vendors/{vendor}
- **PASS** `the-export-is-a-route` — GET /vbom/dependency/export

## What this does not prove

- the inventory is a fixture in this shape, not a live database: the mapper's contract is the dict the API assembles, and the API tests exercise it against SQLite
- runtime usage is not mapped: a static finding is not an observation, so the runtime level is empty on a purely stored estate
- applicability stops at UNKNOWN where the estate keeps firmware but not the product release — that is a finding about the estate, not about the graph
- the network and PKI projections are not read by this mapper; their sections are named in not_mapped rather than left empty
- the CycloneDX export is shape-correct but not schema-validated here: the CBOM exporter owns validation
