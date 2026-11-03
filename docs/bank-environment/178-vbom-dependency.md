# The VBOM dependency graph: vendor → product → release → asset → system

`cryptoscan.vbom-dependency-guide/1` · generated 2026-11-03T10:55:14Z · **29 pass · 0 partial · 0 fail** · 90 probes

**29 of 29 points of vendor-dependency depth hold, across 90 probes; 57 asset(s) and 85 claim(s) over 10 vendor level(s)**

```
VENDOR → PRODUCT → RELEASE → FIRMWARE / PACKAGE → ASSET
       → APPLICATION → CRYPTO → RUNTIME → BUSINESS SYSTEM

and underneath everything: evidence → identity resolution → digital twin → VBOM
```

| Level | Nodes |
|---|---|
| `vendor` | 5 |
| `product` | 6 |
| `release` | 7 |
| `firmware` | 4 |
| `package` | 2 |
| `asset` | 7 |
| `application` | 2 |
| `crypto` | 8 |
| `runtime` | 1 |
| `system` | 2 |

| Applicability | Declaration/deployment pairs |
|---|---|
| `DEPLOYMENT_UNVERIFIED` | 4 |
| `EXPIRED` | 2 |
| `MATCHED` | 6 |
| `PARTIAL_MATCH` | 4 |
| `VERSION_MISMATCH` | 8 |

| Coverage | Value |
|---|---|
| components | 100 |
| vendor identified | 82 (82.0%) |
| vendor unknown | 13 |
| internal | 5 |
| accounted for | 87.0% |

| Row | Section | Question | Verdict | Probes |
|---|---|---|---|---|
| `VBOM-01` | vendor→product | a product is a first-class node with its own identity | **PASS** | 3, 0 failing |
| `VBOM-02` | vendor→product→version | a claim is attached to a release, not to a company | **PASS** | 3, 0 failing |
| `VBOM-03` | version-applicability | applicability is one of eight states, and the first failing question decides | **PASS** | 6, 0 failing |
| `VBOM-04` | vendor→asset | a vendor dependency reaches the asset the bank actually runs | **PASS** | 3, 0 failing |
| `VBOM-05` | vendor→hardware | a hardware vendor's product reaches the device, with the HBOM's identity | **PASS** | 3, 0 failing |
| `VBOM-06` | vendor→software | a software vendor reaches an application through a package | **PASS** | 3, 0 failing |
| `VBOM-07` | vendor→crypto | a capability is a provider, an algorithm, a key size, a mode and a purpose | **PASS** | 3, 0 failing |
| `VBOM-08` | declared≠observed | a vendor's ML-KEM claim is a declaration, never a usage | **PASS** | 3, 0 failing |
| `VBOM-09` | vendor→application | the question is which applications depend on the product | **PASS** | 3, 0 failing |
| `VBOM-10` | vendor→business system | business impact is a property of the graph | **PASS** | 3, 0 failing |
| `VBOM-11` | vendor→crypto→system | which business systems depend on this vendor for this algorithm | **PASS** | 3, 0 failing |
| `VBOM-12` | vendor→runtime | the last hop is a process that was watched | **PASS** | 3, 0 failing |
| `VBOM-13` | vendor→network | a network vendor's device reaches the application behind it | **PASS** | 3, 0 failing |
| `VBOM-14` | vendor→certificate | a PKI vendor reaches the endpoint its certificate is on | **PASS** | 3, 0 failing |
| `VBOM-15` | vendor→firmware | firmware is versioned, dated and supportable on its own | **PASS** | 3, 0 failing |
| `VBOM-16` | vendor-lifecycle | a lifecycle state is derived, dated and terminal | **PASS** | 3, 0 failing |
| `VBOM-17` | evidence-freshness | vendor evidence ages, and is labelled rather than deleted | **PASS** | 3, 0 failing |
| `VBOM-18` | document→deployment | five checks decide whether a document applies | **PASS** | 3, 0 failing |
| `VBOM-19` | vendor→SBOM | a declared version and an SBOM version that differ is a finding | **PASS** | 3, 0 failing |
| `VBOM-20` | vendor→CBOM | the declaration and the observation are two answers, both kept | **PASS** | 3, 0 failing |
| `VBOM-21` | vendor→HBOM | the VBOM and the HBOM name the same hardware node | **PASS** | 3, 0 failing |
| `VBOM-22` | vendor→NBOM | the VBOM and the NBOM name the same network nodes | **PASS** | 3, 0 failing |
| `VBOM-23` | vendor→twin | the VBOM is a projection of the estate, not a vendor database | **PASS** | 3, 0 failing |
| `VBOM-24` | vendor-conflict | a version conflict keeps all four layers and picks none | **PASS** | 3, 0 failing |
| `VBOM-25` | vendor-history | a vendor relationship has a history with evidence on both sides | **PASS** | 3, 0 failing |
| `VBOM-26` | vendor-coverage | unknown is not internal and neither is no-vendor | **PASS** | 3, 0 failing |
| `VBOM-27` | vendor-risk | risk travels through dependencies, and stops where they stop | **PASS** | 3, 0 failing |
| `VBOM-28` | vendor-PQC | vendor PQC is DECLARED, deployment is UNKNOWN, usage is NOT_OBSERVED | **PASS** | 3, 0 failing |
| `VBOM-29` | the-graph | the graph the review drew is the graph the module builds | **PASS** | 3, 0 failing |

## What was refused while building the graph

- `PRODUCT_WITHOUT_VENDOR` — Orphan Product: a product with no vendor cannot be attributed, and an unattributed product is a supply-chain blind spot wearing a product name
- `VENDOR_CLAIM_WITHOUT_DOCUMENT` — Acme Datacrypt 4.2 RSA-2048: the vendor claims this on a page nobody filed: a capability with no document cannot be cited, aged, or argued with
- `RELEASE_WITHOUT_VERSION` — payShield 9000: a release with no version is not a release: applicability is a version comparison, and this row has nothing to compare
- `ASSET_WITHOUT_PRODUCT` — HSM-004: an asset that names no product cannot be attributed to a vendor, and an unattributed asset is a vendor dependency nobody owns
- `UNKNOWN_REF` — Acme Datacrypt firmware 4.2.0: RUNS_FIRMWARE names Acme Datacrypt firmware 4.2.0, which no asset in this estate declares; an edge to an undeclared node is refused, not invented

## `VBOM-01` — PASS

*a product is a first-class node with its own identity* (guide 178, vendor→product)

- **PASS** `the-vendor-has-products-not-algorithms` — payShield 9000, payShield SDK
- **PASS** `each-product-carries-family-and-type` — payShield 9000=HSM/payShield, payShield SDK=SDK/payShield
- **PASS** `a-product-with-no-vendor-is-refused-by-name` — Orphan Product refused (PRODUCT_WITHOUT_VENDOR)

## `VBOM-02` — PASS

*a claim is attached to a release, not to a company* (guide 178, vendor→product→version)

- **PASS** `the-product-has-more-than-one-release` — 8.4 [MAINTENANCE], 9.2 [SUPPORTED]
- **PASS** `each-release-carries-its-own-capabilities` — {'8.4': 3, '9.2': 2}
- **PASS** `a-release-with-no-version-is-refused` — a release row with an empty version is refused

## `VBOM-03` — PASS

*applicability is one of eight states, and the first failing question decides* (guide 178, version-applicability)

- **PASS** `eight-states-are-named` — MATCHED, PARTIAL_MATCH, VERSION_MISMATCH, PRODUCT_MISMATCH, DEPLOYMENT_UNVERIFIED, EXPIRED, SUPERSEDED, UNKNOWN
- **PASS** `every-state-has-a-stated-meaning` — 8 meanings
- **PASS** `the-estate-reaches-five-of-them` — DEPLOYMENT_UNVERIFIED 4, EXPIRED 2, MATCHED 6, PARTIAL_MATCH 4, VERSION_MISMATCH 8
- **PASS** `a-claim-about-another-product-is-PRODUCT_MISMATCH` — PRODUCT_MISMATCH
- **PASS** `a-replaced-revision-is-SUPERSEDED` — revision DOC-1006 replaced the claim
- **PASS** `a-claim-with-no-version-is-UNKNOWN` — UNKNOWN

## `VBOM-04` — PASS

*a vendor dependency reaches the asset the bank actually runs* (guide 178, vendor→asset)

- **PASS** `the-asset-is-reached-through-the-product` — HSM-001, HSM-002, HSM-005
- **PASS** `the-asset-carries-location-environment-and-owner` — HSM-001 DC-01/PRODUCTION/Payments; HSM-002 DC-02/PRODUCTION/Payments; HSM-005 DC-02/PRODUCTION/Payments
- **PASS** `an-asset-with-no-product-is-refused-by-name` — HSM-004 refused (ASSET_WITHOUT_PRODUCT)

## `VBOM-05` — PASS

*a hardware vendor's product reaches the device, with the HBOM's identity* (guide 178, vendor→hardware)

- **PASS** `the-chain-runs-vendor-product-firmware-asset` — HSM-001: Thales → payShield 9000 → payShield 9000 firmware 8.4.2 → HSM-001
- **PASS** `the-firmware-carries-dates-and-support-state` — MAINTENANCE until 2027-01-31
- **PASS** `the-hardware-identity-is-shared-with-the-hbom` — HSM-001: HSM payShield 9000 serial PS9K-0001 — shared with HBOM as TECH-HSM-001

## `VBOM-06` — PASS

*a software vendor reaches an application through a package* (guide 178, vendor→software)

- **PASS** `the-release-ships-a-package` — pkg:generic/openssl, pkg:generic/payshield-sdk
- **PASS** `the-package-reaches-the-application` — Payments API, Reporting API
- **PASS** `the-sdk-version-and-the-sbom-version-are-both-kept` — Thales: 1 package(s), 1 declared/observed conflict(s) — pkg:generic/payshield-sdk declared 5.7, saw 5.4

## `VBOM-07` — PASS

*a capability is a provider, an algorithm, a key size, a mode and a purpose* (guide 178, vendor→crypto)

- **PASS** `the-capability-carries-key-size-mode-and-purpose` — AES-256-GCM capability (key block), ECDSA-P-256 capability (firmware signing), ML-KEM-768 capability (key transport), RSA-2048 capability (card verification), RSA-3072 capability (no purpose)
- **PASS** `a-capability-implements-an-algorithm-node` — every capability names its ALGORITHM node
- **PASS** `the-class-is-VENDOR_DECLARED` — VENDOR_DECLARED

## `VBOM-08` — PASS

*a vendor's ML-KEM claim is a declaration, never a usage* (guide 178, declared≠observed)

- **PASS** `the-unused-capabilities-are-named` — ECDSA-P-256 capability, ML-KEM-768 capability
- **PASS** `the-used-ones-are-observed-not-declared` — AES-256-GCM capability=RUNTIME_OBSERVED, ECDSA-P-256 capability=VENDOR_DECLARED, ML-KEM-768 capability=VENDOR_DECLARED, RSA-2048 capability=RUNTIME_OBSERVED, RSA-3072 capability=RUNTIME_OBSERVED
- **PASS** `declared-count-and-observed-count-are-both-printed` — 5 declared, 3 observed

## `VBOM-09` — PASS

*the question is which applications depend on the product* (guide 178, vendor→application)

- **PASS** `the-applications-are-named` — Payments API, Reporting API
- **PASS** `the-path-that-reaches-each-one-is-returned` — SUPPLIED_BY → EMBEDS
- **PASS** `a-vendor-that-reaches-nothing-says-so` — Acme Legacy: no application is reachable from it

## `VBOM-10` — PASS

*business impact is a property of the graph* (guide 178, vendor→business system)

- **PASS** `the-systems-are-reached` — Payments System, Reporting System
- **PASS** `the-impact-is-not-taken-from-the-vendor-criticality-field` — Thales: 2 business system(s) — Payments System, Reporting System
- **PASS** `an-eol-product-on-a-device-nothing-uses-reaches-no-system` — Acme Legacy: reaches no business system

## `VBOM-11` — PASS

*which business systems depend on this vendor for this algorithm* (guide 178, vendor→crypto→system)

- **PASS** `the-answer-names-the-algorithm-and-the-systems` — OpenSSL Project → RSA → 2 application(s) → 2 business system(s): Payments System, Reporting System
- **PASS** `the-crypto-assets-that-carry-it-are-listed` — RSA-2048 capability, RSA-2048 use, RSA-3072 capability
- **PASS** `an-algorithm-the-vendor-does-not-offer-answers-nothing` — OpenSSL Project → 3DES → 0 application(s) → 0 business system(s): none

## `VBOM-12` — PASS

*the last hop is a process that was watched* (guide 178, vendor→runtime)

- **PASS** `a-process-loads-the-vendors-package` — payments-api 1821
- **PASS** `the-operations-are-observations-and-not-declarations` — RSA SIGN [OBSERVED via process-trace], AES ENCRYPT [OBSERVED via process-trace]
- **PASS** `the-observation-carries-its-evidence-reference` — probe:srv-k8s-03:1821, probe:srv-k8s-03:1821

## `VBOM-13` — PASS

*a network vendor's device reaches the application behind it* (guide 178, vendor→network)

- **PASS** `the-device-and-endpoint-are-reached` — F5: 1 network device(s), 1 endpoint(s), 1 application(s) behind them
- **PASS** `the-endpoint-routes-to-the-application` — Payments API
- **PASS** `the-network-identity-names-the-tls-mode` — LB-001: payments.bank.example:443 — the NBOM records the same nodes

## `VBOM-14` — PASS

*a PKI vendor reaches the endpoint its certificate is on* (guide 178, vendor→certificate)

- **PASS** `the-ca-the-certificate-and-the-endpoint-are-reached` — DigiCert: 1 CA instance(s), 1 certificate(s), 1 endpoint(s) — CERT-001
- **PASS** `the-certificate-is-issued-by-the-instance` — CERT-001 ISSUED_BY Issuing CA
- **PASS** `the-application-behind-the-endpoint-is-named` — Payments API

## `VBOM-15` — PASS

*firmware is versioned, dated and supportable on its own* (guide 178, vendor→firmware)

- **PASS** `every-firmware-row-carries-its-fields` — 4 firmware rows
- **PASS** `the-firmware-that-is-eol-is-named` — BIG-IP 9000 firmware 15.1.0[EOL], BIG-IP 9000 firmware 17.1.0[SUPPORTED], payShield 9000 firmware 8.4.2[MAINTENANCE], payShield 9000 firmware 9.2.1[SUPPORTED]
- **PASS** `a-device-that-runs-unrecorded-firmware-is-refused` — HSM-003's firmware is not a node the estate holds

## `VBOM-16` — PASS

*a lifecycle state is derived, dated and terminal* (guide 178, vendor-lifecycle)

- **PASS** `the-seven-states-are-named` — ACTIVE, SUPPORTED, MAINTENANCE, EOL, EOS, RETIRED, UNKNOWN
- **PASS** `eol-is-terminal` — Acme Datacrypt: EOL — the vendor states EOL
- **PASS** `the-fan-out-names-what-the-product-reaches` — Acme Datacrypt [EOL] → 1 asset, 1 release

## `VBOM-17` — PASS

*vendor evidence ages, and is labelled rather than deleted* (guide 178, evidence-freshness)

- **PASS** `an-expired-document-is-EXPIRED` — FRESH 4, VENDOR_EVIDENCE_STALE 1, EXPIRED 2, UNKNOWN 0
- **PASS** `an-undated-document-cannot-be-fresh` — DOC-X: UNKNOWN — the document carries no received_at, so its age is unknown
- **PASS** `an-old-document-is-STALE-not-trusted` — DOC-0900: VENDOR_EVIDENCE_STALE — received 885 days ago, past the 365-day review cadence

## `VBOM-18` — PASS

*five checks decide whether a document applies* (guide 178, document→deployment)

- **PASS** `the-five-checks-are-answered-per-row` — 24 declaration(s), five checks each
- **PASS** `a-matching-verified-deployment-is-MATCHED` — 6 MATCHED
- **PASS** `a-mismatch-is-not-silently-applied` — 24 declaration(s): 6 MATCHED, 18 otherwise — DEPLOYMENT_UNVERIFIED, EXPIRED, MATCHED, PARTIAL_MATCH, VERSION_MISMATCH

## `VBOM-19` — PASS

*a declared version and an SBOM version that differ is a finding* (guide 178, vendor→SBOM)

- **PASS** `the-conflict-names-both-versions` — 3.0.13 is not 3.0.11
- **PASS** `the-conflict-is-not-called-annotated-as-agreement` — VENDOR_DEPLOYMENT_VERSION_CONFLICT
- **PASS** `a-matching-package-is-IMPORTED` — 1 package(s), 1 conflict(s)

## `VBOM-20` — PASS

*the declaration and the observation are two answers, both kept* (guide 178, vendor→CBOM)

- **PASS** `declared-only-algorithms-are-named` — ECDSA, ML-KEM
- **PASS** `the-algorithms-in-both-are-named` — AES, RSA
- **PASS** `the-declaration-keeps-its-own-class` — VENDOR_DECLARED

## `VBOM-21` — PASS

*the VBOM and the HBOM name the same hardware node* (guide 178, vendor→HBOM)

- **PASS** `the-identity-carries-kind-model-serial-and-firmware` — HSM-001: HSM payShield 9000 serial PS9K-0001 — shared with HBOM as TECH-HSM-001
- **PASS** `the-identity-is-a-digest-the-other-boms-can-cite` — b024e7677e
- **PASS** `the-device-is-reached-by-a-claim-not-by-a-name-match` — HSM-001 HAS_MODEL payShield 9000

## `VBOM-22` — PASS

*the VBOM and the NBOM name the same network nodes* (guide 178, vendor→NBOM)

- **PASS** `the-device-listens-on-a-host-port-endpoint` — payments.bank.example:443
- **PASS** `the-endpoint-is-routed-to-an-application-by-a-record` — Payments API
- **PASS** `the-vendor-device-is-a-node-the-nbom-holds` — LB-001 is a LOAD_BALANCER node

## `VBOM-23` — PASS

*the VBOM is a projection of the estate, not a vendor database* (guide 178, vendor→twin)

- **PASS** `every-one-of-the-ten-levels-is-populated` — the twin holds 57 node(s) and 85 claim(s); 10/10 vendor level(s) are populated
- **PASS** `the-vendor-edges-are-in-the-graph` — DOCUMENTED_BY 18, FIRMWARE_OF 4, HAS_MODEL 6, PRODUCT_OF 4, RELEASES 7, RUNS_FIRMWARE 4, SHIPS_PACKAGE 2, SUPPLIED_BY 6, SUPPORTS 9
- **PASS** `the-projection-carries-a-refusal-log` — 4 builder refusal(s), 1 estate refusal(s)

## `VBOM-24` — PASS

*a version conflict keeps all four layers and picks none* (guide 178, vendor-conflict)

- **PASS** `the-four-layers-are-named` — pkg:generic/openssl: VENDOR_DECLARED=3.0.13, SBOM_OBSERVED=3.0.11, RUNTIME_OBSERVED=3.0.11; pkg:generic/payshield-sdk: VENDOR_DECLARED=5.7, SBOM_OBSERVED=5.4
- **PASS** `the-conflict-code-is-explicit` — VENDOR_DEPLOYMENT_VERSION_CONFLICT
- **PASS** `no-layer-is-called-the-truth` — no layer is promoted

## `VBOM-25` — PASS

*a vendor relationship has a history with evidence on both sides* (guide 178, vendor-history)

- **PASS** `the-vendor-change-is-VENDOR_CHANGED` — HSM-001: vendor Acme Legacy → Thales at 2026-10-01
- **PASS** `both-sides-carry-an-evidence-reference` — DOC-0800→DOC-1006, DOC-0900→DOC-1001
- **PASS** `a-field-that-is-not-a-dependency-is-ignored` — 3 change(s), 'colour' excluded

## `VBOM-26` — PASS

*unknown is not internal and neither is no-vendor* (guide 178, vendor-coverage)

- **PASS** `the-coverage-is-computed-not-claimed` — 82 of 100 component(s) have a vendor (82.0%); 13 unknown, 5 internal — 87.0% of the estate is accounted for
- **PASS** `unknown-and-internal-are-counted-separately` — 13 unknown, 5 internal
- **PASS** `the-unidentified-components-are-listed` — pkg:generic/mystery-000, pkg:generic/mystery-001, pkg:generic/mystery-002 …

## `VBOM-27` — PASS

*risk travels through dependencies, and stops where they stop* (guide 178, vendor-risk)

- **PASS** `the-score-is-composed-of-the-levels-it-reaches` — Thales: score 138 = base 46 × 3 (2 business system(s)); levels reached: application 2, asset 3, crypto 2, firmware 2, package 2, product 3, release 4, runtime 1, system 2, vendor 1
- **PASS** `a-terminal-lifecycle-doubles-the-score` — 10 = base 5 × 2 (Acme Datacrypt EOL)
- **PASS** `a-vendor-that-reaches-no-system-scores-nothing-propagated` — Acme reaches no system: s system(s)) × 2 (1 product(s) end of life); levels reached: asset 1, product 1, release 1

## `VBOM-28` — PASS

*vendor PQC is DECLARED, deployment is UNKNOWN, usage is NOT_OBSERVED* (guide 178, vendor-PQC)

- **PASS** `the-vendor-claim-is-DECLARED` — Thales: vendor PQC capability DECLARED (payShield 9000 firmware 9.2.1); deployment PQC capability UNKNOWN; PQC usage NOT_OBSERVED
- **PASS** `the-runtime-is-NOT_OBSERVED` — NOT_OBSERVED
- **PASS** `the-answer-is-not-PQC-READY` — declared DECLARED, deployment UNKNOWN, runtime NOT_OBSERVED

## `VBOM-29` — PASS

*the graph the review drew is the graph the module builds* (guide 178, the-graph)

- **PASS** `every-level-of-the-drawn-graph-exists` — vendor 5, product 6, release 7, firmware 4, package 2, asset 7, application 2, crypto 8, runtime 1, system 2
- **PASS** `the-total-is-assets-and-claims-not-a-vendor-list` — 57 assets, 85 claims
- **PASS** `the-applicability-of-the-estate-is-published` — DEPLOYMENT_UNVERIFIED 4, EXPIRED 2, MATCHED 6, PARTIAL_MATCH 4, VERSION_MISMATCH 8

## What this does not prove

- the payload is a recorded vendor estate, not a live pull: the module is proven against the shapes a bank files, not against a running procurement system
- applicability compares strings: 8.4 covers 8.4.2 and 8.4 does not cover 8.40, because a version algebra invented here would be a guess about the vendor
- a MATCHED claim says the capability exists on the release that is deployed; it does not say anything used it
- the risk weights are stated constants, printed so a bank can replace them with its own rather than trusting hours nobody can see
- coverage counts answers, not correct answers: a wrong vendor field is counted as an identified one
