# The stored inventory becomes a TechBOM

`cryptoscan.cbom-techbom-live-guide/1` · generated 2026-11-03T01:48:54.000043+00:00 · **6 pass · 0 partial · 0 fail** · 29 probes

Guides 164 and 165 built the graph and its answers. This is the adapter from the
inventory the platform already gathers, and the interesting part is what it
refuses.

```
inventory row                  basis                    class
System / registration          operator-registration    IMPORTED
SystemDependency manual        operator-registration    IMPORTED
SystemDependency imported      cmdb-import              IMPORTED
SystemDependency discovered    agent-inventory          CONFIGURED
software row, code import      code-analysis            CONFIGURED
software row, manifest only    sbom-import              IMPORTED
hardware / HSM observation     cmdb-import              IMPORTED
vendor row                     vendor-datasheet         VENDOR_DECLARED
```

Nothing read back through the database is `OBSERVED`: that class belongs to a
capture, a probe or a trace, and the store cannot claim it on a collector's behalf.

20 asset(s) and 17 claim(s) read from the inventory; 8 row(s) skipped with a reason; every class here is IMPORTED, CONFIGURED or VENDOR_DECLARED, because a stored row is not an observation

| kind | assets |
|---|---|
| `BUSINESS_SYSTEM` | 3 |
| `CERTIFICATE` | 2 |
| `CRYPTO_ASSET` | 3 |
| `CRYPTO_LIBRARY` | 2 |
| `FIRMWARE` | 2 |
| `HOST` | 2 |
| `HSM` | 1 |
| `PACKAGE` | 1 |
| `TPM` | 1 |
| `VENDOR` | 2 |
| `VENDOR_PRODUCT` | 1 |

| confidence | relationships |
|---|---|
| `CONFIGURED` | 2 |
| `IMPORTED` | 12 |
| `VENDOR_DECLARED` | 3 |

## Rows that could not be placed

| kind | subject | reason |
|---|---|---|
| `CRYPTO_ASSET` | ECDSA-256 | its source_basis 'unstated-instrument' is not one this model can classify, so it cannot be placed with a confidence |
| `REGISTRATION` | SYS-99 → CA-1 | the registration names a system or an asset this inventory does not hold, and an edge to an undeclared node is refused |
| `PHYSICAL_SERVER` | unknown-appliance | a hardware row with neither asset_id nor id cannot be referenced by an edge, so it is skipped rather than given an invented identity |
| `PACKAGE` | pkg/npm/mystery | its origin (none) does not say whether the code imports it or only a manifest declares it, so its class cannot be set |
| `DEPENDENCY` | pkg/npm/mystery → library/OpenSSL | one end of the edge is not an asset in this estate, and an edge to an undeclared node is refused rather than invented |
| `DEPENDENCY` | pkg:npm/gone@2.0 → library/OpenSSL | one end of the edge is not an asset in this estate, and an edge to an undeclared node is refused rather than invented |
| `DEPENDENCY` | SYS-2 → SYS-1 | its provenance column says (empty), which is not one of manual, discovered or imported: the edge cannot be given a class |
| `DEPENDENCY` | SYS-3 → SYS-404 | the dependency row names a system this inventory does not hold; an edge to an undeclared system is refused rather than invented |

**Roll-up** — Cards (HIGH): 1 crypto asset, 1 host across 2 kind(s); 0 proven by observation or configuration, 2 declared only

**Impact (RSA-2048, required ML-KEM-768)** — RSA-2048: 1 package; 2 blocker(s)

| blocker | asset | who acts |
|---|---|---|
| `FIRMWARE_UPGRADE_REQUIRED` | TECH-FW-001 | the firmware in place does not support a required algorithm |
| `HSM_PQC_UNSUPPORTED` | TECH-HSM-001 | the HSM's firmware does not list a required algorithm |

| Row | Question | Verdict | Probes |
|---|---|---|---|
| `shape` | does the real inventory become a graph the model accepts? | **PASS** | 5, 0 failing |
| `classes` | does a stored row keep the class its provenance supports? | **PASS** | 5, 0 failing |
| `refusals` | are the rows that cannot be placed refused, with the reason? | **PASS** | 7, 0 failing |
| `certificate` | does a certificate stay a certificate? | **PASS** | 3, 0 failing |
| `answers` | do the guide-165 answers work on a live inventory? | **PASS** | 5, 0 failing |
| `empty` | does an uncollected estate stay empty and say so? | **PASS** | 4, 0 failing |

## `shape` — PASS

*does the real inventory become a graph the model accepts?* (review tc / 3 and 6)

- **PASS** `the-inventory-becomes-an-estate-the-builder-accepts` — 20 asset(s) and 17 claim(s) read from the inventory; 8 row(s) skipped with a reason; every class here is IMPORTED, CONFIGURED or VENDOR_DECLARED, because a stored row is not an observation
- **PASS** `systems-registrations-and-assets-all-arrive` — 20 asset(s) across 11 kind(s)
- **PASS** `every-asset-and-claim-carries-an-evidence-reference` — the row id, the scan id or the evidence link it came from
- **PASS** `a-registration-links-the-system-to-what-it-holds` — three registered assets and the HSM row's owner
- **PASS** `the-scan-that-produced-the-software-rows-is-named` — scan SCAN-9281 is the evidence behind the package rows

## `classes` — PASS

*does a stored row keep the class its provenance supports?* (review tc / 5, 22)

- **PASS** `nothing-read-back-from-the-database-is-observed` — CONFIGURED, IMPORTED, VENDOR_DECLARED
- **PASS** `a-discovered-dependency-is-configured` — SystemDependency.source = discovered
- **PASS** `a-manual-registration-is-imported-not-trusted` — a person registering an edge is a claim, and it stays IMPORTED
- **PASS** `a-vendor-row-is-vendor-declared` — a manufacturer field is a declaration, not a delivery record
- **PASS** `the-adapter-states-the-class-ceiling-in-words` — every class here is IMPORTED, CONFIGURED or VENDOR_DECLARED, because a stored row is not an observation

## `refusals` — PASS

*are the rows that cannot be placed refused, with the reason?* (review tc / 22)

- **PASS** `a-dependency-row-with-no-provenance-is-refused-by-name` — an edge nobody vouched for is not drawn
- **PASS** `a-dependency-naming-an-unknown-system-is-refused` — SYS-404 does not exist, so the edge would be invented
- **PASS** `a-registration-naming-an-unknown-system-is-refused` — SA-4 points at SYS-99, which the inventory does not hold
- **PASS** `an-unclassifiable-source-basis-refuses-the-asset` — a source_basis this model does not know is not a class
- **PASS** `a-software-row-with-an-unstated-origin-is-refused` — 8 row(s) skipped, each with the reason
- **PASS** `a-hardware-row-with-no-identity-is-refused-rather-than-named` — a hardware row with neither asset_id nor id cannot be referenced by an edge, so it is skipped rather than given an invented identity
- **PASS** `nothing-was-dropped-silently` — 8 refusal(s), all reported

## `certificate` — PASS

*does a certificate stay a certificate?* (review tc / 9, 13)

- **PASS** `a-certificate-row-becomes-a-certificate-and-stops` — the stored shape carries a fingerprint and a subject, not a key
- **PASS** `the-certificate-keeps-its-fingerprint-as-evidence` — cert:abab… is the evidence id
- **PASS** `the-adapter-says-why-the-key-layer-is-missing` — a certificate is not the application's cryptography

## `answers` — PASS

*do the guide-165 answers work on a live inventory?* (review tc / 8, 19, 20)

- **PASS** `a-roll-up-works-on-live-rows-and-splits_the_classes` — Payments (CRITICAL): 1 business system, 3 crypto assets, 1 HSM, 1 firmware, 1 vendor, 2 hosts across 6 kind(s); 1 proven
- **PASS** `an-hsm-that-does-not-list-a-required-algorithm-is-a-blocker` — FIRMWARE_UPGRADE_REQUIRED, HSM_PQC_UNSUPPORTED
- **PASS** `a-blocker-names-the-device-and-who-acts` — 2 blocker(s), each with an owner of the work
- **PASS** `completeness-uses-the-denominator-the-caller-supplied` — PARTIAL: 2 kind(s) complete, 2 short, 2 stated gap(s), 7 unmeasured
- **PASS** `impact-still-refuses-to-call-exposure-breakage` — the owner's assessment sits above the graph

## `empty` — PASS

*does an uncollected estate stay empty and say so?* (review tc / 16)

- **PASS** `an-empty-inventory-is-an-empty-estate-not-an-error` — 0 asset(s) and 0 claim(s) read from the inventory; every class here is IMPORTED, CONFIGURED or VENDOR_DECLARED, because a stored row is not an observation
- **PASS** `an-empty-estate-is-unmeasured-rather-than-complete` — UNMEASURED: 0 kind(s) complete, 0 short, 0 stated gap(s), 0 unmeasured
- **PASS** `a-roll-up-over-nothing-says-there-is-no-system` — no business system in this TechBOM
- **PASS** `a-none-inventory-is-treated-as-empty-rather-than-a-crash` — a missing inventory reads as nothing collected

## What this does not prove

- the inventory is a fixture shaped like `_gather_inventory`, not a bank's database: the shapes are real, the rows are not
- a stored row records what a collector saw when it ran; the estate may have changed since, and nothing here re-probes
- the class ceiling is a property of the store, not of the collector: a future collector that hands over its own evidence can say OBSERVED itself
- a certificate row carries a fingerprint and a subject, so the key and algorithm layers stay empty until something reads them
- completeness is only as honest as the denominator, which this adapter receives rather than derives
