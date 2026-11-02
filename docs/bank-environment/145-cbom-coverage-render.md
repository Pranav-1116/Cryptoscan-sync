# Coverage in the CBOM, and what an empty CBOM actually says

`cryptoscan.cbom-coverage-render-guide/1` · generated 2026-11-02T18:14:27.655186+00:00 · **5 pass · 0 partial · 0 fail** · 24 probes

The review's items 18 and 19:

> 12 RSA assets discovered, 62/100 applications inspected, coverage 62%, completeness PARTIAL

and an empty CBOM is not "no cryptography exists" — it may be *no crypto detected*, *no inventory ingested*, *paths unsupported or excluded*, *scan failed* or *coverage incomplete*. `cbom.coverage_render` writes both into the document:

1. **The floor travels with the count.** `cryptoscan:coverage` (a JSON block), `cryptoscan:coverage_pct`, `cryptoscan:coverage_completeness` and `cryptoscan:assets_discovered` are metadata properties, so a downstream reader cannot quote the asset count without them.
2. **`quotable_counts` answers the only question a report may ask:** is this a total or a floor? Only a fully inspected estate gets `TOTAL`.
3. **An empty document names its reasons**, in a stable order, with a statement that says it is not evidence that no cryptography exists.
4. **`NO_CRYPTO_DETECTED` is the only reason that is a statement about cryptography**, and it requires detectors that ran, files that were read, no errors and no skipped paths — an incomplete estate is an *additional* caveat, never a substitute.

| Row | Question | Verdict | Probes |
|---|---|---|---|
| `the_floor` | can an asset count be quoted without the coverage that qualifies it? | **PASS** | 6, 0 failing |
| `document_statement` | does the document itself carry the coverage, not only the API? | **PASS** | 5, 0 failing |
| `empty_reasons` | does an empty CBOM say which of the five things happened? | **PASS** | 6, 0 failing |
| `document_empty` | is the explanation in the artefact a reader receives? | **PASS** | 5, 0 failing |
| `api_exposure` | did the coverage land without widening the API surface? | **PASS** | 2, 0 failing |

## `the_floor` — PASS

*can an asset count be quoted without the coverage that qualifies it?* (review 18)

- **PASS** `a-partial-estate-cannot-quote-a-total` — 62/100 inspected, 62.0%
- **PASS** `the-statement-says-what-was-discovered-not-what-exists` — 480 crypto asset(s) discovered; 62/100 application(s) inspected (62%); the count is what was discovered, not what exists; 25 never scanned, 8 failed, 12 stale
- **PASS** `the-unscanned-and-the-failed-are-named` — 25 application(s) were never scanned; their cryptography is unknown, not absent; 8 application(s) failed their scan; a failure is not an empty result
- **PASS** `a-complete-estate-may-quote-a-total` — 40 crypto asset(s) across the estate
- **PASS** `an-unmeasured-estate-makes-no-claim` — 3 crypto asset(s) discovered over 0/0 application(s) (0.0%)
- **PASS** `coverage-never-exceeds-the-estate` — inspected is clamped to total rather than reporting 180%

## `document_statement` — PASS

*does the document itself carry the coverage, not only the API?* (review 18)

- **PASS** `the-coverage-block-travels-as-one-property` — PARTIAL / 62.0%
- **PASS** `the-scalars-exist-for-readers-that-do-not-parse-it` — assets + completeness + pct beside the block
- **PASS** `the-estate-document-carries-the-coverage` — POST-export portfolio BOM states 62/100 rather than 'the bank has'
- **PASS** `the-coverage-endpoint-answers-the-quotable-question` — GET /cbom/coverage returns the block and its phrasing
- **PASS** `attaching-coverage-is-idempotent-and-non-mutating` — re-rendering replaces instead of duplicating

## `empty_reasons` — PASS

*does an empty CBOM say which of the five things happened?* (review 19)

- **PASS** `five-different-statements-not-one` — NO_CRYPTO_DETECTED, NO_INVENTORY_INGESTED, PATHS_UNSUPPORTED_OR_EXCLUDED, SCAN_FAILED, COVERAGE_INCOMPLETE
- **PASS** `no-crypto-detected-requires-a-clean-inspected-scan` — the document has no components: the detectors ran and found no cryptographic material in the paths that were inspected; this is a statement about the inspected paths, not about the estate
- **PASS** `an-empty-document-nobody-filled-in-says-exactly-that` — the document has no components: no scan or inventory reached this system, so nothing was ever looked for; it is not evidence that no cryptography exists
- **PASS** `a-failed-scan-is-never-an-empty-result` — the document has no components: the scan reported errors; an empty result over a failed scan says nothing; it is not evidence that no cryptography exists
- **PASS** `skipped-paths-are-named` — the document has no components: part of the tree was skipped (unsupported file types, exclusions or unreadable paths); it is not evidence that no cryptography exists
- **PASS** `partial-coverage-is-a-caveat-beside-the-finding` — the document has no components: the detectors ran and found no cryptographic material in the paths that were inspected; the estate was only partly inspected, so an empty result here says nothing about the rest; it is not evidence that no cryptography exists

## `document_empty` — PASS

*is the explanation in the artefact a reader receives?* (review 19)

- **PASS** `the-document-carries-the-reason` — the document has no components: the scan reported errors; an empty result over a failed scan says nothing; it is not evidence that no cryptography exists
- **PASS** `the-document-says-it-is-not-an-absence` — an empty document is not a clean bill of health
- **PASS** `rendering-does-not-rewrite-the-document` — only the explanation properties are added
- **PASS** `a-non-empty-document-is-left-alone` — no explanation is attached where none is needed
- **PASS** `the-export-path-renders-it` — a scan CBOM with no components says why

## `api_exposure` — PASS

*did the coverage land without widening the API surface?* (review 18)

- **PASS** `the-coverage-route-keeps-its-original-fields` — the estate rollup is still the top level of the response
- **PASS** `no-new-operation-was-added` — the surface grew by payload, not by endpoint

## What this does not prove

- coverage is about systems that exist in the register. A business application nobody registered is invisible to the denominator, so a 100% figure means 'everything we know about was scanned', not 'everything that exists was scanned'
- inspected means a scan produced current or stale evidence. A scan that ran and found nothing counts as inspected, which is right for coverage and easy to misread as completeness of the CBOM
- the empty-BOM reasons are inferred from counters the collectors report. A collector that does not report files_scanned or files_skipped will produce a weaker explanation, never a stronger one
- an incomplete estate keeps NO_CRYPTO_DETECTED as a reason and adds COVERAGE_INCOMPLETE; a reader who stops at the first reason still over-reads it, so the statement is the field to quote
- the property block is JSON in a string, because CycloneDX properties are name/value pairs. Consumers must parse it to see per-status counts
- the export path explains an empty scan CBOM; the portfolio document states coverage. Other document builders (vendor, host, mainframe) still do not, and this guide does not claim they do
