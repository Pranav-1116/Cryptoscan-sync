# SBOM evidence, enforced where the code runs

`cryptoscan.sbom-enforcement-guide/1` · generated 2026-11-02T16:49:29.161618+00:00 · as of 2026-11-02 · **8 pass · 0 partial · 0 fail** · 39 probes

Guide 133 wrote the SBOM evidence rules as functions and proved each one. This artifact is the answer to the obvious follow-up — *is any of it on the path the product takes?* — and closes five gaps where the answer was no:

1. **The artifact store degraded to `/tmp`.** `artifact_storage()` caught any failure and fell back to a temporary directory, which turns *we hold the evidence* into *we held it until the container restarted*. It now consults the same `storage_policy` the review asked for, verifies integrity with a real write/read/hash round-trip, records the verdict in the manifest, and in production raises `StorageRefused` naming backup, retention and integrity rather than degrading.
2. **The parser budget was a library function.** `scan_source` now measures the merged dependency graph against it and reports the measurement in the scan result: an 80-deep chain withholds the edges and keeps the inventory, a cycle breaks exactly one back edge, and the caller can tighten the limits per request.
3. **An imported SBOM was read before it was screened.** `/sbom/import` now calls `guard_import` first: the parser budget refuses an oversized document by a stated limit, a document that asserts a protected fact (`deployment_identity`, `runtime_evidence`, `authorization`, `observed_fact`) is refused rather than merged, and every row it contributes comes back labelled `UNTRUSTED` with `may_override: False` and a content hash.
4. **A VEX statement never expired.** A `not_affected` analysis now carries a reviewer, an evidence id and an ISO expiry. Complete governance reads `COMPLETE`; a statement without them is `INCOMPLETE` with the missing fields named; and when the expiry passes the finding returns to `in_triage`, with the lapsed claim kept visible rather than deleted.
5. **The API could not say any of it.** The source manifest now carries `parser_budget` and `storage`, the response returns the budget, an import returns its trust label, and a storage refusal is a 503 with the reasons attached.

| Row | Question | Verdict | Probes |
|---|---|---|---|
| `storage_enforcement` | can production evidence still land in a temporary directory? | **PASS** | 6, 0 failing |
| `graph_budget` | does a hostile lockfile hit a stated limit before it hits the CPU? | **PASS** | 5, 0 failing |
| `import_guard` | can an uploaded SBOM change the estate or state a fact nobody observed? | **PASS** | 5, 0 failing |
| `vex_governance` | does a not_affected statement expire, and does it name an owner? | **PASS** | 6, 0 failing |
| `vulnerability_document` | can 0 matches be reported as clean when nothing was assessed? | **PASS** | 4, 0 failing |
| `twin_edges` | can the twin answer where a package is deployed, not which file lists it? | **PASS** | 5, 0 failing |
| `history` | is an SBOM a file, or a series somebody can diff over time? | **PASS** | 5, 0 failing |
| `api_wiring` | does the API surface what the evidence layer measured? | **PASS** | 3, 0 failing |

## `storage_enforcement` — PASS

*can production evidence still land in a temporary directory?* (review item 8 / blocker 2)

- **PASS** `development-uses-its-configured-store` — development -> ALLOW (CONFIGURED) at /tmp/guide134-store-d_5t54jb/dev
- **PASS** `production-with-no-store-raises-instead-of-writing-to-tmp` — refusing to store SBOM evidence in production: no artifact store is configured, and falling back to temporary storage would leave evidence for a production run with no du
- **PASS** `a-store-without-backup-or-retention-is-refused-by-name` — refusing to store SBOM evidence in production: no backup target is configured, so a restore cannot be demonstrated; no retention period is set, so evidence may be deleted early or kept past 
- **PASS** `a-configured-backed-and-retained-store-is-used` — production -> ALLOW; backup=True, retention=2555 days, integrity=True
- **PASS** `an-unwritable-store-is-not-reported-as-verified` — writable=False, integrity=False -> REFUSE (NotADirectoryError: [Errno 20] Not a directory: '/tmp/guide1)
- **PASS** `the-manifest-records-where-the-evidence-went` — manifest storage: ALLOW in /tmp/guide134-store-d_5t54jb/test (integrity True)

## `graph_budget` — PASS

*does a hostile lockfile hit a stated limit before it hits the CPU?* (review item 17.5 / blocker 5)

- **PASS** `an-ordinary-tree-is-measured-and-passes` — 1 component(s), depth 1, no cycles — inside the budget
- **PASS** `an-eighty-deep-graph-withholds-the-edges-and-keeps-the-inventory` — 80 component(s) kept, 79 edge(s) withheld: dependency depth 80 exceeds the 64 limit
- **PASS** `a-cycle-breaks-one-back-edge-instead-of-recursing` — cycle detected, 1 back edge removed, 1 edge(s) kept
- **PASS** `the-budget-can-be-set-by-the-caller` — max_components=0 -> REFUSED; the inventory is still returned (1 component(s))
- **PASS** `the-measurement-travels-with-the-result` — parser_budget carries verdict, problems, limits, component count, depth and cycles into the API response and the stored manifest

## `import_guard` — PASS

*can an uploaded SBOM change the estate or state a fact nobody observed?* (review item 17.1 / blocker 1)

- **PASS** `a-normal-import-is-labelled-untrusted-and-measured` — UNTRUSTED, may_override=False, content hash 7e196a89b3b9…, budget WITHIN_BUDGET
- **PASS** `an-import-may-not-state-an-observed-fact` — imported SBOM refused: the imported document asserts deployment_identity='attacker-prod'; an imported SBOM may add rows and may not state an observed 
- **PASS** `an-oversized-import-hits-the-budget-before-it-is-read` — imported SBOM refused: 1 components exceeds the 0 limit
- **PASS** `every-imported-row-carries-its-provenance` — 1 row(s) labelled UNTRUSTED / imported / may_override=False
- **PASS** `the-import-endpoint-calls-the-guard` — /sbom/import screens the document before it reads a component and returns the trust label, content hash and budget with the rows

## `vex_governance` — PASS

*does a not_affected statement expire, and does it name an owner?* (review item 11)

- **PASS** `a-governed-statement-carries-a-reviewer-evidence-and-expiry` — not_affected, governance COMPLETE, reviewer Security Team, expires 2027-01-01
- **PASS** `an-expired-statement-stops-suppressing-the-finding` — lapsed not_affected -> in_triage: ssued by an operator — the not_affected statement lapsed on 2026-01-01
- **PASS** `an-unsigned-statement-is-marked-incomplete-not-blessed` — governance INCOMPLETE, missing reviewer, evidence_id, expires_on
- **PASS** `a-free-text-expiry-cannot-be-enforced-so-it-is-refused` — expires_on='next year' -> refused: a date nobody can compare is not an expiry
- **PASS** `a-statement-cannot-expire-before-it-was-made` — assessed 2026-05-01, expires 2026-01-01 -> refused
- **PASS** `a-justification-is-still-required` — not_affected without a justification -> refused

## `vulnerability_document` — PASS

*can 0 matches be reported as clean when nothing was assessed?* (review item 10)

- **PASS** `every-component-gets-a-posture-with-its-reason` — 3 component(s): 1 matched, 1 assessed with no match, 1 not assessed against a current feed — 1 of 3 have no posture and may not be reported as clean
- **PASS** `a-document-cannot-be-summarised-clean-when-nobody-looked` — 1 matched, 1 assessed with no match, 1 with no posture
- **PASS** `a-stale-feed-leaves-every-component-unassessed` — 3 component(s): 0 matched, 0 assessed with no match, 3 not assessed against a current feed — 3 of 3 have no posture and may not be reported as clean
- **PASS** `no-feed-is-not-assessed-not-clean` — 3 component(s): 0 matched, 0 assessed with no match, 3 not assessed against a current feed — 3 of 3 have no posture and may not be reported as clean

## `twin_edges` — PASS

*can the twin answer where a package is deployed, not which file lists it?* (review item 14)

- **PASS** `the-chain-reaches-a-running-workload` — 8 edge(s): 8 edge(s) from SBOM-9182, 1 deployment observation(s) reaching PRODUCTION
- **PASS** `every-edge-carries-its-evidence` — every edge has evidence_id, evidence_type, source, observed_at and confidence
- **PASS** `deployment-edges-come-from-observations-not-from-the-sbom` — deployment:payments-api-prod --DEPLOYED_AS--> ghcr.io/bank/payments-api citing OBS-2026-1102-01 from k8s
- **PASS** `an-unobserved-artifact-has-no-path-to-production` — 3 edge(s) from SBOM-9182; no observation reaches this artifact, so no component resolves to a running system
- **PASS** `a-capability-edge-is-never-high-confidence` — 2 capability edge(s), all LOW: algorithm:aes-256-gcm, algorithm:rsa-3072

## `history` — PASS

*is an SBOM a file, or a series somebody can diff over time?* (review item 15)

- **PASS** `a-series-of-snapshots-becomes-a-timeline` — 3 snapshot(s), 2 transition(s), 0 with no change; the longest gap between snapshots is 19 day(s)
- **PASS** `each-transition-carries-its-change-set` — 2 of 2 transition(s) moved: VERSION_CHANGED
- **PASS** `the-timeline-keeps-every-version-it-saw` — openssl: 3.0.11 -> 3.0.12 -> 3.0.13
- **PASS** `the-gap-between-snapshots-is-stated` — longest gap 19 day(s) — a drift engine that never states its own blind spots cannot be audited
- **PASS** `two-identical-snapshots-produce-no-changes` — 2 snapshot(s), 1 transition(s), 1 with no change; the longest gap between snapshots is 1 day(s)

## `api_wiring` — PASS

*does the API surface what the evidence layer measured?* (review item 5-8 (reporting))

- **PASS** `the-scan-response-carries-the-parser-budget` — the source manifest reads result['parser_budget'] and the response returns it, so a withheld graph is visible to the caller
- **PASS** `the-manifest-records-the-storage-verdict` — the source manifest records where the artifact was written and whether that store was allowed to be ephemeral
- **PASS** `a-storage-refusal-is-a-503-with-the-reasons` — an unconfigured production store fails the request with a reason instead of writing evidence to a temporary directory

## What this does not prove

- the storage policy is enforced in the artifact writer, not in the object store itself: an operator who points SBOM_STORAGE_DIR at a node-local disk still has no backup until they set SBOM_STORAGE_BACKUP_DIR, and this code cannot check that the backup target is a different failure domain
- restore is not exercised here. The policy refuses an unbacked store; proving a restore returns byte-identical evidence is an operational drill
- the graph budget protects this repository's parser. A vendor's own lockfile reader has its own limits and would need the same matrix
- twin edges are built from records handed in; the Kubernetes/CMDB collectors that produce observations are outside this artifact
- vulnerability matching is purl+version against a supplied advisory set; range semantics per ecosystem are still outstanding

## How to run it

```bash
python scripts/sbom_enforcement.py --as-of 2026-11-02 \
--json docs/bank-environment/134-sbom-enforcement.json \
--md docs/bank-environment/134-sbom-enforcement.md
python scripts/sbom_enforcement.py --check   # non-zero on FAIL or PARTIAL
```

