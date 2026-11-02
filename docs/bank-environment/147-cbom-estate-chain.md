# The whole chain over one estate: seven seams, seven checks

`cryptoscan.cbom-estate-chain-guide/1` · generated 2026-11-02T18:34:51.981950+00:00 · **6 pass · 0 partial · 0 fail** · 31 probes

Estate `bank-estate-2026-11` · 1 documented asset(s) · 2 candidate(s) excluded · 4 graph edge(s) · coverage PARTIAL

Each guide before this one proved a layer. This one runs them together, because the failures a reviewer finds are at the joins:

```
SBOM ─┐
static ├─→ evidence classes ─→ usage profile ─→ promotion ─→ CBOM document
config │                                              │
runtime┤                                              ├─→ PQC handoff
network┘                                              └─→ twin edges
KMS ──→ key records ─→ configured vs used
coverage ──→ what the document may say about totals
```

`cbom.estate_chain.run` produces the document once from one evidence set and then checks the invariants that must hold regardless of the input:

| # | invariant | what it prevents |
|---|---|---|
| 1 | `no_capability_is_documented_as_usage` | an SBOM's *supports* becoming a CBOM's *uses* |
| 2 | `every_documented_asset_is_attributable` | an asset nobody can trace to a source |
| 3 | `promotion_level_matches_the_evidence` | a level that outruns its classes |
| 4 | `conflicts_survive_to_the_graph` | a disagreement resolved by precedence into silence |
| 5 | `a_disabled_key_never_produces_runtime_evidence` | a decrypt against a disabled key reading as usage |
| 6 | `coverage_travels_with_the_document` | a total quoted from a partial scan |
| 7 | `emptiness_is_explained` | an empty document read as "no cryptography" |

A failing check is not a warning to be adjusted away: it comes back in `checks`, and `summary.status` says `BROKEN`.

| Row | Question | Verdict | Probes |
|---|---|---|---|
| `runtime` | does the runtime layer keep the chain and the disagreement? | **PASS** | 4, 0 failing |
| `keys` | is a configured key kept apart from a used key? | **PASS** | 5, 0 failing |
| `promotion` | does only the evidence reach the document? | **PASS** | 5, 0 failing |
| `the_document` | can the document be read without asking what it left out? | **PASS** | 5, 0 failing |
| `conflicts` | does a disagreement reach the twin, or get resolved quietly? | **PASS** | 7, 0 failing |
| `the_seven` | are the invariants checked, or only documented? | **PASS** | 5, 0 failing |

## `runtime` — PASS

*does the runtime layer keep the chain and the disagreement?* (review 7)

- **PASS** `the-chain-arrives-whole` — application:payments-api → process:payments-api/9182 → provider:OpenSSL@3.0.11 → operation:EVP_EncryptInit_ex → algorithm:AES-256-GCM
- **PASS** `the-version-mismatch-is-reported-not-resolved` — ['3.0.13'] declared, 3.0.11 loaded
- **PASS** `an-unknown-provider-version-is-not-guessed` — the process did not say which provider version it loaded, and the chain does not fill it in from the SBOM
- **PASS** `runtime-evidence-is-runtime-observed-and-nothing-more` — a trace is an observation of an operation, not a quantum verdict

## `keys` — PASS

*is a configured key kept apart from a used key?* (review 11)

- **PASS** `a-key-exists-and-a-key-is-used-are-different-classes` — 1 configured key(s), 2 recorded operation(s); 1 row(s) refused
- **PASS** `a-disabled-key-is-carried-as-not-usable` — DISABLED key: usable=False
- **PASS** `an-operation-on-a-disabled-key-is-refused-with-its-reason` — the key is DISABLED, so a recorded operation on it is a discrepancy, not evidence that the algorithm is in use
- **PASS** `no-suppressed-key-operation-reaches-the-evidence-set` — 5 evidence event(s), none from the disabled key
- **PASS** `no-key-material-is-ever-carried` — metadata only: the key layer stores no secret

## `promotion` — PASS

*does only the evidence reach the document?* (review 5 / 12)

- **PASS** `a-capability-never-becomes-a-document-asset` — 0 CBOM asset(s) promoted from evidence, 2 candidate(s) left out of the document; a capability is not an invocation
- **PASS** `an-observed-operation-becomes-an-asset` — a candidate for 2 algorithm(s), documented for 1
- **PASS** `the-level-is-recomputed-from-the-classes` — {"AES-256-GCM": "VERIFIED"}
- **PASS** `one-observing-mechanism-never-reads-as-verified` — runtime alone is RUNTIME; runtime and a handshake agreeing is VERIFIED
- **PASS** `an-observation-without-an-evidence-id-is-refused` — a runtime observation is missing evidence_id

## `the_document` — PASS

*can the document be read without asking what it left out?* (review 12 / 20)

- **PASS** `the-document-has-no-top-level-properties-array` — platform claims live in metadata.properties, as CycloneDX expects
- **PASS** `the-document-states-its-coverage` — completeness=PARTIAL, pct=62.0
- **PASS** `the-document-does-not-quote-a-total-it-cannot-support` — 62 of 100 systems inspected, so no estate-wide total is asserted
- **PASS** `an-empty-document-says-why-it-is-empty` — the document has no components: the estate was only partly inspected, so an empty result here says nothing about the rest; it is not evidence that no cryptography exists
- **PASS** `the-document-records-what-it-left-out` — 1 promoted, 2 excluded

## `conflicts` — PASS

*does a disagreement reach the twin, or get resolved quietly?* (review 8)

- **PASS** `two-observing-layers-that-disagree-are-a-conflict` — cipher_suite has 2 observed values across 2 source(s); the observation layers disagree and the disagreement is the finding
- **PASS** `a-declaration-against-an-observation-is-a-mismatch-not-a-conflict` — the SBOM does not observe; the process tracer owns that comparison
- **PASS** `the-conflict-survives-to-the-graph-as-an-edge` — 1 conflict edge(s), each carrying its evidence ids
- **PASS** `no-single-value-is-asserted-where-the-sources-disagree` — the disagreement is the finding; a human decides
- **PASS** `every-claim-survives-as-a-row` — 4 claim row(s) kept
- **PASS** `agreement-is-not-a-conflict` — two layers agreeing on the same value is a corroboration
- **PASS** `the-graph-hangs-off-the-estate-it-describes` — 4 edge(s) on system:bank-estate-2026-11

## `the_seven` — PASS

*are the invariants checked, or only documented?* (review 7 / 8 / 11 / 12 / 20)

- **PASS** `all-seven-cross-layer-checks-hold-on-a-mixed-estate` — 7/7 cross-layer checks hold
- **PASS** `the-checks-are-a-named-contract-not-a-count` — no_capability_is_documented_as_usage, every_documented_asset_is_attributable, promotion_level_matches_the_evidence, conflicts_survive_to_the_graph, a_disabled_key_never_produces_runtime_evidence, coverage_travels_with_the_document, emptiness_is_explained
- **PASS** `a-failing-check-makes-the-pipeline-broken-not-warning` — the response carries the failure; it is not smoothed into the document
- **PASS** `the-disabled-key-check-has-teeth` — a leaked RUNTIME_OBSERVED event on a DISABLED key fails the check
- **PASS** `the-route-exists-typed-and-role-gated` — POST /cbom/estate-chain

## The document that comes out

Metadata properties, verbatim:

```json
{
  "cryptoscan:promoted_assets": "1",
  "cryptoscan:candidates_excluded": "2",
  "cryptoscan:promotion_schema": "cryptoscan.cbom-promotion/1",
  "cryptoscan:promotion_statement": "1 CBOM asset(s) promoted from evidence, 2 candidate(s) left out of the document; a capability is not an invocation",
  "cryptoscan:coverage": "{\"as_of\": \"2026-11-02\", \"assets_discovered\": 1, \"completeness\": \"PARTIAL\", \"coverage_pct\": 62.0, \"may_report_total\": false, \"status_counts\": {\"CURRENT\": 50, \"FAILED\": 8, \"NEVER_SCANNED\": 25, \"NO_TARGET\": 5, \"STALE\": 12}, \"systems_inspected\": 62, \"systems_total\": 100, \"unit\": \"application\"}",
  "cryptoscan:coverage_pct": "62.0",
  "cryptoscan:coverage_completeness": "PARTIAL",
  "cryptoscan:assets_discovered": "1"
}
```

Evidence classes: `{"CONFIGURED": 1, "NETWORK_OBSERVED": 2, "RUNTIME_OBSERVED": 2}`

## What this does not prove

- the chain composes the modules; it does not add a collector. An estate that omits a layer produces a document that is honest about that layer and silent about what it never looked at
- a passing check means the layers agree with each other, not that the estate is correctly described. Seven invariants cannot detect a collector that is consistently wrong
- conflicts are only visible when the caller supplies conflicting claims. The chain does not invent a second source to test the first, and an estate with one source can never produce a conflict
- coverage is read from the estate's rollup. If the caller passes a rollup that overstates inspection, the document repeats the overstatement with the same confidence
- emptiness is explained from the file counts and the coverage block. An empty document from a fully covered estate is a real finding; an empty document from an uncovered one is not evidence of absence, and the reasons say which
- the graph is a projection for one run. Persisting it as a twin snapshot and diffing runs for drift is the estate twin's job, not this guide's
- the invariants are structural. They cannot tell whether the seven checks are the seven a regulator wants; that is a scoping decision made in the review, not a property of the code
