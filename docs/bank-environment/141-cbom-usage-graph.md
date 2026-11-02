# Conflicts enter the graph, and a terminator owns its algorithms

`cryptoscan.cbom-usage-graph-guide/1` · generated 2026-11-02T17:49:04.891050+00:00 · **5 pass · 0 partial · 0 fail** · 23 probes

Guides 139 and 140 produce evidence and profiles. Both stop at the document. The questions a bank asks are relational, so this artifact measures the projection into graph edges — with three refusals built in:

1. **Provenance is not decoration.** An algorithm edge is `OBSERVED` only if a collector saw it; an SBOM-only algorithm is `DECLARED`, and `CONFLICTS_WITH` keeps both evidence ids.
2. **A conflict is never resolved into an edge.** CycloneDX has to pick one version to stay valid; a graph does not, so the disagreement survives.
3. **A terminator's algorithms belong to the terminator.** `NEGOTIATES` and `TERMINATES` attach to the endpoint, never to the application behind it.

| Row | Question | Verdict | Probes |
|---|---|---|---|
| `usage_edges` | does an algorithm edge say how it is known? | **PASS** | 5, 0 failing |
| `conflict_edges` | can a disagreement survive the move into the graph? | **PASS** | 4, 0 failing |
| `tls_edges` | does a load balancer's TLS become the application's property? | **PASS** | 4, 0 failing |
| `write_and_refuse` | is the graph a faithful projection or a tidy one? | **PASS** | 6, 0 failing |
| `api_exposure` | can a caller reach the graph without a test harness? | **PASS** | 4, 0 failing |

## `usage_edges` — PASS

*does an algorithm edge say how it is known?* (review 20)

- **PASS** `an-observed-algorithm-is-an-observed-edge` — OBSERVED from NET-9281, RUNTIME-92821
- **PASS** `an-sbom-only-algorithm-is-a-declared-edge` — the graph shows the algorithm and says the claim is a declaration
- **PASS** `an-algorithm-with-no-evidence-gets-no-edge` — 0 USES_CRYPTO edge(s) from system:payments-api; 1 algorithm(s) had no evidence and got no edge
- **PASS** `the-subject-is-explicit` — system / application / component, never an implicit one
- **PASS** `a-usage-graph-with-no-subject-is-refused` — an edge with no owner is not drawn

## `conflict_edges` — PASS

*can a disagreement survive the move into the graph?* (review 16 / 20)

- **PASS** `a-conflict-becomes-an-edge-with-both-evidence-ids` — 1 CONFLICTS_WITH edge(s) across 1 field(s); no conflict is resolved into an edge
- **PASS** `the-edge-names-the-field-and-both-values` — version: 3.0.13 vs 3.0.11
- **PASS** `a-conflict-is-never-resolved-into-an-edge` — the disagreement survives the projection
- **PASS** `agreeing-sources-produce-no-edge` — 0 CONFLICTS_WITH edge(s); the sources agree

## `tls_edges` — PASS

*does a load balancer's TLS become the application's property?* (review 8 / 9)

- **PASS** `a-terminator-owns-the-algorithms-it-negotiated` — 4 edge(s) from 1 endpoint(s); a terminator's algorithms belong to the terminator
- **PASS** `a-terminator-edges-to-its-certificate` — the certificate belongs to the endpoint, not to the application
- **PASS** `a-hop-with-no-endpoint-is-skipped` — no endpoint, no edge
- **PASS** `suite-parsing-is-the-collectors-table-not-a-copy` — one contract with guide 140's cipher-suite table

## `write_and_refuse` — PASS

*is the graph a faithful projection or a tidy one?* (review 16 / 20 / 21)

- **PASS** `every-edge-with-evidence-is-written` — 7 edge(s) written across 9 node(s)
- **PASS** `the-provenance-classes-survive-into-the-graph` — {"DECLARED": 1, "OBSERVED": 6}
- **PASS** `a-edge-with-no-evidence-is-refused` — an unattributable crypto relationship is a guess drawn on a diagram
- **PASS** `the-nodes-are-typed-by-what-they-are` — CERTIFICATE, CRYPTO_ALGORITHM, ENDPOINT, EVIDENCE_SOURCE, SYSTEM
- **PASS** `the-graph-exposes-which-algorithms-had-no-evidence` — families {"conflicts": 1, "tls": 4, "usage": 2}
- **PASS** `coverage-travels-with-the-graph` — a partial estate cannot be read as the whole graph

## `api_exposure` — PASS

*can a caller reach the graph without a test harness?* (review 20)

- **PASS** `the-graph-route-exists-and-is-typed` — POST /cbom/usage/graph
- **PASS** `the-route-uses-the-real-graph-engine` — the response carries the graph the engine would render
- **PASS** `the-route-accepts-all-three-families` — usage, conflicts and TLS in one call
- **PASS** `a-missing-subject-is-a-validation-error` — the edge with no owner is refused at the API too

## What this does not prove

- the graph is built from profiles and conflicts a caller passes in. It does not fetch them, so an out-of-date profile produces an out-of-date graph and nothing here notices
- a CONFLICTS_WITH edge names two sources and a field. It does not say which one is right — deliberately — so a consumer that needs one value must apply a precedence rule of its own, and the graph cannot stop it choosing badly
- USES_CRYPTO edges are per (subject, algorithm), not per call site. Two applications in one process using AES-256-GCM differently share an edge unless the caller separates the subjects
- termination is modelled, hop chaining is not: the graph does not assert that the traffic on both sides of a terminator is the same connection
- coverage is an annotation. A graph rendered without reading coverage_note looks complete even when most of the estate was never inspected
- certificate edges reference the certificate, not its parsed properties — the certificate's own public key and signature algorithm live in the certificate record, not on the edge
