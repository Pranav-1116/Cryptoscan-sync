# The SBOM reaches the graph, and the store becomes a timeline

`cryptoscan.sbom-twin-timeline-guide/1` · generated 2026-11-02T17:30:42.742559+00:00 · as of 2026-11-02 · **5 pass · 0 partial · 0 fail** · 40 probes

Guide 137 stopped the gate believing a document. What it left, and what this artifact measures, is the gap between *declared* and *observed*:

1. **The twin had edges nobody wrote.** `twin_edges` produced them with an evidence id; `apply_twin_edges` now writes them into the graph with the provenance class the evidence earns — SBOM → `DECLARED`, observation → `OBSERVED`, capability → `INFERRED` — and refuses any edge that carries no evidence at all.
2. **History lived in a list, not in the store.** `sbom_timeline` reads the stored manifest and the document behind it, produces the series, and turns each change into a drift event naming both snapshots. One snapshot reports drift as *unmeasured* rather than as no change.

| Row | Question | Verdict | Probes |
|---|---|---|---|
| `twin_edges` | does the graph distinguish declared from observed? | **PASS** | 6, 0 failing |
| `provenance_bridge` | is the provenance class decided by the evidence, not the edge? | **PASS** | 8, 0 failing |
| `artifact_timeline` | can the store answer what moved, between which artifacts? | **PASS** | 10, 0 failing |
| `drift_feed` | can a drift engine consume this without a human reading it? | **PASS** | 8, 0 failing |
| `api_exposure` | can a caller reach these answers through the API? | **PASS** | 8, 0 failing |

## `twin_edges` — PASS

*does the graph distinguish declared from observed?* (review item 14)

- **PASS** `an-sbom-edge-stops-at-the-artifact` — 3 edge(s) from SBOM-1; no observation reaches this artifact, so no component resolves to a running system
- **PASS** `an-observation-is-what-creates-a-path-to-production` — 5 edge(s), including DEPLOYED_AS, RUNS_AS
- **PASS** `an-observation-of-another-digest-does-not-reach-this-artifact` — an observation of a different digest adds nothing to this SBOM's graph
- **PASS** `an-unbound-document-cannot-be-deployed` — an SBOM with no artifact digest has no path to an observation
- **PASS** `a-capability-is-inference-and-says-so` — 1 HAS_CAPABILITY edge(s), confidence LOW
- **PASS** `every-edge-carries-an-evidence-id-and-a-time` — 5 edge(s), each with evidence_id and source

## `provenance_bridge` — PASS

*is the provenance class decided by the evidence, not the edge?* (review item 14)

- **PASS** `the-whole-sbom-graph-is-written` — 7 edge(s) written across 9 node(s)
- **PASS** `each-evidence-kind-earns-its-provenance-class` — {"DECLARED": 4, "INFERRED": 1, "OBSERVED": 2}
- **PASS** `the-rendered-graph-shows-the-classes` — 9 node(s), 7 edge(s)
- **PASS** `every-written-edge-keeps-its-evidence-reference` — 4 distinct evidence reference(s)
- **PASS** `the-nodes-are-typed-by-what-they-are` — APPLICATION, ARTIFACT, BUSINESS_SYSTEM, CAPABILITY, COMPONENT, DEPLOYMENT, SBOM, WORKLOAD
- **PASS** `an-edge-with-no-evidence-is-refused-not-written` — 0 edge(s) written across 0 node(s); 1 refused for carrying no evidence
- **PASS** `one-refused-edge-does-not-stop-the-rest` — 1 written, 1 refused
- **PASS** `an-unknown-evidence-kind-is-visible-as-unattributed` — 1 edge(s) written across 2 node(s); 1 edge kind(s) had no provenance class and were written as UNATTRIBUTED

## `artifact_timeline` — PASS

*can the store answer what moved, between which artifacts?* (review items 12 / 15)

- **PASS** `a-stored-manifest-and-its-document-become-a-snapshot` — ART-1 at 2026-10-01, bound to sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
- **PASS** `an-spdx-document-produces-the-same-shape` — 1 component(s) from SPDX
- **PASS** `a-manifest-with-no-digest-binds-the-document-to-nothing` — no artifact identity is claimed for a manifest with no sha256
- **PASS** `the-scanners-own-crypto-registry-is-read` — openssl is crypto-relevant by the registry the scanner ships
- **PASS** `two-snapshots-produce-a-change-with-both-ends-named` — {'ARTIFACT_CHANGED': 1, 'PACKAGE_REMOVED': 1, 'VERSION_CHANGED': 1}
- **PASS** `the-input-order-does-not-decide-the-timeline` — 2 snapshot(s) for ghcr.io/bank/payments-api: 2 snapshot(s), 1 transition(s), 0 with no change; the longest gap between snapshots is 14 day(s)
- **PASS** `one-snapshot-reports-drift-as-unmeasured` — 1 snapshot(s): with fewer than two snapshots nothing has been compared, so drift is unmeasured
- **PASS** `identical-snapshots-are-no-drift-not-unmeasured` — 2 snapshot(s): 2 snapshot(s), 1 transition(s), 1 with no change; the longest gap between snapshots is 14 day(s)
- **PASS** `two-snapshots-on-the-same-day-keep-their-stored-order` — ['ART-b', 'ART-a'] from the stored timestamps, not from the ids
- **PASS** `the-gap-between-snapshots-is-reported` — 14 day(s)

## `drift_feed` — PASS

*can a drift engine consume this without a human reading it?* (review item 12)

- **PASS** `each-change-becomes-an-event-a-drift-engine-can-consume` — 3 event(s): {'ARTIFACT_CHANGED': 1, 'PACKAGE_REMOVED': 1, 'VERSION_CHANGED': 1}
- **PASS** `an-event-names-the-two-artifacts-it-sits-between` — ART-1 -> ART-2 at 2026-10-15
- **PASS** `a-change-to-the-artifact-is-not-reported-as-a-component` — 1 artifact-level event(s)
- **PASS** `the-event-counts-add-up-to-the-events` — 3 counted, 3 emitted
- **PASS** `a-single-snapshot-emits-no-events-and-says-why` — 1 snapshot(s): with fewer than two snapshots nothing has been compared, so drift is unmeasured
- **PASS** `the-component-series-keeps-every-version-with-its-snapshot` — 2 component series
- **PASS** `the-schema-is-declared-on-every-report` — cryptoscan.sbom-timeline/1
- **PASS** `an-empty-store-is-an-empty-timeline-not-an-error` — 0 snapshot(s): with fewer than two snapshots nothing has been compared, so drift is unmeasured

## `api_exposure` — PASS

*can a caller reach these answers through the API?* (review items 12 / 14)

- **PASS** `the-twin-edges-are-reachable` — POST /sbom/{artifact_id}/twin is declared
- **PASS** `the-history-is-reachable` — GET /sbom/{artifact_id}/history is declared
- **PASS** `both-routes-are-typed` — both responses are Pydantic models, so the untyped inventory is unchanged
- **PASS** `the-schema-key-is-not-renamed-by-the-response-model` — the report's `schema` key survives response validation
- **PASS** `the-twin-route-can-bind-a-digest-and-carry-observations` — an operator can bind the stored SBOM to a digest and hand it observations
- **PASS** `the-twin-route-uses-the-real-graph-engine` — the response carries the graph the engine would render
- **PASS** `the-history-route-reads-the-store-not-the-request` — history is scoped to the tenant and to the artifact's target
- **PASS** `both-routes-require-the-existing-sbom-roles` — no new permission surface was invented for these reads

## What this does not prove

- provenance is a classification of the evidence, not a judgement of it: an SBOM edge marked DECLARED is only as true as the document, and the graph saying OBSERVED means somebody reported an observation, not that the observation is right
- the twin writes what it is given. A deployment observation supplied by a caller can be fabricated, which is why the evidence id and observed_at travel onto the edge rather than being summarised away
- HAS_CAPABILITY is inference from a name-based registry: a component that can do AES is not a component that uses AES, and the edge keeps confidence LOW for that reason
- the timeline is built from stored manifests for one target. Two targets with the same components produce two separate timelines, and nothing here decides whether an artifact change is a release or a rebuild
- drift events describe what the documents say changed. A component whose version is identical but whose bytes differ is invisible to a component-level diff
- retention is the store's policy: a history is only as long as the artifacts that were kept, so a pruned series can report fewer transitions without anything having been stable
