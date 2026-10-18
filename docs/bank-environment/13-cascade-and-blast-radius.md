# 13 — How cascade and blast-radius calculations work

[Guide index](README.md) · Previous: [Dependency discovery](12-dependency-discovery-and-evidence.md) ·
Next: [Detailed bank examples](14-bank-cascade-examples.md)

## 1. Direction before numbers

For this guide, every dependency arrow means the left-hand system relies on the
right-hand one:

```text
Mobile Banking -> Gateway -> Payments API -> Signing Service
```

- Starting at Payments API and following arrows asks what it depends on.
- Starting there and walking backwards asks who depends on it.
- A change-review bundle may need both, but their operational meanings differ.

A component's dependency is not automatically a victim of that component's
failure. A database used by a stopped application may remain healthy.

## 2. There are several analysis surfaces

| Surface | Input | Interpretation |
|---|---|---|
| Scanner source cascade | File imports/calls/includes, crypto findings, manifests, system declarations | Static source change-review scope |
| Graph blast radius | Built graph backend | Forward dependency context for the selected system/asset users |
| Graph dependents | Built graph backend | Reverse consumer exposure |
| NBOM cascade | The supplied/generated network BOM's component relationships | Dependents within that document, not automatic whole-bank discovery |
| Unified cascade | Live or captured twin snapshot | Target-specific cross-domain evidence and bounded system propagation |

They are related but not interchangeable. In particular, a source-file consumer
is not necessarily a registered production service or an observed network caller.

## 3. Unified cascade inputs

`POST /api/v1/technology-bom/cascade` accepts a target, optional explicit kind
and `max_depth` (default 6, allowed 1..12). The engine supports algorithm,
certificate, endpoint, system, vendor, device, library and process targets.
The API model's prose is narrower than the engine's supported kinds; consult
the engine and tests rather than treating descriptive text as the full enum.

The API builds a twin snapshot or loads a captured twin version. The live adapter
collects relevant system, crypto-live-state, evidence, network, certificate,
hardware, supplier and linking records.

System propagation normally reads persisted `SystemDependency` rows. Only when
that dependency list is empty does the adapter use a latest graph snapshot as a
fallback. It does not merge every missing graph/mesh edge into a nonempty partial
registered list. Canonical IDs must remain compatible across stores.

Sources: [snapshot adapter](../../services/api/api/routers/digital_twin.py),
[cascade API](../../services/api/api/routers/techbom.py),
[pure engine](../../services/cbom/cbom/unified_cascade.py).

## 4. Target identification

Prefer an explicit kind and exact identity:

| Target | Strong starting reference | Ambiguity to review |
|---|---|---|
| System | Actual registered ID | Same/similar name across environments |
| Certificate | SHA-256 fingerprint | Shared subjects; endpoint association may still use subject matching |
| Endpoint | Exact registered/observed host and port | Ownership mapping, aliases, virtual hosting and intended scope |
| Device | Actual hardware asset ID | Manufacturer/model queries can match broadly |
| Library | Estate library identity | Partial names, ecosystem/version attribution |
| Vendor | Actual intended registry entry/name | Substring names and first-match selection |
| Algorithm | Intended family/parameterized name | Substring matching and family-level network evidence |
| Process | Actual process ID/name | Missing supporting-system links |

Auto-detection checks more specific forms before broad certificate-subject
containment. That reduces ambiguity; it does not create universally exact
resolution. Confirm `target.kind` and `target.matched` in the answer.

## 5. From a target to seed systems

| Kind | How applicable seed systems/context are obtained |
|---|---|
| Algorithm | Matching evidence and crypto-live assets, then asset/system links |
| Library | Named libraries on twin crypto assets, then asset/system links; optional catalog context |
| Certificate | Recorded certificate usage plus matching endpoints and their registered owners |
| Endpoint | Registered system ownership of that endpoint |
| Device | Declared crypto-to-hardware links, then linked assets' systems |
| Vendor | Recorded system/vendor links, plus separate vendor inventory context |
| System | The selected system itself |
| Process | Systems explicitly linked to the selected process |

No seed linkage means less system impact can be named, even when a concrete
hardware, endpoint or crypto object is found.

Library catalog capabilities are not proof of estate algorithm execution.
Algorithm network matching uses cipher-family tokens and does not establish a
particular certificate key size or all application-level crypto behavior.

## 6. Breadth-first propagation

The engine builds adjacency from dependency `source -> target` pairs. It uses
breadth-first search (BFS), a visited set, and a configured hop bound:

```text
frontier = directly implicated seed systems
seen = seeds
for each depth up to the limit:
    visit unvisited neighbors in the requested direction
    record newly reached systems at that depth
    stop early when no new systems are reachable
```

Benefits:

- Cycles do not cause an infinite walk.
- Shared consumers are deduplicated.
- Depth groups show how many modeled edges separate a consumer from the seed.
- A consistent snapshot/input gives deterministic set membership.

Depth is not a probability, propagation time, transaction latency or outage
severity. The current traversal does not simulate transaction execution,
redundancy, interface compatibility or failover.

### Not every target walks both directions

Algorithm, library and linked-device paths principally propagate to dependents.
System, certificate, endpoint and vendor paths can include both dependents and
supporting dependencies; process paths have their own returned context. Inspect
the actual `layers.system` fields, not a universal assumed rule.

The BFS uses supplied relationships without a confidence threshold or a
relation-specific availability model. An `imports-crypto` or `contains` edge is
not operationally equivalent to a mandatory synchronous service call, even if
it contributes to the current traversal.

## 7. Reading a unified answer

**Step-1 update:** new answers also include `impact.system_classification` with
separate direct exposure, dependent consumers and supporting context. Legacy
`affected_*` totals below retain the full review union for compatibility. See
[the implemented contract](17-classified-system-scope.md), including historical
unknowns and unchanged traversal limitations.

| Field | What to inspect |
|---|---|
| `target` | Did the engine match the intended kind/object? |
| `layers.code` | Evidence IDs, files, assets and seed-system context where supplied |
| `layers.network` | Matching listeners, observed status and supported transport context |
| `layers.system.dependents_by_depth` | Reverse consumers reached from seeds |
| `layers.system.downstream_by_depth` | Supporting dependencies reached where that kind includes them |
| `layers.hardware` | Concrete device facts and `inventory_only` status |
| `layers.vendor` / `layers.library` | Recorded supplier/capability context, not verified runtime behavior |
| `impact.affected_systems` | Deduplicated aggregate, potentially combining directions |
| `impact.affected_processes` | Available process associations; not guaranteed full transitive process closure |
| `impact.migration_waves` | Readiness-based grouping, not an approved execution schedule |
| `honest_unknowns` | Named limits; not an exhaustive automatically detected list of all possible gaps |
| `as_of` | Analysis time, not proof that every input was collected at that instant |

### Verdicts are not release gates

- `NOT_FOUND`: the target was not matched in this snapshot. This is not proof it
  does not exist in the bank.
- `INSUFFICIENT_DATA`: a match exists but applicable concrete reachability is
  insufficient for the engine's impact verdict.
- `AFFECTED`: at least one applicable concrete object/context is named. This can
  occur for an inventoried device with **zero known affected systems**.

Do not use a verdict alone as “safe”, “all affected”, “exploitable”, or “outage
confirmed”. See [14](14-bank-cascade-examples.md) for exact synthetic results.

## 8. Forward graph traversal is not reverse failure exposure

`GET /api/v1/graph/blast-radius` follows forward dependencies from a system.
Its asset-start form resolves asset-owning systems and unions their forward
walks. `GET /api/v1/graph/dependents` is the reverse consumer question.

A graph endpoint's `systems` list need not include the selected seed; an
asset-start result separately reports owning systems. Unified aggregate counts
use different assembly rules. Comparing counts without reconciling these
contracts is misleading.

### Backend differences that matter

The graph facade can prefer Neo4j, fall back to in-process traversal, or use an
in-process tenant-isolated graph. This is not evidence of automatic semantic
parity:

- Neo4j's blast-radius query traverses `CALLS` edges.
- In-process blast traversal follows its stored outgoing relationships more
  generally, including applicable non-CALLS edges.
- Unified cascade walks the twin's dependency list, which is not the same graph
  assembly path and does not apply identical relation semantics.
- A healthy persisted graph can lag relational inventory; check graph drift/sync
  rather than assuming backend health means current contents.

Sources: [memory engine](../../services/graph_engine/graph_engine/core/engine.py),
[Neo4j query](../../services/graph_engine/graph_engine/queries/blast_radius.py),
[facade](../../services/graph_engine/graph_engine/core/facade.py).

## 9. History, replay, watches and migration planning

The pure engine does not alter targets. The API **does** store a cascade run and
emit a platform event. “Read-only” means no changes to bank systems, not no writes
to CryptoScan's analysis/audit database.

A captured twin snapshot can be replayed with the cascade API's `version` query.
That is a twin-snapshot version, not a TechBOM snapshot version, scan ID or SBOM
artifact ID. Replay answers a historical modeled question; it is not proof an
outage occurred at the captured time.

Past-run diffs compare stored answers rather than re-scanning the bank. Watches
can rerun selected targets through the run-due route. Saving a watch alone does
not prove an external scheduler is invoking it or that inputs were refreshed.

Cycles and migration waves aid planning. Shared providers and cyclic consumers
need interface/backward-compatibility testing and bank-approved change windows.
The graph does not perform key ceremonies, deploy upgrades or establish that a
PQC migration is production-compatible.

Continue with [bank examples](14-bank-cascade-examples.md),
[API runbook](15-dependency-cascade-api-runbook.md), and
[limitations/acceptance](16-dependency-limitations-and-acceptance.md).
