# 16 — Dependency limitations, improvement priorities and bank acceptance

[Guide index](README.md) · Previous: [API runbook](15-dependency-cascade-api-runbook.md)

**Source-traced baseline limitations.** This guide originally recorded a
documentation-only review. The implementation update below identifies subsequently
delivered changes. Recommended improvements are not implemented merely by writing
this guide, and no bank production approval is implied.

## Implementation update

The limitation table below records the pre-implementation baseline documented
at commit `94001ff2`. [Step 1](17-classified-system-scope.md) now adds disjoint
direct/consumer/context classification and UI counts while retaining legacy
aggregate fields. [Step 2](18-shared-dependency-semantics.md) adds a shared
versioned system relationship policy and deterministic adapter parity fixtures;
real Neo4j qualification, differing collector inputs and stale-edge reconciliation
remain outstanding. [Step 3](19-package-artifact-deployment-identity.md) adds
explicit package-SBOM/release-digest/application deployment joins, not automatic
whole-estate package discovery or verified current runtime placement. The baseline table is not a claim those pending items are
resolved.
Current engineering status is tracked in the
[ten-step plan](../dev/dependency-intelligence-roadmap.md).

## 1. The defensible product claim

> CryptoScan correlates supported discovered and declared evidence, traverses
> modeled dependencies, and identifies systems requiring impact review, with
> explicit coverage boundaries.

Avoid claiming universal discovery, complete exploit reachability, automatic
failure prediction, guaranteed backend parity or fully autonomous remediation.

A dependency-exposure graph is useful without being a digital execution model
of every bank transaction. Its quality depends on identity, coverage, semantics,
freshness, provenance and bank validation—not just node count.

## 2. Current limitations and their consequences

| Limitation | Concrete bank consequence | Operator mitigation / recommended improvement |
|---|---|---|
| Source patterns are not full runtime call graphs | Unused/test imports can overstate exposure; reflection/plugins can be missed | Reconcile build/deployment scope and representative runtime evidence |
| Package SBOM graphs are not automatically fully joined into unified cascade | A transitive package can be present without a complete package-to-business-service path | Bind ecosystem/version, artifact digest, deployment and canonical system identity |
| Inventory co-presence is not linkage | An HSM can exist with no identifiable consumers | Substantiate crypto/hardware and asset/system links; preserve unknowns |
| Different assembly paths read different edge sets | Graph/mesh view and unified cascade can disagree on scope | Record edge source and reconcile persisted versus view-only relationships |
| Twin graph fallback only runs when the registered edge list is empty | A partially populated registered graph can omit edges present in snapshots | Explicitly reconcile missing edges; do not assume automatic union |
| Source-system synchronization is additive | Removed input dependencies can survive in inventory | Review stale/deleted links and implement an approved reconciliation policy |
| Confidence is not calibrated operational probability | A heuristic score can be mistaken for an outage likelihood | State the meaning of each score; never invent probability semantics |
| Unified BFS does not apply a confidence threshold or hard/optional dependency model | Weak/declarative/containment relations can contribute to broad reachability | Separate relationship meaning and substantiation from traversal membership |
| Aggregate impact can combine consumers and supporting dependencies | A broad review set can be sold as confirmed outage victims | Display seeds, reverse consumers and supporting context separately |
| Process support inventory can be incomplete | Step 6 closes over all classified systems, but absent support mappings remain unknown | Inspect inclusion reasons and source caps; reconcile missing process support |
| Some target matching is substring/first-match based | A broad vendor/library/device query can select an unintended object | Use explicit kind and canonical identity; inspect matched object |
| Certificate endpoint association can use subject matching | Different/renewed certificates with the same subject can be conflated | Prefer exact fingerprint usage/deployment evidence and inspect ambiguity |
| Algorithm matching and cipher tokens have different precision | Family-level transport evidence can be overstated as exact application/key usage | Preserve parameter unknowns and use the actual evidence type |
| Service-mesh coverage/configuration is optional | Non-mesh/idle/unmapped traffic relationships are absent | Check telemetry health, name mapping, scope and freshness |
| Current Istio query uses request totals | Historical counter presence can look like current dependency evidence | Interpret correctly; qualify a suitable observation-window policy |
| Neo4j and memory graph traversals differ | Non-CALLS relationships can affect backend count parity | Run same-estate parity tests and document relation rules |
| Persisted graph health is not graph freshness | A healthy backend can still serve old topology | Use drift/sync checks and retain analysis backend/source context |
| Bounded reads and propagation depth limit completeness | Large/deep estates can be underrepresented | Reconcile caps, depth and approved scope denominators |
| No BFS simulation of failover, HA or queue buffering | A reachable consumer may continue functioning during an incident | Validate availability architecture and run authorized operational tests |
| Vendor/sub-tier data is declared and directionally bounded | Missing links or reverse supplier exposure may be unmodeled | Obtain release-specific provenance; do not invent complete supply-chain coverage |
| Verdicts are not acceptance gates | `AFFECTED` can have zero known systems; `NOT_FOUND` is not safe | Inspect layers, linkage, counts, unknowns and bank risk decisions |
| Snapshot capture is not independent whole-bank observation | Analysis time can be mistaken for fresh input measurement time | Retain each input's observation/deployment/capture identity |
| Watches do not guarantee fresh evidence or delivery | Repeated runs can repeat a stale graph; events may not reach incident tooling | Qualify executor, refresh jobs, failures and delivery receipts |
| Edge-management API authentication is not a complete bank approval workflow | A UI guard alone does not establish authorized architecture changes | Negative-test roles/tenants and enforce approved governance externally where needed |

These are source-inspection findings. They do not claim every failure occurs in
every deployment, nor that every unknown is automatically diagnosed in the
`honest_unknowns` array.

## 3. Current bounds worth retaining in reports

| Surface | Current relevant bound | Interpretation |
|---|---|---|
| Unified system propagation | Default 6; configurable 1..12 hops | Nodes beyond depth remain outside the result |
| Graph blast/dependents request | Default 5; configurable 1..12 hops | Hold depth constant for comparisons |
| Twin evidence rows | 20,000 | Large estates can undercount code-layer reachability |
| Twin system-dependency gather | 50,000 | A bounded collection is not an exhaustive census |
| Several twin secondary sections | Commonly 20,000 per named section | Systems, hardware, certificates and link stores have distinct bounds |
| Source dependency file reader | 2 MB per file | Oversized source can be absent from that helper's graph |
| Source transitive-dependent helper | Default 10,000 reached files | Static dependent counts also have limits |
| Discovered candidate scan history | Latest 200 scans | Older-only candidates need separate reconciliation |
| Registered edge-list API | Default 500; selectable up to 5,000 | Current system filter follows the limit; not guaranteed complete neighborhood |
| Vendor sub-tier traversal | 3 levels | Not a complete unlimited or reverse supply-chain search |

Other collectors, exports and lists have their own limits. A fidelity report,
graph collection metadata or unknowns list is helpful but not a guarantee that
every truncation is signaled uniformly across paths.

## 4. Priority improvement plan — recommendations, not delivered features

### Priority A: make results harder to misinterpret

1. Separate `direct`, `dependent_consumers` and `supporting_context` in API/UI
   summaries instead of presenting one undifferentiated failure count.
2. Display matched identity, observation age, depth, backend and truncation
   alongside the count.
3. Distinguish measured/declared/imported/inferred provenance through every path;
   a populated timestamp or a HIGH label is not independent verification.
4. Expand process reporting over the intended implicated-system set, preserving
   which path and relationship justified inclusion.

### Priority B: make the dependency graph more complete and consistent

1. Define shared edge semantics for memory, Neo4j, twin and source-cascade paths.
2. Reconcile persisted relationships, code-derived edges and mesh observations
   using explicit identity and provenance rather than silent union/overwriting.
3. Add reviewed expiry/removal/reconfirmation for stale dependencies.
4. Bind package SBOM -> immutable artifact -> deployed instance/system -> business
   process, without claiming package presence equals exploitability.
5. Tighten certificate fingerprint, vendor product/version and ecosystem-specific
   library identities to reduce name-match ambiguity.

### Priority C: improve operational modeling and qualification

1. Model mandatory/optional, synchronous/asynchronous, fallback and redundant
   relationships separately where supported by bank evidence.
2. Retain end-to-end edge evidence, freshness and confidence meaning in exports.
3. Qualify role/tenant boundaries for write/read/history/replay/watch paths.
4. Test large-estate bounds, backend parity, storage/restart and snapshot lineage.
5. Tie remediation closure to bank deployment/operational checks, not count
   reduction alone.

A proposed backlog does not change current readiness or security guarantees.

## 5. Proposed bank acceptance exercises

Agree scope, thresholds, owners and safe test environments before execution.
The following table is an acceptance plan, not completed bank evidence.

| Exercise | Expected proof | False conclusion to reject |
|---|---|---|
| Known dependency chain | Resolve approved IDs and verify both traversal directions | Forward dependencies equal reverse affected consumers |
| Static provider change | Find known direct/transitive imports and show a skipped/dynamic case | Every importing file executes in production |
| Source-to-system map | Correct paths, named systems and declared dependencies survive the intended pipeline | Every declared relationship is a measured production call |
| Missing HSM link | Device remains inventory-only and consumer uncertainty is visible | Zero known consumers means no consumers |
| Linked HSM | Substantiated asset/system links produce the expected bounded set | The entire set necessarily suffers an outage |
| Certificate replacement | Exact fingerprint usage is distinguished from subject-only associations | Same subject means same deployed certificate |
| Package advisory | Package/version/artifact/deployment match is auditable | Package name alone proves vulnerable function reachability |
| Process mapping | Verify [step-6](22-business-process-impact-and-inclusion-reasons.md) consumer/context closure, identity deduplication, inclusion reasons and missing-link warnings | Empty process list means no business impact |
| Backend parity | Same estate/depth, explicit CALLS/non-CALLS expectations, documented differences | Healthy Neo4j automatically gives identical memory results |
| Edge removal | Demonstrate actual persisted state after a source-map change | Removed YAML entry automatically removed old inventory edges |
| Depth/cap boundary | Show why a deeper/larger estate changes coverage | A bounded list is the whole-bank denominator |
| Snapshot replay | Actual twin version and run IDs reproduce intended modeled scope | Replay proves a real outage occurred |
| Authorization | Allowed roles/tenants succeed; denied/revoked/foreign context fails | Frontend visibility alone enforces API governance |
| Watch execution | Actual executor, refreshed inputs and receipt/failure evidence | Saving a watch guarantees continuous fresh monitoring |

Bank owners still approve incident response, interface changes, key ceremonies,
compatibility, rollback, maintenance windows and residual risk.

## 6. Implementation and test map

| Area | Source | Supporting tests |
|---|---|---|
| Static dependency extraction/system rollup | [Scanner cascade](../../services/scanner/scanner/analysis/cascade.py) | [Cascade tests](../../services/scanner/tests/unit/test_cascade.py) |
| Additive declared-system persistence | [Worker pipeline](../../services/worker/worker/pipeline/pipeline_runner.py) | [Estate pipeline example](../../services/worker/tests/unit/test_pipeline_end_to_end_estate.py) |
| Registered relationships | [Model](../../services/database/db/models/system_dependency.py), [graph API](../../services/api/api/routers/graph.py) | [Graph engine tests](../../services/graph_engine/tests/test_engine.py) |
| Graph assembly and telemetry | [Builder](../../services/api/api/graph_builder.py), [Istio client](../../services/graph_engine/graph_engine/service_mesh/istio_client.py) | [Istio tests](../../services/graph_engine/tests/test_istio.py) |
| Backend selection and traversal | [Facade](../../services/graph_engine/graph_engine/core/facade.py), [memory engine](../../services/graph_engine/graph_engine/core/engine.py), [Neo4j query](../../services/graph_engine/graph_engine/queries/blast_radius.py) | [Analytics tests](../../services/graph_engine/tests/test_graph_analytics.py) |
| Unified cross-domain propagation | [Engine](../../services/cbom/cbom/unified_cascade.py), [twin adapter](../../services/api/api/routers/digital_twin.py) | [Unified cascade tests](../../services/cbom/tests/test_unified_cascade.py) |
| Runs, replay and watches | [Technology API](../../services/api/api/routers/techbom.py) | The local checks below do not claim full API/history/tenant qualification |

## 7. Documentation validation record

Local checks completed for this documentation expansion on 2026-10-18:

- **64 selected tests passed in 0.89s:** unified cascade, scanner source cascade,
  graph engine, graph analytics and Istio parsing. These are selected local tests,
  not a full backend/frontend suite or a CI execution.
- The exact Bash fixture in [14](14-bank-cascade-examples.md) executed with the
  real pure engine. Assertions verified six-system device/algorithm exposure,
  eight-system application context, depth 3 versus 2, the documented process
  gaps (then seed-only; subsequently closed by step 6), and the missing hardware-link/inventory-only case.
- The system-map YAML in [12](12-dependency-discovery-and-evidence.md) parsed
  successfully through the actual `load_system_map` function and retained its
  three named systems and declared Payments API dependencies.
- The runbook's registration and cascade bodies passed the actual `EdgeRequest`
  and `CascadeRequest` models; the adoption pair also passed `EdgeRequest` as a
  shape check. The dict-based adoption/hardware examples received structural
  checks only. No write endpoint was executed and no bank records were created.
- Across the **18 Markdown files** in this directory, checks passed for **18 JSON
  blocks**, **23 Bash blocks** (syntax only except the explicitly executed local
  fixture), local links/anchors, whitespace and conflict markers.
- **69 explicit API method/path references** matched router declarations;
  **22 positive console-route references** in the console guide matched the SPA.
  These declaration checks do not prove deployed endpoint, authorization or
  browser behavior.
- No customer target, registry pull, live service-mesh query, HSM connection,
  Docker/Neo4j deployment, production outage simulation or customer acceptance
  was performed. Application behavior and CI workflows remain unchanged.

Historical SBOM/six-BOM checks remain separately recorded in
[08](08-implementation-map-and-limits.md). They are not evidence of additional
coverage for this dependency-analysis task. Production readiness decisions and
bank-specific qualification requirements remain unchanged.
