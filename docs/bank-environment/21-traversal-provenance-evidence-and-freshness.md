# 21 — Traversal provenance, evidence and freshness

**Implementation step 5, 18 October 2026.** This is implemented behavior, not a
claim that a modeled dependency is a runtime call or that an exposed bank service
will fail. Read [17](17-classified-system-scope.md),
[18](18-shared-dependency-semantics.md),
[19](19-package-artifact-deployment-identity.md) and
[20](20-relationship-lifecycle-and-reconciliation.md) first for the existing scope,
identity, relationship policy and eligibility contracts.

## 1. What changed

The additive `cryptoscan.traversal-evidence/1` format supplies explicit witnesses
alongside membership/count answers. It is carried through:

- Unified cascade: direct seed context; reverse dependent-consumer paths; forward
  supporting-context paths; separate potential paths through uncertain,
  nonterminal assertions; and declared vendor sub-tier witnesses.
- Memory and native Bolt adapters: blast radius, dependents, shortest paths and
  vendor paths. Business-impact/compliance results include the underlying system
  witnesses and separately bounded, actual domain/context links.
- Asset-start blast radius: real ownership join records and selected dependency
  witnesses across all owning systems, without borrowing an asset's confidence.
- Vendor-chain assets: actual system→vendor and system→asset edges, with mixed
  walk direction explicitly distinguished from physical edge direction.
- JSON graph export/import and SQL→graph→twin projections: relationship pointers,
  confidence meaning, recorded origin and verification timestamps survive.
- Stored new cascade answers: explanations remain part of that historical
  answer. The UI never manufactures explanations for old answers by consulting
  today's graph. Existing stored answers are not rewritten.

Process closure and economic aggregation semantics were **not** upgraded by
step 5; [step 6](22-business-process-impact-and-inclusion-reasons.md) subsequently
delivered that separate projection. Domain links explain recorded associations; the next step must resolve
process impact over all explicitly defined implicated-system scopes. XML graph
exports remain lossy external formats, not a substitute for the JSON witness
contract.

## 2. Origin is a per-edge assertion, not a path score

| Provenance | Meaning in an explanation | What it does not establish |
|---|---|---|
| `OBSERVED` | The producer labeled this specific edge as measured | Independent revalidation of its evidence or continued runtime use |
| `DECLARED` | Operator, imported declaration, supplier or registry assertion | Measured traffic, runtime deployment or outage certainty |
| `SCANNER_DERIVED` | Derived from scan/inventory evidence | A measured call between those systems |
| `INFERRED` | Correlation or heuristic association | A verified operational dependency |
| `UNATTRIBUTED` | Origin absent or unrecognized | Permission to invent a known source |

Persisted `SystemDependency.source` maps `manual`/`imported` to `DECLARED`, and
`discovered` to `SCANNER_DERIVED`. Unknown values remain unattributed. Traversal
never promotes a declaration because its confirmation is recent, its confidence
is high, or its endpoint uses a well-detected cryptographic asset.

For compact twin dependency rows, `source` is a **system endpoint ID**. The
producer's source is carried separately as `relationship_source`; canonical
witness edges restore it as their metadata `source`. A consumer's ID must never
appear as the name of the scanner that discovered the relationship.

A path can contain observed, declared, derived and unknown edges together.
`provenance_classes` and `mixed_provenance` disclose this. There is deliberately
no multiplied confidence, aggregate path confidence or inferred failure
probability. A producer-supplied `confidence` remains attached to its edge;
`confidence_meaning` is retained or explicitly unspecified.

## 3. Evidence references and gaps

Each edge includes its physical `from`/`to`, relation, origin, optional source,
assertion `record_id`, references, confidence meaning and freshness object.
References can include a supplied `evidence_ref`, lifecycle/change reference, or
structured evidence IDs and hashes. `references_verified_by_traversal` is always
false: returning a URI, hash or evidence ID does not dereference a pointer, verify
a signature, sweep a hash chain, or prove that external bytes remain available.

`evidence_missing` means that no supporting reference was supplied on that edge;
`evidence_gap_count` counts those edges in this witness. A relationship row's
identifier is useful for locating the assertion, but is not silently substituted
for missing independent support. A malformed or incomplete native path is marked
unavailable, rather than reconstructed from membership IDs.

Graph enrichment now separates `asset_detection_confidence` and asset record
creation/update times from relationship confidence and relationship timestamps.
It no longer sets `verified=true` from a `HIGH` asset confidence. Legacy `USES`
asset evidence references remain labeled **asset detection support, not proof of
a runtime relationship**. Other relationships do not inherit those references.

## 4. Timestamp meanings and expiry

Every witness edge reports its eligibility at the analysis clock and keeps:

1. `observed_at`: the producer's observation timestamp, if supplied.
2. `last_confirmed_at`: lifecycle/source confirmation; this is not a runtime
   measurement merely because a collector returned the assertion again.
3. `last_verified`: the stored verification timestamp; traversal does not repeat
   the verification or infer what that historical verification covered.
4. `valid_until`: eligibility deadline, not a promise that an operational
   relationship disappears at that instant.

Timestamp status is `MISSING`, `INVALID`, `FUTURE` or `DATED`, with a nonnegative
age only when meaningful. `DATED` deliberately does not say “fresh.” A recent
record creation timestamp is not substituted for an observation. Legacy naive
stored datetimes follow the existing UTC interpretation; supplied aware clocks
are normalized to UTC.

`UNBOUNDED` means no expiry deadline was supplied. It is not verified freshness.
The prior inclusive-expiry policy remains in force: an edge expiring at the
analysis instant is excluded from current system propagation. Stale/expired or
unknown nonterminal links can appear only in the separate potential explanation;
deleted/superseded links cannot extend that traversal. Historical replay uses its
captured/requested clock without modifying older evidence.

## 5. Direct seeds across the six BOM families

A dependency witness starts at an implicated system; it does not by itself
explain why that system was selected. `direct` and `potential_direct` carry that
separate seed context:

- **SBOM:** package PURL→explicit SBOM/release binding→registered immutable
  artifact→explicit deployment→system. Binding and deployment record IDs,
  assertion sources, evidence references, document SHA, artifact digest and
  artifact identity source remain separate. A measured artifact digest does not
  turn a deployment assertion into an observed running deployment.
- **CBOM / TechBOM:** selected evidence records keep their IDs and hashes; real
  system-asset association records are carried when present. An inventory join
  whose original producer was not recorded remains unattributed.
- **NBOM:** endpoint scan-run ID and record time, when available, are distinct
  from a registered target's system ownership. A TLS observation does not prove
  the bank independently observed that ownership association.
- **HBOM:** declared crypto↔hardware linkage records remain declared, not inferred
  from a manufacturer's name or a generic HSM capability.
- **VBOM:** recorded system-vendor mappings and separately labeled vendor-supplier
  witnesses do not become runtime system calls.

Certificate usage and process-system seed records retain available source
context. Legacy snapshots may contain only compact ID lists with no original
join metadata. Such seeds expose unverified context/empty record lists, never a
fabricated fully evidenced chain. Existing matching algorithms and ambiguity
behavior are not requalified here; exact target resolution is step 7.

## 6. Selection, bounds and direction

Each destination gets **one minimum-hop witness**, not all alternatives. System
paths remain within the shared relation policy and maximum 12 system hops. The
caller-specific depth still applies; vendor sub-tier traversal retains its
existing three-hop bound. The final vendor domain hop is not counted as an
additional propagating system dependency.

Reverse traversal changes the walk order, not the recorded relationship. A walk
`payments → gateway → mobile` can therefore contain physical edges
`gateway → payments` and `mobile → gateway`. `walk_direction` discloses this.
Mixed-direction vendor/asset walks likewise keep physical arrows intact.

Bounds are explicit:

- At most **500** witnesses per envelope, selected by sorted destination ID.
- At most 500 direct and 500 potential seed explanations; at most 20 context
  records per ordinary seed.
- At most **50** listed references per edge, including supplied/lifecycle
  references; truncation survives native serialization and re-import.
- At most 500 domain/context links or vendor-chain asset witnesses per result.
- The UI previews ten seeds and twenty paths per group and labels those display
  limits separately from response limits.

`requested_count`, `returned_count`, `missing_witness_count`, selected missing
IDs, `truncated`, and `complete_for_requested_systems` describe explanation
coverage. Missing-ID lists have a separate 200-ID cap. Completeness here means
available witnesses for the requested systems **only**. It does not certify that
inventory discovery, evidence collection or all possible dependency paths are
complete.

Membership/count calculations run independently. For example, 502 reached
systems can have 500 returned witnesses; the exposure count stays 502. A missing
native witness does not remove its system from exposure or authorize an invented
edge. Native membership aggregates remain separate from selected-property witness
queries; vendor chains fetch their actual requested neighborhood, not the entire
graph as a replacement proof.

These bounds constrain explanation payloads, not dense-graph query cost or total
serialized bytes. Native variable-length path enumeration still needs deployment
load testing. Tied legacy parallel edges without stable IDs may not have the same
selected record on different backends; no all-paths/backend-certification claim
is made.

## 7. Runnable bank example

Run with the repository service/shared packages on `PYTHONPATH`:

```python
from datetime import datetime, timezone
from cbom.unified_cascade import unified_cascade

now = datetime(2026, 10, 18, tzinfo=timezone.utc)
estate = {
    "systems": [{"id": s, "name": s} for s in ("mobile", "gateway", "payments", "ledger")],
    "dependencies": [
        {"id": "edge-1", "source": "mobile", "target": "gateway", "type": "CALLS",
         "relationship_source": "mesh", "provenance": "OBSERVED",
         "observed_at": "2026-10-17T12:00:00Z", "evidence_ref": "mesh:span-42"},
        {"id": "edge-2", "source": "gateway", "target": "payments", "type": "CALLS",
         "relationship_source": "change-register", "provenance": "DECLARED",
         "last_confirmed_at": "2026-10-17T12:00:00Z", "evidence_ref": "change:42"},
        {"source": "payments", "target": "ledger", "type": "IMPORTS"},
    ],
}
answer = unified_cascade(estate, target="payments", kind="system", now=now)
scope = answer["impact"]["system_classification"]
assert scope["exposure_system_count"] == 3
assert scope["review_system_count"] == 4
explanation = answer["traversal_evidence"]
mobile = next(p for p in explanation["dependent_consumers"]["paths"] if p["system_id"] == "mobile")
assert mobile["nodes"] == ["payments", "gateway", "mobile"]
assert mobile["available"] and mobile["mixed_provenance"]
assert mobile["edges"][0]["provenance"] == "DECLARED"
assert mobile["edges"][0]["from"] == "gateway"
assert mobile["edges"][0]["freshness"]["observation"]["status"] == "MISSING"
assert mobile["edges"][1]["evidence_references"] == ["mesh:span-42"]
ledger = explanation["supporting_context"]["paths"][0]
assert ledger["edges"][0]["provenance"] == "UNATTRIBUTED"
assert ledger["evidence_gap_count"] == 1
```

The mobile consumer path has mixed provenance. Its first hop is declared despite
recent confirmation. Ledger is supporting context with missing origin/reference
metadata, not an additional predicted failed service.

## 8. Migration, checks and remaining acceptance

Apply migration **0100** after 0099 before running the updated ORM/API against an
existing database. It adds nullable `system_dependencies.evidence_ref` (500
characters) and `confidence_meaning` (200 characters). Legacy rows retain nulls;
no historical proof or verification time is backfilled. Downgrading removes these
two fields and therefore loses their values; retain/export required evidence
before any downgrade.

Focused regressions cover source/endpoint separation, mixed provenance, reverse
orientation, observation-vs-confirmation, invalid/future timestamps, missing native
paths without lost counts, software seed chains, unknown legacy seed linkage,
reference truncation/re-import, and the 500-witness bound across both adapters.
Migration tests exercise real SQLite upgrade/downgrade. UI tests cover legacy
unavailability, pointer text without automatic links, physical arrows and bounds.

Local release checks: **1,996 backend tests passed, 1 skipped and 7 deselected**;
**358 frontend tests passed across 39 files**; TypeScript checking, production
build, changed-Python F/E9 lint, documentation links/JSON/shell/API-route checks
and the runnable example passed. These local results are not a live bank-estate
acceptance certificate. CI workflows were not changed.

The Bolt double does not parse/execute Cypher. Real Neo4j, PostgreSQL concurrency,
dense-graph load, external pointer verification, full bank role/tenant negatives,
and independent evidence qualification remain open. Step 6 is now delivered in [guide 22](22-business-process-impact-and-inclusion-reasons.md);
steps 7–10 remain pending;
read the [implementation roadmap](../dev/dependency-intelligence-roadmap.md).
