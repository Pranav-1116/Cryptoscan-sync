# Dependency graph and business impact

CryptoScan walks:

- systems and `CALLS` edges
- `USES` links to crypto assets
- business processes, owners, vendors, certificates, and cloud accounts

When `NEO4J_URI` points at a healthy Bolt listener the walk is Cypher against Neo4j. Otherwise the same model is held in process.

APIs:

- `GET /api/v1/graph` — nodes + edges + `backend`
- `GET /api/v1/graph/health` — Bolt probe
- `POST /api/v1/graph/sync` — MERGE current inventory
- `GET /api/v1/graph/blast-radius?system_id=` — downstream systems
- `GET /api/v1/graph/blast-radius?asset_id=` — the same walk from a crypto
  asset: every system that uses it (SystemAsset) is a start, and the walks
  are unioned with each system keeping its minimum hop — a shared key or
  library breaks all its users at once
- `GET /api/v1/graph/impact?system_id=` — revenue / customers / scopes
- `GET /api/v1/graph/compliance?system_id=` — inherited standards
- `GET /api/v1/graph/vendor-path?system_id=` — shortest path to a vendor
- `GET /api/v1/priorities` — assets ranked by business risk

Edge management — the graph's input side (everything above reads these
edges; this is the only write surface for them):

- `GET /api/v1/graph/edges` — list registered edges (`?relation=`,
  `?system_id=` filters by either endpoint)
- `POST /api/v1/graph/edges` — register one edge; parent/child by system id
  or name, `relation` defaults to `CALLS`. Unknown system → 404,
  self-loop → 400, duplicate → 409
- `DELETE /api/v1/graph/edges/{parent_id}/{child_id}` — remove an edge

Edges are tenant-scoped like every other row: a tenant sees its own edges
plus the un-attributed platform estate, and cannot register an edge into
another tenant's systems. Every edge carries provenance: `source`
(manual / discovered / imported), who registered it, an optional confidence
and when it was last verified.

Discovered-edge adoption closes the loop between scanners and the graph:

- `GET /graph/edges/discovered` — candidate edges the scanners already
  observed (scanner-cascade `depends_on_systems`, latest graph snapshot);
  unresolvable system names are reported, never guessed
- `POST /graph/edges/adopt` — the operator approval step: selected proposals
  become `SystemDependency` rows with `source=discovered` and the adopter's
  name. A dependency edge is a claim about production; nothing is
  registered without that approval

Two declared-linkage surfaces complete the graph model:

- `POST /graph/hardware-links` — declare which hardware device serves which
  crypto asset (never inferred); with it, device cascades name dependents
- `POST /graph/vendor-edges` — declare vendor-of-vendor (sub-tier supply
  chain) edges; vendor cascades walk them transitively

The Dependency Graph page in the UI manages edges and runs the cross-BOM
cascade (target input, verdict, affected systems by wave, run history with
diffs) next to the existing blast-radius explorer.

```bash
python scripts/populate_graph.py
python scripts/blast_radius_query.py payment-api --impact
```
