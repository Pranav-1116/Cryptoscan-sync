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
- `GET /api/v1/graph/impact?system_id=` — revenue / customers / scopes
- `GET /api/v1/graph/compliance?system_id=` — inherited standards
- `GET /api/v1/graph/vendor-path?system_id=` — shortest path to a vendor
- `GET /api/v1/priorities` — assets ranked by business risk

```bash
python scripts/populate_graph.py
python scripts/blast_radius_query.py payment-api --impact
```
