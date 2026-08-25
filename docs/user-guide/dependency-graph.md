# Dependency graph and business impact

The graph engine is in-process (no Neo4j). It walks:

- systems and `CALLS` edges
- `USES` links to crypto assets
- business processes, owners, and vendors

APIs:

- `GET /api/v1/graph` — nodes + edges for the dashboard
- `GET /api/v1/graph/blast-radius?system_id=` — downstream systems
- `GET /api/v1/graph/impact?system_id=` — revenue / customers / scopes
- `GET /api/v1/priorities` — assets ranked by business risk

Add a process under **Business**, link it to a system, then re-open **Graph**.
