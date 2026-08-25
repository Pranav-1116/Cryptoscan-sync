# ADR-010 Neo4j for the dependency graph

## Status

Accepted.

## Decision

Store evidence and inventory in PostgreSQL / SQLite. Store traversable relationships in Neo4j and query them with Cypher. When Bolt is not configured or not healthy, the same graph is built in-process so CI and laptops keep working.

## Consequences

- Blast-radius, business-impact, compliance inheritance, and vendor-path queries are real Cypher.
- Neo4j is optional infrastructure, not a hard runtime dependency.
- A scan job MERGEs the current inventory after dedup; `POST /api/v1/graph/sync` can be used by operators.
