# ADR-001 PostgreSQL over NoSQL

## Status

Accepted.

## Context

Scans, evidence, baselines, drift, assets, and systems are relational. We
need foreign keys, transactions around the evidence chain, and portable local
dev.

## Decision

Use SQLAlchemy against PostgreSQL in Compose. SQLite is the local stand-in
(`data/cryptoscan.db`) with JSON instead of JSONB.

## Consequences

JSONB-only queries are skipped on SQLite. Combined multi-service pytest is
avoided because of `tests.conftest` path clashes, not because of the database.
