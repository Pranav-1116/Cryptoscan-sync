# Neo4j setup

PostgreSQL (or SQLite) stays the system of record for evidence. Neo4j holds the traversable relationship graph.

## Docker Compose

`docker compose up` starts `neo4j:5.26-community` on `7687` / `7474` with:

```
NEO4J_AUTH=neo4j/cryptoscan
```

The API and worker receive `NEO4J_URI=bolt://neo4j:7687`. On first graph read or after each scan, CryptoScan MERGEs systems, assets, processes, owners, vendors, certificates, and cloud accounts, then applies the Cypher files under `services/graph_engine/graph_engine/migrations/versions/`.

## Local process (no Compose)

```
export NEO4J_URI=bolt://127.0.0.1:7687
export NEO4J_USER=neo4j
export NEO4J_PASSWORD=cryptoscan
python scripts/populate_graph.py
```

Leave `NEO4J_URI` empty to keep the memory backend. Scans never fail because Neo4j is down unless `NEO4J_REQUIRED=1`.

## Browser

http://localhost:7474 — user `neo4j`, password `cryptoscan`.
