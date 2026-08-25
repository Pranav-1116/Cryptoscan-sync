# Blast-radius analysis

If a crypto asset or system fails, CryptoScan walks `(:System)-[:CALLS*1..N]->(:System)` and reports every downstream system plus the business processes those systems support.

```bash
python scripts/blast_radius_query.py payment-api --hops 5
python scripts/blast_radius_query.py payment-api --impact
```

APIs:

- `GET /api/v1/graph/blast-radius?system_id=&hops=`
- `GET /api/v1/graph/impact?system_id=`
- `GET /api/v1/graph/compliance?system_id=`
- `GET /api/v1/graph/vendor-path?system_id=`

When `NEO4J_URI` is set and Bolt answers, those queries run as Cypher. Otherwise the same traversal runs in-process against the relational inventory.
