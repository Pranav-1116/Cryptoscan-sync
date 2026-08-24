# System overview

```
Git / local path
    → scanner (regex Java AST fallback)
    → evidence chain (SHA-256 content + chain hashes)
    → database (scans, evidence_records)
    → normalization (IANA / NIST / CBOM fields)
    → policy engine (4 baseline YAML rules)
    → drift detector (optional, vs approved baseline)
    → API + dashboard
```

The worker (`PipelineRunner`) is the only orchestrator. The API either enqueues a Redis job or runs the pipeline inline when `REDIS_URL` is empty.
