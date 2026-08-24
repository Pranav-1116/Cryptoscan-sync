# System overview

CryptoScan is a deterministic cryptographic inventory platform. A scan never
asks a model to decide whether an algorithm is allowed — policy is YAML, hashes
are SHA-256, and the worker is a single synchronous pipeline.

```
Git URL or local:// path
        │
        ▼
 ┌──────────────┐     language detect (Java / Python / JS / C#)
 │   Scanner    │──── regex + stdlib `ast` (no tree-sitter / Roslyn required)
 └──────┬───────┘
        │ RawFinding
        ▼
 ┌──────────────┐     content hash + chain hash
 │   Evidence   │
 └──────┬───────┘
        ▼
 ┌──────────────┐     SQLite locally / Postgres in Compose
 │   Database   │
 └──────┬───────┘
        │
        ├── Normalization (IANA / NIST / CBOM fields)
        ├── Policy engine (baseline + scoped PCI / NIST / CNSA / FIPS / HIPAA)
        ├── Dedup → crypto_assets
        ├── Drift vs approved baseline
        └── CBOM (CycloneDX 1.5)
        │
        ▼
 API (`/api/v1`) + dashboard (`index.html`)
```

The worker (`PipelineRunner`) is the only orchestrator. The API either
enqueues a Redis job or runs the pipeline inline when `REDIS_URL` is empty.

Part 2 additions (this tree):

- Multi-language static scanners (Python AST, JS/C# regex)
- Container / image-root inventory (package manifests + JAR string scan)
- Deduplicated asset inventory and simple systems
- CycloneDX 1.5 CBOM, including `POST /cbom/custom`
- Scoped advanced policy (PCI-DSS, NIST SP 800-131A, CNSA 2.0, FIPS, HIPAA)

Still out of scope: network/runtime/cloud, full graphs, AI, OT/ICS, GitHub
workflow fills, tree-sitter/Roslyn as hard dependencies.
