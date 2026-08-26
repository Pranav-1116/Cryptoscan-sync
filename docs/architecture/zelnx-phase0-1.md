# ZELNX CryptoScan — Phase 0 / Phase 1 architecture

This repository is already a **modular monolith**, not an empty tree. Phase 0
and most of Phase 1 are running as CryptoScan on isolated Compose ports
(55432 / 56379 / 57474 / 57687 / 8088). This document is the architecture
plan for completing the Phase 1 vertical slice **without rewriting the core**.

## What we will not do in Phase 0 / 1

- Do not rename the product tree into `apps/` + `scanners/` + `packages/`.
  Extraction later is possible because service packages already have
  boundaries (`scanner`, `evidence`, `policy`, `worker`, `api`).
- Do not add RabbitMQ, MinIO, or Celery. Redis + a synchronous
  `PipelineRunner` is the working orchestrator. Swapping the broker later
  does not require a new discovery engine.
- Do not fill `services/dashboard/src` (React shells are placeholders).
  The operator UI is `services/dashboard/index.html`.
- Do not change host ports, copy foreign `.env` files, or depend on
  tree-sitter / Eclipse JDT / Roslyn as hard requirements.
- Do not invent tenant rows or fake scanner findings to decorate the UI.

## Existing map (keep)

```
discover   → services/scanner (+ cloud / container / network)
evidence   → services/evidence (canonical JSON, SHA-256, chain)
persist    → services/database (Postgres in Compose, SQLite local)
normalize  → services/normalization
dedup      → services/deduplication
policy     → services/policy (YAML packs)
cbom       → services/cbom
drift      → services/drift
graph      → services/graph_engine (Neo4j, memory fallback)
worker     → services/worker (Redis queue or inline)
api        → services/api (FastAPI `/api/v1`)
ui         → services/dashboard/index.html
```

Pipeline (already the product principle):

repository → scan → RawFinding → evidence chain → normalize → asset →
policy → drift → CBOM → API → dashboard.

## Phase 0 (foundation) — status

| Requirement | Status |
|---|---|
| Compose (Postgres, Redis, Neo4j, API, worker, nginx) | Done, isolated ports |
| FastAPI + health `/health` `/ready` | Done |
| Dashboard login | Done (`admin` / `cryptoscan` in development) |
| Migrations / schema ensure | Done |
| `.env.example` (no secrets in git) | Done |
| Local scripts | `scripts/run_stack.sh`, `scripts/dev_setup.sh` |

Added this slice: `scripts/bootstrap-local.sh`, `scripts/zelnx` (evidence verify).

## Phase 1 (Java → evidence → API) — this slice

| Requirement | Implementation |
|---|---|
| Java AST, not regex-only | `scanner/parsers/java_ast.py` walks tokens/invocations; comments ignored; local string constants resolved. Regex remains a fail-open fallback. |
| Python / JS / C# plugins | Same `DiscoveryPlugin` contract. Python uses stdlib `ast` (local `hashlib.new(name)` resolved). JS/C# strip comments before regex and resolve JS locals. |
| Parse errors do not abort the scan | `Scanner.scan` already isolates per file; AST does not require balanced braces. |
| Canonical observation | `shared_models.observation.CryptoObservation` |
| Plugin contract | `scanner.core.plugin.DiscoveryPlugin` + Java/Python/JS/C# source plugins |
| Evidence hash + chain | Existing `ContentHasher` / `ChainHasher` |
| Verify command | `scripts/zelnx verify-evidence-chain --scan-id` → `VALID` / `INVALID` / `BROKEN_AT_SEQUENCE` |
| Findings + scan API + dashboard | Already present |

## Later phases (do not start here)

Multi-tenancy, OIDC, RabbitMQ/MinIO, Helm, simulation engine, sector policy
packs as a separate product line, and a React rewrite stay behind this
vertical slice. The plugin interface and observation contract are the
extension points those phases will use.

## Folder structure (actual, not a second monorepo)

```
CryproScan/
  docker-compose.yml          # local / isolated
  docker-compose.prod.yml     # nginx :80 only
  services/{api,worker,scanner,evidence,database,policy,cbom,...}
  shared/{shared_config,shared_logging,shared_models}
  docs/{architecture,plugin-sdk.md,api-reference}
  scripts/{bootstrap-local.sh,zelnx,verify_evidence_chain.py}
  demo/                       # fixtures, not production data
```
