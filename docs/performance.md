# Static scanner performance benchmark

Measured 2026-09-15T17:32:51.562121+00:00 — `scripts/perf_benchmark.py` on a
deterministic synthetic corpus (realistic crypto API shapes; no
customer code, no fabricated findings).

| Metric | Value |
|---|---|
| Corpus | 10,000 files (2000 py / 2000 java / 2000 js / 3950 config / 50 pem) |
| Deep-scanned (per-file language parsers) | 6,000 |
| Findings raised | 16,050 |
| Parse errors | 0 |
| Wall time (whole pipeline incl. config + PEM walkers) | 4.3 s |
| Corpus throughput | **2,324.0 files/s** |
| Finding throughput | 3,730.1 findings/s |
| Status | COMPLETED |

Environment: Linux-6.1.158+-x86_64-with-glibc2.36, Python 3.11.2, 2 CPUs, single process.

These numbers describe this machine and this corpus; they are not
production-hardware claims. Re-run the script to reproduce — the
corpus is deterministic, so findings and (approximately) timings
repeat on identical hardware.

---

# API tier performance (measured 2026-09-21)

Method: live dev API (single uvicorn process, SQLite in WAL mode, 2-CPU
sandbox), endpoint mix `GET /api/v1/monitor/status` (a representative
read: auth gate → RBAC → 2 DB queries → JSON), keep-alive HTTP client,
8 concurrent virtual users unless stated. Numbers describe THIS machine;
production (PostgreSQL + Redis) has different absolute values but the
same shape of results.

## Before/after the optimization pass

| Setup (single process) | Sequential p50 | 8-way p50 | Throughput |
|---|---|---|---|
| Baseline (committed code: 8× BaseHTTPMiddleware, SQLite NullPool, uvicorn access log) | 15.0 ms | 110.6 ms | ~69 rps |
| After: pure-ASGI middleware + SQLite QueuePool + `--no-access-log` | **6.4 ms** | **41.5 ms** | **160 rps** |

Two-worker scaling (same optimized code, load split across both):
178 rps in this 2-CPU sandbox with a test suite running concurrently
(CPU was shared — on dedicated hardware the second worker scales the
single-process ceiling further; the platform's GIL-bound single event
loop is the per-process wall, which is why production runs
`--workers 2` in `deploy/ha` and `docker-compose.prod.yml`).

## What was changed, and why (each measured, not assumed)

1. **`BaseHTTPMiddleware` → pure ASGI for all 8 custom middleware**
   (`api/middleware/`): BaseHTTPMiddleware wraps every request in an
   anyio task group + memory streams; under 8-way load the event loop
   spent ~40% of its samples inside `starlette.middleware.base`
   (py-spy). The pure-ASGI equivalents wrap `send` instead —
   zero-overhead, and SSE/streaming responses are no longer buffered
   through eight task groups. Behavior is test-pinned, including the
   setdefault contract that route-set headers (e.g. the SSE stream's
   `Cache-Control: no-cache, no-transform`) are never overridden
   (`tests/unit/test_security_headers_middleware.py`).
2. **SQLite `NullPool` → `QueuePool(10)`**
   (`db/connection/engine.py`): NullPool opened a new connection and ran
   3 PRAGMAs per request (~2 ms each, measured). Under concurrency the
   connect/lock churn serialized requests on the SQLite file lock — the
   dominant cause of the 7× p50 inflation at 8-way load. Reused WAL
   connections remove it (the largest single win in this pass).
3. **`--no-access-log` in production** (`docker-compose.prod.yml`,
   `deploy/ha/docker-compose.yml`): uvicorn's access line duplicated the
   structured `http_request` log (which carries more: request_id,
   trace_id, span_id, duration). Removing the redundant line measured
   ~12% off sequential latency (A/B: 15.2 → 13.3 ms).

## Standing guidance

- **Scale horizontally, not vertically**: one worker per core. Each
  worker is GIL-bound (~150 rps for this endpoint class on a 2-CPU box);
  the HA compose already ships 2.
- Rate limiting is a deliberate budget, not a defect: load tests that
  show a high 429 share are measuring the budget ceiling (600 req/min
  per identity), not capacity.
- Scanner throughput is a different pipeline: see
  `scripts/perf_benchmark.py` (static scanner) and
  `scripts/benchmark_scan.py` (scan estate).
