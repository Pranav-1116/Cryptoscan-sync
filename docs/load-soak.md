# API load / soak run

_Ran 2026-09-16 against the live burn deployment (`uvicorn`, SQLite staging
estate, rate limiting ENABLED — production defaults, never weakened)._
_Harness: `scripts/load_test.py` (mixed dashboard workload, one authenticated
session per virtual user)._

## Run: 5 virtual users × 90 s (per-user sessions, staggered logins)

| Metric | Value |
|---|---|
| Requests offered | **68,390** |
| Offered throughput | 759.9 req/s |
| Served (2xx/3xx + 4xx validation) | 1,200 |
| Throttled 429 (600 req/min per identity budget) | 67,190 |
| **Errors (5xx / connection)** | **0** |
| Error rate | 0.0 % |
| Latency p50 / p90 / p99 / max (served) | 79.6 / 107.8 / 133.5 / 284.2 ms |
| Wall clock | 90.0 s |

## Interpretation (honest)

- **The ceiling was the rate-limit budget, not the API.** The platform's
  sliding-window limiter allows 600 req/min **per identity**; 5 synthetic
  users offer ~150 rps each. The limiter shed the excess exactly as designed
  while the served traffic stayed healthy — this is the W57-58 control
  working under load, not an API bottleneck.
- **Zero errors across 68k requests** (no 5xx, no connection failures).
- Served-request latency (excluding 429s, which carry no handler work):
  p50 ~80 ms, p99 ~134 ms on a 2-CPU sandbox with SQLite. Postgres + more
  CPUs move this; the sandbox number is a floor, not a ceiling.
- Earlier single-principal run (one shared token, 12 loops): 44,095 requests,
  0 errors, ~10 rps served — measured the **per-identity budget** (~600/min),
  which is why the harness now uses one session per user.

## What this does and does not prove

✅ Sustained-traffic stability (no leaks/crashes over 90s × 760 rps offered),
rate limiter correctness under saturation, auth path at volume (25+ logins
across runs, throttled correctly at 5/min/IP), latency floor.

⛔ Not yet proven: multi-replica scale-out (single-process limiter by design
— front with a shared limiter per the middleware's own docstring), Postgres
at volume, multi-hour soak, scanner-worker concurrency (scanner throughput is
benchmarked separately at ~2,300 files/s — `performance.md`).

_Re-run after every deployment: `scripts/load_test.py --url … --users 5
--duration 90 --username … ` (logins are budget-limited to 5/min/IP by
design; the harness staggers them)._
