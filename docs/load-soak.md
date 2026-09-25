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

## 2026-09-23: 20 users × 180 s on the Postgres staging stack

78,039 requests, 433 rps, **0 errors**, p50 164 ms / p99 321 ms — but 75,665
of them were 429. All twenty virtual users log in as the same `admin`, so the
production per-identity budget (600 req/min) was the ceiling; the API tier
answered every one of those 433 rps correctly and stayed up, which is the
resilience result, not a capacity result. Raw output and the concurrent soak
in [`docs/soak-evidence/2026-09-23-staging/`](soak-evidence/2026-09-23-staging/REPORT.md).
To measure capacity, give each virtual user its own API key.

## Re-run 2026-09-25 — one identity per virtual user

`scripts/load_test.py` now defaults to `--identity api-keys`: the admin session mints one
read-only machine key per VU (1 h expiry, revoked at the end), each VU is paced at
`--rps-per-user 8` (< 600/min), and any non-2xx/3xx status other than 429 counts as an
error (`by_status` histogram in the output). Sandbox: 2 vCPU, one uvicorn worker, SQLite.

| VUs | requests / 30 s | rps | 200s | 429s | p50 | p90 | p99 |
|---|---|---|---|---|---|---|---|
| 20 | 4 785 | 158.9 | 100 % | 0 | 7.9 ms | 44.8 ms | 104.5 ms |
| 50 | 5 466 | 181.1 | 100 % | 0 | 273.7 ms | 346.9 ms | 450.0 ms |

Capacity of one API worker on this box is therefore ~180 authenticated, DB-backed requests
per second; beyond that latency climbs while the error rate stays 0. Contrast run,
`--identity shared-session` with 20 VUs unpaced: 37 196 requests, 36 596 of them 429 — the
original "97 % 429" result reproduced, confirming it measured the per-identity budget.

Defects found by this run (all fixed, see PRODUCTION-READINESS): keys with an expiry were
rejected on first use; the auth middleware blocked the event loop on the revocation lookup
(20 concurrent session requests → every request 30 081 ms); the load test scored 401/404 as
success.
