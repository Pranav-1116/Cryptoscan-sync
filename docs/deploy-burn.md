# Deployment burn — full-surface smoke

Ran 2026-09-16T06:14:43Z against `http://127.0.0.1:8010` (live process, real login).

| Metric | Value |
|---|---|
| Schema paths | 612 |
| Safe operations exercised | 360 / 365 |
| 2xx/3xx (working) | 251 |
| 400 (probe shapes the API rightly rejects) | 5 |
| 401/403 (unauthorized surfaces) | 0 |
| 404 (reachable, empty estate/params) | 68 |
| 422 (validation) | 36 |
| Other 4xx | 5 |
| 429 throttled (burst limiter active — expected) | 0 |
| **5xx / connection errors** | **0** |
| Duration | 26.2s |
| **Verdict** | **PASS** |

Zero server errors across the entire exercised surface.

## Skipped

- `/api/v1/cbom/stream/{system_id}` — SSE (long-lived) — data endpoints cover it
- `/api/v1/events/stream` — SSE (long-lived) — data endpoints cover it
- `/api/v1/security/posture/stream` — SSE (long-lived) — data endpoints cover it
- `/api/v1/stream/events` — SSE (long-lived) — data endpoints cover it
- `/api/v1/stream/stats` — SSE (long-lived) — data endpoints cover it

Method note: every GET plus read-only POSTs (health/validate/verify/stats/search markers) is exercised with a real authenticated session; destructive verbs are not fired by the burn. 404s are expected for probe IDs on an empty estate — they prove routing+authz, not data.