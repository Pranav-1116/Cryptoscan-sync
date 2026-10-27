# Eleventh bounded increment — correctness, measured performance, executed recovery

**2026-10-23 UTC.** Baseline `c48f667e3dee70b0ffc48f338004382b6543f94f`,
branch `arena/bb4b80dd-cryproscan`, PR34. Existing-product improvements only.
No workflow/main change, CI dispatch, new service/collector/profile or readiness
promotion. Publication uses `[skip ci]`, which does **not** mean CI passed.

| Requested work | Delivered evidence | Still open |
|---|---|---|
| **4 — six-BOM correctness** |21-case matrix across **SBOM, CBOM, NBOM, TechBOM, HBOM, VBOM**; corrected published baseline13fail/8pass, current matrix included in248pass. Original SBOM integrity and current SSH coverage defects fixed. | Not universal collector/reader or full-bank runtime/hardware truth qualification. |
| **5 — measure before optimizing** | User-approved relative target; N+1 demonstrated before changing it; identical native workload SQL169→20; p95≈381→42ms; exact successful JSON equality. | Selected trace target met; broader supported API/parser/browser/concurrency/large-payload workload acceptance **not complete**. |
| **6 — execute recovery** | Actual encrypted PostgreSQL dump/restore, fixture files/keys, post-backup revocation replay, SQL and attempt fences, UNKNOWN, new accepted API writes preserved through failback. Actual Redis SIGKILL/RDB loss measured and eight-role scratch reconciliation executed. | Joint production-shaped cohort/integrated consumers, external-process/site/HA/TLS and independent review **pending**. |

## Detailed records

1. [Six distinct BOM semantics, negative tests and changes](quality-six-bom-correctness-2026-10-23.md).
2. [Agreed targets, before/after methodology, samples, plans and remaining performance work](quality-trace-performance-2026-10-23.md).
3. [Actually executed recovery, loss/duration, failures, reproduction and remaining review](quality-isolated-recovery-2026-10-23.md).
4. [Machine-readable results, source hashes and raw-record hashes](quality-six-bom-perf-recovery-results-2026-10-23.json).

**Final relevant checks:**248 passing selected API/auth/SQL/worker contracts,
19 passing actual native PostgreSQL tests; no skips in either retained suite.
PostgreSQL16.2 and Redis8.2.4 are disposable local lab versions, **not current
patch or bank-authentication qualification**. Current frontend/browser performance
was not rerun. Older dated frontend/native results remain historical.

The RDB drill deliberately lost **35 of105 acknowledged scratch IDs**; later
witness replay/UNKNOWN/invalidation does not erase this loss. PostgreSQL candidate
checks took about1.224s and failback1.055s in the tiny single-writer fixture, not
a production RTO. Different-person review remains pending; no SLA or zero-loss
site claim follows from this work.
