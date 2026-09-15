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
