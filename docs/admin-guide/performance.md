# Scan Performance Benchmark

The original spec's acceptance criterion — **"10,000 files scanned in under
5 minutes"** — is now measured, reproducible, and enforced by a script.

## Latest result (2026-08-28, this repository's CI environment)

| Metric | Value |
|---|---|
| Corpus | 10,000 generated files (Java/Python, deterministic seed 1337) |
| Pipeline | full inline run: workspace clone → language detect → scanners → evidence chain → policy → dedup → graph → business enrich → persist |
| **Wall clock** | **59.1 s** steady-state (budget 300 s — PASS with ~5× headroom) |
| Throughput | ~169 files/s |
| Evidence records | 10,000 (≥1 crypto finding per file) |
| DB state at run time | already held ~20k evidence records + ~10k assets from prior runs |

### Regression the benchmark caught (and fixed) on its first run

The first 10k run clocked 90.3 s — and a follow-up 50-file scan against
the now-loaded database took **49.7 s** (vs 2.1 s on an empty DB): per-scan
cost was growing with accumulated history. Profiling showed the business
enrichment stage computed a full-graph blast-radius BFS **per asset**
(10.5k assets → 10.5k BFS traversals per scan), and the asset repository
loaded every historical asset row plus one PK query per asset. After
per-system memoization of `business_impact`, identity-filtered asset
loading, and bulk evidence-link fetching, the same 50-file scan runs in
**7–9 s** on the loaded DB (measured 6.9 s and 8.9 s across runs) and the 10k run dropped to 59.1 s.

Every file in the corpus contains real cryptographic usage (Cipher
transformations incl. weak modes, MessageDigest incl. MD5/SHA-1, RSA
KeyPairGenerator, pycryptodome/cryptography calls, hardcoded keys), so the
scanners, normalizer, policy engine, and dedup all do full work — this is
not a trivial-file smoke test.

## Reproduce

```bash
python3 scripts/benchmark_scan.py                 # 10k files, 300s budget, exit 0 on PASS
python3 scripts/benchmark_scan.py --files 1000    # quicker regression check
python3 scripts/benchmark_scan.py --files 100 --keep   # inspect the generated corpus
```

Exit code `0` = within budget, `1` = over budget (usable as a CI perf
gate), `2` = pipeline failure. The corpus is deterministic (`--seed`), so
numbers are comparable across commits and machines — compare only within
one machine class.

## Interpreting regressions

- The run includes one-time startup (DB session, workspace copy of the
  corpus); small corpora (`--files 100`) therefore show lower files/s
  than large ones.
- 10k evidence records also stress the dedup stage (canonical identity
  grouping) and the policy engine (10k evaluations) — regressions in
  either show up here directly.
- The benchmark writes a real scan into the configured database; run it
  against a scratch database (`DATABASE_URL`) or delete the scan after.

## Query indexes (W59-60)

Five composite indexes cover the measured hot queries (declared on the models for
fresh databases, mirrored in migration `0026` for existing deployments):

| Index | Hot query |
|---|---|
| `evidence_records (scan_id, chain_position)` | per-scan evidence listing, chain verification |
| `evidence_records (scan_id, compliance_status)` | failing findings per scan — remediation suggestions, migration auto-tasks, gate evidence |
| `crypto_assets (algorithm, file_path)` | asset listing filter + ordering |
| `systems (current_agility_score)` | agility ranking dashboards |
| `migration_tasks (project_id, status)` | migration progress/status derivation |

PostgreSQL-only tuning from the original spec that we do **not** claim here:
partitioning (pg_partman), PgBouncer pooling, JSONB GIN indexes, and
materialized views — those are deployment-layer choices, verified in
`docs/admin-guide/air-gap-install.md` territory, not code this repo ships.

## Response compression (W59-60)

`GZipMiddleware` (minimum 1024 bytes) wraps the API. Bulk JSON (asset lists,
template catalogs, reports) compresses ~5–10× in practice; clients that send
`Accept-Encoding: identity` always receive plain bytes. Note: the logging /
request-ID middleware chain re-streams responses, which removes
`Content-Length` — in that topology every accepted-encoding response is
compressed regardless of the 1024-byte floor.

## Estate findings export (W59-60)

`GET /api/v1/export/findings.csv?algorithm=&compliance_status=&scan_id=&limit=`
— Excel-compatible CSV over all scans (honest scope: CSV, not `.xlsx`).
Rows are capped (`limit` ≤ 50,000) so one request cannot exhaust memory;
`X-Total-Matching`, `X-Exported-Rows`, and `X-Truncated` report the whole
truth on every response.
