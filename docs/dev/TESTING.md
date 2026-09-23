# Testing

The suite is **hermetic** and **parallel**. That is what makes it a CI gate
rather than a thing people run occasionally.

## Backend

```bash
make test            # everything, xdist (-n auto, --dist loadfile), ~8 min on 2 cores
make test-serial     # per-service, one process — for debugging import/order issues
make test-live       # only tests marked `live` (real network / real PostgreSQL)
```

4,808 test functions across `services/*/tests` and `shared/*/tests`.

**Hermetic** means no test may open a non-loopback socket. The root
`conftest.py` installs `pytest-socket` so any attempt to reach GitHub, a
cloud API, an SMTP relay or a live TLS host fails immediately with
`SocketBlockedError` instead of hanging on DNS — the failure mode that made
the suite too slow and too flaky to gate on. Loopback is allowed, so the
FastAPI `TestClient`, in-process fakes and a local PostgreSQL all work.

A test that genuinely needs the network:

```python
@pytest.mark.live          # excluded from `make test` (pytest.ini: -m "not live")
def test_real_tls_handshake(): ...
```

`pytest.ini` also sets `--import-mode=importlib` (duplicate test basenames in
different services no longer collide) and a 120 s per-test timeout.

### The PostgreSQL migration-chain test

`services/database/tests/unit/test_migration_chain_postgres.py` is marked
`live` and skips unless a PostgreSQL is reachable (`CRYPTOSCAN_TEST_PG_URL`,
or the staging server on `127.0.0.1:55432`). It proves four things dev and
unit tests cannot, because they build the schema with `create_all` on SQLite:

1. `alembic upgrade head` applies on a **fresh** PostgreSQL
2. no column is left typed `uuid` where the ORM says `String(36)`
3. every model table and column exists after migration
4. `downgrade -1` and `upgrade head` both succeed

Run it with `deploy/staging/staging-up.sh up && make test-live`. The
CI equivalent is `deploy/ci-workflows/db-migration.yml`. This test exists
because the chain did not apply on PostgreSQL until 2026-09-23 and nothing
had noticed — see [PRODUCTION-READINESS.md](../PRODUCTION-READINESS.md).

## Frontend

```bash
make test-frontend   # tsc --noEmit, then vitest
```

vitest + Testing Library, jsdom, API mocked at `fetch`:

| File | Covers |
|---|---|
| `src/App.test.tsx` | app boots, login gate, routing |
| `src/pages/pages.smoke.test.tsx` | every page in `src/pages` renders without throwing against a mocked API |
| `src/components/ui.test.tsx` | ui primitives |
| `src/i18n/I18n.test.tsx` | en / ar keys resolve, no missing translations |
| `src/lib/api.test.ts` | auth header, 401 → refresh, error shaping |
| `src/lib/maturity.test.ts` | GA / beta / preview lookup matches the generated table |

Smoke-level by design: the goal is that a page that throws on mount cannot
ship, not pixel assertions.

## Longer-running checks (not part of the gate)

| Command | What |
|---|---|
| `python scripts/soak.py --hours 168 --out docs/soak-evidence/<date>` | 7-day soak of the real pipeline on Postgres+Redis ([soak-evidence/README.md](../soak-evidence/README.md)) |
| `python scripts/burn_in.py --target all` | one-shot integration burn-in: GitHub webhook round-trip, live TLS, SMTP, Neo4j, cloud, container ([burn-in.md](../burn-in.md)) |
| `python scripts/load_test.py` | API load ([load-soak.md](../load-soak.md)) |
| `python scripts/perf_benchmark.py` | scanner throughput ([performance.md](../performance.md)) |
