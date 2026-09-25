# Production readiness — where the platform stands and why

_2026-09-23. Assessed against evidence in this repository (tests, staging
runs, soak data), not against the roadmap. Numbers are a judgement; every
line that moves them points at the file that justifies it._

## The number

**~80% overall. The core path is ~92%.**

"Core path" means: source scan → evidence chain → normalise → policy → dedup
→ CBOM → drift → gate → alert, running as separate API / worker / monitor
processes on PostgreSQL + Redis with `ENVIRONMENT=production` guards on.
That path has now been exercised end to end on a real PostgreSQL, and every
defect it exposed is fixed with a regression test.

Everything outside the core is labelled **beta** or **preview** in the UI and
at `GET /api/v1/platform/capabilities` ([CAPABILITY-MATURITY.md](CAPABILITY-MATURITY.md):
33 GA · 30 beta · 8 preview). Those labels are the honest scope statement; a
beta surface is not counted against the core number, but it is not counted
*for* production either.

## What changed on 2026-09-23 and why it moved the number

| Item | Before | Now | Evidence |
|---|---|---|---|
| Test suite | serial, >30 min, hit real hosts, effectively not a CI gate | **hermetic** (loopback-only sockets) and **parallel** (xdist, `make test`, ~8 min on 2 cores), 4,808 test functions; `make test-live` for the opt-in real-network tests | `conftest.py`, `pytest.ini`, `Makefile` |
| Frontend tests | none | vitest smoke suite: app boots and routes, every page renders against a mocked API, ui primitives, i18n en/ar, api client auth | `frontend/src/**/*.test.ts(x)`, `make test-frontend` |
| Scope | 52 services presented as equal | GA / beta / preview from one source of truth (`shared_models/capability_maturity.py`), shown in the nav and page headers, served by the API and GraphQL | `docs/CAPABILITY-MATURITY.md` (generated) |
| Migrations on PostgreSQL | **never run on a real PostgreSQL**; `alembic upgrade head` failed at 0011 on a fresh database | 60-revision chain applies on fresh PostgreSQL 16; guarded by `test_migration_chain_postgres.py` (chain applies, no `uuid` columns remain, schema == models, downgrade/upgrade) | `services/database/migrations/versions/0011_*.py`, `0060_*.py` |
| Scans on PostgreSQL | **every scan failed** at the policy stage (`UUID is not JSON serializable`; 15 columns typed `uuid` vs ORM `String(36)`) | migration 0060 converts them; scans complete with `chain_intact: true` | `docs/soak-evidence/2026-09-23-staging/` |
| Worker disk | one workspace directory leaked per job, forever | fixed (`WorkspaceManager.cleanup` resolved-path compare) + regression tests | `services/worker/worker/workspace/workspace_manager.py` |
| Staging | Docker compose only | `deploy/staging/staging-up.sh`: embedded PostgreSQL 16 + Redis 7 + api/worker/monitor with production guards, no Docker, up in ~8 s | `deploy/staging/` |
| Soak harness | `burn_in.py` (one-shot integrations) | `scripts/soak.py` cycles the real pipeline and samples RSS/fds/PG connections/queue every cycle; `scripts/soak_report.py` renders evidence | `docs/soak-evidence/README.md` |

The three PostgreSQL defects are the important part. Before this date a
fresh PostgreSQL install of this product could not run its migrations, and
with the migrations patched by hand it could not complete a scan. Dev and
tests used SQLite with `create_all` from the models, so nothing caught it.
That was a hidden zero under an otherwise plausible readiness story, and it
is why the earlier ~70–75% estimate was, in hindsight, generous.

## What keeps it at 80

| Gap | Weight | Detail | Closes when |
|---|---|---|---|
| **Soak is ~20 min, not 7 days** | largest | Leaks, connection exhaustion and queue stalls show over days. One leak was found in 20 minutes; nobody can say there is not another at hour 40. | `scripts/soak.py --hours 168` on a host that stays up; pass criteria in `docs/soak-evidence/README.md` |
| ~~**No capacity number**~~ — closed | — | Closed 2026-09-25. Re-run with one machine API key per virtual user (`scripts/load_test.py --identity api-keys`, VUs paced at 8 rps under the 600/min identity budget) on the 2-vCPU sandbox, single uvicorn worker, SQLite: **20 VUs → 159 rps, 100 % 200s, p50 7.9 ms / p99 105 ms; 50 VUs → 181 rps, p50 274 ms** — i.e. ~180 authenticated DB-backed rps per API worker before latency climbs; scale is horizontal (N workers behind the ingress). The run found and fixed three real defects: (1) API keys created *with* an expiry were rejected 401 on first use (naive SQLite datetime vs aware `utcnow()` → TypeError swallowed as "invalid key"; regression test added); (2) the session revocation check ran synchronously inside the ASGI auth middleware and blocked the event loop while waiting for a DB connection — with > `pool_size` concurrent session requests every request stalled for the 30 s pool timeout (now `run_in_threadpool`, pool overflow 20, timeout 10 s); (3) the load test counted 401/404 as success (now any non-2xx/3xx except 429 is an error and the per-status histogram is printed). | Re-measure on the target host with Postgres; RSS grew 158 → 181 MB over ~120 k requests, watch in the 7-day soak. |
| **Neo4j, cloud, container never burned live** | medium | `burn_in.py` skips them honestly on a host without Neo4j / credentials / Docker. These are also exactly the surfaces labelled beta/preview. | run `burn_in.py --target all` on a host with all three |
| ~~**Crashed job stays QUEUED forever**~~ — closed | — | Closed 2026-09-25: the worker now dequeues with `BLMOVE` into a per-worker processing list and acks only when the scan finished (either way); a lease key (TTL `JOB_LEASE_TTL_SECONDS`, 60 s) marks live workers; `recover_orphans` requeues the processing lists of dead workers (head of queue, `_attempts` counter, dead-letter list + DB `FAILED` after `JOB_MAX_REDELIVERIES`); a DB reaper fails `RUNNING` rows with no progress for `JOB_RUNNING_TIMEOUT_MINUTES` and re-publishes `QUEUED` rows missing from Redis for `JOB_QUEUED_TIMEOUT_MINUTES` (at most twice). Runs at worker start and every 60 s. Redis < 6.2 falls back to the old at-most-once `BLPOP` with a logged warning. Tests: `services/worker/tests/unit/test_job_path_hardening.py` (fakeredis + sqlite). | Closed — verify once on the target host with `REDIS_URL=… python scripts/queue_kill9_drill.py` (spawns a worker process, `SIGKILL`s it while the job is in its processing list, asserts nothing is recovered before lease expiry and exactly one redelivery with `attempts=1` after it; own queue name, cleans up; exit 0 = PASS). The sandbox has no Redis binary and no Docker, so only the `--fake` self-check ran here (PASS); the runbook: [runbooks/job-queue.md](runbooks/job-queue.md) |
| **Single api / worker process tested** | small | `deploy/ha/` exists but was not exercised in this pass; **not executable in this sandbox** (no Docker/compose, no Redis or PostgreSQL binaries — the pipeline evidence here used SQLite + fakeredis, and the multi-process evidence is the in-process scan pool, `docs/scale/`). Same limitation applies to the SSO/SAML GA sign-off (needs a bank IdP), the ITSM/SIEM connectors (need ServiceNow/Splunk endpoints) and the air-gap *update* drill (needs a second, disconnected host); each has a runbook but no measured run. | HA drill, IdP integration test, connector smoke and offline-update drill on the target host, in that order |
| **External attestation** | n/a | SOC 2 / ISO 27001 of the product itself is a company action. [soc2-readiness-gap-analysis.md](soc2-readiness-gap-analysis.md) | — |

## How to check this yourself

```bash
make test                      # hermetic backend gate, ~8 min
make test-frontend             # vitest
deploy/staging/staging-up.sh up  # real PostgreSQL + Redis, production guards
make test-live                 # includes the PostgreSQL migration-chain test
python scripts/soak.py --cycles 3 --interval 10 --out /tmp/soak-check
python scripts/burn_in.py --target all --api http://127.0.0.1:8010 ...
```

## Related

- [PLATFORM-STATUS.md](PLATFORM-STATUS.md) — capability-by-capability history of the plan vs. what ships
- [CAPABILITY-MATURITY.md](CAPABILITY-MATURITY.md) — GA / beta / preview per surface (generated)
- [enterprise-readiness.md](enterprise-readiness.md) — what a bank will ask for
- [soak-evidence/](soak-evidence/README.md) — raw soak, burn-in and load data
- [production-evidence.md](production-evidence.md) — signed one-command evidence run
- [ops/production-checklist.md](ops/production-checklist.md) — go-live checklist
