# CryptoScan (ZELNX) — Codebase Audit Report

**Branch reviewed:** `arena/01a07cf0-cryproscan` (260 commits, the branch you meant)
**Date:** 2026-09-08
**Scope:** backend microservices, frontend SPA, database layer, README, build/test toolchain.

---

## 1. Executive summary

This is a large, unusually well-engineered crypto/security inventory & compliance platform.
The architecture is coherent and **security-conscious**: fail-closed production config
validation, PBKDF2-SHA256 (210k iterations) password hashing with constant-time compare,
account lockout, anti-enumeration login, RBAC + optional ABAC, Redis-backed distributed
rate limiting, security headers, audit trail, immutable evidence chain, and 51 ordered
Alembic migrations. The frontend is genuinely live-data-only (no demo dataset).

**Overall verdict: structurally sound and mostly green — but not "shippable as-is."**
The test suite is overwhelmingly green across ~20 suites, yet there are a small number of
**real, reproducible defects** (schema/migration drift, two runtime `NameError`s, a stale
test, empty CI workflows, a broken local Makefile path) plus **test-suite hangs** caused by
live network I/O in tests and some lint debt. None of these are architecture-killing, but
several would bite in production or CI.

---

## 2. What is genuinely good (verified)

- **Fail-closed runtime validation** — `services/api/api/config/settings.py::validate_runtime_settings()`
  refuses to start in `production` on weak `SECRET_KEY` / admin password / webhook secret /
  SQLite / wildcard CORS.
- **Password & auth hygiene** — PBKDF2-SHA256 210k iterations, `hmac.compare_digest`,
  password-strength policy, account lockout (8 failures / 900s), uniform
  "Invalid username or password" (anti-enumeration), TOTP + OIDC + session-manager support.
- **Data layer** — 51 ordered Alembic migrations; SQLite↔PostgreSQL abstraction with health
  checks (WAL + NullPool for dev, QueuePool + `statement_timeout=30s` + `pool_pre_ping` for prod).
- **Frontend** — `tsc --noEmit` passes with **0 errors**; `vite build` succeeds. Browser never
  calls localhost (Vite proxies `/api` → `:8010`). No mock/demo data — every call goes live.
- **Scale** — 42 backend services, 70 API routers mounted under `/api/v1`, ~45 ORM models,
  ~35 repositories, ~54 frontend pages, ~3,487 test functions across 438 test files.
- **Test health** — the following suites are **fully green**: policy (68), evidence (43),
  normalization (114), drift (72), deduplication (12), cbom (48), graph_engine (41),
  remediation (21), reporting (37), business_context (6), quantum (21), universal_crypto (134),
  universal_vendor (336), cloud_scanner (411), container_scanner (107), ot_scanner (39),
  runtime (31+1), vendor_intel (12), agility (37), payment_crypto (26), universal_platform (20),
  sector_profiles (17), worker unit (124), shared_models (165), scanner (107+12 skip).

---

## 2b. Fixes applied (updated after implementation)

| Bug | Fix | Status |
|-----|-----|--------|
| 3.1 schema/migration drift | Added **migration `0052`** adding `api_keys.allowed_ips` + `rotate_after_days` (matches the `ApiKey` ORM model) | ✅ `test_schema_parity.py` passes |
| 3.2a NameError `Fernet` | Imported `Fernet` in `services/api/api/routers/resilience.py` | ✅ ruff F821 clean |
| 3.2b NameError `db` | Added `db: Session = Depends(get_db_session)` to `airgap_build()` | ✅ ruff F821 clean |
| 3.3 stale acceptance test | Made `test_acceptance_demos.py` data-driven; replaced the `CC6.7→BASELINE-005` fail target (a **shared** prefix that cascaded to SC-8/Art.9/Art.20) with `SA-15→SBOM-001` (unique) | ✅ 2 passed |
| 3.4 empty CI workflows | Repopulated `ci.yml`, `db-migration.yml`, `docker-build.yml`, `scanner-tests.yml` (lint + migration gate + frontend typecheck/build + deterministic test gate) | ✅ files non-empty |
| 3.5 stale Makefile PYTHONPATH | Replaced the hardcoded 30-dir list with `find $(ROOT)/services $(ROOT)/shared -mindepth 1 -maxdepth 1` auto-discovery; made `PY` fall back between `.venv`/`venv` | ✅ `make test` runs |
| 3.6 test-suite hangs | Added `pytest-timeout` + root `pytest.ini` (120s per-test); added `_under_test()` guard so the app lifespan's event tailer/telemetry don't start under pytest (fixes the teardown hang when fixtures set `ENVIRONMENT=development`); **fixed a real product bug** in the network scan router (below) | ✅ `test_enforcement_delivery` exits clean |
| 3.6b **NEW real bug** | `services/api/api/routers/network.py` — `scan_network()` called `scan_hosts(safe_hosts, body.hosts, ...)` with a **second positional arg** that `scan_hosts()` doesn't accept → `TypeError` on every `/api/v1/network/scan`. Removed the extra `body.hosts`. | ✅ `test_network_run_persistence.py` 7 passed |
| 3.7 lint debt | `ruff --fix` over production code (unused imports). The remaining F401s are intentional `__init__.py` re-export facades (documented). Also fixed a test F821 (`Any` unimported). | ✅ production lint-clean |
| 3.8 frontend bundle | Converted `frontend/src/App.tsx` static page imports to `React.lazy` + `<Suspense>` → route-level code splitting | ✅ index 554→208 KB, page chunks 6–26 KB, typecheck+build clean |
| 3.9 JWT in localStorage | **Not changed** (hardening recommendation only; an auth-transport switch is a larger change) | ⏸ kept as recommendation |

---

## 3. Defects found (priority order)

### 3.1 — HIGH: Schema/migration drift on `api_keys`
**Where:** `services/database/tests/unit/test_schema_parity.py`
**Reproducible failure:**
```
AssertionError: alembic head is missing model columns (add them to the next migration):
{'api_keys': ['allowed_ips', 'rotate_after_days']}
```
The `ApiKey` model (`services/database/db/models/api_key.py`) declares columns
`allowed_ips` and `rotate_after_days`, and they are used by the api-key repository,
router, and identity guard — **but no migration creates them** (grep across
`migrations/versions/` finds zero references). SQLite dev builds the table with
`create_all` so it works there; **PostgreSQL/`alembic upgrade head` would produce a
table missing those columns** → runtime `OperationalError` on key create/rotate.

**Fix:** add a migration (e.g. `0052`) that adds the two nullable columns, or reconcile the
model vs. migration 0047. This is the single clearest prod-affecting defect.

### 3.2 — HIGH: Two runtime `NameError`s in the resilience/airgap API
**Where:** `services/api/api/routers/resilience.py`
- **Line 54** — `_EPHEMERAL_FERNET = Fernet.generate_key()` but `Fernet` is **never imported**
  in the module (no `cryptography.fernet` import anywhere). This fallback path runs whenever
  no `BACKUP_ENCRYPTION_KEY` and no persisted backup key exist → `NameError: name 'Fernet' is not defined`.
- **Line 486** — `airgap_build()` calls `_signing_secret(db)` but the function signature is
  `airgap_build(body, user)` with **no `db` parameter** → `NameError: name 'db' is not defined`
  on `POST /api/v1/resilience/airgap/build-bundle`.

These are exactly what `ruff F821` flagged. Both are real latent crashes reachable via API.

### 3.3 — MEDIUM: Stale acceptance test (asserts 19, reality is 29)
**Where:** `services/api/tests/unit/test_acceptance_demos.py::test_compliance_demo_three_violations_across_full_pool`
```
assert len(pool) == 19   # 15 estate + 4 payment PCI requirements
AssertionError: assert 29 == 19
```
The compliance template registry (`reporting.report_templates.py`) now has **8 templates**
(added DORA, NIST SP 800-131A, FIPS 140-3, SOC2, ISO 27001, SP 800-53, UAE PDPL) yielding
29 unique requirement IDs. The test was never updated when new templates landed — i.e. the
**test lags product growth**, not the reverse.

### 3.4 — MEDIUM: All 4 GitHub Actions workflows are empty (0 bytes)
`.github/workflows/ci.yml`, `db-migration.yml`, `docker-build.yml`, `scanner-tests.yml`
are **all 0 bytes**. CI currently does **nothing** — no lint, no typecheck, no test run, no
migration gate, no docker build. (Commit history notes "Revert workflow file fills so the
branch can be pushed.") This explains why the F821 bugs and schema drift reached the branch.

### 3.5 — MEDIUM: Stale/broken local Makefile `PYTHONPATH`
`Makefile` sets a **hardcoded** `PYTHONPATH` listing only 30 services. **16 service dirs are
missing**, including ones the API imports directly (`identity`, `governance`, `anomaly`,
`marketplace`, `datalake`, `automation`, `devsecops`, `control_plane`, `apikeys`, `keyassure`,
`ot_safety`, `ruleset`, `sla`, `vaultlease`, `sector_profiles`, `dashboard`). Consequence:
`make api` / `make test` fail locally with `ModuleNotFoundError: No module named 'identity'`.
Docker works because `.docker/api/Dockerfile` builds a **`.pth` file that auto-discovers every
`services/*/` and `shared/*/` package**. The fix is to switch the Makefile to the same
discovery mechanism (or use the `.pth` in the local venv).

### 3.6 — LOW/MEDIUM: Test-suite hangs from live network I/O
Two large suites hang when run as a whole but pass per-file:
- `services/network_scanner/tests` (585 tests) — hangs at
  `test_deep_probes.py` (real OpenSSL TLS server + live sockets; ordering/stress dependent).
- `services/api/tests/unit` (483 tests) — hangs at
  `test_enforcement_delivery.py::test_siem_export_records_failed_delivery_when_endpoint_errors`
  (real outbound HTTP to a SIEM endpoint).

These are **test-harness flakiness concerns** (real sockets without reliable timeout/cleanup),
not product-code bugs — they block a green CI run and will hang on a fresh pipeline.

### 3.7 — LOW: Lint debt (ruff)
Across the codebase (error classes F401/F841/F821/E902): **72 issues**, 52 auto-fixable.
Breakdown: 63 `F401` unused imports, 6 `F841` unused locals, 2 `F821` undefined names
(the two NameErrors above), 1 `E902`. `services/network_scanner` (40) and
`services/api/api` (15) are the worst. Not functional, but worth a `ruff --fix` pass.

### 3.8 — LOW: Frontend bundle size
`vite build` emits a single **554 KB** JS bundle (158 KB gzip) with a warning:
> Some chunks are larger than 500 kB… consider dynamic import() to code-split.

Given ~54 route pages behind a hash router, the app loads everything eagerly. Code-splitting
per route would cut initial load meaningfully.

### 3.9 — INFO (design note): JWT in `localStorage`
`frontend/src/lib/api.ts` stores the auth token under `localStorage["zelinx_token"]` and reads
roles/user from localStorage too. This is accessible to any XSS. The backend also supports
httpOnly cookie/session handling (`COOKIE_SECURE`), so switching to httpOnly-cookie transport
would be more secure. **This is a hardening recommendation, not an active defect** (the Vite
/proxy means no third-party cookies are at play today).

---

## 4. Security posture (verified strengths worth keeping)

- Production config **fails closed** on weak secrets / SQLite / wildcard CORS.
- PBKDF2-SHA256 with `compare_digest`; account lockout; anti-enumeration on login.
- RBAC in place, ABAC optional (Region→BU→Environment→Asset) and a no-op unless `ABAC_ENFORCED`.
- Security headers, request-ID, GZip, CORS, logging and control-event middleware stack.
- Immutable evidence chain (scan→evidence→DB→normalize→policy→drift→API→dashboard).
- 51 ordered Alembic migrations with schema-parity guard (which is exactly what caught 3.1).
- Redis-backed cluster rate limiting.

---

## 5. Recommended next actions

1. **Fix 3.1** — add migration `0052` for `api_keys.allowed_ips` + `rotate_after_days`
   (or align model vs migration). Highest value; prevents a prod crash.
2. **Fix 3.2** — import `Fernet` (or `from cryptography.fernet import Fernet`) and add a
   `db` param to `airgap_build`.
3. **Fix 3.3** — update the acceptance test's expected pool count (derive it from templates,
   don't hardcode 19).
4. **Fix 3.4** — repopulate the four empty CI workflows (lint, typecheck, test, migration gate).
5. **Fix 3.5** — replace the Makefile hardcoded PYTHONPATH with the `.pth` auto-discovery
   used by Docker.
6. **Fix 3.6** — add per-test timeouts / proper socket teardown (or mark network-touching
   tests to run against a mock) so the suites don't hang.
7. Run `ruff check --fix` for the lint debt; code-split the frontend bundle.

---

## 6. Verified environment notes

- Python 3.11.2, Node v22.22.3; `tsc --noEmit` clean; `vite build` succeeds.
- Backend deps were **not** preinstalled (PEP 668); a venv is required. The repo's
  production/container path relies on a generated `.pth` file, not a literal PYTHONPATH.
  A local venv must recreate that `.pth` (or set the full PYTHONPATH) to run tests locally.
