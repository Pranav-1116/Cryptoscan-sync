# 11_TESTING_AUDIT.md
## ZELNX CryptoScan — Testing Audit

**Generated:** 2026-09-20  
**Method:** Source code inspection of test files, fixtures, configuration, and CI integration  
**Scope:** What is ACTUALLY tested vs. documented — coverage, gaps, quality

---

## 1. TEST INFRASTRUCTURE

### 1.1 Backend (Python)
| Component | Tool | Version | Config |
|-----------|------|---------|--------|
| **Test runner** | pytest | 9.1.1 | `pytest.ini` |
| **Async support** | pytest-asyncio | 1.4.0 | Auto mode |
| **Parallel execution** | pytest-xdist | 3.5 | `-n auto` |
| **Timeout** | pytest-timeout | 2.3.0 | 60s default |
| **Socket blocking** | pytest-socket | 0.7 | `disable_socket` fixture |
| **Redis mock** | fakeredis | 2.20 | In-process Redis double |
| **PostgreSQL** | pgserver | 0.1.4 | Embedded PG 16 for migration tests |
| **Coverage** | Not configured | — | No `pytest-cov` in requirements |

### 1.2 Frontend (TypeScript/React)
| Component | Tool | Version | Config |
|-----------|------|---------|--------|
| **Test runner** | Vitest | 2.1.9 | `vitest.config.ts` |
| **Environment** | jsdom | 30.1.1 | Browser simulation |
| **React testing** | @testing-library/react | 16.3.3 | Component rendering |
| **User events** | @testing-library/user-event | 14.6.7 | Interaction simulation |
| **DOM matchers** | @testing-library/jest-dom | 6.9.1 | Custom matchers |
| **Coverage** | @vitest/coverage-v8 | 2.1.9 | V8 provider |

---

## 2. TEST ORGANIZATION

### 2.1 Backend Test Structure
```
services/
├── scanner/tests/
│   ├── unit/                    # 30+ test files
│   │   ├── detectors/           # 6 detector tests
│   │   ├── extractors/          # 6 extractor tests
│   │   ├── models/              # Model validation
│   │   └── *.py                 # Parser, cascade, constant_index, etc.
│   ├── integration/             # 4 test files
│   │   ├── test_full_scan_pipeline.py
│   │   ├── test_git_clone_scan.py
│   │   ├── test_output_validation.py
│   │   └── test_polyglot_and_fixtures.py
│   ├── accuracy/                # 8 validation docs (not tests)
│   └── fixtures/                # Test data
├── api/tests/
│   ├── unit/                    # Per-router/unit tests
│   ├── integration/             # Cross-router tests
│   └── security/                # Auth, RBAC, rate limit, SSRF tests
├── evidence/tests/
│   ├── unit/                    # Hashing, pipeline
│   └── integration/             # Full pipeline
├── database/tests/
│   ├── test_migrations.py       # Up/down + schema parity
│   └── test_tenancy.py          # Tenant isolation
└── worker/tests/
    └── test_job_path_hardening.py  # 9 tests (requires fakeredis)
```

### 2.2 Frontend Test Structure
```
frontend/src/
├── test/
│   ├── setup.ts                 # Offline fetch stub, mocks
│   └── render.tsx               # Test providers wrapper
├── pages/
│   ├── *.test.tsx               # Page smoke tests (71 pages)
│   ├── Tenancy.test.tsx         # Tenant switching
│   └── pages.smoke.test.tsx     # All pages render
└── components/
    └── ui.test.tsx              # Component rendering
```

---

## 3. TEST COVERAGE — BY DOMAIN

### 3.1 Scanner (High Coverage)
| Area | Test Files | Key Tests |
|------|------------|-----------|
| **Parsers** | 25+ | Java, Python, Go, JS, C#, Rust, Ruby, PHP, COBOL, etc. |
| **Detectors** | 6 | Cipher, HMAC, Digest, Signature, KeyGen, HardcodedKey |
| **Extractors** | 6 | Algorithm, CipherSuite, Confidence, Context, Entropy, Snippet |
| **Cascade** | 1 | `test_cascade.py` (8.2K lines) |
| **ConstantIndex** | 1 | Cross-file constant resolution |
| **Config Parser** | 1 | TLS, K8s, cloud config |
| **Materials (PEM)** | 1 | Key/cert detection |
| **Binary (JAR/DLL)** | 2 | JAR strings, .NET assemblies |
| **Mobile** | 1 | APK/IPA scanning |
| **Language Detection** | 2 | Extension + content heuristics |
| **File Discovery** | 1 | Exclude dirs, test dirs, multiprocess threshold |
| **Output Schema** | 1 | JSON contract validation |
| **Tree-sitter** | 1 | Incremental parsing |
| **Bank Triage** | 1 | Banking-specific rules |
| **External Validation** | 1 | Regression prevention (16K lines) |

**Gap:** No property-based testing, no fuzzing, no mutation testing.

### 3.2 API (Medium Coverage)
| Area | Test Files | Coverage |
|------|------------|----------|
| **Authentication** | Multiple | Login, MFA, lockout, session, API keys |
| **RBAC** | Multiple | Role checks, permission enforcement |
| **Rate Limiting** | Multiple | Redis backend, fail-closed, limits |
| **SSRF/Path Traversal** | Multiple | Workspace guard validation |
| **CBOM** | Unit + integration | Generation, validation, signing, diff |
| **Graph** | Unit | Blast radius, vendor chains, cycles |
| **Drift** | Unit | Digest, ack, resolve, FP |
| **Drift Alerts** | Unit | Daily digest building |
| **Crypto Live** | Unit | Event ingestion, state, timeline |
| **DevSecOps** | Unit | Container, K8s, cloud, SBOM, binary |
| **Migrations** | `test_migrations.py` | Up/down, schema parity (pgserver) |
| **Tenancy** | `test_tenancy.py` | Row-level isolation, filtered_get |

**Gap:** No contract testing (OpenAPI), no chaos testing, no load testing.

### 3.3 Evidence (Good Coverage)
| Area | Test Files | Coverage |
|------|------------|----------|
| **Canonical Serializer** | Unit | Deterministic JSON, excluded fields |
| **Content Hasher** | Unit | SHA-256, batch, verification |
| **Chain Hasher** | Unit | Chain compute, verify, single link |
| **Pipeline** | Integration | Full pipeline, dedup, manifest |

### 3.4 Database (Migration-Focused)
| Test | Purpose |
|------|---------|
| `test_migrations.py` | All 71 migrations up + down, schema parity vs models |
| `test_tenancy.py` | `filtered_get()` enforces tenant, cross-tenant blocked |

**Gap:** No data integrity tests (FK, unique, check constraints), no performance tests.

### 3.4 Frontend (Smoke Only)
| Test | Purpose |
|------|---------|
| `pages.smoke.test.tsx` | All 71 pages render without crash (offline) |
| `Tenancy.test.tsx` | Tenant switcher component |
| `ui.test.tsx` | Button, Badge, Table, Panel render |
| `PortfolioDependencyPanel.test.tsx` | Graph panel component |
| `App.test.tsx` | Routing, auth flow |

**Gap:** No integration tests with live API, no visual regression, no accessibility tests, no E2E.

---

## 4. TEST FIXTURES & DATA

### 4.1 Backend Fixtures
| Fixture | Location | Purpose |
|---------|----------|---------|
| **Sample code** | `services/scanner/tests/fixtures/` | Per-language crypto samples |
| **Binary samples** | `services/scanner/tests/fixtures/binaries/` | JAR, DLL, APK, IPA |
| **Config samples** | `services/scanner/tests/fixtures/configs/` | TLS, K8s, cloud configs |
| **Cascade fixtures** | `services/scanner/tests/fixtures/cascade/` | Multi-system import graphs |
| **DB fixtures** | `conftest.py` (per service) | SQLAlchemy session, test data factories |

### 4.2 Frontend Fixtures
- **None** — Offline-first philosophy; tests mock fetch per test
- **Mock data:** Inline in each test via `mockFetch()`

---

## 5. CI/CD INTEGRATION

### 5.1 GitHub Workflows (`.github/workflows/`)
| Workflow | Triggers | Steps |
|----------|----------|-------|
| **Lint** | PR, push | `ruff check`, `ruff format --check`, `mypy` (if configured) |
| **Backend Tests** | PR, push | `pytest -n auto --timeout=60` (all services) |
| **Frontend Tests** | PR, push | `npm run test:coverage` |
| **Migration Parity** | PR, push | `pgserver` + up/down all 71 migrations |
| **Polyglot Matrix** | PR, push | Scanner against multi-language fixture corpus |
| **E2E Seed Smoke** | PR, push | `scripts/scan_estate.py` minimal run |
| **Docker Build** | PR, push | Build all 4 Dockerfiles |
| **Security** | Schedule | Not found |

### 5.2 Test Commands
```bash
# Backend
pytest services/scanner/tests -n auto --timeout=60
pytest services/api/tests -n auto --timeout=60
pytest services/database/tests -n auto --timeout=60

# Frontend
cd frontend && npm run test:coverage

# Migrations
pgserver pytest services/database/tests/test_migrations.py
```

---

## 6. TEST QUALITY ASSESSMENT

### 6.1 Strengths
| Strength | Evidence |
|----------|----------|
| **Comprehensive scanner tests** | 30+ unit tests covering all parsers/detectors |
| **External validation regression** | 16K-line test preventing accuracy regressions |
| **Migration parity tests** | Up/down + schema parity on real PostgreSQL |
| **Security tests** | Auth, RBAC, rate limit, SSRF, path traversal |
| **Offline-first frontend tests** | No flaky network dependencies |
| **Fakeredis for worker tests** | Job path hardening without external Redis |
| **pgserver for migrations** | Real PostgreSQL without external server |

### 6.2 Weaknesses
| Weakness | Impact |
|----------|--------|
| **No coverage reporting** | Cannot measure/improve coverage |
| **No property-based testing** | Edge cases in parsers/normalizers untested |
| **No fuzzing** | Binary parser, config parser vulnerable to malformed input |
| **No mutation testing** | Test effectiveness unknown |
| **Frontend: smoke only** | No behavior verification, no API contract tests |
| **No E2E tests** | Critical user flows untested (scan → CBOM → graph) |
| **No load/performance tests** | Scalability unknown |
| **No chaos testing** | Failure modes untested |
| **Test data management** | Fixtures duplicated across services |

---

## 7. TEST EXECUTION PERFORMANCE

| Suite | Tests | Time (est.) | Parallel |
|-------|-------|-------------|----------|
| Scanner unit | ~200 | 60-120s | ✅ xdist |
| Scanner integration | ~20 | 30-60s | ❌ Sequential |
| API unit | ~150 | 60-120s | ✅ xdist |
| API integration | ~30 | 60-120s | ❌ Sequential |
| Database migrations | 71 up + 71 down | 120-300s | ❌ Sequential |
| Frontend | ~100 | 30-60s | ✅ Vitest |
| **Total CI** | ~600 | 15-25 min | Partial |

---

## 8. MISSING TEST CATEGORIES

| Category | Needed For | Priority |
|----------|------------|----------|
| **Contract testing** | API schema compatibility | P1 |
| **E2E (Playwright/Cypress)** | Critical user flows | P1 |
| **Visual regression** | UI consistency | P2 |
| **Accessibility (axe-core)** | WCAG compliance | P2 |
| **Load testing (k6/locust)** | Scalability validation | P2 |
| **Chaos testing** | Failure resilience | P2 |
| **Property-based (hypothesis)** | Parser/normalizer edge cases | P2 |
| **Fuzzing (atheris)** | Binary/config parsers | P1 |
| **Mutation testing (mutmut)** | Test effectiveness | P3 |
| **Performance benchmarks** | Regression detection | P2 |

---

## 9. TEST DOCUMENTATION

| Document | Status |
|----------|--------|
| `pytest.ini` | Minimal — only timeout, asyncio mode |
| `vitest.config.ts` | Basic — jsdom, coverage |
| `conftest.py` (root) | Shared fixtures for scanner tests |
| `conftest.py` (api) | 12K lines — extensive fixtures, mocks |
| `conftest.py` (evidence) | Minimal |
| `conftest.py` (scanner) | 3K lines — fixtures, polyglot corpus |

---

## 10. RECOMMENDATIONS

### P0 — Critical
1. **Add coverage reporting** — `pytest-cov` + `vitest --coverage` with CI gates (minimum 80%)
2. **Implement E2E tests** — Playwright for: scan → evidence → CBOM → graph → drift
3. **Add fuzzing** — `atheris` for binary parser, config parser, normalization

### P1 — High
4. **Contract testing** — `schemathesis` or `pytest-contract` against OpenAPI spec
5. **Property-based testing** — `hypothesis` for parsers, normalizers, chain hasher
6. **Load testing** — `k6` scripts for API endpoints (scan trigger, CBOM, graph)
7. **Mutation testing** — `mutmut` for critical paths (evidence chain, policy engine)

### P2 — Medium
8. **Visual regression** — Playwright + Percy/Chromatic for UI components
9. **Accessibility tests** — `axe-core` in Vitest/Playwright
10. **Chaos testing** — `chaostoolkit` for DB/Redis/Neo4j failure scenarios
11. **Test data factory** — Centralized `factory_boy` fixtures for all services

### P3 — Enhancement
12. **Benchmark suite** — `pytest-benchmark` for parser performance
13. **Test report dashboard** — Allure/ReportPortal for CI visibility
14. **Flaky test detection** — `--reruns` + quarantine
## UPDATE — round 17 verification + build (2026-10-09)

**Built this round (this report's §5 recommendations):**

- **Property-based testing (P2 recommendation):** hypothesis is now a
  pinned test dependency and `services/evidence/tests/unit/
  test_hashing_properties.py` explores the input space of the hashing
  core: canonical-serializer determinism and key-order insensitivity,
  content-hash stability, runtime-field exclusion, chain verify-iff-
  untampered (mutate/reorder/delete/append all fail), verify_single
  agreement, and content→chain composition. 7 properties × 50 examples.
- **Coverage measurement (the "not configured" row in §1):** `pytest-cov`
  is pinned in requirements.txt, root `.coveragerc` measures branch
  coverage over the eight backend packages, and `scripts/coverage.sh`
  produces per-service term + XML reports. Deliberately **opt-in** — the
  gate remains the suite result, never a percentage; CI wiring stays
  blocked by the standing no-workflows constraint (staged in
  `.github/workflows-pending/`).
- **OpenAPI contract tests:** `services/api/tests/unit/
  test_openapi_contract.py` pins the spec invariants the reference doc is
  generated from — unique operationIds (a real duplicate was found and
  fixed this round), versioned paths (with an explicit allowlist for the
  six unversioned infra probes), and tagged operations.

**Verified stale:** none of the backend test-count claims in this report
survived verification (4.1k+ backend tests now, 132 frontend tests); the
pipeline-matrix and CI rows remain accurate as constraints, not findings.
