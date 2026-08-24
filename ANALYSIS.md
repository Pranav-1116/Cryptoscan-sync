# CryptoScan (CryproScan) — Full Repository Analysis

**Repository:** `ZKChainForge/CryproScan`  
**Branch:** `arena/01a034cc-cryproscan` (from `main` @ `8772dde` — “add the cores”)  
**Date:** 2026-08-24  
**Verdict:** A well-specified Part-1 platform skeleton with substantial isolated service code, **not a runnable product**. The folder tree matches the 15-month spec; about **61% of files are empty**; the non-empty Python/Java is internally inconsistent and cannot execute end-to-end.

---

## 1. Executive summary

This repo is a **cryptographic discovery / inventory / compliance platform** (marketed as “CryptoScan Intelligence Platform”). The design principle is explicit:

> Deterministic evidence first. Policy is binary. AI never determines compliance.

The vision spans 15 months across five spec files (`logic-1.md` … `logic-5.md`, ~900 KB of product/engineering spec). The **checked-in code only attempts Part 1** (months 1–3): Java static scan → SHA-256 evidence chain → PostgreSQL → normalize → 4 baseline policies → drift vs baseline → webhook/API/dashboard.

**What is real**

- Clear monorepo layout for 9 services + 3 shared libraries + infra + scripts + docs.
- Meaningful Python implementations for scanner (regex), evidence hashing, DB models/migrations, normalization, policy conditions, drift comparison, FastAPI surface, and an 8-stage worker.
- A few hundred lines of Eclipse JDT Java (unbuildable).
- A Makefile and `docker-compose.yml` that describe the intended runtime.

**What is not real**

- 304 of 500 files are empty, including **the entire React dashboard**, all Dockerfiles, all CI workflows, all docs/ADRs, all policy YAML rules, all Java test fixtures, and most unit tests.
- Multiple **parallel implementations of the same types** (settings, sessions, `PipelineContext`, `ScanResult`, `EvidenceRecord`, `RawFinding`) that do not agree.
- Cross-service call sites would fail at import or first invocation.
- `.gitignore` is empty. `docker-compose.prod.yml` / `docker-compose.test.yml` are empty. The platform cannot be built or deployed from this tree.

**Honest completion vs Part 1 spec: ~25–35% of intended behavior, ~0% of a working E2E path.**

---

## 2. What the product is supposed to be

### Problem

Enterprises cannot inventory crypto (algorithms, key sizes, certs, TLS, KMS). They cannot prove compliance, detect silent downgrades, or plan post-quantum migration.

### Pipeline (foundational architecture)

```
1. Deterministic evidence collection   (scanner — facts only)
2. Normalization                       (IANA / NIST / CBOM names)
3. Policy engine                       (hard rules, no AI)
4. Verification layer                  (hash + chain + human sign-off)
5. AI assistance                       (explain / prioritize only — out of scope forever in this spec)
```

### Roadmap in-repo

| Spec | Phase | Scope | In this repo? |
|------|--------|--------|----------------|
| `logic-1.md` | Months 1–3 | Java scanner, evidence chain, Postgres, normalize, 4 policies, drift, dashboard, GitHub webhook | Attempted (skeleton + cores) |
| `logic-2.md` | Months 4–6 | Python/JS/C# scanners, binaries/containers, CBOM export, advanced policy | Not started |
| `logic-3.md` | Months 7–9 | TLS/runtime, cloud KMS, dependency graph, business context | Not started |
| `logic-4.md` | Months 10–12 | Crypto agility, quantum risk, OT/ICS, vendor discovery | Not started |
| `logic-5.md` | Months 13–15 | CI gates, migration tracking, reports, HA | Not started |

`README.md` is **not** a developer README. It is the product manifesto (CBOM schema, dependency graph, agility scoring). There is no install / run / architecture README.

---

## 3. Inventory

| Metric | Value |
|--------|--------|
| Files (excl. `.git`) | 500 |
| Empty files | **304 (61%)** |
| Non-empty files | 196 |
| Python files | 304 (many empty) |
| TS/TSX (dashboard) | 67 files, **all 0 bytes** |
| Java | 6 files; 4 have code, `pom.xml` + `FindingSerializer.java` empty |
| Spec markdown | ~14,085 lines (`logic-1`…`5` + README) |
| Docs under `docs/` | 20 files, **all empty** |
| Single commit on `main` | `8772dde add the cores` — 39,399 insertions |

Empty-but-named is the dominant pattern: the **file tree was generated from the Part 1 folder spec**, then some “core” modules were filled independently.

---

## 4. Architecture as designed

```
                    GitHub webhook / Manual trigger / CLI
                                    │
                                    ▼
                              FastAPI (api)
                                    │  LPUSH Redis queue
                                    ▼
                           Worker (8 stages)
              clone → scan → evidence → load → normalize
                     → policy → drift → alert
                                    │
                    ┌───────────────┼───────────────┐
                    ▼               ▼               ▼
               PostgreSQL        SMTP mail       GitHub
               (scans,           (CRITICAL/      status API
                evidence,         HIGH drift)
                baselines,
                drift, jobs)
                                    │
                                    ▼
                          Dashboard (React/Vite)   ← entirely empty
```

**Services**

| Service | Role | Language |
|---------|------|----------|
| `scanner` | Java static analysis → `RawFinding` JSON | Python + JDT Java |
| `evidence` | Canonical JSON → SHA-256 content + chain hashes + manifest | Python |
| `database` | SQLAlchemy models, Alembic, loader, repositories | Python |
| `normalization` | YAML rules → IANA/NIST/CBOM | Python |
| `policy` | Deterministic YAML rules (4 baseline) | Python |
| `drift` | Baseline fingerprint vs current, email alerts | Python |
| `api` | FastAPI REST + webhooks + auth | Python |
| `worker` | Redis consumer + pipeline | Python |
| `dashboard` | React/Vite/Tailwind SPA | TypeScript — **empty** |
| `shared_*` | config, logging, models | Python |

**Intended data model (Alembic 0001–0009)**

- `scans`, `evidence_records` (JSONB `finding_data`, `normalized_crypto`, `policy_evaluation`)
- `verification_log`
- `baselines`, `drift_events`
- `scan_jobs`, `repo_configurations`

Integrity model (spec-accurate where implemented):

```
content_hash[i] = SHA-256(canonical_json(finding))
chain_hash[0]   = SHA-256(content_hash[0] + scan_session_id)
chain_hash[n]   = SHA-256(content_hash[n] + chain_hash[n-1])
manifest_hash   = SHA-256(sorted evidence IDs)   # weaker than spec’s “hash of entire manifest”
```

---

## 5. What is actually implemented (by service)

Grades: **A** solid isolated logic · **B** useful but incomplete · **C** stub / broken contracts · **F** empty or unusable.

### 5.1 Scanner — B− (regex MVP; JDT not wired)

**Works on paper**

- `java_parser.py` (~580 lines) detects five Part-1 patterns via regex:
  1. `Cipher.getInstance("…")`
  2. `MessageDigest.getInstance("…")`
  3. `KeyGenerator.getInstance` + nearby `.init(n)`
  4. `Signature.getInstance("…")`
  5. `SecretKeySpec` hardcoded byte[] / `"…".getBytes()` (does **not** store the key)
- Variable (non-literal) arguments → `algorithm=None`, MEDIUM confidence.
- Algorithm / mode / padding split, snippet ±N lines, method/class heuristics, try/catch heuristic.
- CLI (`click`) for `--source` or `--repo`.
- `RawFinding` Pydantic model with `to_canonical_json()` for hashing.

**Broken**

| Caller | Expects | Callee actually has |
|--------|---------|---------------------|
| `scanner.main.scan()` | `Scanner(exclude_test_dirs=…)` then `scan(root_path=…, scan_id=…)` | `Scanner.__init__(config: ScannerConfig)` and `scan(repo_path, target_url)` |
| `Scanner` | `JavaParser(config)` then `parse(file, repo, git)` | `JavaParser(repo_root)` and `parse_file(path)` |
| `Scanner` | `ScanResult(scan_start=datetime, statistics=dict, status=…)` | `ScanResult` is Pydantic: `scan_start` is ISO **string**, `statistics` is `ScanStatistics`, no `status` field |
| Worker `stage_scan` | `await scanner.scan()` then `scan_result.model_dump()` / `statistics.total_findings` | `scan()` is **sync**, returns a differently shaped object |

JDT: `CryptoASTParser.java`, `ASTVisitorImpl.java`, `CryptoPatternMatcher.java`, `CryptoFinding.java` exist (~650 LOC). `CryptoASTParser` uses `Files.readAllBytes` **without** `import java.nio.file.Files`. `pom.xml` and `FindingSerializer.java` are empty → **JAR cannot be built**. Parser comments say JDT is “production” and regex is “MVP”; production path is dead.

Test fixtures (`CipherSamples.java`, expected JSON, detector unit tests) are **empty**. The one non-empty integration test cannot run without samples.

`scanner/detectors/*` (the spec’s detector package) are empty — detection lives only inside `java_parser.py`.

### 5.2 Evidence — B

Solid isolated design:

- Canonical serializer (sorted keys, drop runtime ids).
- Content hasher + chain hasher matching the spec formula.
- `EvidencePipeline.process_findings()` builds records + chain.
- `verify_chain` / tamper tests exist and look purposeful.

Broken vs worker:

- Worker calls `EvidencePipeline()` with **no args** and `await evidence_pipeline.process(...)`.
- Real class: `__init__(scan_session_id)` and sync `process_findings(findings)`.
- Worker then uses `manifest.summary.manifest_hash` and `r.model_dump()`.
- Pipeline `create_manifest()` hashes **sorted evidence IDs**, not the full canonical manifest (weaker than spec).
- Standalone `verify_evidence.py` and verification-script generator are empty.

There are **two** `EvidenceRecord` types: Pydantic in `evidence/models` (`finding` dict) vs SQLAlchemy in `database/db/models` (`finding_data`, extracted columns). Mapping is not unified.

### 5.3 Database — B

Strongest “core”:

- Engine factory: pooling, `pool_pre_ping`, UTC, statement timeout, URL from env.
- Sync `SessionFactory` + context manager.
- `BaseModel` with UUID + timestamps.
- ORM for scans, evidence, verification, baselines, drift, jobs, repo configs.
- Nine Alembic migrations matching the spec tables.
- Loader: pre-verify → transactional bulk insert → post-verify.
- Repositories for the main entities.

Broken:

- API `dependencies.py` imports **`AsyncSessionFactory`** — **does not exist**. Engine/session are **sync**.
- `ScanJob` FK is `scans.scan_id` but `Scan` PK is mixin `id` (UUID), not `scan_id`.
- `ScanJob` inherits `from .base import Base` while other models use `BaseModel` from `session.Base` — two Base lineages.
- Trigger router uses `JobType`, `JobStatus`, `job.job_id` — enums/fields don’t match `ScanJob` (`ScanJobStatus`, no `JobType` enum, `job_id` vs `id`).
- `api` and `database` `pyproject.toml` are empty → not installable packages.
- Health-check module is empty.

### 5.4 Normalization — B−

Engine is coherent: exact match → pattern (`algo/mode/padding`) → UNKNOWN fallback → NIST / IANA / CBOM / family enrichers.

Partial YAML:

| Rule file | Status |
|-----------|--------|
| `aes.yaml`, `des.yaml`, `rsa.yaml`, `md5.yaml`, `sha2.yaml`, `signature_combos.yaml` | Present |
| `3des.yaml`, `rc4.yaml`, `sha1.yaml`, `ecdsa.yaml` | **Empty** |

Empty rules matter: DES/3DES/RC4/SHA-1 are exactly the forbidden-algorithm set. Policy will see un-normalized names.

`normalization/pyproject.toml` is empty.

### 5.5 Policy — C+

Condition types from the spec are implemented:

- `ALGORITHM_IN_LIST`
- `KEY_SIZE_MINIMUM`
- `ALGORITHM_MODE_WHITELIST`
- `BOOLEAN_FLAG`
- Factory + evaluator (FAIL beats WARN beats PASS)

**All four baseline YAML files are empty.** The engine can load nothing. All policy integration tests are empty.

`policy/models/policy_evaluation.py` is empty; evaluation is stuffed into `policy_result.py`.

### 5.6 Drift — B

Detector is the most complete isolated algorithm:

- Location fingerprint vs semantic fingerprint (same algo/mode/key/purpose, different file → `MOVED`).
- `NEW` / `REMOVED` / `UPGRADED` / `DOWNGRADED`.
- Weak algos (`DES`, `MD5`, `SHA1`, `RC4`) as new → CRITICAL; key-size downgrade → CRITICAL.
- Email templates (txt present; html empty).
- Integration tests for new/removed crypto exist.

Gaps vs spec: no DB-backed baseline lookup in the detector itself; worker stage must glue it. HTML templates and several unit tests empty. Spec said Month 2 only does NEW/REMOVED; this code already does move/upgrade/downgrade (fine, slightly ahead).

### 5.7 API — C

`main.py` is a real FastAPI factory: CORS, TrustedHost in prod, request-id, logging, auth middleware, exception handlers, `/health` `/ready`, routers under `/api/v1`.

Then it falls apart:

| Issue | Detail |
|-------|--------|
| Settings schema clash | `main.py` uses `settings.ENVIRONMENT`, `API_VERSION`, `CORS_ORIGINS`, `DOCS_ENABLED`, `TRUSTED_HOSTS`. `APISettings` defines `debug`, `api_version`, `cors_origins`, `api_docs_enabled` — **no `ENVIRONMENT` / `SECRET_KEY` / `JWT_*`**. Instantiating `APISettings()` requires `hmac_secret`, `session_secret`, `database_url` (≥32-char secrets). App likely dies on import. |
| Auth implemented **three times** | (1) JWT middleware (`settings.SECRET_KEY`, `JWT_ALGORITHM`). (2) HMAC cookie `SessionManager(secret)`. (3) `auth.py` `SessionManager` + `CredentialValidator` (PBKDF2). `auth` router uses a **fourth** shape: `AuthService`, `SessionManager()` with no secret, `await create_session(user_id, username, roles)`, cookie `session_token`. Dependencies use cookie `cryptoscan_session` and `validate_api_token`. |
| Auth router not mounted | `auth.py` exists; `create_app` never `include_router(auth)`. Middleware still allows `/api/v1/auth/login`. |
| Double prefix | `trigger.py` router prefix `/api/scans` + app prefix `/api/v1` → **`/api/v1/api/scans/trigger`**. Spec/CLI expect `/api/scans/trigger`. |
| Scans/findings/stats | Mostly **TODO / mock empty list / 404**. |
| Trigger | Writes a job then `lpush` Redis — closest-to-real write path, but depends on missing async repos. |
| `pyproject.toml` | Empty. No FastAPI/uvicorn declared. |

### 5.8 Worker — C

Two **incompatible** orchestrators:

1. `pipeline/pipeline_runner.py` — constructs stages itself, `PipelineContext` frozen dataclass, `await stage.execute(ctx)`.
2. `core/job_executor.py` — **different** `PipelineContext`, expects injected stages that return `StageResult`, plus `database_service.mark_scan_running`.

`main.py` constructs `JobConsumer(redis_url, queue_name, timeout)` and `JobExecutor(db_session, workspace_base)` and calls `consumer.consume(handler=…)`.

Actual `JobConsumer.__init__(redis_url, poll_interval_seconds, max_retries, …)` and method is `consume_jobs`. Queue name hardcoded `cryptoscan:jobs:queue`. API trigger uses `settings.SCAN_JOB_QUEUE_KEY` (not defined on `APISettings`). Worker settings use `QUEUE_NAME = "scan-jobs"`.

**Three queue names, two consumer APIs, two pipeline contexts.** Jobs published by the API will never be consumed by the worker as written.

`worker/pyproject.toml` empty. Import `from database.db.connection.session import SessionLocal` — **`SessionLocal` does not exist**.

### 5.9 Dashboard — F

67 TS/TSX files, Vite/Tailwind configs, tests — **all 0 bytes**. Month 3 UI does not exist. `package.json` empty.

### 5.10 Shared libs — C+

- `shared_config.BaseSettings`: env file, extra=allow.
- `shared_logging`: JSON logger + context.
- `shared_models`: a **third** `RawFinding` (datetime objects, enum types) vs scanner’s stringly `RawFinding`.

Service settings do not consistently inherit this base. Scanner config uses lowercase `java_home` + `env_prefix=SCANNER_`; API uses mixed styles.

### 5.11 Infra / ops — D

| Asset | Status |
|-------|--------|
| `docker-compose.yml` | Written (Postgres 15, Redis 7, api, worker, dashboard, nginx) |
| Dockerfiles (all 6) | **Empty** — `docker compose build` fails |
| `docker-compose.prod.yml` / `.test.yml` | Empty |
| `.github/workflows/*` | Empty |
| `.gitignore` | **Empty** — secrets, `__pycache__`, workspaces, `.env` would be committed |
| `infra/postgres/init/*.sql` | Small but real (DB + uuid-ossp/pgcrypto) |
| `postgres.conf`, `pg_hba.conf`, nginx, prometheus, grafana | Empty |
| `scripts/dev_setup.sh`, migrations, seed, export, verify | Empty |
| `scripts/trigger_scan.py`, `approve_baseline.py` | Present (call API that doesn’t match) |
| Makefile | Present; `make test` / `make up` cannot succeed |

Compose also mounts `./services/shared` but shared code lives at **`./shared`**. Dashboard `VITE_API_BASE_URL=http://localhost:8000` breaks in the preview/proxy model (browser is not the sandbox).

---

## 6. Part 1 week-by-week scorecard

| Week | Spec deliverable | Status |
|------|------------------|--------|
| 1–2 | Java scanner, 5 patterns, JSON out, fixtures | Regex detectors yes; CLI/core API mismatch; **fixtures empty**; JDT not built |
| 3 | Evidence chain + standalone verify script | Hash/chain yes; verify CLI empty; worker API mismatch |
| 4 | Postgres + transactional loader + queries | Models/migrations/loader yes; async/sync split; FK bugs |
| 5 | Normalize 20+ algos + YAML | Engine yes; 4/10 YAML empty |
| 6–7 | 4 baseline policies | Evaluators yes; **YAML empty** → no rules fire |
| 8 | Baseline + NEW/REMOVED drift + email | Detector/alerter yes; not wired through a working worker |
| 9–10 | Dashboard 4 pages | **0%** (empty SPA) |
| 11 | GitHub webhook HMAC + queue + status check | HMAC + parser + poster exist; not a working path |
| 12 | Manual trigger UI + docs | Trigger stub; docs empty |

**E2E story from the spec (push → webhook → scan → DES FAIL → drift email → dashboard) cannot happen.**

---

## 7. Integration fractures (why it cannot boot)

These are not polish issues. They are independent “cores” written against imagined neighbors.

1. **Scanner constructed three ways** (config object / kwargs / `await scan()`).
2. **Two `ScanResult` shapes** (orchestrator vs Pydantic).
3. **Two `PipelineContext` + two executors**.
4. **Three Redis queue names**.
5. **Sync SQLAlchemy vs async FastAPI dependencies**.
6. **`Scan.id` vs `ScanJob.scan_id` FK**.
7. **Three auth systems**, auth router unmounted.
8. **`APISettings` fields ≠ `create_app` usage** → startup failure.
9. **Policy YAML empty** → compliance always vacuous.
10. **Shared `RawFinding` ≠ scanner `RawFinding`**.
11. **Empty packaging** (`pyproject.toml` for api/database/evidence/normalization/worker).
12. **Empty Docker / CI / gitignore**.

This is characteristic of a **spec-driven tree fill** (likely multi-agent) rather than an incrementally integrated system.

---

## 8. Security review

**Intentional good choices**

- HMAC verification sketched for GitHub (`hmac_verifier.py`).
- Hardcoded-key detector does not persist key material.
- PBKDF2-HMAC-SHA256 (100k) exists in one auth module.
- Evidence chain is a real (if simple) tamper-evident design.
- Policy is deterministic — no LLM in the compliance path.

**Problems**

| Severity | Issue |
|----------|--------|
| Critical | Empty `.gitignore` + `.env.example` with token placeholders — high leak risk |
| Critical | Default compose password `cryptoscan_secret`, `SECRET_KEY=dev-secret-key-change-in-prod` |
| High | Auth is incoherent; one path is unsigned random tokens with format-only validation |
| High | JWT middleware references settings fields that do not exist |
| High | Webhook path is “unprotected” — correct only if HMAC is actually enforced on that route |
| Medium | `TrustedHost` only when `ENVIRONMENT==production`, but settings use `debug` |
| Medium | Dashboard would call `localhost` API (wrong in browser/preview) |
| Medium | Manifest hash is ID concatenation, not full manifest canonicalization |
| Medium | Regex Java parse is easy to evade (`Cipher.getInstance(CONST)`, concatenation, reflection) — acceptable for MVP if labeled LOW confidence; JDT was the mitigation and is dead |
| Low | `datetime.utcnow()` everywhere (naive UTC) |

---

## 9. Code quality

**Strengths**

- Consistent narrative comments; modules map 1:1 to the spec.
- Pydantic models, typed enums, repository pattern, Alembic versions.
- Isolated algorithms (chain hash, drift fingerprints, condition evaluators) are readable and testable.
- Structured logging (`structlog` / extra dicts) in several services.

**Weaknesses**

- Duplicate types instead of depending on `shared_models`.
- “Production-grade” in almost every module docstring; contracts are not production-grade.
- Mix of sync/async, Pydantic v1 `class Config` vs v2 `model_config`, `validator` vs `field_validator`.
- Tests: **17 non-empty vs 78 empty**. No CI. Java samples missing → scanner tests cannot prove the 5 patterns.
- No lockfiles with real deps for most services (`poetry.lock` empty).
- Repo name typo: **CryproScan**.

---

## 10. Parts 2–5 (not in code)

Do not treat empty detector files or “include_languages: java, python, go…” in the worker as multi-language support. That list is a wish. Missing entirely:

- Python / JS / C# / Go scanners  
- Binary / container / SBOM correlation  
- CycloneDX CBOM export as a product feature (only enricher fields)  
- Live TLS, cert inventory, cloud KMS  
- Dependency / blast-radius graph  
- Agility scoring, PQC / HNDL analysis  
- OT/ICS, vendor questionnaires  
- CI policy gates, migration tracker, HA/DR  

Building those on this tree before integrating Part 1 would multiply the fracture.

---

## 11. Recommended path (if the goal is a working Part 1)

Do **not** fill more empty files in parallel. Collapse contracts first.

### Phase A — Make one vertical slice run (1–2 weeks)

1. **Pick one of each duplicate and delete the other.**  
   - One `RawFinding` (prefer `shared_models`, scanner emits it).  
   - One `ScanResult`.  
   - One `PipelineContext` + one runner.  
   - One `SessionManager` (HMAC-signed cookie).  
   - One queue name (`cryptoscan:jobs:queue`).  
   - Sync **or** async SQLAlchemy — not both.
2. **Fix `Scan` PK vs `scan_jobs.scan_id` FK.**
3. **Write the four policy YAML files** from `logic-1.md` (DES/3DES/RC4/MD5/SHA-1; RSA≥2048; AES GCM/CCM/CTR; hardcoded keys).
4. **Fill missing norm YAML** (3DES, RC4, SHA-1, ECDSA).
5. **Align scanner CLI + `Scanner.scan` + worker `stage_scan`** on one sync API.
6. **Align `EvidencePipeline` with `stage_evidence`.**
7. **Add real `pyproject.toml` + Dockerfile** for api, worker, scanner (regex-only is fine).
8. **`.gitignore`** immediately.
9. **Java fixtures** from the spec + make `test_full_scan_pipeline` pass.

Success = `make scan REPO=…` (or local `--source`) produces findings, hashes, DB rows, and a DES sample fails BASELINE-001.

### Phase B — Wire the product surface

10. Implement scans/findings/drift/stats routers against repositories (delete mocks).
11. Mount auth; one cookie name; drop unused JWT **or** finish JWT and drop sessions.
12. Minimal dashboard **or** server-rendered pages — do not resurrect 67 empty React files until the API returns real data.
13. Webhook: HMAC → repo_config allowlist → enqueue. One queue.
14. Fill `docs/` from `logic-1.md` Week 12 outline (short, accurate to what exists).

### Phase C — Only then

JDT JAR + subprocess, GitHub status checks, HTML mail, CI, prod compose.

---

## 12. File-level “source of truth” map

If you keep working in this repo, treat these as the real cores (non-empty, non-trivial):

| Concern | Best existing file | Do not trust |
|---------|-------------------|--------------|
| Java detection | `services/scanner/scanner/parsers/java_parser.py` | `detectors/*` (empty), JDT (unbuilt) |
| Finding schema | pick one: `scanner/models/raw_finding.py` **or** `shared_models/finding.py` | Using both |
| Scan orchestration | `scanner/core/scanner.py` | `scanner/main.py` (different API) |
| Evidence chain | `evidence/hashing/chain_hasher.py` + `content_hasher.py` | Worker `stage_evidence` call shape |
| DB schema | `services/database/migrations/versions/0001`–`0009` | `ScanJob` FK / dual Base |
| Policy logic | `policy/conditions/*` + `evaluator.py` | `rule_definitions/baseline/*.yaml` (empty) |
| Drift logic | `drift/core/detector.py` | Worker/API glue |
| HTTP app | `api/main.py` | settings field names, scans router TODOs |
| Jobs | neither — rewrite one path | `job_consumer` vs `main` vs `trigger` |

---

## 13. Bottom line

CryptoScan is a **serious product spec** with a **theatrical codebase**: the tree, names, and comments describe a compliance-grade platform; the bits describe several unfinished cores that do not compose.

The valuable artifacts are:

1. The five `logic-*.md` specs (roadmap + acceptance tests).
2. Isolated algorithms: regex Java detectors, SHA-256 chain, drift fingerprints, policy condition types, Alembic schema.

Everything else is scaffolding or conflicting glue.

**If the next action is implementation:** start at Phase A (one contract, one slice, four YAML rules, fixtures, gitignore).  
**If the next action is review / due diligence:** do not treat this as a shippable scanner. It is a design dump plus partial libraries.

---

*Analysis based on the tree at `8772dde` / working branch `arena/01a034cc-cryproscan`. No services were successfully executed; conclusions follow from source, emptiness counts, and cross-module API comparison.*
