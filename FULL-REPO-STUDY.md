# CryptoScan — Full End-to-End Repository Study

**Repository:** `ZKChainForge/CryproScan` (GitHub)
**Studied branch (the "main full code"):** `arena/01a052d9-cryproscan` — **124 commits**, tip `6b81a03`
(`feat(hardware): Universal Hardware Scanner (spec §1–§25)`), dated 2026-08-31.
**Study date:** 2026-08-31 · **Verification:** full test suite run locally + live end-to-end scan executed.

---

## 1. The five branches — decoded

| Branch | Commits | What it is |
|---|---|---|
| `main` | 2 | Seed only: `7fffa4d first commit` + `8772dde add the cores`. The skeleton tree ("the cores") — mostly empty files at that point. |
| `arena/01a02f50-cryproscan` | 12 | **Divergent side-branch** forked from the root commit. Early standalone attempt: scanner service boundaries, webhook pipeline + worker execution, secure worker outbox/Postgres/evidence anchors, normalization + job intake. Never merged into the main line. |
| `arena/01a034cc-cryproscan` | 36 | Part 1→2 era of the **main line** (ancestor of the final branch): fills the cores, Java AST discovery + observation contract, Python/JS/C# plugins, AWS/Azure estate inventory, CycloneDX CBOM estate export. |
| `arena/01a03d0e-cryproscan` | 108 | Part 3→5 era of the **main line** (ancestor of the final branch): enterprise integration (SSE event stream, machine API keys), 24/7 live scanning, HA/DR (leader lease, replication), payment-crypto/HSM loop, certificate renewal workflow, ceremonies, load tests. |
| `arena/01a052d9-cryproscan` | **124** | **The full main line** = everything above, plus the 24/7 live vendor engine (68 plugins / 16 categories), honest platform boundaries, real-world benchmarks, full-estate scans + PDF reports, and finally the **Universal Hardware Scanner** (30 hardware plugins, spec §1–§25, 92 new tests). **This is the "122-commit main full code" branch — the current session branch sits exactly on its tip.** |

Ancestry: `7fffa4d → 8772dde → (01a034cc → 01a03d0e → 01a052d9)`, with `01a02f50` diverging from `7fffa4d`. Total unique commits across all 5 branches: **135** (124 on the main line).

---

## 2. What the product is

**CryptoScan** is a self-hosted, deterministic **cryptographic inventory & compliance platform** for regulated estates (banks, healthcare, energy) and cloud platforms (AWS/Azure/GCP). Core doctrine (stated everywhere and enforced by tests):

> **"Deterministic Truth First, AI Assists Second."**
> Scanners collect facts → SHA-256 evidence chain → normalize (IANA/NIST/CBOM) → YAML policy (binary, no AI) → drift/gates → graph/agility/quantum → API + dashboard. **Policy is never decided by AI. Key material is never touched — metadata only, read-only, always.**

The 5 spec files (`logic-1.md` … `logic-5.md`, ~14,000 lines) define a 15-month plan: Part 1 (months 1–3) source scanning + evidence; Part 2 containers/CBOM; Part 3 TLS/cloud/graph; Part 4 agility/quantum/OT/vendor; Part 5 CI gates/migration/reports/HA. The repo has grown well beyond that plan (24/7 monitoring, payment HSM, hardware scanning), and `docs/PLATFORM-STATUS.md` is an unusually honest week-by-week (W37–W60) accounting of what ships vs. what is deliberately not claimed.

---

## 3. Scale of the codebase (measured)

| Metric | Value |
|---|---|
| Files (excl. `.git` / `.venv`) | **1,838** |
| Python files / lines | **1,494 files / ~147,000 lines** |
| Services | **25** Python microservices + 3 `shared_*` libraries |
| Database migrations | **35** (Alembic `0001`–`0035`) |
| API paths (live, OpenAPI) | **258** |
| Tests | **2,575 passing** (26 suites, run locally — exit 0) |
| Dashboard | single-file vanilla-JS SPA, ~34 views, `index.html` (2,031 lines, zero build step, air-gap friendly) |
| Docs | 116 markdown files (architecture, ADRs, runbooks, security, user guides) |
| CI | 4 workflows: lint+23 suites, migrations up/down, Docker builds, scanner tests |
| Infra | docker-compose (dev + prod overlays), Kubernetes manifests, Prometheus+Grafana, nginx, Neo4j, Postgres, Redis |

---

## 4. End-to-end architecture (as actually implemented)

```
Git URL / local:// path / network endpoint / cloud creds / OT capture / HSM feed / vendor
        │
        ▼
┌─ WORKER ─────────────────────────────────────────────────────────────┐
│ PipelineRunner (synchronous, 15+ stages; bounded thread pool,        │
│ Redis queue or inline; per-job SQLAlchemy session):                  │
│  clone → language detect → scan → evidence → load → normalize →      │
│  policy → dedup → graph → business enrich → agility → drift →        │
│  quantum → CI gate → CBOM → coverage stamp → alert (SMTP/GitHub)     │
└───────────────┬──────────────────────────────────────────────────────┘
                │ findings / evidence / assets / drift / gate / cbom
                ▼
┌─ DATABASE (Postgres prod / SQLite dev) ──────────────────────────────┐
│ 35 migrations · 42 ORM models: scans, evidence_records (hash-chain   │
│ columns), baselines, drift_events, crypto_assets, systems,           │
│ certificates, cloud_accounts, containers, vulnerabilities,           │
│ users/sessions/audit_chain, monitor targets/leases, payment HSM,     │
│ api_keys, report snapshots, migration projects, vendors …            │
└───────────────┬──────────────────────────────────────────────────────┘
                │
                ▼
┌─ API (FastAPI /api/v1, 258 paths) + DASHBOARD (SPA) ────────────────┐
│ auth (PBKDF2, lockout, MFA TOTP, OIDC SSO, RBAC 3 roles, API keys,  │
│ rate limits, tamper-evident audit, security headers, gzip)          │
│ SSE event stream (thread-safe bus + DB tailer, Last-Event-ID)       │
│ /metrics (Prometheus) · /readyz drain · /health                     │
└──────────────────────────────────────────────────────────────────────┘
        ▲                    ▲
        │ 24/7 monitor daemon (leader lease → one scanner; backoff;    │
        │ alert-once; change-watch rescan; BLOCKED-honesty)            │
        └─ network / cloud / repo / container / payment / OT / vendor  │
```

**Evidence integrity model** (the platform's backbone):
```
content_hash[i] = SHA-256(canonical JSON of finding i)
chain_hash[0]   = SHA-256(content_hash[0] + scan_session_id)
chain_hash[n]   = SHA-256(content_hash[n] + chain_hash[n-1])
manifest_hash   = SHA-256(sorted evidence IDs)
```
Verified live: `/api/v1/scans/{id}/verify` returned `chain_intact: true` for the seeded scan.

---

## 5. Service-by-service deep dive

### 5.1 Shared libraries (`shared/`)
- **`shared_models`** (1,689 lines): the single source of truth — enums, `algorithm_registry` (708 lines, IANA/CBOM canonicalization), canonical serializers, `chrono`, `platform_scope` (the tested boundary manifest), `quantum_classify` (registry-backed quantum verdict used by every service).
- **`shared_config` / `shared_logging`**: env loader (`.env`), strict settings base, structlog factory with JSON output in prod.

### 5.2 `services/scanner` — static source scanner (8.5K lines)
Deterministic multi-language detection: Java (AST walker + JAR string scanner), Python (stdlib `ast`), JavaScript/TypeScript, C#, Go, Rust, Kotlin, PHP, Ruby, plus config-tree scanning (TLS/IaC crypto config) and PEM/certificate material scanning. ~40 detectors (cipher, message digest, signature, MAC, key generator, hardcoded key/secret, JWT, webcrypto, BouncyCastle, PyCryptodome, bcrypt, crypto-js, node-forge…). Each finding carries algorithm/mode/key-size/padding/purpose/confidence + file/line/method + git context. Extraction helpers compute entropy (hardcoded-key evidence), snippets, confidence, and dedup identity.

### 5.3 `services/evidence` — integrity layer (2.7K lines)
Canonical serializer → content hash → chain hash → scan manifest. Includes tamper-evident **audit packs** (`audit_zip`, examiner export), **scan transfer** (digest-verified cross-instance import/export), standalone verifier scripts, and intelligence helpers (agility, work orders).

### 5.4 `services/database` — data layer (9.2K lines)
SQLAlchemy 2.0 models + 35 Alembic migrations + ~20 repositories + loaders (evidence loader with pre-load verification, certificate upserts, OT devices, vulnerability replace-for-scan) + connection management with `check_db_health` for `/readyz`.

### 5.5 `services/normalization` (3K lines) + `services/policy` (2.3K lines)
- Normalization: YAML rule definitions per family (RSA/ECDSA/AES/3DES/DES/RC4/MD5/SHA-1/SHA-2, signature combos) → IANA/NIST/CBOM canonical names + key-size coercion.
- Policy: versioned YAML rules in `rule_definitions/` — **29 rules across 6 scopes**: `BASELINE` (5), `PCI-DSS` (6), `NIST SP 800-131A` (6), `CNSA 2.0` (4), `FIPS 140` (3), `HIPAA` (2), plus schema validation. Condition types: algorithm-in-list, key-size minimum, mode whitelist, boolean flags, complex scoped conditions, timelines. Evaluations are deterministic; `scope_resolver` maps system scopes.

### 5.6 `services/drift` — baseline & gates (4.8K lines)
`DriftDetector` (new/removed/changed/degraded crypto vs. approved baseline → severity), email alerts, and the **CI/CD gate**: purpose-aware (`BLOCKING_PURPOSES`: encryption/key-exchange/signing…), weak-algorithm list, standard/strict/lenient profiles, SARIF output, fail-open recording, `POST /api/v1/ci/gate`.

### 5.7 `services/worker` — orchestration (7.5K lines)
`PipelineRunner` (15+ stages, detailed above), bounded `WorkerPool` with backpressure + graceful drain, Redis job consumer, progress logging, and the **24/7 monitor tier**: due-target engine with exponential backoff (cap 24 h), alert-once, jitter, bounded concurrency, change-watch (git HEAD / image id probes → immediate rescan), and DB **leader lease** (`UPDATE … WHERE holder=:me OR expires_at < now` — single atomic statement; failover within TTL), report sweep (scheduled compliance reports), per-type intervals (NETWORK 15 min … VENDOR weekly).

### 5.8 `services/api` — API + auth (19.4K lines, the largest service)
49 routers, 258 paths: scans, findings, assets, algorithms, systems, drift, baselines, jobs, webhooks (signed GitHub), repo configs, CBOM, container(+scans), vulns, policy, quantum, intelligence, network(+scans), cloud(+scans), estate, graph, reachability, remediation, report schedules, monitor, payment-crypto, audit, events (SSE), api-keys, runtime, business(+context), agility, exceptions, OT, analytics, platform, metrics.
Security stack: PBKDF2 password hashing, persistent lockout, **RFC 6238 TOTP MFA** (tested against RFC appendix vectors), OIDC verification side, session manager with revocation, rate limiting (login 5/min/IP, scans 100/min/user; cluster-wide via Redis with per-replica fallback), tamper-evident audit chain (verify + WORM-ready JSONL export), security headers, trusted hosts, gzip, request IDs. Production startup **fails closed** on demo secrets / plaintext admin passwords / SQLite / wildcard CORS.

### 5.9 `services/network_scanner` (21.6K lines, tied-largest)
Passive TLS/cert posture: cert extraction/parsing/chain validation/order, SAN extraction, hostname matching, CRL/OCSP revocation (with live + cached paths), expiry alerting, escalation. Discovery: DNS (incl. DNSSEC checks), subnets, Kubernetes, service mesh. Enterprise layer: blast radius, cert intel, geo, HSM posture, firewall/LB, credentials diagnostics, and a live agent suite (drift, alerts, CBOM, events, health, evidence chaining).

### 5.10 `services/cloud_scanner` (21.6K lines, tied-largest)
AWS (12 scanners: KMS, ACM, S3 SSE, ELB/ALB, CloudFront, API Gateway, Lambda, RDS, EBS, SSM, Secrets Manager, region coordinator), Azure (Key Vault, Storage, SQL, App Gateway, Front Door, subscription coordinator), GCP — plus live mode (`scan_live`), IAM role assumption, credential diagnostics (which SDK credential source each provider would use), reliability layer (retries/backoff), enterprise extras (asset inventory, cost intelligence, dependency graph, compliance mapping). Reads only what the operator's credentials can see.

### 5.11 `services/container_scanner` (6K lines)
Image-root / filesystem inventory: package manifests (requirements.txt, package.json, pom.xml, go.mod, csproj…), embedded JAR string scanning, libcrypto/libssl fingerprinting, Dockerfile/IaC crypto config, layer-level attribution, live CVE lookup (optional, off by default), vulnerability records.

### 5.12 `services/universal_vendor` (15.2K lines) — vendor + hardware
- **Live Vendor Engine**: 68 plugins across 16 categories, trust gating, SDK + connector template (see `sdk_template/`), continuous 24/7 monitoring of vendor surfaces.
- **Universal Hardware Scanner** (latest commit, spec §1–§25): canonical `HardwareObservation` model, 30 plugins (server, network, HSM, TPM, smartcard, storage, GPU, virtualization, IoT, industrial), multi-signal identity resolution (≥2 distinct kinds → HIGH), weighted fingerprinting → HIGH/MEDIUM/LOW, CPU extension capabilities, **metadata-only** TPM/HSM with hard `_FORBIDDEN` assertions (never keys/secrets), firmware intelligence with crypto re-evaluation, hardware→software→network correlation, lifecycle (EOS/EOL/PQC → CRITICAL migration candidate), live state engine (NEW/CHANGED/REMOVED), expected-vs-current drift incl. `SECURITY_HARDWARE_DRIFT`, risk tiers (CRITICAL ≥ 12), HBOM output, evidence chain, OT safety tiers (passive SAFE/CAUTIOUS; ACTIVE needs approval), regions with offline durable queue, kill switch.

### 5.13 The analytical services
- **`graph_engine`** (3.8K): Neo4j Cypher with in-memory fallback; system/crypto-asset/certificate/vendor/cloud-resource syncers; reachability, dependents, blast radius, hotspots, cycle detection (Tarjan SCC), migration waves, business impact, compliance inheritance; optional Istio mesh poller.
- **`quantum`** (852): Mosca inequality (HNDL), Shor/Grover exposure, PQC migration plans (workstreams/waves), per-asset risk scoring.
- **`agility`** (1.4K): 6-factor explainable scoring, trajectory history, what-if simulation, portfolio roadmap, PQC readiness blockers.
- **`remediation`** (1.2K): rule-driven engine, family-prefix matching, 15 rules × 4 languages = 60 before/after snippets + 3 guides, priorities, backlog, CLI.
- **`reporting`** (1.6K): 6 compliance templates, requirement-by-requirement from policy evidence (NOT_EVALUATED never guessed), PKI RS256 report signing when key configured, **PDF export** (fpdf2, deterministic A4), scheduled snapshots + email distribution.
- **`payment_crypto`** (1.7K): HSM key inventory, TR-31 header parsing, audit-trail ingestion (JSONL/syslog/CSV, deduped), 13 PAY rules (weak algos, rotation, dual control, clear-key exports, auth storms, firmware, B0 blocks, dormancy PAY-011, dead-key PAY-012, shadow keys PAY-013, transaction correlation PAY-014, overdue ceremonies PAY-015/016), forecast calendar, usage telemetry, connectors.
- **`ot_scanner`** (1.6K): passive-only protocol parsing (Modbus, DNP3, OPC-UA, IEC 61850 GOOSE/SV, EtherNet/IP, PROFINET, S7comm, MQTT) from `.otlog` captures — **zero packets to OT networks** (tested promise), IEC 62443 zones/conduits.
- **`business_context`** (787): business processes/owners, stakeholder alerts, enrichment.
- **`deduplication`** (858): canonical dedup identity, merge stats, registry-backed.
- **`cbom`** (2.9K): CycloneDX 1.5/1.7 generation (components, dependencies, evidence, vulnerabilities, signing), assessment (score/grade), coverage, JSON/XML serializers.
- **`container`/`runtime`/`vendor_intel`**: container posture, runtime findings, vendor risk 0–100 (API scan, CBOM import, questionnaire).

### 5.14 Dashboard (`services/dashboard/index.html`, 2,031 lines)
Vanilla JS SPA — no build step, no CDN (air-gap friendly): login/MFA, scans, findings, drift, jobs, systems, assets, CBOM, container, cloud, TLS/certs, graph, quantum, agility, analytics, payment, OT, vendors, monitor (live 5 s refresh), events (SSE), API keys, policy, exceptions, migrations, work orders — 34 views against `/api/v1`.

---

## 6. Live verification (performed during this study)

1. **Full test suite re-run locally: 2,575 passed, 0 failed** (26/26 dirs, exit 0) — matches the repo's claim exactly:
   network_scanner 555 · cloud_scanner 411 · api unit 240 · api integration 39 · worker 121 · scanner 107 · container 107 · shared_models 103 · policy 68 · drift 63 · cbom 40 · ot 39 · agility 37 · reporting 33 · database 32 · payment 26 · runtime 21 · remediation 21 · quantum 17 · normalization 114 · evidence 43 · graph 41 · dedup 12 · vendor_intel 12 · business_context 6 · universal_vendor 267.
2. **End-to-end scan executed**: `seed_demo.py` ran the real pipeline (clone→scan→evidence→load→normalize→policy→dedup→graph→agility→drift→quantum→gate→CBOM→alert) on `demo/vulnerable-app` — 14 findings across 5 Java files (MD5/SHA-1/AES/RSA-1024/DES violations), quantum HNDL + migration alerts fired.
3. **API booted** (`uvicorn`, SQLite dev mode): admin login works (`admin`/`cryptoscan`, dev only), 258 OpenAPI paths, `/health` healthy, dashboard served at `/`.
4. **Evidence chain verified via API**: `chain_intact: true`, 14 records, valid manifest hash `d12565a1…`.
5. **CBOM exported via API**: CycloneDX 1.5, 14 components.
6. **Platform scope served**: `GET /api/v1/platform/scope` returns the boundary manifest.

---

## 7. Honesty mechanics (the distinctive feature)

- **Scope as tested code**, not prose: `shared_models/platform_scope.py` + `test_platform_scope.py` (module-path/docstring boundary checks + evidence-whitelist leakage tests — fake secrets planted in source records must not appear in any pack output).
- **Never faked statuses**: unscannable → `BLOCKED` with reason; untestable → `NOT_EVALUATED`, never guessed PASS; email without SMTP → `SKIPPED_NO_SMTP` recorded; report signing absent without key — never a fake signature.
- **Docs name the gaps**: `PLATFORM-STATUS.md` (W37–60 matrix), `real-world-comparison.md` (honest benchmark vs. SandboxAQ Cryptosense / Venafi / Keyfactor / Prowler / Trivy / testssl.sh / Nozomi), `bank-vs-zelnx.md` (vs. an actual bank's crypto estate).
- **Metadata-only guarantee**: key material never leaves the estate; tests enforce the whitelists.

---

## 8. Observations & honest critique

**Strengths**
- Extraordinarily broad, coherent end-to-end implementation: 25 services, 35 migrations, 2,575 green tests, one command boots a real pipeline.
- The evidence-chain + metadata-only + no-AI-policy doctrine is a genuinely differentiated, audit-friendly compliance story.
- Engineering maturity signals: leader-lease HA, drop-oldest SSE with Last-Event-ID resync, backpressure pools, fail-closed prod config, digest-verified transfers, benchmark with regression history (10k files in 59 s vs 300 s budget).
- Excellent documentation culture (ADRs, runbooks, threat model, honest status matrix).

**Gaps / limitations (as the repo itself declares)**
- No React/Vite app — the previous empty scaffolding was removed in favor of the self-contained SPA (documented decision).
- Cloud/network scanning depth is crypto-config-focused (deliberately not a CSPM/TLS-lab competitor — stated in the comparison doc).
- Some APIs need real infrastructure to fully exercise (Neo4j, Postgres replication, cloud creds); local runs use SQLite + in-memory fallbacks (honestly labeled).
- Minor runtime warnings observed: two Pydantic field names shadowing `BaseModel` attributes (`cloud.py`, `network.py` `register` fields).
- The divergent 12-commit branch (`01a02f50`) is dead history; `main` remains a 2-commit seed — all real work lives on the arena branches.

---

## 9.5 The missing parts — a verified gap inventory

Everything below was verified against the current tree (`6b81a03`), not copied
from older analysis docs. Categories: **never built** (spec items absent from
the whole codebase) · **built but never proven live** (gated/unverified) ·
**partial/thin** · **deliberately not claimed** · **repo-level**.

### A. Never built (in the 15-month spec, absent everywhere)

| Missing | Spec reference | Notes |
|---|---|---|
| eBPF kernel runtime agent | logic-3 §27–28 (spec marked *optional — advanced*) | Replaced by a passive TLS tap (forward proxy that reads handshake records only) + process scan + JSONL import. The API router states it explicitly: *"without requiring a kernel agent."* |
| Runtime crypto-call tracing (dynamic analysis) | logic-3 | CryptoScan is **static-only** for source trees. No runtime call graphs, which is exactly what SandboxAQ Cryptosense does deeper (acknowledged in `real-world-comparison.md`). |
| Tree-sitter / Roslyn / Eclipse JDT deep parsers | ADR-002, 005, 006 | ADRs document the intended strong parsers; the shipped implementation is AST-lite + regex. Works on normal code, weaker on obfuscated / macro-heavy code. |
| AI assistance layer | README "STEP 5" | **Zero AI anywhere** — no plain-language explanations, no prioritization, no migration-cost prediction. Deliberate ("policy never decided by AI"), but note the README still *describes* this layer; the codebase has none of it. |
| 8 RBAC roles | logic-5 W57–58 | Only **3 roles ship** (admin / auditor / viewer). The spec's 5 extra roles (e.g. business-owner, security-analyst granularity) were never built. |
| First-class configuration-drift event class | logic-3 "Drift v2.0" | Config/IaC files are scanned for findings, but drift detection compares **code findings**; there is no separate `CONFIG_DRIFT` event class vs. code drift. |
| Certificate lifecycle automation (issue/renew/revoke, ACME/SCEP) | (market comparison) | Inventory + expiry + a renewal-**tracking** workflow (CR-001, `renewal_status` column) exist — but nothing issues/renews/revokes. Venafi/Keyfactor's core business. |
| JWS CBOM signing | logic-2 §23–24 | Spec said JWS; implementation is **HMAC** signing (documented standards-conformance nit). |
| Deployed observability | logic-5 W57–58 | Prometheus+Grafana dashboards ship in `infra/monitoring/`, but ELK/Jaeger, uptime numbers, 7-year WORM storage are **not claimed** — infrastructure the operator must deploy. |

### B. Built + tested, but never proven against the real thing

| Area | Status |
|---|---|
| Live TLS probing | Gated behind `CRYPTOSCAN_TLS_LIVE=0` (safe default). Never run against a live endpoint in this environment. |
| Cloud scanning (AWS/Azure/GCP) | Gated behind `CRYPTOSCAN_CLOUD_LIVE=0`. All 20+ scanners unit-tested with mocks; **never run against a real account**. IAM policies + setup scripts provided. |
| Neo4j graph | In-memory fallback used in all tests; live Bolt + constraints never exercised here (compose ships it). |
| Container scanning via Docker/registry | Filesystem/docker-save mode works; real image pull + CVE lookup path not proven E2E. |
| SMTP delivery | Alerter built + tested; no real email ever sent (`SKIPPED_NO_SMTP` recorded honestly). |
| GitHub webhook round-trip | HMAC verified + burn-in simulation; no real-repo push → scan → status-post proof. |
| Postgres streaming replication promotion | `promote-replica.sh` + split-brain guard exist; never exercised on a live cluster. |
| payShield HSM connector | **Labeled SIMULATOR.** Real connectors exist only for HTTP JSONL feeds and syslog file tailing — no vendor device protocol is implemented. |
| OT capture | Parses **pre-captured** `.otlog` files (Modbus/DNP3/OPC-UA/GOOSE…). Zero packets to OT nets — but there is no live passive capture interface; capture must be produced by external gear. |
| Scheduled reports / monitor daemon | Built + tested; long-run behavior (multi-day backoff, lease failover) only proven in short simulations. |

### C. Partial / thin implementations

- **RBAC**: 3 of 8 spec roles (see A).
- **PDF reports**: "basic structured PDF, not branded layout" (their words).
- **Prioritization dashboard**: `/priorities` + work orders exist; the SPA has no dedicated prioritization view (work orders surface on the home view).
- **Stakeholder alerting**: 98-line module — email optional, "always logs".
- **Business context**: tables + YAML config + seed scripts exist, but the seeded demo DB starts with **0 processes/owners** unless you run the seed scripts manually.
- **GCP coverage**: 4 scanners (Cloud KMS, Cloud SQL, GCS, Load Balancer) vs AWS's 12 and Azure's 5 — the thinnest cloud provider leg.
- **Drift blind spot** (self-documented): a *new* weak-algorithm occurrence is suppressed when that algorithm already exists in the baseline (semantic-signature dedup).
- **Hardware scanner**: 30 plugins, but discovery agents (DMI/PCI/USB/BMC, SNMP/SSH) are structured collectors — nothing was exercised against a real machine; confidence rules are unit-tested against synthetic inputs.
- **HA**: leader lease covers the **monitor tier only**. API/worker multi-replica operation has `/readyz` drain + shared Redis rate limits + replication overlay, but no full multi-AZ API/worker runbook (honestly "deployed by you").

### D. Repo-level gaps

- **`main` is still a 2-commit skeleton.** All 124 commits of real code live on `arena/01a052d9-cryproscan` (and ancestors); nothing has ever been merged to `main`, no tags/releases exist. A real handoff should fast-forward `main`.
- **No CHANGELOG**; `API_VERSION` hardcoded `1.0.0`.
- **Dashboard has no automated frontend tests** — the 2,031-line SPA is only exercised indirectly via API tests.
- **`requirements.txt` uses unbounded ranges** (a pinned `requirements.lock.txt` exists and is what CI installs).
- **Stale analysis docs**: `ANALYSIS.md` / `PRODUCTION-READINESS.md` / `ANALYSIS-2026-08-26.md` predate the current tree — they claim "CI is empty", "single-admin auth", "221 API paths / 23 services / 1,233 tests", while the current tree has 4 CI workflows, multi-user RBAC+MFA, **258 paths / 25 services / 2,575 tests**. Read them as history, not status.
- Minor nits: two Pydantic `register` field-shadowing warnings at import (`cloud.py`, `network.py`); 9 empty `__init__.py` files; `GET /api/v1/stats` is actually `/api/v1/stats/summary`.

### E. What is NOT missing (so the list above is fair)

All of this works and was re-verified live during this study: the full 15+ stage
pipeline, SHA-256 evidence chain + verification, deterministic YAML policy (29
rules / 6 scopes), drift + CI gates, CBOM export, quantum/agility scoring,
remediation templates, compliance reports (JSON/HTML/PDF + optional PKI
signing), MFA + lockout + rate limiting + tamper-evident audit, SSE realtime
stream, 24/7 monitor daemon with leader lease, and the 2,575-test suite.

---

## 10. How to run it

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt   # setup
export CRYPTOSCAN_ROOT=$PWD
export PYTHONPATH=$(ls -d shared/* services/* | tr '\n' ':')
.venv/bin/python scripts/seed_demo.py          # first scan through the real pipeline
bash scripts/run_stack.sh                      # or: make api → http://localhost:8000
.venv/bin/python -m uvicorn api.main:app --host 0.0.0.0 --port 8000   # API + dashboard
.venv/bin/python scripts/run_monitor.py --once # one 24/7 monitor sweep
```
Dev login `admin` / `cryptoscan` (refused in production). Production overlay: `docker compose -f docker-compose.yml -f docker-compose.prod.yml up --build` after setting secrets; `bash scripts/deploy_prod.sh -d`.

*The API from this study session is still running on port 8000 (live preview) if you want to click through the dashboard.*
