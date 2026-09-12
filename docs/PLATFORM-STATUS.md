# CryptoScan platform status — the full plan vs. what ships here

Honest accounting, capability by capability, for every week in the plan
(Part 4: W37–48, Part 5: W49–60). "Built" means code + tests in this repo.
"Partial (honest)" means the testable core is built and the gaps are named.
"Not claimed" means we deliberately did not fake it — usually because it needs
real infrastructure or credentials.

> **Current-state correction (2026-09-08):** the numbers at the top of this
> document were measured at an earlier commit and are now out of date. The
> tables below are a historical record of the plan vs. what existed at those
> commits; they are retained for traceability and should not be read as the
> current state.

Measured at the release HEAD (`v1.0.0` + supervisory portal + telecom scanner + ops layer + enterprise readiness, 2026-09-11):
**583 OpenAPI paths** (measured from the live schema), **56 ordered database migrations** (0001–0056),
**64 frontend pages**, **9 RBAC roles** (superadmin, ciso, security_analyst,
developer, auditor, business_owner, scanner, readonly, supervisor — plus
admin→superadmin / viewer→readonly aliases), and **4,004 test functions**
across every service suite (collected at the release commit). Releases are cut through
`python3 scripts/release_check.py` (VERSION == API version == `v` tag,
dated CHANGELOG section, contiguous migrations, prod-guard intact).

**Update (2026-09-12, commit `e90cdd8`):** **585 OpenAPI paths / 644 operations**
(measured live), migrations still 0001–0056, **64 frontend pages**, same 9 RBAC
roles. New since the last measurement: six first-class scanner languages
(Python/Java/C#/JavaScript/Go/Rust — weak-primitive + key-size extraction pinned
by tests), the examiner **audit pack** (`GET /audit-export/pack`), the PoC
**exit report** with deterministic SHA-256 and SC-1…4 scorecard
(`GET /audit-export/exit-report`, SC-4 met only by a human name), the
**engagement archive** (`GET /audit-export/engagement-archive` — pack + report +
manifest, all sha256sum-verifiable), and the hardware catalog PQC refresh
(`GET /hardware/catalog` → 60 device types, `quantum_resistant_count: 10`,
firmware-cited provenance, shipping-only evidence). Full regression lane at this
commit: **1370 passed / 12 skipped / 0 failed**.

Earlier measurement, kept for traceability — at `24a7a0c` (ZELNX security &
scanning policy): 505 OpenAPI paths, ~44 service packages, 54 migrations
(0001–0054), 60 frontend pages, ~3,660 test functions.

## Scope & honest boundaries

What CryptoScan is (and is not) is a tested, versioned manifest, not prose:
`shared/shared_models/shared_models/platform_scope.py`, served at
`GET /api/v1/platform/scope`, enforced by
`shared/shared_models/tests/test_platform_scope.py` (module-path and
docstring boundary checks + evidence-whitelist leakage tests), documented in
[docs/architecture/platform-boundaries.md](architecture/platform-boundaries.md).

Highlights: **read-only, evidence-chained, key *metadata* only (never key
material)**; no general SAST / malware / SIEM behavior analytics / COBOL or
PL-I application-source scanning / employee endpoints; z/OS mainframe
coverage IS in scope as crypto-configuration inventory via operator-produced
extracts (RACF/ICSF/DB2/CICS) — never application-code parsing; cloud scanning is limited to the
accounts/tenants the operator's credentials can see — external surface only
via public internet scanning of configured targets.

## Part 4 — Months 10–12 (logic-4.md)

| Week | Capability | Status | Where it lives |
|---|---|---|---|
| 37–38 | Crypto agility scoring (6-factor, deterministic, history, recommendations) | Built | `services/agility`, `GET /agility`, `GET /systems/{id}/agility`, `GET /agility/roadmap` |
| 39–40 | Quantum deep analysis (Shor/Grover, HNDL, Mosca, deadlines, PQC picks) | Built | `services/quantum`, `GET /quantum/plan`, `POST /quantum/mosca`; classifier in `shared_models` |
| 41–42 | OT/ICS passive scanning (OPC-UA/DNP3/Modbus/IEC 61850, zones, device CVEs) | Built | `services/ot_scanner`, `GET /ot/*`; read-only verified (zero packets to OT net) |
| 43–44 | Vendor crypto discovery — 4 methods, risk 0–100, dashboard | Built | `services/vendor_intel`, `POST /vendors/{id}/api-scan`, `/cbom`, `/docs`, questionnaire, `GET /vendor-risks` |
| 45–46 | Analytics v2 (trends, heat maps, forecast, top-10, executive summary) | Built | `GET /analytics/{trends,heatmap,forecast,recommendations,executive}` |
| 47–48 | Exception management (approval, expiry auto-revert, audit) + migration readiness (5-factor, waves) | Built | `GET/POST /exceptions/*`, readiness stage in worker pipeline |

## Part 5 — Months 13–15 (logic-5.md)

| Week | Capability | Status | Where it lives |
|---|---|---|---|
| 49–50 | CI/CD policy gates (standard/strict/lenient profiles, 422 at boundary, fail-open recording, PR comments) + GitHub/Jenkins/GitLab/ArgoCD | Built | `drift/core/gate.py`, `POST /ci/gate`, `GET /ci/gate-evaluations`, `scripts/ci_gate.py`, `integrations/` |
| 51–52 | Remediation templates: language-specific snippets, testing checklists, real standards refs, multi-step guides, fix-branch payloads | Built | `remediation/templates.py` — 15 rules × 4 languages = 60 snippets + 3 guides (`kms-migration`, `pqc-hybrid`, `tls-upgrade`); `GET /remediation/*`, `POST /remediation/fix-branch` (advisory — never pushes) |
| 53–54 | Migration tracking (auto-project from scan, tasks/milestones, derived progress, velocity forecast, GitHub export + sync) | Built | `POST /migrations/from-scan`, `GET /migrations/{id}/{tasks,progress,forecast}`, `export/github-issues`, `POST /sync`; demo: 207 assets → 207 tasks, 50 done → 24.2% |
| 55–56 | Compliance reports (6 templates, requirement-by-requirement from policy evidence, attestation + canonical SHA-256 hash) | Built | `reporting/report_templates.py`, `GET /scans/{id}/report[.html]`, `GET /scans/{id}/report.pdf`, `GET /report-templates`. NOT_EVALUATED never guessed as PASS. **PDF built**: deterministic A4 rendering of the same report JSON (`reporting/pdf_export.py`, `fpdf2`) — a basic structured PDF, not branded layout. PKI signing built: set `REPORT_SIGNING_KEY` and reports carry a real RS256 signature (OpenSSL-verifiable, `POST /report/verify`); absent when unconfigured — never faked. Scheduling built: `POST /report-schedules` + `run-due` cron entry, immutable `report_snapshots` (migration 0027), email via configured SMTP (`SKIPPED_NO_SMTP` recorded honestly) |
| 57–58 | Hardening: MFA (RFC 6238 TOTP + recovery codes), lockout, RBAC, rate limiting, tamper-evident audit, security headers, prod config fail-closed | Partial (honest) | Migration 0022 (MFA), 0025 (audit chain); `RateLimitMiddleware`; `GET /auth/audit/{verify,export}` (WORM-ready JSONL); OIDC SSO verification (`POST /auth/oidc`, bring-your-own-IdP). RBAC ships 3 roles (admin/auditor/viewer), not the spec's 8. **Not claimed:** mTLS, WAF/DDoS, multi-AZ/DR, Prometheus/ELK/Jaeger, 7-year WORM storage — infrastructure, deployed by you (see `docs/admin-guide/hardening.md`) |
| 59–60 | Performance & polish: measured scan benchmark, hot-path composite indexes, gzip, estate CSV export | Partial (honest) | `scripts/benchmark_scan.py` (10k files in 59.1 s vs 300 s budget, regression-caught history in `docs/admin-guide/performance.md`); migration 0026 indexes; `GET /export/findings.csv` with honest truncation headers. **Not claimed:** Redis caching, materialized views/partitioning, GraphQL, PWA/frontend polish, Lighthouse, uptime numbers |

## Beyond the plan: live monitoring (24/7)

Not in the original W37–60 plan — added later as `scripts/run_monitor.py`:
watch-list daemon (network endpoints probed live every interval, cloud via
`scan_live`, repos via the job pipeline, containers via image scan), failure
backoff, alert-once semantics, BLOCKED-honesty for unscannable targets, event
feed, `GET /monitor/status` + dashboard "Live monitor" view (5 s refresh).
Migration 0028. See `docs/user-guide/live-monitoring.md`.

**Unified live scan flow (the "one product")** — instead of four independent
scanners, Network / Hardware / Vendor / Cryptography are now driven by ONE
integrated **scan orchestrator** (`api/live_scan/orchestrator.py`,
`GET/POST /api/v1/live/orchestrator/*`, `GET /api/v1/live/environment`). Every
run gets ONE global scan id (`SCAN-YYYY-NNNN`, unique across restarts via the
persisted `scan_seq` counter) and a deterministic phase machine
(`scope_validated → discovery → correlation → risk_calculation →
live_monitoring`). Scope is **fail-closed** (empty authorized scope denies the
scan) and execution delegates to the real `LiveScanRunner`. Run history is
rebuilt from the durable platform event log (`GET /live/orchestrator/history`),
so past integrated scans survive restarts and are visible from any worker.

**Payment crypto (bank gap #1)** — HSM key inventory + ceremonies, audit-trail
ingestion (JSONL/syslog/CSV, timestamp-deduped), TR-31 header parsing, 10
PAY-xxx rules (weak algorithms, rotation, dual control, clear-key exports,
auth storms, firmware changes, B0 blocks), risk acceptance that survives
re-evaluation, `PAYMENT` monitor target, CEF/webhook/SMTP alert routing,
HA compose stack + DR runbook, threat model + dependency audit (0 known CVEs),
API load-test tool. Migration 0030. See `docs/user-guide/payment-crypto.md`.

**Scale/HA/DR (bank gap #2)** — monitor **leader lease** (run N daemons,
exactly one scans; SIGTERM = instant failover, hard loss = failover within
TTL — *verified live* in this environment), Postgres streaming-replication
overlay + `promote-replica.sh` (split-brain guarded), `/api/v1/readyz` LB
drain endpoint (unauthenticated, 503 when DB is down), cluster-wide rate
limits via shared Redis (honest per-replica fallback), automated quarterly
`drill.sh`, load test re-run with throttle accounting (capacity ~1.5k rps
single-process; per-identity budget enforced under 30-VU flood). Migration
0031. See `docs/runbooks/dr-recovery.md`.

**Payment usage analytics (Aug 30)** — key-usage telemetry (ops per key/day,
dormancy PAY-011, dead-key usage PAY-012, shadow keys PAY-013), daily
transaction-volume series + crypto-per-transaction correlation (PAY-014,
honest `insufficient_data` under 14 days), HSM feed connectors (HTTP JSONL
poll with since-cursor, rotation-safe syslog tail, labeled payShield drill
simulator), PAY-xxx evidence wired into the PCI-DSS 4.0 report template with
a `payment_crypto` block. Migration 0032.

**Payment loop automation (Aug 30, pm)** — PAYMENT monitor runner now polls
connector feeds (HTTP `?since=` cursor or rotation-safe file cursor), ingests
daily transaction exports (`transactions_path`), and runs usage + correlation
inside every sweep (PAY-011..014 fire from live data); bulk transaction push
endpoint; dashboard usage/correlation card with ops/tx trend.

**Rotation calendar (Aug 30, evening)** — expiry forecasting across payment
keys and the TLS certificate inventory (horizon buckets, per-ISO-week load),
PAY-015 (rotation inside 90d without a scheduled ceremony), `GET
/payment-crypto/forecast`, dashboard rotation-calendar card, and the payment
section in scheduled report emails (keys, findings, upcoming rotations).

**Ceremony scheduling (Aug 30, night)** — ceremony lifecycle PLANNED/HELD/
ABANDONED (migration 0033): future-dated bookings clear PAY-015, ABANDONED
does not; **PAY-016** flags planned ceremonies past their date (missed
rotation window); PATCH /ceremonies/{id}, ?upcoming=true listing, dashboard
ceremonies card with schedule/mark-held/abandon.

**Certificate renewals + audit pack (Aug 31)** — certificate renewal workflow
(NONE/PLANNED/IN_PROGRESS/DONE, ticket + timestamp, migration 0034),
**CR-001** (certificate ≤30d from expiry with no renewal in flight; sev 4
inside 7d), dashboard "Plan renewal" action, and **GET /audit-export/pack**:
one examiner ZIP (payment keys/ceremonies/findings/forecast, HSM events 90d,
certificate inventory, watch-list, latest PCI report with payment evidence,
evidence chain verification) with a per-file SHA-256 manifest and honest
NO_*.txt notes for anything absent.

**First full end-to-end scan (Aug 31)** — `POST /scans/trigger` on the live
stack scanned this repository itself (HTTPS clone of
`ZKChainForge/CryproScan@96cd6ec`, branch `arena/01a03d0e-cryproscan`):
940 files → 197 deduped findings (10 collapsed) → 197 evidence records with
an intact hash chain (independently re-verified) → gate decision FAIL
(5 blocking: DES/3DES/RC4 in `demo/` apps), quantum HNDL CRITICAL (69
vulnerable sites), agility 67.0, 17 work orders. The audit pack now ships a
real `compliance/pci-dss-4.0-report.json` (attestation + policy-pack hash,
`signature: null` honestly) and `evidence/chain-verification.json` = PASS —
no more NO_COMPLETED_SCAN placeholders. Known cosmetic defect surfaced by
this run: dependency-manifest findings record workspace-prefixed paths
(`data/workspaces/job-…/repo/…`) instead of repo-relative ones.

**Real-time API + machine access (Aug 31)** — the product moved from
poll-and-refresh to push. `GET /events/stream` (SSE, Last-Event-ID resume,
drop-oldest backpressure, heartbeat) backed by an in-process event bus:
scan queued/stage/completed (with gate decision), monitor probe outcomes
(federated from the separate monitor process by a 2s DB tailer — latency
stated, not hidden), logins, API-key changes; `GET /events/recent` for
fallback. Dashboard "Live events" view subscribes live and degrades to
polling honestly. **Machine API keys** (`X-API-Key` on every endpoint,
SHA-256-at-rest, shown once, own RBAC role set, immediate revocation,
throttled `last_used_at`, admin-only management + audit trail, migration
0035) for CI/SIEM integration; rate limiter buckets per key. Honest limits
documented: single-process fan-out (Redis bus is the upgrade path), history
not durable across restarts. See `docs/user-guide/realtime.md`.

## Platform-wide (earlier parts, for completeness)

Evidence hash chain (content + chained hashes, verification script) · CBOM
export (CycloneDX 1.5 crypto-asset) · container SBOM (SPDX-2.3) · deterministic policy engine
with 6 standards packs · multi-user auth with sessions + revocation · HMAC
webhook signing (`X-CryptoScan-Signature`) · dedup via canonical identity
tuples · dependency graph (Tarjan) + blast radius + reachability · drift
detection with blocking severities · cloud/container/network/host scanning ·
air-gap install guide (`docs/admin-guide/air-gap-install.md`).

## Explicitly open (needs real credentials/infrastructure — never stubbed)

- **SSO federation** — OIDC (token relay + server-side authorization-code flow with signed state/nonce), SAML 2.0 SP (metadata/AuthnRequest/ACS with signature verification) and LDAP/AD group→role login are all built, bring-your-own-IdP; what still needs yours: a real issuer/IdP. PKCE for pure-SPA public clients is the next hardening step (`docs/enterprise-readiness.md`)
- **Cloud KMS collectors** — AWS KMS + Azure Key Vault are built (read-only metadata → the shared crypto-asset inventory; unknown key types skipped with their reason). GCP KMS / AWS ACM / DB-TDE / mainframe collectors are not built and will not be faked
- **PKI-signed reports** — needs a signing certificate; reports carry an
  HMAC integrity hash today and `signature: null` honestly
- **Live burn-ins** (10k scans/day, 100k assets, uptime) — needs production
  hardware; the repo ships the reproducible benchmark instead
- **Email distribution** — needs SMTP credentials
- **Frontend polish (PWA, dark mode, Lighthouse 97)** — no web frontend ships
  in this repository
