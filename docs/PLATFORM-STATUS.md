# CryptoScan platform status — the full plan vs. what ships here

Honest accounting, capability by capability, for every week in the plan
(Part 4: W37–48, Part 5: W49–60). "Built" means code + tests in this repo.
"Partial (honest)" means the testable core is built and the gaps are named.
"Not claimed" means we deliberately did not fake it — usually because it needs
real infrastructure or credentials.

Measured at this commit: **221 API paths**, **23 services**, **1,233 tests
passing (`make test`, exit 0)**, 26 database migrations (0001–0026).

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
| 55–56 | Compliance reports (6 templates, requirement-by-requirement from policy evidence, attestation + canonical SHA-256 hash) | Partial (honest) | `reporting/report_templates.py`, `GET /scans/{id}/report[.html]`, `GET /report-templates`. NOT_EVALUATED never guessed as PASS. **No PDF** (JSON + HTML), no scheduled email distribution (needs SMTP). PKI signing now built: set `REPORT_SIGNING_KEY` and reports carry a real RS256 signature (OpenSSL-verifiable, `POST /report/verify`); absent when unconfigured — never faked. Scheduling built: `POST /report-schedules` + `run-due` cron entry, immutable `report_snapshots` (migration 0027), email via configured SMTP (`SKIPPED_NO_SMTP` recorded honestly) |
| 57–58 | Hardening: MFA (RFC 6238 TOTP + recovery codes), lockout, RBAC, rate limiting, tamper-evident audit, security headers, prod config fail-closed | Partial (honest) | Migration 0022 (MFA), 0025 (audit chain); `RateLimitMiddleware`; `GET /auth/audit/{verify,export}` (WORM-ready JSONL); OIDC SSO verification (`POST /auth/oidc`, bring-your-own-IdP). RBAC ships 3 roles (admin/auditor/viewer), not the spec's 8. **Not claimed:** mTLS, WAF/DDoS, multi-AZ/DR, Prometheus/ELK/Jaeger, 7-year WORM storage — infrastructure, deployed by you (see `docs/admin-guide/hardening.md`) |
| 59–60 | Performance & polish: measured scan benchmark, hot-path composite indexes, gzip, estate CSV export | Partial (honest) | `scripts/benchmark_scan.py` (10k files in 59.1 s vs 300 s budget, regression-caught history in `docs/admin-guide/performance.md`); migration 0026 indexes; `GET /export/findings.csv` with honest truncation headers. **Not claimed:** Redis caching, materialized views/partitioning, GraphQL, PWA/frontend polish, Lighthouse, uptime numbers |

## Beyond the plan: live monitoring (24/7)

Not in the original W37–60 plan — added later as `scripts/run_monitor.py`:
watch-list daemon (network endpoints probed live every interval, cloud via
`scan_live`, repos via the job pipeline, containers via image scan), failure
backoff, alert-once semantics, BLOCKED-honesty for unscannable targets, event
feed, `GET /monitor/status` + dashboard "Live monitor" view (5 s refresh).
Migration 0028. See `docs/user-guide/live-monitoring.md`.

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

## Platform-wide (earlier parts, for completeness)

Evidence hash chain (content + chained hashes, verification script) · CBOM
export (CycloneDX 1.5 crypto-asset) · container SBOM (SPDX-2.3) · deterministic policy engine
with 6 standards packs · multi-user auth with sessions + revocation · HMAC
webhook signing (`X-CryptoScan-Signature`) · dedup via canonical identity
tuples · dependency graph (Tarjan) + blast radius + reachability · drift
detection with blocking severities · cloud/container/network/host scanning ·
air-gap install guide (`docs/admin-guide/air-gap-install.md`).

## Explicitly open (needs real credentials/infrastructure — never stubbed)

- **SSO federation** — OIDC verification is now built (bring-your-own-IdP: `POST /auth/oidc`, RS256 + JWKS, `docs/admin-guide/oidc-sso.md`); what still needs yours: a real issuer. SAML remains unclaimed
- **PKI-signed reports** — needs a signing certificate; reports carry an
  HMAC integrity hash today and `signature: null` honestly
- **Live burn-ins** (10k scans/day, 100k assets, uptime) — needs production
  hardware; the repo ships the reproducible benchmark instead
- **Email distribution** — needs SMTP credentials
- **Frontend polish (PWA, dark mode, Lighthouse 97)** — no web frontend ships
  in this repository
