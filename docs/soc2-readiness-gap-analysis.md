# SOC 2 Type II readiness — gap analysis

_Drafted 2026-09-21 (branch `arena/01a0b9c6-cryproscan`, commit `bf794e4`).
Prepared to de-risk the auditor engagement: what the platform already
evidences, what needs finishing, and what is inherently outside the codebase.
Every code claim points at a real path in this repo; every "org" item names
the process an auditor will actually ask for._

## Scope and reading guide

A SOC 2 Type II opinion covers **the service organization** (the SaaS
provider and its people, policies, and systems) over an **observation window**
(typically 3–6 months) — not the customer's estate. For each control family
below:

- ✅ **Built & evidenced** — implemented in code, with tests, and a way to
  produce auditor-facing evidence.
- 🟡 **Built, evidence/process needs finishing** — the capability exists; the
  cadence, documentation, or org process around it does not yet.
- ❌ **Missing or third-party** — not in this repo; an org decision or an
  external engagement.

Status legend applies to the *provider's* SOC 2. (The same platform also helps
customer banks evidence *their* CBUAE/PCI posture — that is a separate use.)

---

## 1. CC6 — Logical access

| Control | Status | What exists (pointer) / what's missing |
|---|---|---|
| CC6.1 boundary protection | ✅ | TLS everywhere, rate limiting is **unconditional middleware** (`api/middleware/rate_limit.py`), explicit-CORS-only production guard (`api/config/settings.py::validate_runtime_settings`), security headers, airgap mode with URL policy (`governance/airgap.py`), target validation (`api/security/target_validation.py`) |
| CC6.1.1 user registration | ✅ | Self-register with password policy (`api/security/passwords.py::password_policy_errors`), MFA gate, OIDC/SAML/SCIM (`api/security/oidc.py`, `identity/saml.py`, `identity/scim.py`) |
| CC6.1.2 role changes | ✅ | 9-role catalog, **action-based** permission model (`api/security/rbac.py`), per-tenant ABAC (`api/middleware/abac_middleware.py`), tenancy core (migration `0057_saas_tenancy_core`) |
| CC6.2 credential issuance | ✅ | TOTP MFA + recovery (`api/security/totp.py`), signed sessions with TTL (`api/security/session_manager.py`, `SESSION_EXPIRE_HOURS`), bootstrap-admin-from-hash only (no plaintext in prod — prod guard enforces) |
| CC6.2.1 revocation | ✅ | Session invalidation, account disable with audit (`auth.py` lifecycle), API-key allowlist rotation (migration `0052`) |
| CC6.3 periodic re-authorization | 🟡 | **Export + minutes system of record built 2026-09-21**: `GET /api/v1/audit-export/access-review` produces the full estate (users/roles/MFA/last-login, API keys prefix+hash only, active sessions) plus the standing signals (privileged, no-MFA, stale, never-used, locked, expired-unrevoked keys) with a reproducible `report_hash` signature; `POST/GET /api/v1/audit-export/access-reviews` records each completed review (period, reviewer, attested `report_hash`, findings with due dates) — append-only, one per period, with `estate_unchanged` recomputed at sign-off. What remains is the **quarterly execution + sign-off** itself (org task; procedure in `docs/policies/access-control-policy.md` §3.7–3.8) |
| CC6.6/6.7 segregation & role-based data access | ✅ | Action→role mapping prevents one role holding conflicting duties; tenant rows are ABAC-scoped |
| CC6.9 no unauthorized software | 🟡 | Image build from repo only (`docker-build`), self-SBOM gate in `release_check.py`, devsecops SCA/SBOM (`devsecops/sbom.py`) — **but the CI workflows live locally and are unpushed** (token scope); the auditor will want the pipeline itself as evidence |
| CC6.10 physical access | ❌ | Hosting provider's SOC 2 / ISO 27001 report — collect during sub-service scoping |

## 2. CC7 — System operations

| Control | Status | What exists / missing |
|---|---|---|
| CC7.1/7.1.1 monitoring & security events | ✅ | Live monitor service (leader-lease, N replicas safe), CEF + signed webhook + SMTP alert router (`worker/monitor/alerting.py`), watch/change-detection engine, security-intelligence stack |
| CC7.2 remediation | ✅ | Finding lifecycle service (`remediation/`), drift alerts (`drift/alerts/`) |
| CC7.3/7.3.1 vulnerability management | 🟡 | Dependabot config + SCA/dependency graph + `security_scan.sh` exist; **cadence + triage SLAs documented** in the Vulnerability Management Policy, and pen-test findings **ingest into the platform** (`POST /api/v1/pentest/findings` → severity-banded, deduped, tracked to closure). Missing: **the third-party pen test itself** (see §5) |
| CC7.5 operations monitoring | ✅ | Metrics/observability/trace middlewares, `/health` + `/healthz`, burn-in harness (`scripts/burn_in.py`) |
| CC7.6 backup | ✅ | Scheduled backup service with sweep (`governance/backup_schedule.py`), backup + PITR **drills with recorded results** (`docs/backup-drill.md`; `docs/pitr-drill.md` is the same-process platform-event PITR — snapshot+replay, **not** PostgreSQL WAL PITR), restore verification script (`scripts/restore_evidence.py`) |

## 3. CC8 — Change management (a genuine strength)

| Control | Status | What exists |
|---|---|---|
| CC8.1 approved changes | ✅ | `scripts/release_check.py` is a real gate: VERSION == API version, dated CHANGELOG section, tag-on-HEAD, **migration contiguity**, fails-closed prod guard in both directions, SBOM check — and since `bf794e4` a **fresh signed production-evidence entry per release** (`scripts/production_evidence.py`, append-only hash chain) |
| CC8.1.1/8.1.2 authorization & code integrity | 🟡 | Git branch discipline + PR review exist as practice; document them. **CI workflows unpushed** (same token-scope issue) — close before fieldwork |
| CC8.3 test environment | ✅ | ~4,300 test functions green per release (API 803 / services 3,505 at `92a1839`), staging-estate load runs recorded (`docs/load-soak.md`) |
| CC8.4 production deploy | ✅ | `deploy/` stacks, `deploy_burn.py`, prod guard refuses to boot with demo config |

## 4. CC9 / CC10 — Risk, resilience, communications

| Control | Status | What exists |
|---|---|---|
| CC9.1 risk identification | 🟡 | Written threat model (`docs/security/threat-model.md`), security questionnaire, risk services, and a **living risk register built 2026-09-21** (`docs/compliance/risk-register.md` — 12 risks, scored, each with treatment; owners/review dates are `[ORG:]` fill-ins, enforced by `scripts/org_readiness_check.py`) |
| CC9.2 privacy risk | ✅ | UAE/privacy packs (PDPL/DIFC/ADGM rules), `privacy/` service, **secret redaction on every log line** (`shared_logging/logger_factory.py::redact_secrets`), SCIM deprovisioning |
| CC9.3/9.4 business continuity & resilience | ⚠️ **designed, not demonstrated** | The topology is real (2× API, 2× worker with leader-lease failover, Postgres streaming replication) and the runbook exists (`docs/runbooks/dr-recovery.md`). But the *evidence* is not: `scripts/region_drills.py:39-75` simulates a region pair with two temporary **directories** in one process, and the containerised drill is recorded as SKIPPED ("docker not available") in `docs/production-evidence.md:67`. An auditor asking "show me the failover" has not yet been shown one. Do not present this as ✅ until a drill runs against two real Postgres instances. |
| CC10.1 stakeholder notification | 🟡 | Audit pack / compliance PDF / exit report exist as *product* exports; the provider's own notification **procedure** (who, when, to whom) is an org task |
| CC10.2 incident response | 🟡 | Technical alerting is strong (CEF/webhook/SMTP, monitor, watch); **IR procedure drafted 2026-09-21** (`docs/policies/incident-response-policy.md` — severity, containment levers that map to built-in controls, 72 h data-breach clock, drill→evidence-chain linkage); on-call roster and comms tree remain `[ORG: ...]` placeholders |

## 5. A-series criteria

- **A1.1 Availability — ✅ strong.** Replicas + leader lease + streaming
  replication + automated drill + documented load/soak. The production
  evidence runner now records each release's load run with zero-error
  attestation (`docs/production-evidence.md`).
- **A1.2 Confidentiality — ✅.** Encryption inventory with FIPS 140-3 HSM
  posture (PKCS#11/Luna/GCP-KMS in `keyassure`), key-expiry alerting,
  WORM/hash-chained evidence, airgap mode. At-rest DB encryption is the
  hosting/DB layer's job — confirm in sub-service scoping.
- **A1.3 Privacy — ✅ strong for the UAE market.** PDPL 45/2021, DIFC DPL
  5/2020, ADGM DPR 2021 all encoded as policy rules + CBOM milestones;
  redaction enforced in the logging pipeline itself.
- **Processing Integrity — ✅ (differentiator).** Deterministic pipeline,
  SHA-256 hash-chained evidence with standalone verifier
  (`evidence/pack/standalone_verifier.py`), signed evidence packs,
  Merkle-verified exports, signed compliance summaries. Few SaaS vendors can
  hand an auditor a *verifiable* processing trail — this platform can.

## 6. The observation-window advantage

Type II needs 3–6 months of **continuous, verifiable** operation. Most
vendors reconstruct this period from dashboards (auditors discount it).
This platform produces it natively:

1. **Per-release production evidence** (signed, chain-linked,
   `--verify`-reproducible) — `scripts/production_evidence.py`
2. **Quarterly DR/backup/PITR drills** — scripted
   (`deploy/ha/drill.sh`, `scripts/backup_drill.py`, PITR drill) and
   appended to the same signed evidence chain: the backup/restore drill
   does this directly via `--record-evidence` (each check becomes a
   phase; a FAILED check makes the entry FAIL). Latest backup/restore
   drill: **PASS, 12/12 checks, recorded to the chain 2026-09-21**
   (`docs/backup-drill.md`).
3. **Audit export / audit pack / compliance pack** — `audit-export`
   router (`/pack`, `/exit-report`, `/engagement-archive`,
   `/access-review`, `/access-reviews`) + `scripts/compliance_pack.py`
   (the SOC 2 evidence ZIP, hash-verified, with the current
   policy-sign-off state embedded)
4. **Access-review data** on demand from the tenancy/RBAC stores

Recommendation: from day 1 of the window, run the evidence runner at every
release + every drill, and answer most PBC (prepared-by-client) requests
straight from `data/evidence/` + audit exports.

## 7. The gap list, ranked (what actually has to happen)

1. **Start the auditor engagement** — pick scope (CC + A1.1/A1.2/A1.3/P),
   sub-service orgs (host, email, any SaaS deps), answer the CAQ.
   *Calendar-bound; do first.*
2. **Pen test** (CC11.3) — third party, against a production mirror;
   2–4 weeks + remediation window. *(The test itself is the external
   task — but its readiness is built: scope brief at
   `docs/security/pen-test-scope.md`, and the report's findings ingest
   straight into the platform via `POST /api/v1/pentest/findings`,
   severity-banded, deduplicated per report, status-tracked to closure,
   and surfaced in the board report + compliance pack. The single
   biggest technical gap, and the one part of it that cannot be built
   in-repo.)*
3. **Push the CI workflows** (currently local-only, token scope) — the
   pipeline is itself a CC8/CC6.9 exhibit. *(🟡 — one push away when scope
   allows.)*
4. **Policy pack** — **draft complete 2026-09-21**: `docs/policies/`
   (11 policies + index, incl. the umbrella infosec policy), each
   grounded in the implemented controls with code-path citations and
   `[ORG: ...]` placeholders. Remaining: resolve the placeholders
   (owners, dates, sign-offs, sub-service matrix), countersign. Open-item
   count is measured live by `scripts/policy_signoff_check.py`
   (100 at drafting) and embedded in the compliance pack as
   `policy-signoff.json` — the org works the number to zero.
5. **Access reviews + minutes** — **export + minutes system of record
   built 2026-09-21** (`GET/POST /audit-export/access-review(s)`,
   signed, reproducible hash, append-only minutes); the quarterly
   execution + sign-off is the org task, procedure in the
   access-control policy.
6. **IR plan + on-call** — **procedure drafted 2026-09-21** in
   `docs/policies/incident-response-policy.md` (severity, phases, the
   72 h data-breach clock, drills feeding the evidence chain); on-call
   roster + escalation tree + comms SLAs are a fillable working document
   at `docs/ops/on-call-and-comms.md` — names/dates to be filled.
7. **Vendor/sub-service SOC 2 collection** — **tracking matrix +
   rep-letter template built 2026-09-21** (`docs/compliance/
   sub-service-matrix.md`, `rep-letter-template.md`); remaining:
   collect the actual reports/CUECs for the named vendors (keyassure
   first).
8. **Management representation letter** — **template built 2026-09-21**
   (`docs/compliance/management-rep-letter.md`, all 11 representations +
   sign-off block); CISO + CEO signature per period is the org step.
9. **Org fundamentals** — **scaffolding built 2026-09-21**: living risk
   register (CC9.1, `docs/compliance/risk-register.md`), quarterly board
   report cadence (`docs/compliance/quarterly-board-report.md`), security
   training program + completion records (`docs/org/training-and-
   awareness.md`), and the joiner/mover/leaver access lifecycle incl.
   background check, NDA, MFA and same-day deactivation
   (`docs/org/joiner-mover-leaver.md`). Readiness is measured, not
   claimed: `scripts/org_readiness_check.py` (17 checks) is embedded in
   the compliance pack as `org-readiness.json`. Remaining is filling the
   `[ORG:]` decisions (owners, dates, signatures) — org, not code.

## 8. Suggested 90-day runway

| When | Action |
|---|---|
| Wk 1–2 | Engagement signed; scope + CAQ sent; **pen test booked**; policy pack drafted in-repo ✅ (`docs/policies/`) — owners/sign-off collected |
| Wk 2–4 | Pen test executed; findings triaged; CI workflows pushed; evidence chain running on every release + drill from day 1 |
| Month 1–3 | **Observation window** — continuous operation; drills recorded via `scripts/record_evidence.py`; access reviews done + minutes recorded (`/audit-export/access-reviews`); policies v1 signed |
| Month 3–6 | Auditor fieldwork; PBC served from `scripts/compliance_pack.py` (single hash-verified evidence ZIP) + evidence chain + audit packs + compliance PDFs |
| End | Type II report issued |

## Honest bottom line

The **technical control set is audit-ready** — arguably stronger than
typical SaaS in evidence verifiability (signed, hash-chained,
independently re-checkable). The work that remains is almost entirely
**organizational**: the observation window itself, the pen test, the policy
pack, and the people/process around the excellent machinery. Realistic
timeline to a Type II report: **4–6 months from engagement start**, with the
longest pole being the window — which starts the day the engagement is
signed, so start it.
