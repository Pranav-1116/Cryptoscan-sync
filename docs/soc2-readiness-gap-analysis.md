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
| CC6.3 periodic re-authorization | 🟡 | Platform can produce the review data (user/role/last-activity exports via `audit-export` router); the **quarterly access-review process + minutes** is an org task |
| CC6.6/6.7 segregation & role-based data access | ✅ | Action→role mapping prevents one role holding conflicting duties; tenant rows are ABAC-scoped |
| CC6.9 no unauthorized software | 🟡 | Image build from repo only (`docker-build`), self-SBOM gate in `release_check.py`, devsecops SCA/SBOM (`devsecops/sbom.py`) — **but the CI workflows live locally and are unpushed** (token scope); the auditor will want the pipeline itself as evidence |
| CC6.10 physical access | ❌ | Hosting provider's SOC 2 / ISO 27001 report — collect during sub-service scoping |

## 2. CC7 — System operations

| Control | Status | What exists / missing |
|---|---|---|
| CC7.1/7.1.1 monitoring & security events | ✅ | Live monitor service (leader-lease, N replicas safe), CEF + signed webhook + SMTP alert router (`worker/monitor/alerting.py`), watch/change-detection engine, security-intelligence stack |
| CC7.2 remediation | ✅ | Finding lifecycle service (`remediation/`), drift alerts (`drift/alerts/`) |
| CC7.3/7.3.1 vulnerability management | 🟡 | Dependabot config + SCA/dependency graph + `security_scan.sh` exist; missing: **documented cadence, triage SLAs, and the third-party pen test** (see §5) |
| CC7.5 operations monitoring | ✅ | Metrics/observability/trace middlewares, `/health` + `/healthz`, burn-in harness (`scripts/burn_in.py`) |
| CC7.6 backup | ✅ | Scheduled backup service with sweep (`governance/backup_schedule.py`), backup + PITR **drills with recorded results** (`docs/backup-drill.md`, `docs/pitr-drill.md`), restore verification script (`scripts/restore_evidence.py`) |

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
| CC9.1 risk identification | 🟡 | Written threat model (`docs/security/threat-model.md`), security questionnaire, risk services — but a living org **risk register** with owners is an org task |
| CC9.2 privacy risk | ✅ | UAE/privacy packs (PDPL/DIFC/ADGM rules), `privacy/` service, **secret redaction on every log line** (`shared_logging/logger_factory.py::redact_secrets`), SCIM deprovisioning |
| CC9.3/9.4 business continuity & resilience | ✅ | HA: 2× API, 2× worker with leader-lease failover, Postgres streaming replication (RPO≈0, RTO seconds), **automated DR drill** (`deploy/ha/drill.sh`) with runbook (`docs/runbooks/dr-recovery.md`) and region-failover doc |
| CC10.1 stakeholder notification | 🟡 | Audit pack / compliance PDF / exit report exist as *product* exports; the provider's own notification **procedure** (who, when, to whom) is an org task |
| CC10.2 incident response | 🟡 | Technical alerting is strong (CEF/webhook/SMTP, monitor, watch); the org **IR plan + on-call roster + post-mortem cadence** is not yet documented |

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
2. **Quarterly DR/backup/PITR drills** — already scripted
   (`deploy/ha/drill.sh`, `scripts/backup_drill.py`, PITR drill) and their
   outputs can be appended to the same evidence chain
3. **Audit export / audit pack / compliance PDF** — `audit-export` router
   (`/pack`, `/exit-report`, `/engagement-archive`)
4. **Access-review data** on demand from the tenancy/RBAC stores

Recommendation: from day 1 of the window, run the evidence runner at every
release + every drill, and answer most PBC (prepared-by-client) requests
straight from `data/evidence/` + audit exports.

## 7. The gap list, ranked (what actually has to happen)

1. **Start the auditor engagement** — pick scope (CC + A1.1/A1.2/A1.3/P),
   sub-service orgs (host, email, any SaaS deps), answer the CAQ.
   *Calendar-bound; do first.*
2. **Pen test** (CC11.3) — third party, against a production mirror;
   2–4 weeks + remediation window. *(❌ today; the single biggest
   technical gap.)*
3. **Push the CI workflows** (currently local-only, token scope) — the
   pipeline is itself a CC8/CC6.9 exhibit. *(🟡 — one push away when scope
   allows.)*
4. **Policy pack** (~15 docs): AUP, infosec, risk, backup, DR (convert the
   existing runbooks — they're 80% done), access review, vendor management,
   training, IR plan (convert alerting + runbooks), privacy. *Most content
   already exists as docs in this repo; this is an editing + sign-off job,
   ~2–3 weeks part-time.*
5. **Access reviews + minutes** — quarterly, data from audit exports.
6. **IR plan + on-call** — document the existing alerting into an org
   procedure.
7. **Vendor/sub-service SOC 2 collection** — host, email provider, etc.
8. **Management representation letter** — CISO/CEO sign-off per period.
9. **Org fundamentals** — background checks, NDAs, security training
   records, board/committee reporting cadence. *(All org; none in code.)*

## 8. Suggested 90-day runway

| When | Action |
|---|---|
| Wk 1–2 | Engagement signed; scope + CAQ sent; **pen test booked**; policy pack drafting starts from repo docs |
| Wk 2–4 | Pen test executed; findings triaged; CI workflows pushed; evidence chain running on every release + drill from day 1 |
| Month 1–3 | **Observation window** — continuous operation; drills recorded; access reviews done; policies v1 signed |
| Month 3–6 | Auditor fieldwork; PBC served from evidence chain + audit packs + compliance PDFs |
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
