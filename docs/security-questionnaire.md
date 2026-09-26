# Security questionnaire — standardized answers (SIG-lite format)

Answers describe CryptoScan/ZELNX **as shipped at commit `933fff9`** (rounds
1–14). Every claim is grounded in a named code artifact or test; anything not
built is listed in §12 as a gap, never hedged. Paired with
`docs/enterprise-readiness.md` (capability matrix) and
`docs/proposals/fab-poc.md` (engagement plan).

## 1. Product overview

CryptoScan is a deterministic cryptographic discovery, inventory and
compliance platform: it builds a Crypto Bill of Materials (network TLS/cert
probing, cloud KMS/ACM metadata, source-code detectors, telecom 5GC/roaming
posture), maps quantum-vulnerable families to migration-roadmap buckets, and
produces examiner-verifiable evidence packs. Policy decisions are
**deterministic and replayable — no AI/ML makes policy decisions** (stated in
every UI footer and enforced by architecture: pure engines + rules engine).

## 2. Hosting & deployment model

| Question | Answer |
|---|---|
| SaaS or on-prem? | **Self-hosted / on-prem.** No vendor-operated SaaS, no multi-tenancy. Full production stack: `docker-compose.yml` (Postgres/Redis/Neo4j/worker). PoC stack: `deploy/poc/docker-compose.poc.yml` (two containers, SQLite in a named volume). |
| Data egress | **None.** No telemetry leaves the process: the "telemetry heartbeat" is an in-process event-bus statistics publisher (`api/routers/events.py: publish_telemetry` → local SSE). Air-gap install documented (`docs/admin-guide/air-gap-install.md`), incl. file-based OIDC JWKS (`OIDC_JWKS_FILE`). |
| Network exposure | API + dashboard only; health/readiness/metrics endpoints documented; admin ports configurable; containers run non-root with `no-new-privileges` and all capabilities dropped (compose `security_opt`/`cap_drop`). |

## 3. Data flows & classification

- **Collected:** cryptographic metadata — TLS versions, ciphers, certificate
  fields, cloud key ALGORITHMS/SIZES/STATES, code-level API usage locations,
  telecom verdicts. **Never collected or stored: private key material,
  secrets, credentials, payload data.** Cloud collectors are read-only
  metadata APIs (KMS `List/Describe`, ACM `get_certificate`); credentials stay
  in the customer's vault as role references.
- **Stored:** PostgreSQL (prod) or SQLite (PoC) + snapshot JSON mirrors.
- **Leaves the tenancy:** nothing, by construction (§2).

## 4. Encryption

| Scope | Implementation |
|---|---|
| In transit | TLS terminated per deployment (compose TLS profile provided: `docker-compose.tls.yml`); OIDC/SAML/LDAP verification enforces https for https issuers; JWKS discovery has an SSRF guard (same-host, scheme discipline — `api/security/oidc.py:_validate_jwks_uri`). |
| Passwords | PBKDF2-SHA256, 210,000 iterations, per-user salt (`api/security/passwords.py`). Password policy enforced (`validate_password_policy`). |
| API keys | Shown once at creation; stored as SHA-256 hashes only (`db/models/api_key.py`). |
| Backups | **Encrypted backups**: Fernet (AES-128-CBC + HMAC) with key resolution vault-ref → persisted → HKDF-derived from the platform secret (stable across restarts) — `api/routers/resilience.py`. |
| Database at rest | Not encrypted by the application. **Deployment-owned**: use encrypted volumes/LUKS/KMS-encrypted disks. Stated plainly — we do not claim app-level DB encryption we do not have. |
| Platform secret | `SECRET_KEY` required ≥32 chars and checked against a known-weak list (fail-fast at startup — `config/settings.py: validate_runtime_settings`). |

## 5. Authentication & authorization

- Local auth + **TOTP MFA** (`api/security/totp.py`; `/auth/login/mfa`).
- **SSO:** OIDC token-relay **and** server-side authorization-code flow with
  HMAC-signed state (nonce-bound) and **PKCE S256 for public clients**
  (verifier rides a callback-scoped HttpOnly cookie, never the front channel;
  callback fails closed without it); SAML 2.0 SP (metadata/AuthnRequest/ACS
  with enveloped-signature verification + InResponseTo replay binding);
  LDAP/AD bind with explicit group→role map. SCIM 2.0 provisioning cannot
  mint a superadmin.
- **RBAC:** 9 roles (superadmin, ciso, security_analyst, developer, auditor,
  business_owner, scanner, readonly, supervisor) mapped through an explicit
  permission matrix; dependencies fail **closed** (`require_permission`);
  aliases normalized; unknown roles dropped, never granted.
- **Sessions:** server-tracked, 24h expiry, HttpOnly + SameSite=Lax cookies
  (`secure` in production), revocation endpoints, self-service session
  listing; ABAC middleware available for asset-level conditions.
- **Rate limiting:** `RateLimitMiddleware` per-route classes; security
  headers (`X-Content-Type-Options`, `X-Frame-Options: DENY`, …) applied by
  middleware; request-id/trace IDs on every request.

## 6. Logging, audit & monitoring

- Structured JSON request logs with request/trace IDs; Prometheus exposition
  (`/metrics`) incl. gauges that render even during DB outages.
- **Hash-chained audit trail**: every auth/admin action recorded with a
  previous-hash chain; `verify_audit_chain` detects **tampered entries and
  deletions** (unit-tested: `test_audit_chain.py::test_tampered_entry_*`,
  `test_deleted_entry_breaks_the_chain`).
- Examiner exports are content-hashed: `GET /audit-export/pack` returns a ZIP
  with a SHA-256 `manifest.json` covering every file (verified end-to-end in
  tests and on the live stack).

## 7. Vulnerability & dependency management

- Static gate: `ruff` (F + E9) clean required before any commit; test lanes:
  **871 backend tests** across api-unit/telecom/automation/cbom/inventory
  suites; release gate `scripts/release_check.py` (version/tag/changelog
  consistency, prod-guard).
- Dependencies: declared in `requirements.txt` with minimum versions.
  **Honest gap:** no fully-pinned lockfile and no published third-party SBOM
  of the product yet (§12). The platform's own scanning pipeline is the
  customer's dependency story — we apply it to ourselves where practical.
- Disclosure/contact: via the maintainer repository issues (private security
  advisories supported by GitHub).

## 8. Backup, resilience & continuity

- Encrypted backup/restore with retention planning (`/resilience/backup/*`,
  `/resilience/backup/retention-plan`); compliance report generation
  (signed-PDF path requires a configured signing key — otherwise HMAC
  integrity hash and `signature: null` honestly).
- Readiness probe carries drain semantics (503 while DB unreachable);
  health/readiness aliases for LB/K8s.
- **Honest HA status:** read-only mirrors and drain design exist; a
  multi-active control plane is untested without real infrastructure (§12).
  For PoC scope: single node, state in one volume, `down -v` destroys it —
  documented in `deploy/poc/CHECKLIST.md` (data-handling section).

## 9. Secure development lifecycle

- Determinism policy: findings/plans are pure functions of inputs; approval
  gates fail closed (`request_approval` never auto-executes; governance
  approvals persisted with rationale).
- Test-before-commit discipline; endpoint security tests
  (`test_security_vulns.py`, `test_oidc*.py`, `test_password_policy.py`,
  `test_rate_limit.py`, `test_production_hardening.py`).
- Access to the source: customer receives the repository (private repo,
  branch-per-engagement) — the audit trail of the code itself is git history.

## 10. Sub-processors & third parties

**None.** On-prem deployment has no vendor-side processing, no external
endpoints, no license phones-home. Open-source runtime dependencies are
listed in `requirements.txt` / frontend `package.json`.

## 11. Incident response

On-prem: the customer operates IR; we commit to support-tier response times
post-contract (PoC: best-effort within engagement hours). Product support for
IR: the audit chain + evidence pack give tamper-evident forensics of all
administrative actions.

## 12. Known gaps (we publish them — no vendor hedging)

Same list as `docs/enterprise-readiness.md` §"honest one-liner": external
certifications (ISO/SOC 2) not held; product SBOM/lockfile not yet published;
GCP ACM-PCA/DB-TDE/mainframe collectors not built; multi-active HA untested
at scale; SaaS multi-tenancy deliberately out of scope. Nothing on this list
is simulated or claimed as present.
