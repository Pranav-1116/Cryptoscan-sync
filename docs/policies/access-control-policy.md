# Access Control Policy

**Version:** 1.0 (draft) · **Owner:** [ORG: CISO] · **Applies to:** all
users, service accounts, API keys and integrations of the CryptoScan platform
**Next review:** [ORG: YYYY-MM-DD] · **Criteria:** TSC CC6.1–CC6.8

## 1. Purpose

Define how logical access to the CryptoScan platform and its data is
requested, granted, maintained and removed. Access is granted on a
least-privilege, need-to-know basis and is reviewed at least quarterly.

## 2. Roles

The platform enforces a fixed, code-defined role catalogue
(`services/api/api/security/rbac.py`). Roles are never free-text:
unknown values are dropped at normalisation time, so a token minted before
an upgrade can only ever grant what the permission matrix allows.

| Role | Grants |
|------|--------|
| `superadmin` | Full platform configuration |
| `ciso` | All compliance, policy and exception handling |
| `security_analyst` | View findings, create exceptions |
| `developer` | View findings for own systems |
| `business_owner` | View findings for owned systems |
| `auditor` | Read-only access to all reports (SOC 2 review role) |
| `readonly` | Dashboard view only |
| `scanner` | API-only scan-job submission |
| `supervisor` | Read-only regulatory supervisory view |

Aliases `admin` → `superadmin` and `viewer` → `readonly` exist for
legacy tokens and are normalised on every request.

## 3. Requirements

1. **Grant.** Access requests are raised to [ORG: access manager]; grants
   are recorded with requester, approver, role, scope and expiry. No
   standing access is granted without a documented business justification.
2. **Permission matrix.** Enforcement is declarative and versioned in
   `rbac.py` (role → action matrix). Changes to the matrix are code
   changes and follow the Change Management Policy.
3. **MFA.** All human accounts require MFA (see Authentication & MFA
   Policy). Accounts without MFA are flagged by the access review export.
4. **Sessions.** Sessions are HMAC-signed tokens with a 24-hour maximum
   lifetime (`SESSION_EXPIRE_HOURS`); they can be revoked server-side and
   are counted per user in access reviews. MFA challenges use short-lived
   purpose-scoped tokens that `validate_session` always rejects as
   sessions.
5. **API keys.** Machine access uses scoped API keys
   (`services/api/api/db/models/api_key.py`) with explicit roles,
   methods, scopes and rate limits. Key material is stored only as a
   hash; exports show the display prefix only. Expired keys must be
   revoked; the review export surfaces expired-but-unrevoked keys as a
   standing signal.
6. **Tenancy.** Multi-tenant isolation is enforced in the tenancy
   middleware (`api/security/tenancy.py`) and ABAC middleware; cross-tenant
   reads are denied regardless of role.
7. **Quarterly access review (CC6.3).** At least quarterly, [ORG: access
   manager] exports the estate with
   `GET /api/v1/audit-export/access-review` and signs off the signals:
   privileged accounts, active accounts without MFA, stale and
   never-logged-in accounts, locked accounts, expired/unrevoked and
   revoked keys, active session counts.
8. **Review minutes (system of record).** Each completed review is
   recorded with `POST /api/v1/audit-export/access-reviews`, referencing
   the export's `report_hash`. The platform recomputes the estate hash at
   record time and stores `estate_unchanged`, so a review signed against
   an estate that changed in the meantime says so. One record per period
   (a quarter is reviewed, not re-issued); the minutes are append-only —
   there is no update or delete path. `GET /api/v1/audit-export/
   access-reviews` lists the standing record. Findings (e.g. an account
   inactive > 90 days) are stored on the record with action and due date,
   and must be remediated or risk-accepted by [ORG: CISO] within one
   review cycle.
9. **Removal.** Departures trigger deactivation (the account is
   soft-deleted and all sessions/keys are invalidated). Deactivation is
   verified in the next access review: deactivated accounts must not
   appear in active signals.
10. **Rate limiting.** Unconditional, per-identity rate limiting
   (`api/middleware/rate_limit.py`) bounds abuse even if other controls
   fail: login 5/min/IP, registration 10/hour/IP, scan submission
   100/min/user, general API 600/min/identity.

## 4. Monitoring and evidence

- Access-review exports and their `report_hash` values, archived by
  [ORG: compliance function].
- Audit events for privilege changes are written to the tamper-evident
  evidence chain (see `docs/production-evidence.md`).
- The `auditor` role provides the external auditor read-only visibility.

## 5. Exceptions

Deviations require written approval from [ORG: CISO], carry an expiry
date, and are listed in the exception register reviewed at each access
recertification. No exception may grant standing access without MFA.
