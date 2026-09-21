# Authentication & MFA Policy

**Version:** 1.0 (draft) · **Owner:** [ORG: CISO] · **Applies to:** all
human and machine accounts · **Next review:** [ORG: YYYY-MM-DD]
**Criteria:** TSC CC6.2, CC6.3, CC6.7

## 1. Purpose

Define the authentication requirements for all access to the CryptoScan
platform: credential quality, multi-factor authentication, session
handling and machine-to-machine identity.

## 2. Password policy (human accounts)

Implemented in `services/api/api/security/passwords.py`:

1. Minimum length **12 characters**; at least **three** character classes
   (uppercase, lowercase, digit, punctuation).
2. Reuse of the platform's own stem/branding and common passwords is
   rejected by the built-in policy checks.
3. Hashing is PBKDF2-SHA256 with the iteration count defined in
   `passwords.py`; plaintext and reversible encodings are never stored.
4. [ORG: define rotation trigger — recommended: mandatory change on
   suspected compromise, otherwise periodic review at 12 months.]

## 3. Multi-factor authentication

1. **Totp is required for all human accounts.** TOTP activation is
   enforced at account setup and verified per login
   (`services/api/api/security/totp.py`).
2. **FIPS 140-3 hardware MFA** (keyassure) is available for
   high-privilege accounts (`superadmin`, `ciso`) and is recommended for
   the service account used by the release gate. [ORG: confirm which
   accounts are enrolled and record in the MFA register.]
3. **OIDC / SAML federation** may be used for enterprise SSO
   (`api/security/oidc.py`); the IdP must enforce MFA itself, and
   platform-side MFA requirements continue to apply to direct logins.
4. SCIM provisioning (`api/security/oidc.py` companion endpoints) is the
   preferred lifecycle path for federated tenants; provisioning events
   are audit-logged.
5. An account **cannot** have MFA disabled once enabled, except by
   `superadmin` with a documented justification recorded in the audit
   trail.

## 4. Session security

1. Sessions are HMAC-signed tokens issued by the session manager
   (`api/security/session_manager.py`): 24-hour maximum lifetime,
   purpose-scoped (a session token and an MFA challenge token are
   cryptographically distinct and each is rejected in the other's role).
2. Tokens carry no client-side state; revocation is server-side.
3. Session creation never silently elevates privileges — a session is
   bound to the role set at issue time.
4. Concurrent sessions per user are counted and visible in the access
   review export; a user with an unexplained active session must
   investigate it.

## 5. Machine authentication

1. API keys are the only machine credential. They carry explicit roles,
   HTTP methods, scopes and per-minute rate limits.
2. Key material is generated server-side, displayed once, and stored only
   as a hash; exports expose the prefix only.
3. Keys **must** have an expiry. Expired keys are revoked; the access
   review export flags any key that expired without being revoked.
4. Long-lived CI/CD and backup automation keys [ORG: list owners and
   review dates] are treated as privileged machine accounts.

## 6. Lockout and brute-force protection

1. Interactive logins are rate-limited (5/min/IP) and account-level
   failed-attempt tracking locks the account
   (`User.failed_attempts` / `locked_until`); locked accounts appear as a
   standing signal in access reviews.
2. Registration (the only open endpoint) is limited to 10 accounts/hour
   per IP.

## 7. Evidence

- MFA enrollment and enforcement are unit-tested
  (`services/api/tests/unit/` — TOTP and session suites).
- The access-review export's `active_without_mfa` signal is the recurring
  control test for requirement 3.1.
- Login and MFA-verification events are written to the audit trail.

## 8. Exceptions

Exemptions (e.g. a break-glass account) require [ORG: CISO] approval, are
documented with an expiry, and are reviewed at each quarterly access
recertification.
