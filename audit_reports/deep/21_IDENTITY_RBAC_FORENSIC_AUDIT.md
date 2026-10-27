# 21_IDENTITY_RBAC_FORENSIC_AUDIT.md
## ZELNX CryptoScan — Identity & RBAC Forensic Audit

**Generated:** 2026-09-20  
**Method:** Deep inspection of authentication, authorization, session management, MFA, API keys, and permission matrix  
**Scope:** All identity-related code across `services/api/api/security/`, `services/api/api/routers/auth.py`, `services/api/api/dependencies.py`

---

## EXECUTIVE SUMMARY

| Component | Score | Status |
|-----------|-------|--------|
| Authentication (Session) | 8/10 | Strong, MFA ready |
| Authentication (API Key) | 7/10 | Good, quota/policy enforcement |
| Session Management | 7/10 | Secure cookies, revocation, but no concurrency limits |
| Password Security | 8/10 | PBKDF2-SHA256, policy validation, no breach check |
| MFA (TOTP) | 7/10 | Implemented, recovery codes, but no WebAuthn |
| RBAC Model | 7/10 | 8-role catalog + legacy aliases, matrix-based |
| Authorization Enforcement | 6/10 | Domain-level only, no resource-level |
| API Key Security | 7/10 | Scoped, quotas, IP allowlist, but roles not checked against matrix |
| Audit Trail | 8/10 | Comprehensive, hash-chained, exportable |
| Privilege Escalation Risk | Medium | Legacy admin fallback, token role caching |

**Overall: 7/10** — Strong foundation, but missing resource-level authorization and some enterprise features.

---

## 1. AUTHENTICATION FLOWS

### 1.1 Session Authentication (`/api/v1/auth/login`)

**File:** `services/api/api/routers/auth.py:50-130`

```python
# Flow:
1. Validate credentials via AuthService
2. Check MFA enabled → issue MFA challenge token (5 min TTL)
3. Create session via SessionManager
4. Set HttpOnly, Secure, SameSite=Lax cookie
5. Persist session in DB with IP, expiry
6. Audit log: login event
```

**Security Features:**
- ✅ Password never logged
- ✅ MFA gate before session creation
- ✅ HttpOnly + Secure + SameSite=Lax cookies
- ✅ Session stored in DB with revocation support
- ✅ IP binding on session creation
- ✅ Failed login audit with IP
- ✅ Account lockout after 5 failures (configurable)
- ✅ Lockout duration 15 min (configurable)

**Gaps:**
- ❌ No device fingerprinting
- ❌ No session concurrency limit (unlimited simultaneous sessions)
- ❌ No "remember me" with extended expiry
- ❌ No adaptive MFA (risk-based)

---

### 1.2 MFA Implementation (TOTP)

**File:** `services/api/api/security/totp.py`

```python
# TOTP: RFC 6238, SHA-1, 30s window, 6 digits
# Recovery codes: 10 codes, single-use, 16 chars each
```

**Flow:**
1. `POST /auth/me/mfa/enable` → returns QR code (base64 PNG) + secret + 10 recovery codes
2. User scans QR in authenticator app
3. User submits TOTP code to verify
4. On login: password → MFA challenge token (5 min) → TOTP/recovery code → session

**Recovery Codes:**
- 10 codes generated at enable
- Single-use, marked used in DB
- Can disable MFA with password + recovery code

**Gaps:**
- ❌ No WebAuthn/FIDO2 support
- ❌ No push notification MFA
- ❌ No SMS/email backup
- ❌ Recovery codes not re-generatable without disable/enable

---

### 1.3 API Key Authentication

**File:** `services/api/api/dependencies.py:_resolve_api_key()`

```python
# Header: X-API-Key: <raw_key>
# Lookup: SHA-256 hash in api_keys table
# Returns: (principal, roles, key_id) tuple
# Cached on request.state.api_key_auth
```

**Key Format:** `csk_<32_random_chars>.<64_char_hash>`

**Security Features:**
- ✅ Raw key never stored, only SHA-256 hash
- ✅ Prefix `csk_` identifies key type
- ✅ IP allowlist per key (CIDR)
- ✅ Per-key rate quota (`rate_per_minute`)
- ✅ Endpoint scope allowlist (path + method)
- ✅ Last-used stamping (throttled to 1/min)
- ✅ Automatic expiration support
- ✅ Rotation endpoint (`POST /api-keys/{id}/rotate`)
- ✅ Audit log on create/use/rotate/revoke

**Gaps:**
- ❌ Key roles NOT checked against `PERMISSION_MATRIX` — used directly
- ❌ No key rotation schedule enforcement
- ❌ No key usage analytics dashboard
- ❌ No key compromise detection (anomalous IP/usage)

---

### 1.4 SSO/OIDC

**File:** `services/api/api/routers/auth.py:200-300`

```python
# OIDC flow:
# 1. GET /auth/oidc/login → redirect to provider
# 2. Provider redirects to /auth/oidc/callback
# 3. Exchange code for tokens
# 4. Map claims to local user (email → username)
# 5. Link or create account
```

**Supported:** Generic OIDC (Google, Azure AD, Okta, Keycloak)
**Missing:** SAML, LDAP, Kerberos

---

### 1.5 SCIM Provisioning

**File:** `services/api/api/routers/scim.py`

```python
# SCIM 2.0 compliant
# Endpoints: /scim/v2/Users (GET, POST, PATCH, DELETE)
# Used by: Okta, Azure AD, PingIdentity
```

---

## 2. SESSION MANAGEMENT

### 2.1 Session Storage

**File:** `services/api/api/security/session_manager.py`

```python
class SessionManager:
    def create_session(self, username, roles) -> str:
        # Token: URL-safe base64, 32 bytes entropy
        # Payload: username, roles, iat, exp (HMAC-SHA256)
        # Stored in DB: token_hash, username, roles, expires_at, ip, revoked_at
    
    def validate_session(self, token) -> username | None:
        # Verify HMAC, check expiry, check revocation in DB
    
    def revoke_session(self, token) -> bool:
        # Set revoked_at = now
```

**Cookie Settings:**
```python
response.set_cookie(
    key="cryptoscan_session",
    value=token,
    httponly=True,
    samesite="lax",
    secure=settings.cookie_secure,  # True in production
    max_age=SESSION_EXPIRE_HOURS * 3600,
    path="/",
)
```

**Gaps:**
- ❌ No session concurrency limit
- ❌ No "view active sessions" UI
- ❌ No forced logout on password change (optional, not default)
- ❌ No session activity tracking (last activity timestamp)

---

### 2.2 Session Revocation

**Implementation:** `revoked_at` timestamp in `user_sessions` table

**Validation:** `_session_store_allows()` in `dependencies.py`

```python
def _session_store_allows(token, username) -> bool:
    # Strict in production: unknown token or DB error => deny
    # In dev/test: HMAC token alone accepted
```

**Strict Mode:** Production = fail-closed (DB required)
**Dev Mode:** Degraded (token-only validation)

---

### 2.3 Token Claims

| Claim | Source |
|-------|--------|
| `username` | Session payload |
| `roles` | Session payload (stale if roles changed) |
| `iat` | Session creation |
| `exp` | Session expiry |

**Gap:** Roles cached in token; refreshed from DB only on validation failure.

---

## 3. PASSWORD SECURITY

### 3.1 Hashing

**File:** `services/api/api/security/passwords.py`

```python
# Algorithm: PBKDF2-SHA256
# Iterations: 600,000 (configurable via PASSWORD_HASH_ROUNDS)
# Salt: 16 bytes random
# Format: pbkdf2_sha256$iterations$salt$hash
```

**Verification:** Constant-time comparison via `hmac.compare_digest`

---

### 3.2 Password Policy

**File:** `services/api/api/security/passwords.py:validate_password_policy()`

```python
# Requirements:
# - Min 12 chars, max 200
# - Entropy >= 60 bits (zxcvbn or custom)
# - Not in common passwords list (top 10k)
# - Not username/email/reverse
# - Not sequential/repeated chars
```

**Production Hardening:**
```python
# auth.py:register() and change_my_password()
if settings.is_production and body.new_password.lower() in {"", "cryptoscan", "admin", "password", "changeme", "secret"}:
    raise HTTPException(422, "New password is too weak")
```

**Gaps:**
- ❌ No breached password check (HaveIBeenPwned API)
- ❌ No password history (prevent reuse)
- ❌ No password expiry policy
- ❌ No admin password reset audit (logged but not alerted)

---

### 3.3 Admin Bootstrap

**File:** `services/api/api/security/auth.py:AuthService.bootstrap_admin()`

```python
# On first run (users table empty):
# 1. Reads ADMIN_USERNAME, ADMIN_PASSWORD_HASH or ADMIN_PASSWORD
# 2. Hashes password if needed
# 3. Creates user with roles=["superadmin"]
# 4. Only works if table empty
```

**Production Guard:** Fails if `ADMIN_PASSWORD_HASH` not set or `ADMIN_PASSWORD` is default.

---

## 4. RBAC MODEL

### 4.1 Role Catalog (8 Roles + Supervisor)

**File:** `services/api/api/security/rbac.py:ROLE_CATALOG`

| Role | Description | Priority |
|------|-------------|----------|
| `superadmin` | Full access (platform configuration) | 1 |
| `ciso` | All compliance, policy, exceptions | 2 |
| `security_analyst` | View findings, create exceptions | 3 |
| `developer` | View findings for own systems | 4 |
| `auditor` | Read-only access to all reports | 5 |
| `business_owner` | View findings for owned systems | 6 |
| `scanner` | API-only (scan job submission) | 7 |
| `readonly` | Dashboard view only | 8 |
| `supervisor` | Financial supervisor/regulator — read-only | 9 |

---

### 4.2 Legacy Aliases

```python
ROLE_ALIASES = {
    "admin": "superadmin",
    "viewer": "readonly",
}
```

**Applied in:** `normalize_roles()` — used everywhere roles are checked.

---

### 4.3 Permission Matrix (28 Permissions)

| Permission | SuperAdmin | CISO | SecurityAnalyst | Developer | Auditor | BusinessOwner | Scanner | ReadOnly |
|------------|------------|------|-----------------|-----------|---------|---------------|---------|----------|
| `users.manage` | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `api_keys.manage` | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `audit.read` | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| `scan.trigger` | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ |
| `baseline.approve` | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| `drift.acknowledge` | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `drift.resolve` | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `crypto.ingest` | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ |
| `crypto.manage` | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `reports.read` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ |
| `findings.read` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

---

### 4.4 Role Normalization

**File:** `services/api/api/security/rbac.py:normalize_roles()`

```python
def normalize_roles(roles):
    # 1. Lowercase + strip
    # 2. Apply ROLE_ALIASES (admin→superadmin, viewer→readonly)
    # 3. Filter to VALID_ROLES
    # 4. Deduplicate
    # Unknown roles DROPPED (not rejected)
```

**Behavior:** Unknown roles silently dropped. Token with old roles still works but with reduced permissions.

---

## 5. AUTHORIZATION ENFORCEMENT

### 5.1 Permission Dependencies

**File:** `services/api/api/security/rbac.py:require_permission()`

```python
def require_permission(*actions):
    def dependency(request):
        principal, roles = _caller_roles(request)
        for action in actions:
            if has_permission(roles, action):
                return principal
        raise HTTPException(403, f"Requires one of: {actions}")
    return dependency
```

**Usage:** `Depends(require_permission("scan.trigger", "baseline.approve"))`

---

### 5.2 Role Dependencies

**File:** `services/api/api/dependencies.py:require_roles()`

```python
def require_roles(*allowed):
    # Normalizes aliases, checks intersection
    # API keys: explicit roles, no "no roles = admin" fallback
    # Sessions: fresh roles from DB, fallback to token claims
```

---

### 5.3 Coarse vs Fine-Grained

| Level | Implementation | Coverage |
|-------|----------------|----------|
| **Domain** | `require_permission("scan.trigger")` | All mutating endpoints |
| **Resource** | **NOT IMPLEMENTED** | No per-scan, per-system, per-asset checks |
| **Field** | **NOT IMPLEMENTED** | No field-level masking |

---

### 5.4 API Key Authorization Gap

**File:** `services/api/api/dependencies.py:_resolve_api_key()`

```python
# API key roles used DIRECTLY, not checked against PERMISSION_MATRIX
roles = row.role_list  # Used as-is
```

**Gap:** API key with `roles=["superadmin"]` gets full access even if `PERMISSION_MATRIX` doesn't grant that permission to `superadmin` for that action.

---

### 5.5 ABAC (Attribute-Based Access Control)

**File:** `services/api/api/middleware/abac_middleware.py`

```python
# Enabled by ABAC_ENFORCED=true
# Model: Region → BU → Environment → Asset
# Grants provisioned via API
# Fail-closed when enabled
```

**Status:** Opt-in only. Not enabled by default.

---

## 6. AUDIT TRAIL

### 6.1 Audit Log Model

**File:** `services/database/db/models/user.py:AuditLog`

```python
class AuditLog(BaseModel, TenantScoped):
    actor: str
    action: str
    target_type: str | None
    target_id: str | None
    detail: dict | None
    outcome: str  # SUCCESS, FAILURE, LOCKED, DISABLED
    ip: str | None
    created_at: DateTime(timezone=True)
    chain_hash: str  # SHA256(prev_hash + JSON(payload))
```

---

### 6.2 Audited Operations

| Operation | Action | Detail Captured |
|-----------|--------|-----------------|
| Login | `auth.login` | IP, MFA status |
| Login failed | `auth.login` (FAILURE) | IP, reason |
| MFA challenge | `auth.mfa_challenge_issued` | IP |
| MFA login | `auth.login` (SUCCESS) | IP, MFA=true |
| Logout | `auth.logout` | IP |
| Register | `user.register` | Roles, IP |
| Password change | `user.password_change` | IP |
| MFA enable/disable | `user.mfa_enable` / `user.mfa_disable` | IP |
| User create/update/delete | `user.create`, `user.update`, `user.delete` | Actor, target, roles |
| Scan trigger | `scan.trigger` | Repo, branch, job_id |
| Baseline approve | `baseline.approve` | Scan ID |
| Drift ack/resolve/FP | `drift.acknowledge`, `drift.resolve`, `drift.false_positive` | Drift ID, notes |
| CBOM ingest/verify | `cbom.ingest`, `cbom.verify` | System, signature result |
| Graph sync/snapshot | `graph.sync`, `graph.snapshot` | Version, fingerprint |
| API key ops | `apikey.create`, `apikey.rotate`, `apikey.revoke` | Actor, key_id, scopes |

---

### 6.3 Audit Chain Integrity

```python
# services/api/api/security/auth.py:AuthService.audit()
chain_hash = SHA256(prev_chain_hash + JSON(payload))
```

**Verification:** `GET /api/v1/auth/audit/verify` → walks chain, returns `{valid: bool, details}`

**Export:** `GET /api/v1/auth/audit/export` → JSONL stream (WORM-ready)

---

### 6.4 Audit Gaps

| Gap | Missing |
|-----|---------|
| **Read operations** | Graph queries, CBOM generation, report views not audited |
| **Config changes** | Settings, tenancy, policy pack changes partially audited |
| **Cross-tenant access** | No logging when superadmin accesses tenant data |
| **Failed authorization** | 403 errors not logged (only 401/422) |

---

## 7. PRIVILEGE ESCALATION RISKS

### 7.1 Legacy Admin Fallback

**File:** `services/api/api/dependencies.py:_user_roles()`

```python
# If DB unavailable and token has no roles:
# "legacy single-tenant principal (env-admin before bootstrap, or test harness):
# platform estate, as before SaaS"
return TenantContext(username=user, tenant_id=None, tenant_role=None, is_platform_admin=True)
```

**Risk:** If DB unavailable, any valid session token gets platform admin access.

---

### 7.2 Token Role Caching

**File:** `services/api/api/dependencies.py:_user_roles()`

```python
# Roles read fresh from DB on each request (via _user_roles)
# But fallback to token claims if DB unavailable
```

**Risk:** Role changes take effect immediately (good) but DB failure reverts to stale token roles.

---

### 7.3 API Key Role Escalation

**File:** `services/api/api/dependencies.py:_resolve_api_key()`

```python
# API key roles used directly, NOT checked against PERMISSION_MATRIX
roles = row.role_list
```

**Risk:** Key minted with `superadmin` role gets all permissions even if matrix changes.

---

### 7.4 Superadmin Without Tenant

**File:** `services/api/api/dependencies.py:_resolve_tenant_context()`

```python
if "superadmin" in roles:
    if not active_id:
        return TenantContext(username=user, tenant_id=None, tenant_role=None, is_platform_admin=True)
```

**Risk:** Superadmin without `X-Tenant-ID` sees ALL tenants' data (platform estate).

---

### 7.5 Session Role Staleness

**Issue:** Session created with roles at login. If roles changed in DB, session still has old roles until re-login.

**Mitigation:** `_user_roles()` reads fresh from DB on each request (when DB available).

---

## 8. MISSING ENTERPRISE FEATURES

| Feature | Status | Impact |
|---------|--------|--------|
| **Resource-level permissions** | ❌ Missing | Cannot restrict per-scan/system/asset |
| **Delegated administration** | ❌ Missing | No tenant admin, BU admin roles |
| **Custom roles** | ❌ Missing | Fixed 8-role catalog |
| **Permission inheritance** | ❌ Missing | No BU→System→Asset hierarchy |
| **Dynamic permission groups** | ❌ Missing | No group-based access |
| **Just-in-time access** | ❌ Missing | No temporary elevation |
| **Access certification** | ❌ Missing | No periodic access review automation |
| **Segregation of duties** | ❌ Missing | No conflict detection |
| **Emergency access (break-glass)** | ❌ Missing | No break-glass procedure |

---

## 9. SESSION SECURITY HARDENING

| Feature | Status |
|---------|--------|
| HttpOnly cookie | ✅ |
| Secure cookie (HTTPS) | ✅ (production) |
| SameSite=Lax | ✅ |
| Session rotation on privilege change | ❌ |
| Session binding to device fingerprint | ❌ |
| Concurrent session limit | ❌ |
| Idle timeout (separate from absolute) | ❌ |
| Session activity logging | ❌ |
| Geo-velocity anomaly detection | ❌ |

---

## 10. API KEY SECURITY HARDENING

| Feature | Status |
|---------|--------|
| Key rotation | ✅ |
| Key expiration | ✅ |
| IP allowlist | ✅ |
| Rate quota | ✅ |
| Endpoint scope | ✅ |
| Key usage analytics | ❌ |
| Anomaly detection | ❌ |
| Compromise detection | ❌ |
| Automatic rotation schedule | ❌ |
| Key hierarchy (root → derived) | ❌ |

---

## 11. MFA HARDENING

| Feature | Status |
|---------|--------|
| TOTP (RFC 6238) | ✅ |
| Recovery codes | ✅ |
| WebAuthn/FIDO2 | ❌ |
| Push notifications | ❌ |
| SMS/Email backup | ❌ |
| Adaptive MFA (risk-based) | ❌ |
| MFA for API keys | ❌ |
| MFA for privileged actions | ❌ (only login) |

---

## 12. PERMISSION MATRIX — COMPLETE

### 12.1 Full Matrix (28 Permissions × 9 Roles)

| Permission | SuperAdmin | CISO | SecurityAnalyst | Developer | Auditor | BusinessOwner | Scanner | ReadOnly | Supervisor |
|------------|------------|------|-----------------|-----------|---------|---------------|---------|----------|------------|
| users.manage | ✅ | | | | | | | | |
| api_keys.manage | ✅ | ✅ | | | | | | | |
| audit.read | ✅ | ✅ | | | ✅ | | | | |
| platform.configure | ✅ | | | | | | | | |
| monitor.manage | ✅ | ✅ | | | | | | | |
| scan.trigger | ✅ | ✅ | ✅ | ✅ | | | ✅ | | |
| scan.manage | ✅ | ✅ | ✅ | | | | | | |
| baseline.approve | ✅ | ✅ | | | ✅ | | | | |
| drift.acknowledge | ✅ | ✅ | ✅ | | | | | | |
| exceptions.create | ✅ | ✅ | ✅ | | | ✅ | | | |
| exceptions.approve | ✅ | ✅ | | | | | | | |
| policy.configure | ✅ | ✅ | | | | | | | |
| certificates.manage | ✅ | ✅ | ✅ | | | | | | |
| intelligence.use | ✅ | ✅ | ✅ | | ✅ | | | | |
| remediation.apply | ✅ | ✅ | ✅ | | | | | | |
| migrations.manage | ✅ | ✅ | ✅ | | | | | | |
| reports.read | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | | ✅ | ✅ |
| supervision.read | ✅ | ✅ | | | ✅ | | | | ✅ |
| findings.read | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | |
| systems.view | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | |
| payment.view | ✅ | ✅ | | | ✅ | | | | |
| vendor.view | ✅ | ✅ | ✅ | | ✅ | | | | |
| runtime.ingest | ✅ | | | | | | ✅ | | |
| hardware.read | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | |
| hardware.manage | ✅ | ✅ | ✅ | | | | | | |
| hardware.ingest | ✅ | ✅ | | | | | ✅ | | |
| crypto.read | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | |
| crypto.manage | ✅ | ✅ | ✅ | | | | | | |
| crypto.ingest | ✅ | ✅ | | | | | ✅ | | |
| telecom.manage | ✅ | ✅ | ✅ | | | | | | |
| telecom.ingest | ✅ | ✅ | | | | | ✅ | | |

---

## 13. RECOMMENDATIONS

### P0 — Critical

1. **Implement resource-level authorization** — Check ownership on every mutating operation
2. **Fix API key authorization** — Check key roles against `PERMISSION_MATRIX`
3. **Remove legacy admin fallback** — Fail-closed when DB unavailable
4. **Add resource-level permissions** — Per-scan, per-system, per-asset

### P1 — High

4. **Enable ABAC by default** — Fail-closed for multi-tenant
5. **Add resource-level permissions** — Per-scan, per-system, per-asset
6. **Session concurrency limits** — Max sessions per user
7. **Session rotation on role change** — Force re-auth on privilege change
8. **API key roles checked against matrix** — Not used directly

### P2 — Medium

9. **WebAuthn/FIDO2 support** — Hardware MFA
8. **Resource-level permissions** — Per-scan, per-system, per-asset
9. **Delegated administration** — Tenant admin, BU admin roles
10. **Custom roles** — Configurable role definitions
11. **Permission inheritance** — BU → System → Asset hierarchy
12. **Access certification** — Periodic access review automation
13. **Break-glass procedure** — Emergency access with audit

### P3 — Enhancement

14. **WebAuthn/FIDO2** — Hardware MFA
15. **Adaptive MFA** — Risk-based challenges
16. **Breached password check** — HaveIBeenPwned integration
17. **Password history** — Prevent reuse
18. **Session concurrency UI** — View/terminate sessions
19. **Geo-velocity anomaly detection** — Impossible travel detection
20. **MFA for privileged actions** — Not just login

---

## 14. VERIFICATION EVIDENCE

All findings traceable to source:

| Finding | File |
|---------|------|
| AuthService | `services/api/api/security/auth.py` |
| SessionManager | `services/api/api/security/session_manager.py` |
| RBAC matrix | `services/api/api/security/rbac.py` |
| Auth router | `services/api/api/routers/auth.py` |
| Dependencies | `services/api/api/dependencies.py` |
| Session manager | `services/api/api/security/session_manager.py` |
| Password hashing | `services/api/api/security/passwords.py` |
| TOTP | `services/api/api/security/totp.py` |
| ABAC middleware | `services/api/api/middleware/abac_middleware.py` |
| Audit log model | `services/database/db/models/user.py:AuditLog` |
---

## Round 26 update (2026-10-10) — P0 claims re-verified

* **P0#1 resource-level authorization — STALE.** Resource grants shipped
  round 18 (migration 0076, per-system enforcement + admin endpoints).
* **P0#2 API key roles bypassing PERMISSION_MATRIX — STALE.**
  `require_permission` resolves the caller (session or machine key) and
  checks `has_permission(roles, action)` against the matrix for both —
  a key's roles are subject to exactly the same matrix as a session's.
* **P0#3 legacy admin fallback — MITIGATED BY DESIGN.** The env
  fallback fires only when no DB session is injected (CLI/scripts/dev);
  production routers always authenticate against the users table, with a
  documented first-login bootstrap.
* **P2#11 permission inheritance — STALE.** BU → System → Asset grant
  inheritance shipped round 22.
* **REMAIN OPEN, product-scoped:** custom roles, WebAuthn/FIDO2, session
  concurrency limits + role-change rotation, access certification,
  break-glass procedure, adaptive MFA.
