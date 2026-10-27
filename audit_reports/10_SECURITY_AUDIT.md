# 10_SECURITY_AUDIT.md
## ZELNX CryptoScan — Security & Production Readiness Audit

**Generated:** 2026-09-20  
**Method:** Source code inspection of auth, RBAC, secrets, encryption, network, container, API, and operational security  
**Scope:** Actual implementation vs. enterprise security requirements

---

## 1. AUTHENTICATION — IMPLEMENTATION

### 1.1 Session Authentication (`services/api/api/security/auth.py`)
| Feature | Implementation | Status |
|---------|----------------|--------|
| **Password hashing** | bcrypt (configurable rounds via `BCRYPT_ROUNDS`) | ✅ |
| **Session cookies** | HttpOnly, Secure, SameSite=Lax, `session_id` | ✅ |
| **Session store** | `user_sessions` table (DB-backed) | ✅ |
| **Session TTL** | `SESSION_TTL_SECONDS` (default 8h) + sliding window | ✅ |
| **MFA (TOTP)** | Optional, `pyotp`, backup codes | ✅ |
| **Login rate limit** | 5/min/IP (Redis) | ✅ |
| **Account lockout** | 5 failed → 15min lockout (configurable) | ✅ |
| **Admin bootstrap** | `ADMIN_USERNAME`/`ADMIN_PASSWORD[_HASH]` env vars | ✅ |
| **Password reset** | Token-based, 1h expiry, single-use | ✅ |

### 1.2 API Key Authentication
| Feature | Implementation | Status |
|---------|----------------|--------|
| **Format** | `csk_` prefix + 32-char random + `.` + 64-char hash | ✅ |
| **Storage** | `api_keys` table: `key_hash` (SHA-256), `prefix`, `scopes` | ✅ |
| **Rotation** | `POST /api/v1/api-keys/{id}/rotate` → new key, old revoked | ✅ |
| **Allowlist** | IP CIDR allowlist per key | ✅ |
| **Scopes** | Fine-grained permissions (read/write per domain) | ✅ |
| **Expiry** | Optional `expires_at` | ✅ |
| **Audit** | All key operations logged | ✅ |

### 1.3 SSO / OIDC (`services/api/api/routers/sso.py`)
| Provider | Status | Implementation |
|----------|--------|----------------|
| **Generic OIDC** | ✅ Implemented | `OIDCClient`, discovery, PKCE, state |
| **SAML** | ❌ Not implemented | Stub only |
| **LDAP** | ❌ Not implemented | Not found |
| **SCIM** | ✅ Implemented | `services/api/api/routers/scim.py` — provisioning |

### 1.4 Auth Gaps
| Gap | Severity | Impact |
|-----|----------|--------|
| **No password complexity policy** | P2 | Weak passwords possible |
| **No session concurrency limit** | P2 | Unlimited simultaneous sessions |
| **No device fingerprinting** | P3 | Cannot detect session hijacking |
| **OIDC only — no SAML/LDAP** | P2 | Enterprise integration gap |
| **Refresh token rotation not implemented** | P2 | Long-lived access tokens |

---

## 2. AUTHORIZATION — RBAC + ABAC

### 2.1 RBAC Model (`services/api/api/security/rbac.py`)
| Role | Permissions | Use Case |
|------|-------------|----------|
| `admin` | All permissions | Platform administration |
| `auditor` | `scans.trigger`, `baselines.approve`, `drift.acknowledge`, `drift.resolve`, `crypto.ingest`, `crypto.read` | Compliance operations |
| `viewer` | Read-only (`crypto.read`, scan/findings/cbom/graph read) | Dashboard consumers |

### 2.2 Permission System
```python
# Permissions (api/security/rbac.py)
PERMISSIONS = {
    "scans.trigger", "baselines.approve", "drift.acknowledge", "drift.resolve",
    "drift.false_positive", "crypto.ingest", "crypto.read", "crypto.manage",
    "users.manage", "tenants.manage", "settings.manage", "audit.read",
    "api_keys.manage", "webhooks.manage", "connectors.manage",
}
```

### 2.3 ABAC (`services/api/api/middleware/abac_middleware.py`)
- **Enabled by:** `ABAC_ENFORCED=true`
- **Model:** Region → Business Unit → Environment → Asset
- **Grants:** Provisioned via API (`/api/v1/abac/grants`)
- **Fail-closed:** When enabled, missing grant = 403
- **Integration:** Middleware runs after AuthMiddleware

### 2.4 Authorization Gaps
| Gap | Location | Severity |
|-----|----------|----------|
| **No resource-level authorization** | All routers | P1 — Tenant isolation via middleware only |
| **No ownership checks** | Scan/CBOM/Graph endpoints | P1 — User can access any tenant's data if middleware bypassed |
| **ABAC not default** | Middleware | P2 — Opt-in only |
| **Permission granularity** | Coarse (domain-level) | P2 — No per-system/per-asset permissions |

---

## 3. SECRETS MANAGEMENT

### 3.1 Current State (docker-compose.yml)
| Secret | Used By | Rotation | Storage |
|--------|---------|----------|---------|
| `SECRET_KEY` | Auth sessions, CSRF, CBOM fallback | ❌ Manual | Env var |
| `CBOM_SIGNING_SECRET` | CBOM JWS HS256 | ⚠️ Retired secrets list | Env var |
| `CBOM_PRIVATE_KEY` | CBOM JWS RS256/ES256 | ❌ Manual | Env var (or file path) |
| `STREAM_SECRET` | Event stream HMAC | ❌ Manual | Env var |
| `REGISTRY_WEBHOOK_SECRET` | Registry webhook verify | ❌ Manual | Env var |
| `GITHUB_WEBHOOK_SECRET` | GitHub webhook verify | ❌ Manual | Env var |
| `AUDITOR_API_KEY` | Auditor read-only auth | ❌ Manual | Env var |
| `NEO4J_PASSWORD` | Graph DB | ❌ Manual | Env var |
| `POSTGRES_PASSWORD` | Primary DB | ❌ Manual | Env var |
| `REDIS_PASSWORD` | Queue/Rate limit | ❌ Manual | Env var |

### 3.2 Production Hardening (main.py startup checks)
```python
# Fails fast in production if:
- SECRET_KEY < 32 chars or default value
- DATABASE_URL is SQLite
- CORS_ORIGINS = "*"
- ADMIN_PASSWORD_HASH not set (plaintext password)
- CBOM_SIGNING_SECRET not set (for signing)
```

### 3.3 Secrets Gaps
| Gap | Severity | Recommendation |
|-----|----------|----------------|
| **No secret rotation automation** | P1 | Integrate Vault/AWS Secrets Manager |
| **Secrets in env vars** | P1 | Use Docker secrets / Kubernetes secrets |
| **CBOM signing fallback to SECRET_KEY** | P1 | Require dedicated key in production |
| **No secret versioning** | P2 | Key rotation requires restart |
| **No encryption at rest for DB** | P2 | Enable PostgreSQL TDE / filesystem encryption |

---

## 4. ENCRYPTION

### 4.1 In Transit
| Path | Protocol | Implementation |
|------|----------|----------------|
| **Client → Nginx** | TLS 1.2/1.3 | Nginx termination (`.docker/nginx/`) |
| **Nginx → API** | HTTP (internal Docker network) | ❌ No mTLS |
| **API → PostgreSQL** | TLS | `psycopg2` with `sslmode=require` (configurable) |
| **API → Redis** | TLS | `redis-py` with `ssl=True` (configurable) |
| **API → Neo4j** | TLS | Bolt over TLS (configurable) |
| **Worker → API** | HTTP + API key | Internal network |

### 4.2 At Rest
| Data Store | Encryption | Status |
|------------|------------|--------|
| **PostgreSQL** | None configured | ❌ |
| **Redis** | None configured | ❌ |
| **Neo4j** | None configured | ❌ |
| **File system (evidence, CBOM)** | None | ❌ |
| **Backups** | SHA-256 manifest only | ❌ Not encrypted |

### 4.3 Application-Level Encryption
| Feature | Implementation |
|---------|----------------|
| **Key material** | Never stored — enforced by `safe_finding()` and tests |
| **CBOM signing** | JWS (HS256/RS256/ES256) — not encryption |
| **Audit log chain** | Hash chain (SHA-256) — integrity only |
| **Evidence chain** | Hash chain (SHA-256) — integrity only |

---

## 5. NETWORK SECURITY

### 5.1 Docker Network (`docker-compose.yml`)
- Single bridge network `cryptoscan-net`
- All services communicate internally
- No network segmentation (API, worker, monitor, DB, Redis, Neo4j all same network)

### 5.2 Exposed Ports
| Service | Port | External | Purpose |
|---------|------|----------|---------|
| Nginx | 8088 | ✅ | TLS termination, frontend + API proxy |
| API | 8010 | ❌ (via nginx) | Internal |
| Frontend | 3003 | ❌ (via nginx) | Internal |
| PostgreSQL | 55432 | ⚠️ Mapped | Dev access |
| Redis | 56379 | ⚠️ Mapped | Dev access |
| Neo4j | 57474/57687 | ⚠️ Mapped | Dev access |

### 5.3 Network Gaps
| Gap | Severity |
|-----|----------|
| **No mTLS between services** | P1 |
| **DB/Redis/Neo4j ports exposed** | P1 (dev only; prod should not map) |
| **No network policies** | P2 |
| **No egress filtering** | P2 |

---

## 6. CONTAINER SECURITY

### 6.1 Dockerfile Hardening (`.docker/*/Dockerfile`)
| Hardening | API | Worker | Frontend | Nginx |
|-----------|-----|--------|----------|-------|
| Non-root user | ✅ `cryptoscan` uid | ✅ | ✅ | ✅ |
| `no-new-privileges:true` | ✅ | ✅ | ✅ | ✅ |
| `cap_drop: ALL` | ✅ | ✅ | ✅ | ✅ (except NET_BIND_SERVICE) |
| Read-only rootfs | ❌ | ❌ | ❌ | ❌ |
| Distroless/Alpine | Alpine | Alpine | Alpine | Alpine |
| Multi-stage build | ✅ | ✅ | ✅ | ✅ |

### 6.2 Image Scanning
- **Base images:** Pinned tags (`postgres:15-alpine`, `redis:7-alpine`, `neo4j:5.26-community`)
- **Dependency scanning:** Not automated in CI
- **SBOM generation:** Not for own images

---

## 7. API SECURITY

### 7.1 Input Validation
| Layer | Implementation |
|-------|----------------|
| **Path parameters** | FastAPI path converters (UUID, str) |
| **Query parameters** | Pydantic `Query()` with constraints |
| **Request bodies** | Pydantic models (`api/schemas/*.py`) |
| **File uploads** | `python-multipart` with size limits |

### 7.2 SSRF Protection
**Implementation:** `api/dependencies.py:validate_workspace_path()`
- Resolves path, checks under `WORKSPACE_BASE_PATH` or `CRYPTOSCAN_SOURCE_ROOTS`
- **Used in:** Scan trigger (`trigger.py`), SBOM scan (`devsecops.py`)
- **Gap:** Not applied to all file operations (artifact download, report export)

### 7.3 Path Traversal
- **Guard:** `validate_workspace_path()` as above
- **Static files:** Served by nginx (no path traversal risk)
- **Gap:** CBOM artifact download uses `artifact_id` (UUID) — safe

### 7.4 Command Injection
| Location | Command | Input Validation |
|----------|---------|------------------|
| `scanner/git/git_client.py` | `git clone`, `git log` | Repo URL not validated for shell metacharacters |
| `container_scanner` | `docker`, `trivy` | Image ref not validated |
| `scripts/scan_estate.py` | Multiple subprocess | Internal config only |

### 7.5 Rate Limiting (`api/middleware/rate_limit.py`)
- **Backend:** Redis (fail-closed in production)
- **Key:** `ratelimit:{user_id}:{endpoint}` or `ratelimit:ip:{ip}:{endpoint}`
- **Default:** 100/min/user, 5/min/IP for login
- **Response:** 429 + `Retry-After`
- **Gap:** No WebSocket/SSE rate limiting

### 7.6 CORS
- **Config:** `CORS_ORIGINS` env var (comma-separated)
- **Production:** Must not be `*` (startup fails)
- **Credentials:** `allow_credentials=True` when origins specified

---

## 8. AUDIT LOGGING & INTEGRITY

### 8.1 Audit Log (`services/api/api/security/auth.py:AuthService.audit()`)
| Event | Logged | Detail |
|-------|--------|--------|
| Login/logout | ✅ | IP, user agent, MFA method |
| Scan trigger | ✅ | User, repo, branch, job_id |
| Baseline approve | ✅ | User, scan_id |
| Drift ack/resolve/FP | ✅ | User, drift_id, notes |
| CBOM ingest/verify | ✅ | User, system, signature result |
| Graph sync/snapshot | ✅ | User, version, fingerprint |
| User management | ✅ | Actor, target, role changes |
| API key ops | ✅ | Actor, key_id, scopes |

### 8.2 Audit Chain Integrity
```python
# Hash chain over audit entries
chain_hash = SHA256(prev_chain_hash + JSON(payload))
```
- **Verification:** `GET /api/v1/auth/audit/verify` → returns `{valid: bool, details}`
- **Export:** `GET /api/v1/auth/audit/export` → WORM-ready JSONL

### 8.3 Control Events (`api/middleware/control_events.py`)
- **Emits:** `api.<segment>.<verb>` on every mutating request
- **Bus:** In-process + Redis federation + DB tailer
- **Consumers:** Monitor, dashboard SSE, audit log

---

## 9. VULNERABILITY MANAGEMENT

### 9.1 Dependency Scanning
- **Python:** `requirements.lock.txt` pinned; `pip-audit` not in CI
- **Node.js:** `package-lock.json` pinned; `npm audit` not in CI
- **Docker:** Base images pinned; Trivy not in CI for own images

### 9.2 Security Testing
| Test Type | Status |
|-----------|--------|
| **SAST** | Ruff (lint) only; no bandit/semgrep |
| **DAST** | Not implemented |
| **Dependency scan** | Not automated |
| **Container scan** | Not for own images |
| **Penetration test** | Not documented |

---

## 10. OPERATIONAL SECURITY

### 10.1 Backup & Restore
| Script | Purpose | Encryption |
|--------|---------|------------|
| `scripts/backup_evidence.py` | Evidence chain + manifest + DB dump | ❌ Not encrypted |
| `scripts/restore_evidence.py` | Restore + chain verification | ❌ |
| **Schedule** | Not automated | — |
| **Tested** | Not documented | — |

### 10.2 Disaster Recovery
- **RPO/RTO:** Not defined
- **Multi-region:** Not implemented
- **Failover:** Manual only

### 10.3 Monitoring & Alerting
| Component | Implementation |
|-----------|----------------|
| **Metrics** | Prometheus `/metrics` (scan counts, findings, drift, queue) |
| **Health** | `/health` (liveness), `/ready` (readiness + migrations) |
| **Logs** | Structlog JSON → stdout (Docker) / file |
| **Traces** | W3C trace-context → JSONL file + OTLP optional |
| **Alerts** | Monitor daemon only (CEF/syslog, webhook, email) |
| **Alerting on metrics** | ❌ No PrometheusAlertmanager |

### 10.4 Incident Response
- **Runbooks:** Not documented
- **Forensics:** Audit chain + evidence chain provide tamper evidence
- **Communication:** Not defined

---

## 11. COMPLIANCE POSTURE

| Standard | Coverage | Evidence |
|----------|----------|----------|
| **SOC 2 Type II** | Partial | Audit trail, access control, encryption gaps |
| **ISO 27001** | Partial | Asset inventory, risk assessment, gaps in DR |
| **PCI-DSS** | Partial | Payment crypto service; network segmentation missing |
| **GDPR** | Partial | Data subject rights not implemented; retention undefined |
| **NIST CSF** | Strong | Identify, Protect, Detect, Respond, Recover — Respond/Recover gaps |

---

## 12. SECURITY FINDINGS SUMMARY

| Category | P0 | P1 | P2 | P3 |
|----------|----|----|----|----|
| Authentication | 0 | 0 | 4 | 1 |
| Authorization | 0 | 2 | 2 | 0 |
| Secrets | 0 | 3 | 2 | 0 |
| Encryption | 0 | 3 | 2 | 0 |
| Network | 0 | 1 | 2 | 0 |
| Container | 0 | 0 | 4 | 0 |
| API Security | 0 | 1 | 3 | 0 |
| Audit/Integrity | 0 | 0 | 0 | 0 |
| Vuln Management | 0 | 0 | 4 | 0 |
| Operational | 0 | 2 | 2 | 2 |
| **TOTAL** | **0** | **12** | **25** | **3** |

---

## 13. RECOMMENDATIONS — PRIORITIZED

### P1 — High (Do First)
1. **Implement resource-level authorization** — Check tenant ownership on every mutating endpoint
2. **Neo4j tenant isolation** — Separate databases or document limitation
3. **Secret rotation automation** — HashiCorp Vault or AWS Secrets Manager integration
4. **mTLS between services** — At minimum API ↔ Worker ↔ Monitor ↔ DB
5. **Enable DB/Redis/Neo4j encryption at rest** — PostgreSQL TDE, Redis TLS, Neo4j encryption
6. **Remove dev port mappings in production** — DB/Redis/Neo4j not exposed
7. **Automated dependency scanning** — `pip-audit`, `npm audit`, Trivy in CI

### P2 — Medium
8. **ABAC enabled by default** — Fail-closed for multi-tenant
9. **Password complexity policy** — Configurable via settings
10. **Session concurrency limits** — Max sessions per user
11. **SAML/LDAP support** — Enterprise integration
12. **PrometheusAlertmanager** — Alerting on metrics
13. **Backup encryption** — GPG/age for evidence backups
14. **DR runbooks** — Documented RPO/RTO, failover procedures

### P3 — Enhancement
15. **Device fingerprinting** — Session anomaly detection
16. **Refresh token rotation** — Short-lived access tokens
17. **Distroless images** — Further reduce attack surface
18. **SBOM for own images** — Supply chain transparency
19. **Penetration testing** — Annual third-party assessment
---

## UPDATE — round 16 verification + build (2026-10-09)

**Built this round:**

- **Clone-URL transport validation (§7.4's unvalidated git input):**
  `GitClient.clone` validates the repository URL as its first statement —
  remote-helper transports (`ext::<command>`, CVE-2022-24439), any
  `<helper>::<address>` form, and leading-dash option injection are refused
  with a clear ValueError **before the git module is even imported**.
  http/https/git/ssh/file URLs, scp-style targets and local paths remain
  supported (the scanner clones local checkouts with the same client).
  20 parametrized tests cover the matrix.
- **Scan-queue backpressure (operational security):** admission refuses new
  scans with 429 once QUEUED+RUNNING jobs exceed `MAX_QUEUE_DEPTH` — an
  unbounded accept-everything queue is an outage that hasn't noticed yet
  (audit 05 build, same round).

**Verified stale:**

- "No password complexity policy" — stale: `validate_password_policy` runs
  at register, password change, and both reset paths.
- "SSRF guard not applied to artifact download" — stale: SBOM/binary
  artifact downloads resolve by UUID through the tenant-bucketed, encrypted
  artifact store (wrong-tenant reads raise, no client-supplied paths).
- "Repo URL not validated for shell metacharacters" — the shell part was
  already moot (GitPython, no shell); the real transport vectors are now
  blocked (above).
- Session concurrency limits, device fingerprinting, refresh-token
  rotation, SAML/LDAP, mTLS, Vault, encryption at rest — remain open,
  deployment- or product-scoped, unchanged from the report's P2/P3 ranking.

## UPDATE — round 20 re-verification (2026-10-10)

Re-read in full. One security-relevant correctness fix this round:
estate-wide views that silently truncated at 500/1000 rows could
under-report exactly the systems an operator needs to see (including
which systems are overdue for re-scan — the due-scan planner itself was
capped). Fixed with bounded full walks + explicit truncation flags (see
audit 03/05 addenda). All round-16 verdicts stand; deployment-scoped
items (session limits, mTLS, Vault, encryption at rest) unchanged.
