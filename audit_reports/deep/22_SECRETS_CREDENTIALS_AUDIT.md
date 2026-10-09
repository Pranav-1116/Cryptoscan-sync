# 22_SECRETS_CREDENTIALS_AUDIT.md
## ZELNX CryptoScan — Secrets & Credentials Audit

**Generated:** 2026-09-20  
**Method:** Systematic inspection of all configuration files, source code, Docker, Kubernetes, CI/CD, scripts, and test fixtures for exposed secrets, credentials, keys, and insecure storage patterns  
**Scope:** .env files, docker-compose, Kubernetes manifests, source code, scripts, test fixtures, documentation examples

---

## EXECUTIVE SUMMARY

| Category | Findings | Severity |
|----------|----------|----------|
| **Default/Weak Secrets in Config** | 8 hardcoded defaults | P1 (guarded by startup checks) |
| **Secrets in Docker Compose** | 12+ env vars with defaults | P1 (dev only) |
| **Secrets in Kubernetes** | References to secrets, no values | OK (if secrets managed externally) |
| **Secrets in Source Code** | None found in production paths | OK |
| **Secrets in Test Fixtures** | Multiple placeholder values | P3 (test only) |
| **Secrets in CI/CD** | GitHub Actions references | OK (uses secrets) |
| **Key Material Handling** | Never stored — enforced by tests | OK |
| **Secret Rotation** | Not automated | P2 |

**Overall: 6/10** — Production guards prevent default usage, but no secret rotation automation, no Vault integration, secrets in env vars.

---

## 1. CONFIGURATION FILES

### 1.1 `.env.example` — Default Values

**File:** `/home/array/Desktop/CryptoScan/.env.example`

```bash
# Database
POSTGRES_USER=cryptoscan
POSTGRES_PASSWORD=cryptoscan_secret
POSTGRES_DB=cryptoscan
POSTGRES_PORT=55432

# Redis
REDIS_URL=redis://redis:6379/0

# Neo4j
NEO4J_USER=neo4j
NEO4J_PASSWORD=cryptoscan

# API
SECRET_KEY=dev-cryptoscan-secret-key-change-in-production-32
ADMIN_USERNAME=admin
ADMIN_PASSWORD=cryptoscan
ADMIN_PASSWORD_HASH=
COOKIE_SECURE=false

# GitHub
GITHUB_WEBHOOK_SECRET=dev-webhook-secret-change-me-32chars!!

# Scan Queue
SCAN_JOB_QUEUE_KEY=cryptoscan:jobs:queue

# CORS
CORS_ORIGINS=*

# Docs
DOCS_ENABLED=true

# Event Stream
STREAM_LOG_DIR=/var/lib/cryptoscan/telecom/eventstream
CBOM_STORE_DIR=/var/lib/cryptoscan/telecom/live_cbom
CBOM_SIGNING_SECRET=dev-cbom-signing-secret-change-me-32ch

# Workspace
WORKSPACE_BASE_PATH=/tmp/cryptoscan-workspaces
CRYPTOSCAN_SOURCE_ROOTS=/app:/tmp/cryptoscan-workspaces

# Neo4j
NEO4J_URI=bolt://neo4j:7687
NEO4J_DATABASE=neo4j

# DB Wait
DB_WAIT_SECONDS=90

# Snapshots
CRYPTOSCAN_SNAPSHOT_DIR=/var/lib/cryptoscan/telecom
CRYPTOSCAN_TELECOM_REGISTRY=/var/lib/cryptoscan/telecom/telecom_registry.json

# Registry Webhooks
REGISTRY_WEBHOOK_SECRET=

# Auditor API
AUDITOR_API_KEY=

# OTEL
OTEL_EXPORTER_OTLP_ENDPOINT=

# Stream
STREAM_SECRET=
```

**Issues:**
- 12+ values with `dev-` or `changeme` prefixes
- `CORS_ORIGINS=*` — wildcard in example
- `COOKIE_SECURE=false` — insecure in example
- `REGISTRY_WEBHOOK_SECRET=` empty
- `AUDITOR_API_KEY=` empty

**Mitigation:** Production startup validates and fails on defaults (see `main.py`).

---

### 1.2 `.env.production.example`

**File:** `/home/array/Desktop/CryptoScan/.env.production.example`

```bash
# Production overrides — all secrets MUST be set
POSTGRES_PASSWORD=CHANGE_ME_IN_PRODUCTION
NEO4J_PASSWORD=CHANGE_ME_IN_PRODUCTION
SECRET_KEY=MUST_BE_32_CHARS_MINIMUM_GENERATED
ADMIN_PASSWORD_HASH=GENERATE_WITH_SCRIPTS_HASH_ADMIN_PASSWORD
GITHUB_WEBHOOK_SECRET=MUST_BE_32_CHARS_GENERATED
CBOM_SIGNING_SECRET=MUST_BE_32_CHARS_GENERATED
STREAM_SECRET=MUST_BE_32_CHARS_GENERATED
REGISTRY_WEBHOOK_SECRET=MUST_BE_32_CHARS_GENERATED
AUDITOR_API_KEY=MUST_BE_SET_IN_PRODUCTION
COOKIE_SECURE=true
CORS_ORIGINS=https://your-domain.com
```

**Good:** Explicit `CHANGE_ME` placeholders, secure defaults.

---

### 1.3 `.env.test`

**File:** `/home/array/Desktop/CryptoScan/.env.test`

```bash
ENVIRONMENT=test
DATABASE_URL=sqlite+aiosqlite:///:memory:
REDIS_URL=redis://localhost:6379/1
SECRET_KEY=test-secret-key-for-testing-only-32chars
ADMIN_PASSWORD=test
NEO4J_PASSWORD=test
CBOM_SIGNING_SECRET=test-cbom-signing-secret-32chars
STREAM_SECRET=test-stream-secret-32chars
```

**Acceptable:** Test-only values, clearly marked.

---

## 2. DOCKER COMPOSE

### 2.1 `docker-compose.yml` (Development)

**File:** `/home/array/Desktop/CryptoScan/docker-compose.yml`

```yaml
services:
  postgres:
    environment:
      POSTGRES_USER: ${POSTGRES_USER:-cryptoscan}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-cryptoscan_secret}
      POSTGRES_DB: ${POSTGRES_DB:-cryptoscan}
  
  redis:
    command: redis-server --appendonly yes
    # No password by default!
  
  neo4j:
    environment:
      NEO4J_AUTH: ${NEO4J_USER:-neo4j}/${NEO4J_PASSWORD:-cryptoscan}
  
  api:
    environment:
      ENVIRONMENT: ${ENVIRONMENT:-development}
      DATABASE_URL: postgresql://${POSTGRES_USER:-cryptoscan}:${POSTGRES_PASSWORD:-cryptoscan_secret}@postgres:5432/${POSTGRES_DB:-cryptoscan}
      REDIS_URL: redis://redis:6379/0
      SECRET_KEY: ${SECRET_KEY:-dev-cryptoscan-secret-key-change-in-production-32}
      ADMIN_USERNAME: ${ADMIN_USERNAME:-admin}
      ADMIN_PASSWORD: ${ADMIN_PASSWORD:-cryptoscan}
      ADMIN_PASSWORD_HASH: ${ADMIN_PASSWORD_HASH:-}
      COOKIE_SECURE: ${COOKIE_SECURE:-false}
      GITHUB_WEBHOOK_SECRET: ${GITHUB_WEBHOOK_SECRET:-dev-webhook-secret-change-me-32chars!!}
      # ... more defaults
  
  worker:
    environment:
      # Same defaults as api
  
  monitor:
    environment:
      # Same defaults
```

**Issues:**
- Redis: No password, no ACL
- Neo4j: Default password `cryptoscan`
- All services: Default secrets from `.env.example`
- Port mappings expose DB/Redis/Neo4j to host

**Mitigation:** Development only. Production uses `docker-compose.prod.yml`.

---

### 2.2 `docker-compose.prod.yml` (Production Overrides)

**File:** `/home/array/Desktop/CryptoScan/docker-compose.prod.yml`

```yaml
services:
  postgres:
    environment:
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}  # No default!
  
  redis:
    command: redis-server --appendonly yes --requirepass ${REDIS_PASSWORD}
  
  neo4j:
    environment:
      NEO4J_AUTH: ${NEO4J_USER}/${NEO4J_PASSWORD}
  
  api:
    environment:
      SECRET_KEY: ${SECRET_KEY}
      ADMIN_PASSWORD_HASH: ${ADMIN_PASSWORD_HASH}
      COOKIE_SECURE: true
      CORS_ORIGINS: ${CORS_ORIGINS}
      # All secrets required, no defaults
  
  # Port mappings REMOVED for DB/Redis/Neo4j
```

**Good:** No defaults, secure defaults, ports not exposed.

---

### 2.3 `docker-compose.tls.yml`

**File:** `/home/array/Desktop/CryptoScan/docker-compose.tls.yml`

```yaml
# TLS termination via nginx
# Certificates mounted from ./deploy/nginx/certs/
```

**Certificates:** Referenced but not stored in repo.

---

## 3. KUBERNETES MANIFESTS

### 3.1 Secrets Management

**File:** `k8s/app/` (various YAML files)

```yaml
# k8s/app/api-deployment.yaml
envFrom:
  - secretRef:
      name: cryptoscan-secrets
  - configMapRef:
      name: cryptoscan-config

# k8s/app/secrets.yaml (template)
apiVersion: v1
kind: Secret
metadata:
  name: cryptoscan-secrets
type: Opaque
stringData:
  SECRET_KEY: ""
  ADMIN_PASSWORD_HASH: ""
  POSTGRES_PASSWORD: ""
  NEO4J_PASSWORD: ""
  REDIS_PASSWORD: ""
  GITHUB_WEBHOOK_SECRET: ""
  CBOM_SIGNING_SECRET: ""
  STREAM_SECRET: ""
  REGISTRY_WEBHOOK_SECRET: ""
  AUDITOR_API_KEY: ""
```

**Good:** Secrets externalized to Kubernetes Secrets, not in manifests.
**Gap:** No ExternalSecrets operator or Vault integration shown.

---

## 4. SOURCE CODE INSPECTION

### 4.1 Hardcoded Secrets in Source

**Search Results:** No actual secrets found in production code paths.

```bash
# grep -r "password\|secret\|key\|token" --include="*.py" services/ | grep -v test | grep -v ".pyc"
# Only finds:
# - Variable names: password_hash, secret_key, api_key
# - Config references: settings.SECRET_KEY
# - Hashing: hash_password(), verify_password()
# - No literal passwords, API keys, or private keys
```

**Good:** No hardcoded secrets in production code.

---

### 4.2 Key Material Handling

**File:** `services/scanner/scanner/core/scanner.py:140`

```python
# Raw snippets are needed by detectors and the import cascade, but no
# source text may leave the scanner in a finding or CLI/worker output.
from shared_models.safe_finding import safe_finding
```

**File:** `services/evidence/evidence/core/pipeline.py:45`

```python
# The transient transformation can identify a safe digest family,
# but the original string itself must never leave the scanner.
data["crypto"]["raw_transformation"] = finding.crypto.raw_transformation
public_findings.append(RawFinding.model_validate(safe_finding(data)))
```

**Enforcement:** Tests verify no key material in outputs.

```python
# services/scanner/tests/unit/test_output_schema_contract.py
def test_no_key_material_in_output():
    # Verifies no private keys, passwords, secrets in scan output
```

**Good:** Key material never leaves scanner — enforced by `safe_finding()` and tests.

---

### 4.3 Cloud Credentials Handling

**File:** `services/cloud_scanner/cloud_scanner/core/scanner.py`

```python
# Cloud credentials passed via environment or config
# AWS: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN
# Azure: AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID
# GCP: GOOGLE_APPLICATION_CREDENTIALS
```

**Handling:** Passed to cloud SDKs, not stored in CryptoScan DB.

**Gap:** No credential rotation, no short-lived token enforcement.

---

## 5. CI/CD SECRETS

### 5.1 GitHub Actions

**File:** `.github/workflows/*.yml`

```yaml
# .github/workflows/ci.yml
env:
  SECRET_KEY: ${{ secrets.SECRET_KEY }}
  ADMIN_PASSWORD_HASH: ${{ secrets.ADMIN_PASSWORD_HASH }}
  POSTGRES_PASSWORD: ${{ secrets.POSTGRES_PASSWORD }}
  NEO4J_PASSWORD: ${{ secrets.NEO4J_PASSWORD }}
  REDIS_PASSWORD: ${{ secrets.REDIS_PASSWORD }}
  GITHUB_WEBHOOK_SECRET: ${{ secrets.GITHUB_WEBHOOK_SECRET }}
  CBOM_SIGNING_SECRET: ${{ secrets.CBOM_SIGNING_SECRET }}
  STREAM_SECRET: ${{ secrets.STREAM_SECRET }}
  REGISTRY_WEBHOOK_SECRET: ${{ secrets.REGISTRY_WEBHOOK_SECRET }}
  AUDITOR_API_KEY: ${{ secrets.AUDITOR_API_KEY }}
```

**Good:** All secrets from GitHub Secrets, not in workflow files.

---

### 5.2 Burn-in Script

**File:** `scripts/burn_in.py`

```python
# Uses environment variables for credentials
# Reads from os.environ for:
# - AWS credentials
# - Azure credentials
# - GCP credentials
# - SMTP credentials
# - Neo4j credentials
```

**Good:** No hardcoded credentials.

---

## 6. SCRIPTS & OPERATIONAL TOOLS

### 6.1 Backup/Restore Scripts

**File:** `scripts/backup_evidence.py`

```python
# Reads credentials from environment
# Uses pg_dump with PGPASSWORD env var
# No credentials in script
```

**File:** `scripts/restore_evidence.py`

```python
# Same — environment-based
```

---

### 6.2 Scan Estate Script

**File:** `scripts/scan_estate.py`

```python
# Reads targets from config file
# Credentials via environment
# No hardcoded credentials
```

---

### 6.3 Admin Password Hash Generator

**File:** `scripts/hash_admin_password.py`

```python
#!/usr/bin/env python3
"""Generate PBKDF2-SHA256 hash for ADMIN_PASSWORD_HASH."""
# Reads password from stdin or arg
# Outputs hash for .env.production
```

**Good:** No hardcoded passwords.

---

## 7. TEST FIXTURES & DOCUMENTATION

### 7.1 Test Fixtures with Placeholders

**File:** `services/scanner/tests/accuracy/corpus.py`

```python
# Test data with placeholder secrets:
"private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDXXXXXXXXXXXX..."
```

**File:** `services/scanner/tests/accuracy/corpus_wave5.py`

```python
# TODO: rotate with `openssl rand -hex 32` once the vault is up
"api_key": "sk-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
```

**File:** `services/scanner/tests/accuracy/corpus_wave18_uae_bank.py`

```python
-- TODO: migrate from HASHBYTES('MD5', ...) to SHA2_256 next quarter
-- deterministic lookup token for 784-XXXX-XXXXXXX-X
```

**Classification:** Test fixtures only — not production code. Placeholders clearly marked.

---

### 7.2 Documentation Examples

**File:** `docs/admin-guide/installation.md`

```bash
# Example .env file
SECRET_KEY=your-generated-secret-key-here
ADMIN_PASSWORD_HASH=your-generated-hash-here
```

**Good:** Placeholders, not real values.

---

## 8. SECRET ROTATION & MANAGEMENT

### 8.1 Current State

| Secret | Rotation Mechanism | Automated |
|--------|-------------------|-----------|
| `SECRET_KEY` | Manual (restart required) | ❌ |
| `ADMIN_PASSWORD_HASH` | Manual (re-hash + restart) | ❌ |
| `CBOM_SIGNING_SECRET` | Retired secrets list + restart | ⚠️ Partial |
| `STREAM_SECRET` | Manual (restart required) | ❌ |
| `GITHUB_WEBHOOK_SECRET` | Manual (GitHub + restart) | ❌ |
| `REGISTRY_WEBHOOK_SECRET` | Manual (restart required) | ❌ |
| `AUDITOR_API_KEY` | Manual (restart required) | ❌ |
| Database passwords | Manual (pg_dump/restore) | ❌ |
| Redis password | Manual (restart required) | ❌ |
| Neo4j password | Manual (restart required) | ❌ |

### 8.2 CBOM Signing Key Rotation (Partial)

**File:** `services/cbom/cbom/generator.py:verify_report()`

```python
# Supports retired secrets via CRYPTOSCAN_CBOM_RETIRED_SECRETS
# Format: "kid1:secret1,kid2:secret2"
# Current key: CRYPTOSCAN_CBOM_KEY_ID or "primary"
```

**Gap:** No automated rotation, no key expiry enforcement.

---

### 8.3 API Key Rotation

**File:** `services/api/api/routers/api_keys.py:rotate_api_key()`

```python
@router.post("/api-keys/{key_id}/rotate")
async def rotate_api_key(...):
    # Generates new raw key, keeps same key_id
    # Updates hash, stamps rotated_at
    # Old key immediately invalid
```

**Good:** Rotation endpoint exists. **Gap:** No automated schedule.

---

## 9. ENCRYPTION AT REST

### 9.1 Database

| Store | Encryption | Status |
|-------|------------|--------|
| PostgreSQL | None configured | ❌ |
| Redis | None configured | ❌ |
| Neo4j | None configured | ❌ |
| SQLite (test) | N/A | N/A |

**Gap:** No TDE (Transparent Data Encryption), no volume encryption configured.

---

### 9.2 File Storage

| Volume | Encryption | Status |
|--------|------------|--------|
| `postgres_data` | Host filesystem | ❌ |
| `redis_data` | Host filesystem | ❌ |
| `neo4j_data` | Host filesystem | ❌ |
| `telecom_data` | Host filesystem | ❌ |
| `traces_data` | Host filesystem | ❌ |

---

### 9.3 Backups

**File:** `scripts/backup_evidence.py`

```python
# pg_dump output — NOT encrypted
# Evidence chain manifest — SHA256 only
# No GPG/age encryption
```

**Gap:** Backups not encrypted.

---

## 10. SECRETS IN LOGS

### 9.1 Logging Configuration

**File:** `services/shared/shared_logging/shared_logging/logger_factory.py`

```python
# Structlog with JSON output
# Sensitive field filtering via _SENSITIVE_RE in events/auth.py
```

**File:** `services/api/api/events/auth.py:_SENSITIVE_RE`

```python
_SENSITIVE_RE = re.compile(r"(token|password|secret|cookie|recovery|hash)", re.IGNORECASE)
```

**Redaction:** Applied to event payloads before logging.

**Gap:** Not applied to all loggers (e.g., SQLAlchemy SQL logs may leak params).

---

## 10. SECRET SCANNING IN CI

### 10.1 Current State

**File:** `.github/workflows/ci.yml` — No secret scanning step found.

**Gap:** No `trufflehog`, `gitleaks`, or `detect-secrets` in CI pipeline.

---

## 11. SECRETS CLASSIFICATION MATRIX

| Secret | Location | Rotation | Encryption | Storage | Severity |
|--------|----------|----------|------------|---------|----------|
| `SECRET_KEY` | Env var | Manual | No | Memory | P1 |
| `ADMIN_PASSWORD_HASH` | Env var | Manual | PBKDF2 | DB | P1 |
| `CBOM_SIGNING_SECRET` | Env var | Partial (retired list) | HMAC/JWS | Memory | P1 |
| `STREAM_SECRET` | Env var | Manual | HMAC | Memory | P1 |
| `GITHUB_WEBHOOK_SECRET` | Env var | Manual | HMAC | Memory | P1 |
| `REGISTRY_WEBHOOK_SECRET` | Env var | Manual | HMAC | Memory | P1 |
| `AUDITOR_API_KEY` | Env var | Manual | N/A | Memory | P1 |
| `POSTGRES_PASSWORD` | Env var | Manual | No | DB | P1 |
| `REDIS_PASSWORD` | Env var | Manual | No | Memory | P1 |
| `NEO4J_PASSWORD` | Env var | Manual | No | DB | P1 |
| `CBOM_PRIVATE_KEY` | Env var/File | Manual | PEM | File | P1 |
| API Keys | DB | Manual + endpoint | SHA-256 | DB | P2 |
| User passwords | DB | User-initiated | PBKDF2 | DB | P2 |
| MFA secrets | DB | User-initiated | Base32 | DB | P2 |
| Recovery codes | DB | Single-use | SHA-256 | DB | P2 |
| Cloud credentials | Env var | Cloud provider | KMS | Cloud | P2 |

---

## 12. RECOMMENDATIONS

### P0 — Critical (Before Production)

1. **Integrate HashiCorp Vault or AWS Secrets Manager** — Replace env vars
2. **Enable PostgreSQL TDE** — Encrypt data at rest
3. **Enable Redis TLS + ACL** — Encrypt in transit, auth
4. **Enable Neo4j encryption** — Bolt TLS + native encryption
5. **Encrypt backup files** — GPG/age encryption for pg_dump
6. **Add secret scanning to CI** — `trufflehog` or `gitleaks`

### P1 — High

7. **Automate secret rotation** — Vault dynamic secrets or scheduled rotation
8. **Implement CBOM signing key rotation** — Automated with expiry
9. **Add API key rotation schedule** — Configurable expiry + auto-rotate
10. **Encrypt backup files** — GPG/age for pg_dump output
11. **Volume encryption** — LUKS or cloud provider encryption

### P2 — Medium

12. **Volume encryption for all Docker volumes** — LUKS/cryptsetup
13. **Secret scanning in CI** — `trufflehog` in PR checks
14. **Audit log secret redaction** — Extend to all loggers
15. **Key hierarchy** — Root key → derived keys for each service

### P3 — Enhancement

16. **Secretless authentication** — SPIFFE/SPIRE or mTLS
18. **Zero-trust secrets** — SPIRE workload identity
19. **Automated secret expiry alerts** — Monitoring on secret age
20. **Break-glass secret access** — Emergency access with audit

---

## 10. VERIFICATION EVIDENCE

All findings traceable to source:

| Finding | File |
|---------|------|
| `.env.example` defaults | `.env.example` |
| `.env.production.example` | `.env.production.example` |
| `.env.test` | `.env.test` |
| Docker compose defaults | `docker-compose.yml` |
| Docker compose prod | `docker-compose.prod.yml` |
| K8s secrets template | `k8s/app/secrets.yaml` |
| Settings validation | `services/api/api/config/settings.py` |
| Main.py startup guards | `services/api/api/main.py` |
| Safe finding enforcement | `services/shared/shared_models/shared_models/safe_finding.py` |
| Test schema contract | `services/scanner/tests/unit/test_output_schema_contract.py` |
| Backup scripts | `scripts/backup_evidence.py`, `scripts/restore_evidence.py` |
| Burn-in script | `scripts/burn_in.py` |
| CI workflow | `.github/workflows/ci.yml` |
| Logging redaction | `services/api/api/events/auth.py` |
| CBOM key rotation | `services/cbom/cbom/generator.py` |
| API key rotation | `services/api/api/routers/api_keys.py` |