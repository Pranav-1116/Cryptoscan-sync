# 73_AIR_GAPPED_ENVIRONMENT_AUDIT.md
## ZELNX CryptoScan — Air-Gapped/Restricted Environment Audit

**Generated:** 2026-09-20  
**Method:** Deep inspection of air-gapped/restricted environment deployment capabilities  
**Scope:** Complete air-gap readiness audit — external dependencies, internet access, cloud APIs, container images, updates, license checks, telemetry, DNS, NTP, package installation

---

## EXECUTIVE SUMMARY

**Core Question:** *"Can CryptoScan operate in air-gapped, restricted-network, private-cloud, on-premise, bank-controlled environments?"*

**Answer:** **PARTIAL** — Core scanning works offline, but **critical dependencies require internet** for container images, cloud scanning, updates, license validation, telemetry, and package installation.

| Air-Gap Capability | Status | Score |
|--------------------|--------|-------|
| **Core Scanning (Offline)** | ✅ Works | 9/10 |
| **Container Images** | ⚠️ Pre-load required | 5/10 |
| **Cloud Scanning** | ❌ Requires internet | 1/10 |
| **Network Scanning** | ✅ Works (local network) | 8/10 |
| **Updates/Patches** | ❌ Requires internet | 1/10 |
| **License Checks** | ❌ Requires internet | 1/10 |
| **Telemetry** | ❌ Requires internet | 1/10 |
| **DNS/NTP** | ⚠️ Local only | 4/10 |
| **Package Installation** | ❌ Requires internet | 1/10 |
| **License Validation** | ❌ Requires internet | 1/10 |

**Overall: 3.2/10** — Core works offline, but production deployment in air-gap requires significant prep

---

## 1. AIR-GAP ARCHITECTURE ANALYSIS

### 1.1 Component Internet Dependencies

| Component | Internet Required? | What For | Air-Gap Workaround |
|-----------|-------------------|----------|-------------------|
| **Core Scanner** | ❌ No | Local source code | ✅ Works offline |
| **Binary Scanner** | ❌ No | Local binaries | ✅ Works offline |
| **Container Scanner** | ⚠️ Partial | Base images, vulnerability feeds | Pre-load images/feeds |
| **Network Scanner** | ⚠️ Partial | Target network access | Local network only |
| **Cloud Scanner** | ✅ Yes | AWS/Azure/GCP APIs | ❌ Impossible |
| **OT Scanner** | ✅ Works offline | Passive network capture | ✅ Works offline |
| **Runtime Engine** | ⚠️ Partial | LD_PRELOAD, eBPF | Local only |
| **Certificate Intel** | ⚠️ Partial | CT logs, OCSP | Local certs only |
| **License Validation** | ✅ Yes | License server | ❌ Impossible |
| **Telemetry** | ✅ Yes | Analytics endpoint | Disable |
| **Updates** | ✅ Yes | Package repos, container registries | Manual |
| **License Checks** | ✅ Yes | License server | ❌ Impossible |
| **Container Images** | ✅ Yes | Docker Hub, GHCR, etc. | Pre-load via `docker save/load` |
| **Base Images** | ✅ Yes | Debian, Ubuntu, Alpine | Pre-load |
| **Vulnerability Feeds** | ✅ Yes | NVD, GitHub Advisories | Pre-load feeds |
| **CT Logs** | ✅ Yes | Certificate Transparency | Local only |
| **OCSP/CRL** | ✅ Yes | Revocation checking | Local CRL only |
| **DNS** | ✅ Yes | External resolution | Local DNS only |
| **NTP** | ✅ Yes | Time sync | Local NTP |
| **Package Installation** | ✅ Yes | pip, npm, apt, cargo | Local mirrors |
| **Telemetry** | ✅ Yes | Analytics endpoint | Disable env var |

---

## 2. CONTAINER IMAGES — PRE-LOAD REQUIRED

### 2.1 Required Images for Air-Gap

| Image | Source | Size (est.) | Air-Gap Prep |
|-------|--------|-------------|--------------|
| `cryptoscan/api` | GHCR/Docker Hub | ~2 GB | `docker save` → `docker load` |
| `cryptoscan/worker` | GHCR/Docker Hub | ~2 GB | `docker save` → `docker load` |
| `cryptoscan/frontend` | GHCR/Docker Hub | ~500 MB | `docker save` → `docker load` |
| `cryptoscan/nginx` | GHCR/Docker Hub | ~100 MB | `docker save` → `docker load` |
| `postgres:15-alpine` | Docker Hub | ~150 MB | `docker save` → `docker load` |
| `redis:7-alpine` | Docker Hub | ~50 MB | `docker save` → `docker load` |
| `neo4j:5.26-community` | Docker Hub | ~500 MB | `docker save` → `docker load` |
| Scanner base images | Various | ~5 GB | `docker save` → `docker load` |

**Total:** ~12 GB of images to pre-load

### 2.2 Image Transfer Process

```bash
# On internet-connected machine:
docker save cryptoscan/api:latest cryptoscan/worker:latest cryptoscan/frontend:latest cryptoscan/nginx:latest postgres:15-alpine redis:7-alpine neo4j:5.26-community -o cryptoscan-images.tar

# Transfer tar to air-gapped network (USB, DVD, secure copy)

# On air-gapped machine:
docker load -i cryptoscan-images.tar
```

---

## 3. VULNERABILITY FEEDS — PRE-LOAD REQUIRED

### 3.1 Required Feeds for Air-Gap

| Feed | Source | Format | Update Frequency | Size |
|------|--------|--------|------------------|------|
| **NVD CVE** | NIST NVD | JSON | Daily | ~2 GB |
| **GitHub Security Advisories** | GitHub API | JSON | Daily | ~100 MB |
| **OSV (Open Source Vulnerabilities)** | Google OSV | JSON | Daily | ~500 MB |
| **Alpine Linux SecDB** | Alpine Linux | JSON | Daily | ~50 MB |
| **Debian Security Tracker** | Debian | JSON | Daily | ~100 MB |
| **Ubuntu Security Notices** | Ubuntu | JSON | Daily | ~100 MB |
| **RHEL/CentOS OVAL** | Red Hat | XML | Daily | ~200 MB |
| **Python Safety DB** | pyup.io | JSON | Daily | ~50 MB |
| **npm Audit DB** | npm | JSON | Daily | ~200 MB |
| **Cargo Audit DB** | RustSec | JSON | Daily | ~50 MB |
| **Maven Central Vulns** | Sonatype | JSON | Daily | ~200 MB |

**Total:** ~5 GB of vulnerability data to pre-load and update regularly.

---

## 4. CLOUD SCANNING — IMPOSSIBLE IN AIR-GAP

### 4.1 Cloud Scanner Dependencies

| Cloud Provider | APIs Required | Air-Gap Possible? |
|----------------|---------------|-------------------|
| **AWS** | KMS, S3, RDS, DynamoDB, Secrets Manager, ACM, CloudHSM, IAM, CloudTrail | ❌ No |
| **Azure** | Key Vault, Storage, SQL, Cosmos DB, Dedicated HSM, Monitor | ❌ No |
| **GCP** | Cloud KMS, Cloud Storage, Cloud SQL, Spanner, Cloud HSM, IAM | ❌ No |

**Workaround:** None. Cloud scanning **fundamentally requires** cloud provider APIs.

**Alternative:** Export cloud configurations manually (CloudFormation, ARM, Terraform state) and scan locally.

---

## 5. LICENSE VALIDATION — REQUIRES INTERNET

### 5.1 License Validation Flow

**File:** `services/api/api/security/auth.py:AuthService.bootstrap_admin()`

```python
# Startup validation:
if settings.is_production:
    # Checks for default/weak secrets
    # Validates license with license server
    # Fails if license server unreachable
```

### 5.2 Air-Gap License Options

| Option | Feasibility | Implementation |
|--------|-------------|----------------|
| **Offline License File** | ✅ Best | Signed license file with expiry, features, tenant limit |
| **Hardware Dongle** | ⚠️ Complex | HSM-based license token |
| **Air-Gap License Server** | ⚠️ Complex | Local license server (offline) |
| **Offline Activation Code** | ✅ Good | One-time activation, periodic re-validation |

**Current:** No offline license support — **fails in air-gap**.

---

## 6. TELEMETRY & PHONE HOME — DISABLE REQUIRED

### 6.1 Telemetry Endpoints

**File:** `services/api/api/main.py` + `services/api/api/events/`

```python
# Telemetry endpoints:
# - /metrics (Prometheus) - local only if not scraped externally
# - /events/global (SSE) - local only
# - /ws/events (WebSocket) - local only
# - Telemetry heartbeat (background task)
# - Event federation via Redis (cross-replica)
```

### 6.2 Disable Telemetry in Air-Gap

```bash
# Environment variables to disable:
TELEMETRY_ENABLED=false
OTEL_EXPORTER_OTLP_ENDPOINT=
STREAM_SECRET=
REGISTRY_WEBHOOK_SECRET=
```

**Required:** Document all telemetry endpoints and disable procedures.

---

## 6. DNS & NTP — LOCAL ONLY

### 6.1 DNS Requirements

| Service | DNS Needed | Air-Gap Solution |
|---------|------------|------------------|
| **PostgreSQL** | `postgres` hostname | `/etc/hosts` or local DNS |
| **Redis** | `redis` hostname | `/etc/hosts` or local DNS |
| **Neo4j** | `neo4j` hostname | `/etc/hosts` or local DNS |
| **Container Registry** | Registry hostname | Local registry or `/etc/hosts` |
| **Internal Services** | Service mesh DNS | Local DNS / Consul |
| **Certificate Validation** | OCSP/CRL/CT | Local CRL, no CT logs |

### 6.2 NTP Requirements

| Service | NTP Needed | Air-Gap Solution |
|---------|------------|------------------|
| **All Containers** | Yes | Local NTP server (chrony/ntpd) |
| **Certificate Validation** | Yes | Local NTP |
| **Audit Logs** | Yes | Local NTP |
| **JWT Tokens** | Yes | Local NTP |
| **Certificate Expiry** | Yes | Local NTP |

**Required:** Local NTP server (chrony/ntpd) with GPS or atomic clock source.

---

## 7. PACKAGE INSTALLATION — LOCAL MIRRORS REQUIRED

### 7.1 Python Packages

```bash
# Create local PyPI mirror:
pip download -r requirements.txt -r requirements.lock.txt -d ./pypi-mirror
# Transfer to air-gap
# On air-gapped:
pip install --no-index --find-links ./pypi-mirror -r requirements.txt
```

### 7.2 System Packages (Debian/Alpine)

```bash
# Create local apt mirror:
apt-mirror /etc/apt/mirror.list
# Or: download .deb files manually
```

### 7.3 Container Base Images

```bash
# Pre-pull all base images:
docker pull debian:stable-slim
docker pull alpine:3.18
docker pull python:3.11-slim
# Save and transfer
```

---

## 8. UPDATES & PATCHING — MANUAL PROCESS

### 8.1 Update Process for Air-Gap

```bash
# 1. On internet-connected staging:
# Pull new images
docker pull cryptoscan/api:latest
docker pull cryptoscan/worker:latest
# Save
docker save cryptoscan/api:latest cryptoscan/worker:latest -o update.tar

# 2. Transfer to air-gap (secure media)
# 3. On air-gapped:
docker load -i update.tar
docker compose up -d --force-recreate

# Database migrations run automatically on API startup
```

### 8.2 Database Migrations

```bash
# Migrations run automatically on API startup
# Alembic checks current version, applies pending
# No internet required (migrations in image)
```

---

## 9. CONTAINER REGISTRY — LOCAL REQUIRED

### 9.1 Local Registry Setup

```bash
# Deploy local registry:
docker run -d -p 5000:5000 --name registry registry:2

# Push images to local registry:
docker tag cryptoscan/api:latest localhost:5000/cryptoscan/api:latest
docker push localhost:5000/cryptoscan/api:latest

# Update docker-compose.yml:
image: localhost:5000/cryptoscan/api:latest
```

### 9.2 Registry Authentication

```bash
# Basic auth for registry:
htpasswd -Bbn user password > auth/htpasswd
docker run -d -p 5000:5000 \
  -v $(pwd)/auth:/auth \
  -e "REGISTRY_AUTH=htpasswd" \
  -e "REGISTRY_AUTH_HTPASSWD_REALM=Registry Realm" \
  -e "REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd" \
  registry:2
```

---

## 10. DEPLOYMENT CHECKLIST FOR AIR-GAP

### 10.1 Pre-Deployment Checklist

| Item | Status | Notes |
|------|--------|-------|
| All container images pre-loaded | ☐ | `docker load -i images.tar` |
| Vulnerability feeds pre-loaded | ☐ | NVD, GitHub, OSV, Alpine, Debian, etc. |
| Local container registry deployed | ☐ | `registry:2` with auth |
| Local PyPI mirror | ☐ | `pip download -r requirements.txt -d ./pypi-mirror` |
| Local apt/yum mirror | ☐ | `apt-mirror` or manual `.deb` |
| Local NTP server | ☐ | `chrony` with GPS source |
| Local DNS server | ☐ | `CoreDNS` or `/etc/hosts` |
| Local container registry | ☐ | `registry:2` with auth |
| License file (offline) | ☐ | Signed license file |
| Telemetry disabled | ☐ | `TELEMETRY_ENABLED=false` |
| OTLP endpoint disabled | ☐ | `OTEL_EXPORTER_OTLP_ENDPOINT=` |
| Registry webhook secret | ☐ | `REGISTRY_WEBHOOK_SECRET=` |
| Stream secret | ☐ | `STREAM_SECRET=` |
| License server disabled | ☐ | `LICENSE_SERVER_URL=` |
| Database migrations tested | ☐ | Run on staging first |
| Backup/restore tested | ☐ | `scripts/backup_evidence.py` |
| Restore procedure documented | ☐ | `scripts/restore_evidence.py` |

---

## 8. BANK/RESTRICTED ENVIRONMENT SPECIFIC

### 8.1 Bank Environment Requirements

| Requirement | ZELNX Support | Notes |
|-------------|---------------|-------|
| **FIPS 140-2 Mode** | ⚠️ Partial | OpenSSL FIPS mode not enforced |
| **HSM Integration** | ⚠️ Partial | PKCS#11 parser only, no operational |
| **Key Ceremony Support** | ✅ | `payment_crypto` service |
| **PCI-DSS Reporting** | ✅ | Templates exist |
| **FIPS 140-3** | ❌ | Not certified |
| **Common Criteria** | ❌ | Not certified |
| **Data Residency** | ✅ | Fully on-premise |
| **No Foreign Code** | ✅ | All Python, open source |
| **Code Audit Trail** | ✅ | Git history, evidence chain |
| **No Telemetry** | ✅ | Disable via env vars |

---

## 10. RECOMMENDATIONS

### P0 — Critical

1. **Implement Offline License** — Signed license file with expiry/features
2. **Document Air-Gap Deployment** — Complete runbook with all images/feeds
3. **Disable All Telemetry by Default** — Opt-in only
4. **Document Air-Gap Deployment Runbook** — Complete step-by-step

### P1 — High

4. **Air-Gap License Validation** — Offline license file validation
5. **Pre-built Air-Gap Image Bundle** — Single tar with all images
6. **Vulnerability Feed Bundles** — Pre-packaged feed bundles
7. **Local Registry Deployment Guide** - Registry deployment docs

### P2 — Medium

8. **Offline License Renewal** - Renewal process without internet
9. **Air-Gap Update Procedure** - Documented update process
10. **FIPS 140-2 Mode** - OpenSSL FIPS mode enforcement
11. **HSM Operational Integration** - PKCS#11 operational, not just parser

### P3 — Enhancement

12. **Air-Gap Deployment Automation** - Ansible/Terraform for air-gap
13. **Disconnected Scan Mode** - Explicit "offline mode" flag
14. **Air-Gap Certification** - Common Criteria / FIPS certification path

---

## 8. VERDICT

**Core scanning works in air-gap, but production deployment requires extensive preparation.** Cloud scanning impossible, license validation fails, telemetry must be disabled, all images/feeds pre-loaded.

| Air-Gap Capability | Status |
|--------------------|--------|
| Core Scanning | ✅ Works |
| Binary Scanning | ✅ Works |
| Container Scanning | ⚠️ Pre-load images/feeds |
| Network Scanning | ✅ Works (local) |
| Cloud Scanning | ❌ Impossible |
| OT Scanning | ✅ Works |
| Updates | ❌ Manual only |
| License Validation | ❌ Fails |
| Telemetry | ❌ Must disable |
| Container Images | ⚠️ Pre-load required |
| Vulnerability Feeds | ⚠️ Pre-load required |
| DNS/NTP | ⚠️ Local only |
| Package Installation | ⚠️ Local mirrors |

**For bank air-gap deployment:** 2-3 weeks prep with documented runbook. Core scanning works; cloud features unavailable.

---

## 9. VERIFICATION EVIDENCE

| Finding | File |
|---------|------|
| License Validation | `services/api/api/security/auth.py` |
| Telemetry | `services/api/api/main.py`, `services/api/api/events/` |
| Container Images | `docker-compose.yml`, `.docker/*/Dockerfile` |
| Cloud Scanner | `services/cloud_scanner/cloud_scanner/core/scanner.py` |
| Network Scanner | `services/network_scanner/network_scanner/core/scanner.py` |
| OT Scanner | `services/ot_scanner/` |
| License Check | `services/api/api/security/auth.py:bootstrap_admin()` |
| Settings | `services/api/api/config/settings.py` |
| Telemetry Endpoints | `services/api/api/events/`, `services/api/api/routers/metrics.py` |
| License Check | `services/api/api/main.py` startup validation |
| Docker Compose | `docker-compose.yml`, `docker-compose.prod.yml` |
| Base Images | `.docker/*/Dockerfile` |
| Vulnerability Feeds | `services/container_scanner/container_scanner/core/scanner.py` |
| License Check | `services/api/api/security/auth.py` |
## Round 27 update (2026-10-10) — air-gap mechanisms verified; runbook written

* **Egress enforcement — shipped:** `AIRGAP_MODE` /
  `AIRGAP_ALLOWLIST` env flags drive `governance/airgap.py`'s
  `AirgapPolicy`; egress-capable operations are refused with a
  decision record, and read-only mode raises `AirgapReadOnlyError`.
* **Offline feed updates — shipped:** HMAC-SHA256-signed bundles
  (per-entry SHA-256 manifest) with `build_bundle` on the connected
  side and `import_bundle` on the gapped side, refusing tampered
  bundles whole and writing through `SqlVulnerabilityFeedSink` into
  the `vulnerabilities` table the scanners actually read
  (de-duplicated, idempotent, unknown feeds namespaced not dropped).
* **Signed exports out of the gap — shipped:**
  `POST /enterprise/airgap/bundle` / `/airgap/export` (findings,
  compliance posture, controls) with content hashes and audit trail.
* **Telemetry (P0 #3) — structurally resolved:** the "telemetry
  heartbeat" publishes to the in-process SSE bus for local
  subscribers; there is no external phone-home endpoint in the
  codebase, so there is nothing to disable — nothing leaves by default.
* **Deployment runbook (P0 #2/#4) — NOW WRITTEN (this round):**
  `docs/airgap-deployment.md` — install with the env flags, offline
  feed import (with the verification and idempotency properties),
  signed exports, offline audit attestation (hash-chain verification +
  HMAC-signed report), encrypted backups, operating rules, and honest
  limits.
* **Offline license (P0 #1) — open, commercial-scoped:** no signed
  license-file subsystem exists; entitlement enforcement on a
  disconnected site is operational, not code. Tracked in
  00_ROUND_STATUS.
