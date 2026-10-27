# Enterprise readiness — what the platform has, what a bank will ask for

**Current delta, 2026-10-21:** queue descriptors now reconcile against persisted
jobs before scope; current pinned authority and a QUEUED-only claim precede
collectors. SSH has owned durable jobs/results. Realtime/current-run Redis now
supports verified TLS/ACL/Sentinel with explicit primary-change cursor resets.
See the [current contract](api-reference/execution-and-replay.md).
Older numerical snapshots and broad availability labels below remain contextual,
not a current bank production certification. The generated API header and root
evidence gate take precedence.

Status of the evidence set: the generated API snapshot dated 2026-09-25 contains
**659 OpenAPI paths / 725 operations** across 86 tagged groups. The repository
also contains 60 ordered migrations and 4,808 backend test functions (hermetic,
parallel) plus a frontend smoke suite. These are repository measurements, not a
production approval; use the root readiness gate and dated evidence artifacts for
the current decision.
Overall readiness and its evidence: [root PRODUCTION-READINESS.md](../PRODUCTION-READINESS.md) and the generated `readiness-evidence/bank-readiness.json`. Every row below states the current capability honestly —
✅ shipped and test-verified · ⚠️ partially shipped (gap stated) · ❌ not
built (needs real infrastructure or a decision, never stubbed).

## 1. Identity & access

| Capability | Status | Detail |
|---|---|---|
| Local auth + MFA | ✅ | username/password (argon-class hashing), TOTP MFA, session lifecycle, self-service password change |
| RBAC | ✅ | 9 roles (8-role spec catalog + read-only supervisor), permission matrix, fail-closed `require_permission` |
| OIDC SSO (token relay) | ✅ | `POST /auth/oidc` — verifies IdP RS256 id_tokens (JWKS/discovery/air-gap file), issuer+audience+exp, real `cryptography` math |
| OIDC SSO (authorization code) | ✅ | `GET /auth/oidc/authorize` → IdP → `GET /auth/oidc/callback` — HMAC-signed state carrying the nonce, confidential code exchange, same verification rules, auto-provision as viewer only |
| OIDC PKCE (public clients) | ✅ | RFC 7636 S256 — automatic when no client secret is configured; verifier rides a callback-scoped HttpOnly cookie (never the front-channel state), callback fails closed without it |
| SAML 2.0 SP | ✅ | metadata / AuthnRequest / ACS with enveloped-signature verification + InResponseTo CSRF binding; roles stay admin-managed |
| LDAP/AD login | ✅ | bind + group→role map (explicit JSON map; directory can never mint a superadmin) |
| SCIM 2.0 provisioning | ✅ | `/scim/v2/Users` — directory sync cannot mint a superadmin |
| Auditor role & audit export | ✅ | read-only `auditor` role; `GET /audit-export/pack` — examiner-ready ZIP, deterministic JSON, SHA-256 manifest |
| Hash-chained audit trail | ✅ | every auth/admin action recorded, chain-verifiable |
| API keys | ✅ | scoped keys for machine callers (scanner/worker) |

## 2. Discovery & inventory coverage

| Capability | Status | Detail |
|---|---|---|
| Host/network crypto discovery | ✅ | TLS/cert probing with STARTTLS, chain validation, verdicts + severity |
| CBOM generation | ✅ | CycloneDX-style CBOM, versioned + fingerprinted |
| Cloud KMS inventory (AWS KMS) | ✅ | ListKeys/GetKeyDescription → same crypto-asset table; unknown KeySpecs skipped with reason; read-only, no key material |
| Cloud KMS inventory (Azure Key Vault) | ✅ | key metadata via KeyClient; RSA size from modulus when absent; disabled keys still inventoried |
| AWS ACM certificate inventory | ✅ | list→describe→PEM, fingerprint is the REAL SHA-256 of the DER (never an identifier); pending-validation certs skipped with reason; rows feed the renewal workflow-ready certificate table |
| Telecom network scanner | ✅ | 5GC/roaming/EPC/IMS verdict engine, SEPP PQC readiness, operator ingest for closed networks |
| Payment HSM | ✅ | PQC-capable HSM matching, ceremonies, dual custody |
| Code-repository scanning | ✅ | pattern detectors for Python / Java / C# / JavaScript / Go / Rust (plus Kotlin, PHP, Ruby, config/IaC files) incl. hardcoded keys, PEM material and secrets misuse (services/scanner), run by the worker pipeline into the deduplicated crypto-asset store; weak-primitive and key-size extraction pinned by tests |
| GCP Cloud KMS inventory | ✅ | CryptoKey listing → same crypto-asset table; algorithm table covers symmetric/HMAC/RSA(PSS,PKCS1,OAEP)/EC; unknown algorithms skipped with reason |
| ❌ Database TDE / mainframe (RACF, ICSF) discovery | ❌ | needs customer-environment adapters; never faked from config files |

## 3. Automation & delivery

| Capability | Status | Detail |
|---|---|---|
| Deterministic rules engine | ✅ | WHEN/IF/THEN plans, safety tiers, fail-closed approval gates, governance approvals persisted |
| Playbooks | ✅ | cert rotation, NF-down, crypto-team notify — incl. telecom NF-unreachable |
| Event bus + realtime | ✅ | SSE stream, cooldown dedup, recoveries never spam |
| ServiceNow delivery | ✅ | incident per automation run — impact/urgency from tier, stable `correlation_id` (idempotent on retries), preview endpoint builds the exact payload before anything is sent |
| Splunk HEC delivery | ✅ | one event per run, fixed `sourcetype=cryptoscan:automation`; HEC token never leaves the process — status endpoints report configuration NAMES only |
| Connector SDK | ✅ | registry + validation framework (`/connectors/sdk`) with built-ins |
| Jira delivery | ✅ | issue per run via REST v3 — Atlassian Document Format description, tier→priority ladder, labels carry the event kind |
| Microsoft Sentinel delivery | ✅ | Log Analytics Data Collector API with the documented SharedKey HMAC signature (pure, unit-tested string-to-sign); records flattened for ingestion |
| ❌ Qualys / ServiceNow VR / Jira Server (on-prem) connectors | ❌ | same pure-mapper + injectable-sender pattern; built on demand |

## 4. Operations & compliance artifacts

| Capability | Status | Detail |
|---|---|---|
| Prometheus metrics | ✅ | platform + telecom gauges/counters, rendered even during DB outages |
| Health/readiness probes | ✅ | `/healthz`, `/readyz` (+ K8s root aliases), drain semantics on readiness |
| Smoke test | ✅ | `scripts/smoke_test.sh` covers the live surfaces incl. telecom |
| Operator runbooks | ✅ | telecom operations + production hardening + air-gap install guides |
| Regulatory packs | ✅ | banking action-plan (ECB/FCA-framed), NRA per-carrier packs (json/csv), supervisor pack (hash-manifested) |
| Migration roadmap | ✅ | NIST IR 8547-aligned buckets folded across IT + cloud + telecom estates |
| ❌ ISO 27001 / SOC 2 attestation of THIS product | ❌ | controls are implemented and auditable in-repo; external audit is a company action, not a code feature |

## 5. Deployment

| Capability | Status | Detail |
|---|---|---|
| Compose/K8s manifests | ✅ | docker + nginx + dashboard builds in-repo |
| Air-gap mode | ✅ | JWKS-from-file, feed import, no-phone-home settings |
| SQLite dev / Postgres prod | ✅ | Alembic 0001–0060, **applied and tested on a real PostgreSQL 16** (`test_migration_chain_postgres.py`); before 2026-09-23 the chain did not apply on Postgres — see [root PRODUCTION-READINESS.md](../PRODUCTION-READINESS.md) |
| Staging stack without Docker | ✅ | `deploy/staging/staging-up.sh`: embedded PostgreSQL + Redis + api/worker/monitor, production guards on |
| Soak / burn-in evidence | ⚠️ | harness shipped (`scripts/soak.py`); first run clean but ~20 min long — the 7-day run is an ops action ([soak-evidence/](soak-evidence/README.md)) |
| ⚠️ HA story | ⚠️ | readiness drains + read-only mirrors designed; multi-active control plane is untested without real infra |
| ❌ Managed/SaaS multi-tenancy | ❌ | single-tenant by design today; tenant isolation is a product decision before SaaS |

## The honest one-liner

**Strong**: crypto discovery → CBOM → roadmap → evidence packs, telecom/PQC
posture, deterministic automation with human gates, SSO/RBAC/audit depth.
**Bring to a PoC first**: real IdP + ServiceNow/Splunk endpoints (config, not
code), cloud credentials. **Not claimed and not faked**: external
certifications, GCP/mainframe collectors, multi-tenant SaaS.
