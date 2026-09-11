# Enterprise readiness — what the platform has, what a bank will ask for

Status as of round 12 (measured, not aspirational): **583 OpenAPI paths /
642 operations** (counted from the live schema), 56 ordered migrations,
804 backend tests. Every row below states the current capability honestly —
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
| ⚠️ Code-repository scanning depth | ⚠️ | dedup asset store + evidence links exist; deep monorepo/SAST-grade crypto pattern search is roadmap |
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
| SQLite dev / Postgres prod | ✅ | Alembic 0001–0056; Postgres driver shipped |
| ⚠️ HA story | ⚠️ | readiness drains + read-only mirrors designed; multi-active control plane is untested without real infra |
| ❌ Managed/SaaS multi-tenancy | ❌ | single-tenant by design today; tenant isolation is a product decision before SaaS |

## The honest one-liner

**Strong**: crypto discovery → CBOM → roadmap → evidence packs, telecom/PQC
posture, deterministic automation with human gates, SSO/RBAC/audit depth.
**Bring to a PoC first**: real IdP + ServiceNow/Splunk endpoints (config, not
code), cloud credentials. **Not claimed and not faked**: external
certifications, GCP/mainframe collectors, multi-tenant SaaS.
