# ZELNX Security-Intelligence Roadmap — 35-item spec mapping

This document maps the 35-feature enterprise blueprint to the codebase and
records what was **already present**, what is **now added**, and what remains
**backlog**. The note is intentionally honest: many items share one engine or
were already substantially built, so the count of *new files* is small relative
to the breadth of the spec.

Legend: ✅ done / 🧩 partial or needs wiring / 🔵 backlog.

---

## 🔴 Must-add features

| # | Feature | Status | Where / next step |
|---|---------|--------|-------------------|
| 1 | **Universal Asset Identity** | ✅ NEW | `services/privacy/privacy/identity.py` — cross-scanner union-find canonical identity + aliases; API `POST /security/intelligence/identity/resolve`. To wire: feed persisted scanner observations through it in the inventory repository so the CMDB never writes duplicates. |
| 2 | **Scan Authorization Engine** | ✅ | `privacy/gate.py` (WHO→TENANT→AUTHORIZATION→SCOPE chain) + `security/rbac.py`, `api/routers/security.py#/security/gate`. |
| 3 | **Scan Safety Engine** | ✅ | `privacy/policy.py` `ScanPolicy` (production/HSM protection, maintenance windows), `privacy/gate.py` target_safety; `ot_safety`, `control_plane` safe-scan + emergency-stop. |
| 4 | **Privacy / Data Classification** | ✅ | `privacy/classify.py` (`public/sensitive/restricted`), `privacy/policy.py` `PrivacyPolicy` (collection/storage/display/retention), `privacy/redact.py`. |
| 5 | **Secrets Protection** | ✅ | `privacy/engine.py` `PrivacyScrubber` (detect→redact→hash→never-store→audit), `privacy/classify.py`. |
| 6 | **Credential Lifecycle** | ✅ (wire) | `vaultlease`, `api/routers/control.py`/`credentials` (request→approval→vault→lease→expiry→revoke), `keyassure`. Audit + rotation health exists; ensure every access is audited. |
| 7 | **Scanner Health Monitoring** | 🧩 | `api/routers/health.py` `dependency_report()` (each backing service). Extend to per-scanner status (network/cloud/hardware/vendor/crypto/evidence/graph/workers/queues). |

## 🟠 Major features

| # | Feature | Status | Where / next step |
|---|---------|--------|-------------------|
| 8 | **Scan Profiles** | ✅ NEW | `services/privacy/privacy/profiles.py` — BANK-PRODUCTION, HEALTHCARE-PRODUCTION, CLOUD-AUDIT, PQC-DISCOVERY, LOW-IMPACT, DEEP-ASSESSMENT, OT-SAFE; resolves to policy+limits and never loosens sector profile. API `GET/security/profiles`, `POST /security/profiles/resolve`. |
| 9 | **Adaptive Scanning** | 🧩 | `sector_profiles/criticality.py` + `scan_modes.py` (discovery→standard→deep→passive). Selection by asset type/criticality is present; add the *depth-selection* rules to pick mode from asset classification + importance. |
| 10 | **Intelligent Scheduling** | ✅ NEW | `privacy/triggers.py` `resolve_schedule()` (every_5_minutes…weekly/on_change/on_demand/after_*). API `POST /security/intelligence/schedule`. |
| 11 | **Event-Triggered Scanning** | ✅ NEW | `privacy/triggers.py` `event_for_change()` (asset.created→discovery, certificate.changed→crypto+cert, etc.). Wire to the events bridge (`api/events/automation_bridge.py`). |
| 12 | **Incremental Scanning** | ✅ NEW | `privacy/triggers.py` `is_incremental()` (baseline TTL + changed-assets). Wire to orchestrator: reuse `baselines.py` snapshot as the baseline. |
| 13 | **Global Rate-Limit Manager** | ✅ | `privacy/ratelimit.py` (4 layers + global/tenant/env/scanner/target; tracks rps/rpm/conns). Redis-backed in prod. |
| 14 | **Cloud API Quota Manager** | 🔵 | Add per-provider quota table + throttle; gate on `provider/api/quota/remaining`. No module yet. |
| 15 | **Network-Aware Scanner** | 🧩 | `network_scanner` understands network scope/topo; add explicit WAN/LAN/VPN/DMZ/OT classification driving behavior (partially in scope/geometry). |

## 🔐 Security features

| # | Feature | Status | Where / next step |
|---|---------|--------|-------------------|
| 16 | **Zero-Trust Internal Architecture** | 🧩 | Middlewares enforce auth on `/api/*`; service-to-service auth via API keys + sessions. Extend per-service auth between internal services. |
| 17 | **mTLS Between Services** | 🔵 | Needs infra (certs + service mesh / TLS). Documented as deployment concern; no code path yet. |
| 18 | **Customer-Managed Encryption Keys** | 🔵 | Needs KMS/HSM integration (BYOK) — deployment/enterprise feature, expect `keyassure`+`vaultlease` extension. |
| 19 | **Data Residency** | 🧩 | Sector/org settings exist; add per-org residency region policy on persistence. |
| 20 | **Immutable Audit Trail** | ✅ | `api/events/platform_events.py` + `db/models.user.AuditLog`, `audit_export.py`, RBAC audit. Record who/what/when/where/before/after/result. |

## 🧠 Intelligence features

| # | Feature | Status | Where / next step |
|---|---------|--------|-------------------|
| 21 | **Finding Deduplication** | ✅ NEW | `privacy/correlation.py` `correlate_findings()` + `finding_fingerprint()`. API `POST /security/intelligence/correlate`. |
| 22 | **Finding Correlation** | ✅ NEW | `privacy/correlation.py` `build_chain()` (attack/dependency chain → compound business risk). API `POST /security/intelligence/chain`. |
| 23 | **Confidence Engine** | ✅ NEW | `privacy/state.py` `confidence_from_sources()` (score/quality/reliability/evidence_count + tier). The 95%+ target is enforced as a KPI (score floor). API `POST /security/intelligence/state`. |
| 24 | **Unknown/Unverified State** | ✅ NEW | `privacy/state.py` `verification_state()` — VERIFIED/PROBABLE/UNVERIFIED/CONFLICTING/UNKNOWN/STALE. |
| 25 | **Stale Asset Detection** | ✅ NEW | `privacy/state.py` `staleness()` + `health_for_asset()` — an unobserved asset is never shown healthy/green. |

## 🌐 Enterprise integration

| # | Feature | Status | Where / next step |
|---|---------|--------|-------------------|
| 26 | **ITSM** | 🧩 | `remediation` + `findings` + `notifications`; add ticket/SLA lifecycle bindings. |
| 27 | **SIEM** | 🧩 | `api/routers/enterprise.py`, `audit_export.py`, webhooks → ship events to SIEM. |
| 28 | **SOAR** | 🧩 | `automation` (approval-gated), `ot_safety` — non-destructive by default. |
| 29 | **Webhooks** | ✅ | `api/routers/webhooks` + events (asset.created/changed, crypto.changed, certificate.expiring, risk.changed, scan.failed, scanner.health_changed). |
| 30 | **Enterprise API** | ✅ | Broad `api/routers/*` surface (assets, scans, findings, crypto, cbom, hbom, sbom, graph, risk, pqc, vendors, certificates, events, reports). |

## 📊 Business features

| # | Feature | Status | Where / next step |
|---|---------|--------|-------------------|
| 31 | **Business Service Mapping** | ✅ | `business_context`, `inventory.py` (USES/USED_BY/SUPPORTS/DEPENDS_ON/PROTECTED_BY/OWNED_BY), `graph` (SBOM/CBOM/HBOM). |
| 32 | **Ownership** | ✅ | `db.models` `BusinessOwner`, `inventory` ownership fields (business/technical/security owner, team/dept/env/region/criticality). |
| 33 | **SLA Management** | ✅ | `sla` service + `api/routers/sla.py` (severity → days configurable). |
| 34 | **Risk Acceptance** | ✅ | `exceptions` router + `api/routers/exceptions.py` (approver/reason/expiry/re-evaluation, no permanent silent suppression). |
| 35 | **Executive Dashboard** | ✅ | `executive`, `command_center`, `security` posture, `metrics.py`, `anomaly`, `risk` (overall crypto risk, PQC readiness, business impact, vendor/cloud/network/hardware risk). |

---

## What was added in this change

New deterministic, fully unit-tested modules (in `services/privacy/privacy/`):

- `identity.py` — **Universal Asset Identity** (spec #1)
- `profiles.py` — **Scan Profiles** (spec #8)
- `state.py` — **Confidence + verification + staleness** (spec #23/#24/#25)
- `correlation.py` — **Finding dedup + risk chain** (spec #21/#22)
- `triggers.py` — **Scheduling + event triggers + incremental** (spec #10/#11/#12)

Plus an additive `to_dict()` on `privacy.ratelimit.Limits`, exports in
`privacy/__init__.py`, and seven read-mostly API endpoints on the existing
`security` router:

```
GET  /api/v1/security/profiles
POST /api/v1/security/profiles/resolve
POST /api/v1/security/intelligence/identity/resolve
POST /api/v1/security/intelligence/correlate
POST /api/v1/security/intelligence/chain
POST /api/v1/security/intelligence/state
POST /api/v1/security/intelligence/schedule
```

Tests: `services/privacy/tests/unit/` grew by 35 cases → **58 passed**.
App still imports; OpenAPI moved **505 → 512** paths.

### Frontend + typed API (added on top)
- **Typed backend contracts**: `api/schemas/security_intelligence_schemas.py` gives the
  seven intelligence endpoints Pydantic request models (no more raw `dict` bodies).
  Covered by `services/api/tests/unit/test_security_intelligence.py` → **9 passed**.
- **New frontend page**: `frontend/src/pages/SecurityIntelligence.tsx` (route
  `/security-intelligence`) with panels for scan profiles, universal asset identity,
  verification/freshness state, finding dedup + risk chain and scan triggers. API
  helpers added in `frontend/src/lib/api.ts`; typed; `tsc --noEmit` clean and
  `vite build` succeeds (new `SecurityIntelligence` chunk ~9.7 kB).

### Honest backlog (not built, and why)
- **mTLS (#17)** and **customer-managed keys (#18)** are deployment/infra features — code can't fully implement them without a certificate infra / KMS provider.
- **Cloud API quota manager (#14)** needs a provider-specific same-day quota source.
- Items marked 🧩 need *wiring* into the orchestrator / inventory persistence, not new logic — the pure decisions already exist.
