# Penetration Test Scope Brief

**Version:** 1.0 · **Owner:** [ORG: CISO] · **Used:** hand to the
independent tester at engagement (gap-analysis item 2)

This brief defines what the independent pen test covers and how its
results enter CryptoScan's own tracking. The test itself is performed by
the third party; **the platform ingests the report** via
`POST /api/v1/pentest/findings` (or the CSV/JSON export described in §6),
so findings are severity-banded, deduplicated, status-tracked to closure,
and visible in the board report and the compliance pack.

## 1. Objective

Independent verification of the platform's technical controls — the
evidence the SOC 2 gap analysis marks as its single biggest technical
item — with findings tracked to closure inside the platform.

## 2. In scope

| Area | Details |
|------|---------|
| API | `services/api` — auth (TOTP MFA, sessions, RBAC, tenancy/ABAC), scan pipeline, audit exports, payment crypto, pentest findings API |
| Web | `frontend` (React dashboard) |
| Data | PostgreSQL (tenancy isolation, row-level scoping), Redis, Neo4j |
| Infrastructure | `docker-compose.prod.yml`, `deploy/ha` (replication, failover), nginx config |
| Crypto | HSM integration (keyassure FIPS 140-3), key ceremony flows, evidence hash chain |
| Regime-specific | UAE pack rules (CBUAE/DIFC/ADGM/PDPL) if the bank pilot scope is active |

## 3. Out of scope (declare explicitly to avoid disputes)

- Third-party SaaS (IdP, cloud host, email) — covered by their SOC 2 /
  the sub-service matrix, not this test.
- Client-owned systems reached **through** scan targets — the tester
  tests CryptoScan's handling of scan targets, not the targets.
- DoS / physical / social engineering (unless separately agreed in
  writing).

## 4. Access & environment

- A production-mirror staging environment (same topology, synthetic
  data) plus read-only access to one production-equivalent region.
- Test accounts: one `superadmin`, one `security_analyst`, one
  `readonly`, one tenant `developer`, one API key per role — provided
  via the platform's own onboarding (JML procedure), so the testers
  exercise the real lifecycle.
- Rules of engagement: agreed window, abort criteria, single point of
  contact on both sides ([ORG: names]).

## 5. Evidence the tester receives up front

- This brief + the threat model (`docs/security/threat-model.md`).
- The architecture summary (`docs/admin-guide/production.md`).
- No answer keys: findings must be independently discovered. (Handing
  over the control list would make it a review, not a test.)

## 6. Report intake

The report is delivered as PDF (archive) **plus** a machine-readable
findings file (CSV or JSON: title, description, severity or CVSS,
category, affected asset, recommendation, due date, references). Ingest:

```bash
# 1. hash the report file (provenance)
sha256sum pen-test-report.pdf

# 2. ingest the findings (ciso/security_analyst/superadmin role)
curl -X POST "$API/api/v1/pentest/findings" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d @ingest.json     # {"report": "PT-2026-XX", "source_report_sha256": "...", "findings": [...]}
```

Re-ingestion is idempotent and never re-opens a closed finding, so
report revisions (v1 → v2) are safe to load on top of each other.

## 7. Remediation loop

- Findings enter the platform with the Vulnerability Management Policy
  SLAs (Critical 7d, High 30d — escalated one level for auth/session/
  tenancy/evidence-chain code paths).
- Statuses: `OPEN → IN_PROGRESS → REMEDIATED` (or `ACCEPTED` with a
  written, expiring risk acceptance; or `WONT_FIX` with reason).
- `GET /api/v1/pentest/summary` feeds the board report and the
  compliance pack; the closing evidence for each finding links the
  fixing release (whose evidence entry is in the signed chain).

## 8. Cadence

[ORG: at least annually, and on material platform change or after a
SEV-1.] The bank's CBUAE mandate may require its own cadence — that
wins.
