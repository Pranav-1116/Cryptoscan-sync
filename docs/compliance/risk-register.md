# Risk Register

**Version:** 1.0 · **Owner:** [ORG: CISO] · **Review cadence:** at least
quarterly (same meeting as the access recertification) · **Criteria:**
TSC CC9.1

The living register of security risks to CryptoScan and its tenants.
Every risk has an owner, a treatment, and a review date — enforced by
`scripts/org_readiness_check.py`, which flags any risk missing one.
"Accepted" is a decision with an expiry, not a default.

## Scoring

Likelihood (L) and impact (I) are each scored 1–5:
**1 negligible · 2 low · 3 moderate · 4 high · 5 extreme.**
Score = L × I. Bands: **1–4 low · 5–9 medium · 10–14 high · 15–25
critical.** A critical or high risk without an owner is an incident in
waiting — the readiness check reports it as a failed control.

Treatments: **prevent** (control added/strengthened) · **detect**
(alerting/evidence added) · **respond** (runbook/IR updated) ·
**transfer** (vendor/insurance) · **accept** (written, expiring, by the
owner's approver) · **avoid** (activity stopped).

## Register

| ID | Risk | L | I | Score | Treatment | Owner | Target | Review | Status |
|----|------|---|---|-------|-----------|-------|--------|--------|--------|
| R-001 | No independent pen test performed yet (CC11.3) | 4 | 4 | 16 | respond | [ORG: CISO] | [ORG: 2026-Q4] | [ORG: YYYY-MM-DD] | OPEN |
| R-002 | No SOC 2 Type II report in force | 3 | 4 | 12 | respond | [ORG: CISO] | [ORG: 2027-Q2] | [ORG: YYYY-MM-DD] | OPEN |
| R-003 | Policy pack unsigned (100 `[ORG:]` items at drafting) | 3 | 3 | 9 | respond | [ORG: MD/Board] | [ORG: 2026-Q4] | [ORG: YYYY-MM-DD] | OPEN |
| R-004 | Sub-service SOC 2 reports not yet collected (C.2) | 3 | 3 | 9 | transfer | [ORG: CISO] | [ORG: 2026-Q4] | [ORG: YYYY-MM-DD] | OPEN |
| R-005 | Failover DR drill not yet run on a production host | 2 | 4 | 8 | respond | [ORG: SRE lead] | [ORG: 2026-Q4] | [ORG: YYYY-MM-DD] | OPEN |
| R-006 | No live burn-in at production scale before bank pilot | 3 | 3 | 9 | detect | [ORG: SRE lead] | [ORG: pre-pilot] | [ORG: YYYY-MM-DD] | OPEN |
| R-007 | CI pipeline not yet an audit exhibit (workflows unpushed) | 2 | 3 | 6 | prevent | [ORG: Eng director] | [ORG: 2026-Q4] | [ORG: YYYY-MM-DD] | OPEN |
| R-008 | On-call roster not yet staffed (IR policy §2) | 3 | 4 | 12 | respond | [ORG: Eng director] | [ORG: pre-pilot] | [ORG: YYYY-MM-DD] | OPEN |
| R-009 | Cross-region replication not implemented (single region) | 2 | 4 | 8 | accept | [ORG: CISO] | [ORG: 2027] | [ORG: YYYY-MM-DD] | OPEN |
| R-010 | Expired-but-unrevoked tenant API keys | 2 | 3 | 6 | detect | [ORG: access manager] | ongoing | [ORG: YYYY-MM-DD] | MONITORED |
| R-011 | 72 h personal-data breach notification window | 2 | 5 | 10 | respond | [ORG: DPO] | ongoing | [ORG: YYYY-MM-DD] | MONITORED |
| R-012 | Compromise of HSM-held key material | 1 | 5 | 5 | prevent | [ORG: CISO] | ongoing | [ORG: YYYY-MM-DD] | MONITORED |

### Notes on MONITORED risks (platform controls already in place)

- **R-010** — the access-review export surfaces
  `expired_keys_not_revoked` as a standing signal; the quarterly
  recertification (Access Control Policy §3.7–3.8) is the recurring
  control test. Residual risk accepted because expiry + signal +
  recert cover the lifecycle.
- **R-011** — the IR policy fixes the 72 h clock from *confirmation*
  (Incident Response Policy §5); the DPO is a required incident-team
  member; the annual table-top includes a personal-data breach
  scenario.
- **R-012** — key material lives in a FIPS 140-3 HSM; ceremonies are
  recorded with dual control; a clear-key export event is a standing
  SEV-1 trigger (payment policy PAY-004).

## Change rules

1. New risks are added with an ID, score, treatment and owner **in the
   same review that identifies them** — a risk without an owner is an
   open finding against this register.
2. Closing a risk requires evidence (a link to the control, drill
   result, report or sign-off) and moves the status to CLOSED with the
   closing review date; closed risks stay in the table (history is
   evidence).
3. Accepted risks expire by default after [ORG: 90 days] unless the
   approver re-accepts them in writing at review.
4. The register is embedded in the compliance pack
   (`scripts/compliance_pack.py` → `risk-register.md`) and the
   readiness measurement rides along (`org-readiness.json`).
