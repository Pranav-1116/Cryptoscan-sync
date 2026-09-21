# Security Training & Awareness Program

**Version:** 1.0 (template) · **Owner:** [ORG: CISO] · **Criteria:**
TSC CC1.2 (commitment to competence), CC1.3 (accountability)

Training is a control with evidence: every course has an audience, a
cadence and a completion record. The records below are the exhibit —
a blank row is a gap the readiness check reports.

## 1. Mandatory courses

| ID | Course | Audience | Cadence | Owner |
|----|--------|----------|---------|-------|
| T-01 | Security awareness (basics, phishing, device hygiene) | all personnel + contractors | onboarding, then annual | [ORG: security lead] |
| T-02 | Secure coding for CryptoScan (RBAC, tenancy, secret handling, evidence-chain rules) | engineers | onboarding, then annual | [ORG: security lead] |
| T-03 | Data protection (PDPL / DIFC / ADGM, 72 h clock, de-identification) | all personnel handling tenant data; DPO: full | onboarding, then annual | [ORG: DPO] |
| T-04 | Incident response fundamentals (severity model, escalation, the comms tree) | on-call rotation | on rotation entry, then semi-annual | [ORG: CISO] |
| T-05 | Vendor & third-party handling (C.2 rules, DPA, sub-processor changes) | procurement, engineering | annual | [ORG: CISO] |

## 2. Phishing & practical exercises

- Phishing simulation: [ORG: quarterly, via ORG: tool/vendor] to all
  personnel; clickers retake the awareness module the same week.
- Incident table-top: [ORG: at least annually, including one
  personal-data breach scenario] (Incident Response Policy §6.3) — uses
  the roster in `docs/ops/on-call-and-comms.md`.

## 3. Completion records

New starters complete T-01/T-02 (+ T-03 where applicable) within
[ORG: 30] days; contractors before first access. Records:

| Person | Role | T-01 | T-02 | T-03 | T-04 | T-05 | Last phishing exercise |
|--------|------|------|------|------|------|------|------------------------|
| [ORG: name] | [ORG: role] | [ORG: date] | [ORG: date] | [ORG: date] | [ORG: date or n/a] | [ORG: date or n/a] | [ORG: date] |
| [ORG: name] | [ORG: role] | [ORG: date] | [ORG: date] | [ORG: date] | [ORG: date or n/a] | [ORG: date or n/a] | [ORG: date] |

Records are held by [ORG: HR / LMS] and are producible to the auditor
with the compliance pack.

## 4. Rules

1. No account stays active without current T-01 — the onboarding
   checklist (`docs/org/joiner-mover-leaver.md`) enforces the 30-day
   deadline; expiry is an access-review finding.
2. Course content changes are versioned; re-training is triggered only
   on material change or a relevant incident lesson-learned.
3. Completion data feeds the quarterly board report
   (`docs/compliance/quarterly-board-report.md` §2).
