# Information Security Policy (Umbrella)

**Version:** 1.0 (draft) · **Owner:** [ORG: Chief Information Security
Officer] · **Applies to:** all personnel, contractors, systems and data of
CryptoScan · **Next review:** [ORG: YYYY-MM-DD]

## 1. Purpose and scope

This is the top-level information security policy for CryptoScan. It
states the organisation's security commitments and the hierarchy of the
policies beneath it. Where a specific policy (below) is stricter, the
specific policy wins; where this umbrella says a control MUST exist, the
specific policy says how it is implemented — and in most cases the
platform's code already implements it, cited per policy.

## 2. Security objectives

1. **Confidentiality** — tenant data, credentials and vulnerability
   findings are protected by tenant isolation, encryption and role-based
   access (A1.2; Data Classification Policy, Access Control Policy).
2. **Integrity** — findings, evidence and reports are tamper-evident:
   the platform's own evidence chain (content hash + chained hashes +
   optional JWS signing) is the reference implementation, and the
   release gate refuses to cut a release without a fresh verified
   evidence run (Change Management Policy §3.5).
3. **Availability** — scanning, alerting and reporting remain available
   within RTO 4 h / RPO 1 h through the documented HA and DR controls
   (BC/DR Policy).
4. **Accountability** — every security-relevant action is attributed to
   an identity in the audit trail; quarterly access reviews re-verify
   the estate (Access Control Policy §3.7–3.8).

## 3. Policy hierarchy

This umbrella policy governs:

| Policy | Domain |
|--------|--------|
| Access Control Policy | CC6 — who may do what, MFA, sessions, API keys, reviews |
| Authentication & MFA Policy | CC6.2/6.3/6.7 — credential and session rules |
| Data Classification Policy | A1.2 — sensitivity classes and handling |
| Data Protection & Privacy Policy | A1.3 — PDPL / DIFC / ADGM obligations |
| Incident Response Policy | CC7.2/7.3, A1.4 — detection, response, notification |
| Vulnerability Management Policy | CC7.1/7.2 — scan cadence, SLAs, pen test |
| Change Management Policy | CC8 — authorisation, testing, release gate, rollback |
| Business Continuity & DR Policy | CC9, A1.1 — RTO/RPO, backups, drills |
| Vendor & Third-Party Risk Policy | C.2 — sub-service SOC 2s, DPAs, monitoring |
| Acceptable Use Policy | CC1.3 — individual responsibility |

## 4. Roles and responsibilities

- [ORG: CISO] — owns this policy set, the risk register and exceptions.
- [ORG: Engineering Director] — owns technical control implementation
  and change management.
- [ORG: Data Protection Officer] — owns the privacy policy and breach
  notifications.
- [ORG: Compliance function] — owns the evidence pack, audit
  coordination and the quarterly review calendar.
- All personnel — comply, report concerns immediately, complete
  training [ORG: program and cadence].

## 5. Risk management

Security risk is accepted only in writing, by [ORG: CISO or named risk
owner], with an expiry date; open risks are reviewed at the quarterly
access recertification. Residual risk from the current self-assessment
is summarised in `docs/soc2-readiness-gap-analysis.md`.

## 6. Compliance and enforcement

Deviations from this policy set are handled per the Acceptable Use
Policy §5. Security-relevant violations (circumvention of controls,
concealment of incidents, unauthorised data access) are additionally
treated as potential regulatory-reportable events where applicable
(Incident Response Policy §5).

## 7. Review and approval

Reviewed annually or upon material change. Approved by [ORG: Managing
Director / Board] on [ORG: YYYY-MM-DD]. The approval table in
`docs/policies/README.md` is the sign-off record for this pack.
