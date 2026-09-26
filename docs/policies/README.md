# CryptoScan Information Security Policy Pack

**Version:** 1.0 (draft for owner sign-off)
**Date:** 2026-09-21
**Policy owner:** [ORG: Chief Information Security Officer]
**Approved by:** [ORG: Managing Director / Board]
**Review cycle:** annual, or upon material change to the platform or the
regulatory landscape

> **Status note for the SOC 2 engagement:** this pack was drafted from the
> controls actually implemented and evidenced in this repository. Items
> marked `[ORG: ...]` require organisational owners, dates and sign-off
> before the pack can be presented to the auditor. Do not present this
> pack as approved until every `[ORG: ...]` placeholder is resolved and
> the approval table below is countersigned.

## Document index

| # | Policy | SOC 2 / TSC primary criteria |
|---|--------|------------------------------|
| 1 | [Information Security Policy](information-security-policy.md) | umbrella for all CC / A1 / P |
| 2 | [Access Control Policy](access-control-policy.md) | CC6.1–CC6.8 |
| 3 | [Authentication & MFA Policy](authentication-mfa-policy.md) | CC6.2, CC6.3 |
| 4 | [Data Classification Policy](data-classification-policy.md) | A1.2, CC6.6 |
| 5 | [Data Protection & Privacy Policy](data-protection-privacy-policy.md) | A1.3 (PDPL / DIFC / ADGM) |
| 6 | [Incident Response Policy](incident-response-policy.md) | CC7.2, CC7.3, A1.4 |
| 7 | [Vulnerability Management Policy](vulnerability-management-policy.md) | CC7.1, CC7.2 |
| 8 | [Change Management Policy](change-management-policy.md) | CC8.1, CC8.2, CC8.4, CC9.2 |
| 9 | [Business Continuity & Disaster Recovery Policy](bc-dr-policy.md) | CC8.1, CC9.1, CC9.3, A1.1 |
| 10 | [Vendor & Third-Party Risk Policy](vendor-third-party-risk-policy.md) | C.2 (sub-service SOC 2s), CC6.7 |
| 11 | [Acceptable Use Policy](acceptable-use-policy.md) | CC1.3, CC6.3 |

## Approval table

| Document | Owner | Approved by | Date | Signature |
|----------|-------|-------------|------|-----------|
| All of the above | [ORG: CISO name] | [ORG: approver name] | [ORG: YYYY-MM-DD] | — |

## Versioning and control

- Each policy carries its own version, owner and next-review date.
- Changes follow the [Change Management Policy](change-management-policy.md):
  proposed in the repository, reviewed, and released with the signed
  production-evidence trail.
- The audit trail for policy changes is the repository history plus the
  signed evidence chain recorded in `docs/production-evidence.md`.

## Evidence cross-reference

Every "Requirement" in these policies that maps to implemented technology
names the implementing code path so the auditor can trace policy →
implementation → test. Policies that are organisational in nature (e.g.
training, physical security) state this explicitly rather than implying
coverage that does not exist.
