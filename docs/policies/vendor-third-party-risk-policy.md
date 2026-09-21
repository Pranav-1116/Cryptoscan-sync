# Vendor & Third-Party Risk Policy

**Version:** 1.0 (draft) · **Owner:** [ORG: CISO] · **Applies to:** all
third parties that process, host or influence CryptoScan data and
services · **Next review:** [ORG: YYYY-MM-DD] · **Criteria:** TSC C.2
(sub-service), CC6.7

## 1. Purpose

Ensure that every organisation CryptoScan depends on is assessed before
onboarding, monitored while engaged, and off-boarded cleanly. The SOC 2
Type II report for a platform like CryptoScan will include **complementary
user-entity controls and sub-service SOC 2 reports** — this policy
defines how those are collected and kept current.

## 2. Vendor categories

| Category | Examples | Control level |
|----------|----------|---------------|
| **Tier 1 — data processors** | cloud hosting, the FIPS 140-3 HSM provider (keyassure), IdP, any sub-processor in the tenant-data path | full assessment + sub-service SOC 2 + DPA |
| **Tier 2 — material dependencies** | managed databases, load-balancing/CDN, email/SMS delivery, CI providers | security questionnaire + SOC 2 or ISO 27001 certificate on file |
| **Tier 3 — software components** | open-source libraries, container base images | SBOM tracking + vulnerability monitoring (Vulnerability Management Policy) |

## 3. Requirements

1. **Pre-onboarding assessment.** Every Tier-1/2 vendor passes a
   security questionnaire covering: certifications (SOC 2 Type II /
   ISO 27001), incident response, sub-processors, data location,
   encryption, access controls. Approval by [ORG: CISO] before the
   vendor touches production.
2. **Sub-service reports.** For the SOC 2 engagement: collect the
   current SOC 2 Type II (or ISO 27001 + pen test where SOC 2 is
   unavailable) for each Tier-1 vendor in scope, identify the
   **complementary user-entity controls** the report leaves to CryptoScan,
   and implement those controls (or document why they do not apply).
   [ORG: build the sub-service matrix — vendor, report period, CUECs,
   owner, next due date — before the auditor arrives.]
3. **Representations letters.** Where a vendor's report period does not
   cover the observation window, obtain a representation letter covering
   the gap.
4. **Continuous monitoring.**
   - Tier-1: annual reassessment + immediate notice obligation for
     material changes (sub-processor changes, certification lapses,
     security incidents affecting our data).
   - Tier-2: annual certificate refresh check.
   - Tier-3: SBOM-driven — a newly disclosed vulnerability in a shipped
     component is a finding per the Vulnerability Management Policy.
5. **Data processing.** Every vendor that touches tenant or personal data
   has a signed data-processing agreement (Data Protection & Privacy
   Policy §3.6) and appears in the sub-processor register [ORG:
   maintain register].
6. **Access.** Vendor access to production, where unavoidable, is
   time-boxed, individually assigned, MFA-protected, and recorded in the
   audit trail; standing vendor access is not permitted
   (Access Control Policy §3.1).
7. **Off-boarding.** Access removal, data return/deletion certificates,
   and closure verification logged by [ORG: vendor manager].

## 4. Known Tier-1 dependencies (to be completed with owners)

| Vendor | Role | Certification | Sub-service report on file |
|--------|------|---------------|---------------------------|
| keyassure | FIPS 140-3 HSM / MFA tokens | FIPS 140-3 validation | [ORG: collect] |
| [ORG: cloud host] | hosting | [ORG: SOC 2] | [ORG: collect] |
| [ORG: IdP, if used] | federation | [ORG: ISO 27001 / SOC 2] | [ORG: collect] |
| [ORG: any other] | — | — | — |

## 5. Evidence

- Vendor assessments, questionnaires, DPAs and sub-service reports are
  held by [ORG: compliance function] and versioned annually.
- SBOMs and dependency monitoring outputs are produced per release
  (Change Management Policy §3.5).
- The sub-service matrix is a standing exhibit in the SOC 2 evidence
  pack and is updated whenever a vendor's report period rolls over.
