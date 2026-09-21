# Management Representation Letter — Template

**Version:** 1.0 (template) · **Owner:** [ORG: CISO] · **Used:** once
per SOC 2 period (and per re-issuance) · **Criteria:** TSC general —
management's written assertion, signed by CISO + CEO

This is **management's** representation to the auditor — distinct from
the vendor representation letter (`rep-letter-template.md`, which a
third party signs about *its* services). The auditor cannot complete a
Type II report without it; file the signed original in the compliance
evidence pack.

---

**Date:** [ORG: YYYY-MM-DD]
**To:** [ORG: auditor firm name]
**Re:** CryptoScan SOC 2 Type II examination — period
[ORG: YYYY-MM-DD to YYYY-MM-DD]

To the engagement team of [ORG: auditor firm name]:

We, the undersigned management of [ORG: legal entity name], provide this
representation in connection with the examination of the entity's
internal control over the relevant trust service criteria (Series A —
Availability, Confidentiality, Processing Integrity, Privacy) for the
period [ORG: start] to [ORG: end]. We represent that:

1. **Responsibility & framework.** Management is responsible for
   establishing and maintaining internal control over the criteria
   stated in the engagement, and for the design and operating
   effectiveness of those controls during the period.
2. **Understanding of requirements.** We have read and understood the
   requirements of the AICPA Trust Services Criteria applicable to
   this examination.
3. **Completeness of information.** All information and access made
   available to the auditor — including the compliance evidence pack
   (policies, signed production-evidence chain, access-review minutes,
   drill results, risk register, this letter) — is complete and
   accurate to the best of our knowledge.
4. **Effectiveness of controls.** We are not aware of any instance of
   material non-compliance, or any circumstance indicating a material
   weakness in the design or operating effectiveness of controls,
   during the period.
5. **No management override.** There has been no management override
   of controls that had or could have had a material effect on internal
   control.
6. **No fraud.** We are not aware of any actual or suspected fraud or
   illegal act involving management, employees or third parties that
   could have a material effect on internal control.
7. **IT general controls.** Changes to production software and
   configuration were made through the release gate
   (`scripts/release_check.py`), each carrying a fresh signed
   production-evidence entry; logical access was administered per the
   Access Control Policy and reviewed quarterly.
8. **Incidents.** All incidents meeting the reporting threshold in the
   Incident Response Policy were handled per that policy; [ORG: state
   the count of SEV-1/SEV-2 incidents in the period, or "none"].
9. **Data protection.** Personal-data processing complied with the
   applicable regimes (UAE federal PDPL, DIFC DP Law 5/2020, ADGM DP
   Law 2021); [ORG: state the count of notifiable personal-data
   breaches in the period, or "none"].
10. **Sub-services.** The sub-service organisations listed in
    `docs/compliance/sub-service-matrix.md` provided their services
    during the period, and their reports/representation letters are
    available to the auditor.
11. **Subsequent events.** No subsequent events up to the date of this
    letter require adjustment to, or disclosure in, the controls
    description.

This representation is provided for the sole use of the auditor in
connection with the examination and may not be relied upon by any other
party.

| | |
|---|---|
| CISO | [ORG: name] — Signature: [ORG: —] |
| CEO | [ORG: name] — Signature: [ORG: —] |
| Date | [ORG: YYYY-MM-DD] |

---

**Filing:** signed original → `docs/compliance/` (named
`management-rep-letter-<period>.signed.pdf`); the compliance pack then
carries it automatically.
