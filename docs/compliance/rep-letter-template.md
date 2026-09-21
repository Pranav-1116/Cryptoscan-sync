# Representation Letter — Template

Use this template when a vendor's SOC 2 Type II (or ISO 27001) report
period does **not** cover part of CryptoScan's observation window, so the
auditor can see continuous third-party assurance. The vendor signs and
returns it; the original is filed in the compliance evidence pack
(`scripts/compliance_pack.py` picks up `docs/compliance/` artifacts that
the org places there).

---

**To:** [ORG: auditor name / engagement letterhead]
**From:** [ORG: vendor legal name]
**Date:** [ORG: YYYY-MM-DD]
**Re:** Representation letter supporting CryptoScan's SOC 2 Type II
engagement — services period [ORG: YYYY-MM-DD to YYYY-MM-DD]

We, [ORG: vendor legal name], are a service provider to
[CryproScan's legal entity — ORG: name] ("CryptoScan") in respect of
[ORG: describe the service, e.g. "hosting of production infrastructure" /
"key management services"].

We represent that, for the period from [ORG: start date] to
[ORG: end date]:

1. The services described above were provided in accordance with our
   applicable security policies and the terms of our agreement with
   CryptoScan dated [ORG: agreement reference].
2. [ORG: if applicable — "Our SOC 2 Type II report for the period
   YYYY-MM-DD to YYYY-MM-DD (issued by ORG: firm, report reference
   ORG: ref) is enclosed / remains available to the auditor on request."]
3. No material change has occurred in the controls described in the
   referenced report(s) that would affect the period represented here,
   [ORG: or list material changes and their mitigation].
4. [ORG: if applicable — "No security incident during the period
   represented affected CryptoScan's data or our controls' operating
   effectiveness."]

This representation is provided solely for the auditor conducting
CryptoScan's SOC 2 Type II examination and may not be relied upon by any
other party.

| | |
|---|---|
| Authorised signatory | [ORG: name, title] |
| Signature | [ORG: — ] |
| Date | [ORG: YYYY-MM-DD] |

---

**File with:** the vendor's current report in
`docs/compliance/sub-service-matrix.md` (row: the same vendor). The
matrix's "Rep letter for gap" column records this file's date.
