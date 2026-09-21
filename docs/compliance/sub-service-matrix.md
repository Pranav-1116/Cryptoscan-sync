# Sub-Service SOC 2 & Third-Party Assurance Matrix

**Version:** 1.0 (template — fill in before the SOC 2 engagement)
· **Owner:** [ORG: CISO] · **Next review:** [ORG: YYYY-MM-DD, and
whenever a report period rolls over]

The Vendor & Third-Party Risk Policy (§2–§4) requires, for every Tier-1
vendor in scope: the current SOC 2 Type II (or ISO 27001 + pen test
where SOC 2 is unavailable) on file, the **complementary user-entity
controls (CUECs)** identified and either implemented by CryptoScan or
documented as not applicable, and — where the report period does not
cover the observation window — a **representation letter** for the gap
(template: `rep-letter-template.md`).

## Matrix

| Vendor | Tier | Service | Certification | Report period | On file? | CUECs (what the vendor leaves to us) | CUEC owner in CryptoScan | Rep letter for gap |
|--------|------|---------|---------------|---------------|----------|--------------------------------------|--------------------------|--------------------|
| keyassure | 1 | FIPS 140-3 HSM / MFA tokens | FIPS 140-3 validation | [ORG: period] | [ORG: collect] | [ORG: e.g. key ceremonies, access to HSM portal] | [ORG: owner] | [ORG: n/a or date] |
| [ORG: cloud host] | 1 | hosting / infrastructure | [ORG: SOC 2 Type II] | [ORG: period] | [ORG: collect] | [ORG: e.g. network config, patch verification] | [ORG: owner] | [ORG: n/a or date] |
| [ORG: IdP (if used)] | 1–2 | SSO federation | [ORG: ISO 27001 / SOC 2] | [ORG: period] | [ORG: collect] | [ORG: e.g. MFA enforcement at IdP] | [ORG: owner] | [ORG: n/a or date] |
| [ORG: object storage (backups)] | 1 | off-host backup storage | [ORG: SOC 2] | [ORG: period] | [ORG: collect] | [ORG: e.g. backup encryption keys, access] | [ORG: owner] | [ORG: n/a or date] |
| [ORG: email / SMS delivery] | 2 | notification delivery | [ORG: SOC 2] | [ORG: period] | [ORG: collect] | [ORG: e.g. sender verification] | [ORG: owner] | [ORG: n/a or date] |
| [ORG: CI/CD provider] | 2 | build & deploy | [ORG: SOC 2] | [ORG: period] | [ORG: collect] | [ORG: e.g. pipeline secrets, deploy creds] | [ORG: owner] | [ORG: n/a or date] |
| [ORG: any other] | — | — | — | — | — | — | — | — |

## Rules

1. A Tier-1 vendor with **no** report on file blocks the SOC 2 evidence
   pack for the period it serves — flag it in the compliance pack's
   `missing` notes rather than shipping without it.
2. CUECs are **our** controls: each one maps to a named CryptoScan
   control (policy + implementation pointer). "Documented as not
   applicable" requires a written reason and [ORG: CISO] approval.
3. Report periods roll over: when a vendor's latest report starts after
   our observation window ends, collect a representation letter covering
   the overlap so the auditor sees continuous coverage.
4. Sub-processor changes by a vendor are a **material change** under the
   Vendor & Third-Party Risk Policy — reassess within [ORG: 30] days of
   notice.
