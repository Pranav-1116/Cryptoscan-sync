# Data Protection & Privacy Policy

**Version:** 1.0 (draft) · **Owner:** [ORG: Data Protection Officer]
· **Applies to:** all personal data processed by or for CryptoScan
· **Next review:** [ORG: YYYY-MM-DD] · **Criteria:** TSC A1.3

## 1. Purpose

Commit CryptoScan to lawful, fair and secure processing of personal data
across the jurisdictions in which it operates, and to the specific data
protection regimes applicable to its UAE and wider Middle East client
base.

## 2. Applicable regimes

The platform operates under three parallel UAE data-protection regimes
(detailed with article-level references in `docs/uae/`):

1. **Federal PDPL** (Federal Decree-Law No. 45 of 2021, effective
   2022/2023 with penalty regime from 2024) — applies to main-land
   processing. Articles 20 (security) and related provisions require
   appropriate technical measures including encryption and
   pseudonymisation.
2. **DIFC DP Law 2020** (effective 1 January 2022) — for DIFC clients;
   since July 2025 carries a **private right of action** for data
   subjects.
3. **ADGM DP Law 2021** — for ADGM clients.

Free zones with their own data protection laws are outside the federal
PDPL; the jurisdiction is fixed per tenant at onboarding and drives which
regime's requirements apply.

**Key obligations implemented or tracked here:**

- **72-hour breach notification** window under the federal PDPL and the
  DIFC/ADGM laws (see Incident Response Policy §5).
- Lawful basis and purpose limitation for all processing; data
  minimisation (the platform stores what the scan pipeline needs and no
  more — credentials from scan targets are transient and redacted).
- Data subject rights (access, rectification, erasure, portability)
  handled per [ORG: DPO runbook].
- Cross-border transfer controls: [ORG: state transfer mechanism —
  standard contractual clauses / adequacy assessment — for any data
  leaving the tenant's jurisdiction].

## 3. Technical measures

1. **Encryption at rest** for all personal and tenant data (see Data
   Classification Policy §3); key material in a FIPS 140-3 keyassure HSM.
2. **Encryption in transit** (TLS) on every service boundary, including
   between the API, the database, Redis and the graph store.
3. **Tenant isolation** — tenancy and ABAC middleware make one tenant's
   personal data invisible to all others.
4. **Redaction** — the shared logging layer redacts secrets and, for
   personal-data fields defined in the redaction policy
   ([ORG: enumerate personal-data fields]), keeps production logs and
   exported artifacts free of raw personal data.
5. **Retention and deletion** — scan results, findings and events are
   retained per the retention schedule [ORG: publish schedule with
   per-class retention periods]; erasure requests are executed against
   the primary store, backups are overwritten on rotation, and deletion
   is audit-logged.
6. **Processor commitments** — where CryptoScan processes data on a
   client's behalf, the data-processing terms in the client agreement
   ([ORG: link to DPA template]) apply; sub-processors are managed under
   the Vendor & Third-Party Risk Policy.

## 4. Governance

- [ORG: DPO name] is the data protection officer and point of contact for
  regulators and data subjects.
- A data protection impact assessment is performed before any new
  processing involving Class-4 data (Data Classification Policy).
- The register of processing activities is maintained by [ORG: DPO] and
  updated at least annually.
- Training: all personnel handling tenant data complete data-protection
  training on onboarding and annually [ORG: name the training provider /
  internal program].

## 5. Incidents

Personal-data incidents are handled under the Incident Response Policy;
the 72-hour notification clock runs from confirmation of the breach, and
the DPO is a required member of the incident team.

## 6. Evidence

- UAE regime analysis and article mappings: `docs/uae/`.
- Redaction behaviour: unit tests in `services/api/tests/` and the
  `redact_secrets` implementation in the shared logging layer.
- Tenant isolation: tenancy/ABAC middleware tests.
- This document, the DPA template and the retention schedule are reviewed
  annually by [ORG: DPO].
