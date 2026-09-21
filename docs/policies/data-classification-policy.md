# Data Classification Policy

**Version:** 1.0 (draft) · **Owner:** [ORG: CISO] · **Applies to:** all
data processed by or on behalf of CryptoScan · **Next review:**
[ORG: YYYY-MM-DD] · **Criteria:** TSC A1.2, CC6.6, A1.3

## 1. Purpose

Classify data by sensitivity so that handling, storage, transmission and
retention requirements can be defined per class. The classification
determines what each control — encryption, redaction, access role,
backup, disclosure — must protect.

## 2. Classification scheme

| Class | Definition | Examples in CryptoScan |
|-------|------------|------------------------|
| **1 — Public** | Publishable; no restriction | marketing docs, published status page |
| **2 — Internal** | Business data; no disclosure outside the organisation | findings dashboards, scan reports for the tenant, operational metrics |
| **3 — Confidential** | Disclosure would cause material harm | credentials/keys in the platform, API keys, tenant data, audit chains, vulnerability findings |
| **4 — Restricted** | Regulatory, financial or identity-critical data | client payment-adjacent data under CBUAE mandate, supervisory (DORA) data, evidence signatures, SOC 2 workpapers |

## 3. Handling requirements

1. **Class 2** requires role-based access per the Access Control Policy.
2. **Class 3** requires, in addition to Class 2:
   - encryption at rest (PostgreSQL at rest, keyassure FIPS 140-3 HSM for
     key material; `docs/admin-guide/production.md` documents the
     production topology);
   - encryption in transit (TLS 1.2+ for all service boundaries);
   - **secret redaction** in all logs and exported artifacts — the shared
     logging layer applies `redact_secrets` so that credentials never
     reach log sinks (`shared_logging`);
   - key material is never serialized in full: API keys exist in
     exports as display prefix + hash only.
3. **Class 4** requires, in addition to Class 3:
   - tenant isolation (tenancy + ABAC middleware) so one tenant's
     Class-4 data is invisible to every other tenant and to the platform
     operator;
   - tamper-evident storage where integrity is the control objective —
     the production evidence chain (SHA-256, WORM-style append, Merkle
     verification) is the reference implementation
     (`scripts/production_evidence.py`, `docs/production-evidence.md`);
   - data-protection regime compliance for personal data
     (Data Protection & Privacy Policy).

## 4. Labeling

Data at rest is labeled by its storage location and the policy of that
location (database → schema + tenant mapping; file → repository +
`.gitignore` conventions). [ORG: where CryptoScan ingests client files,
define a labeling standard for those artifacts.]

## 5. De-identification

Any Class-3/4 data shared outside the tenant boundary (support, audits,
demos, research) must be de-identified: usernames generalized, targets
pseudonymized, and no raw key material included. The UAE regulatory pack
(`docs/uae/`) documents the jurisdiction-specific requirements for
DIFC/ADGM clients.

## 6. Review

Data classifications for new data flows are reviewed at design time by
[ORG: data protection officer] and [ORG: CISO]. The classification of
existing flows is re-verified annually.

## 7. Exceptions

Temporary elevation of a data flow's handling (e.g. a support session
with raw logs) requires [ORG: CISO] approval, a defined end, and is logged.
