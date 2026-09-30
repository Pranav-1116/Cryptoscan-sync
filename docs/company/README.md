# CryptoScan company, legal, privacy, assurance, and questionnaire pack

**Status:** controlled drafting pack
**Audience:** prospective customers, procurement, legal, privacy, security,
third-party risk, sales, customer success, and internal approvers
**Owner:** `[VENDOR LEGAL NAME]` / security and privacy owners
**Review rule:** no file in this directory is an executed contract,
certification, customer attestation, legal opinion, or production evidence
until approved, signed, and versioned by the responsible authority.

This directory is the standard starting point for responding to a prospect that
asks for an MSA, NDA, DPA, SLA, security schedule, privacy material, assurance
package, or a 400-question vendor assessment.

## 1. What this pack is designed to do

The pack separates four things that must not be confused:

| Evidence tier | Meaning | Example |
|---|---|---|
| **Repository control** | A mechanism, policy draft, code path, or documented process exists | RBAC code, policy schema, deployment hardening |
| **Operational record** | The mechanism operated in a dated, attributable run | DR drill, release verification, access review |
| **Customer attestation** | A customer or operator accepts a deployment fact or risk | Residency, production topology, residual-risk acceptance |
| **External certification** | An independent body issued an applicable report or certificate | SOC 2 report, ISO 27001 certificate, FIPS validation |

The pack must answer with the highest tier actually supported. It must never
turn a draft policy into a contractual promise or a repository implementation
into SOC 2, ISO 27001, FIPS, PCI, customer, or regulator evidence.

## 2. Directory map

### Legal and contracting

- [MSA template](msa-template.md) — commercial relationship, service orders,
  responsibilities, warranties, liability, indemnities, and general terms.
- [NDA template](nda-template.md) — mutual or one-way confidentiality terms
  for discovery, pilot, and procurement conversations.
- [DPA template](dpa-template.md) — controller/processor roles, instructions,
  security, subprocessors, rights assistance, transfers, and deletion.
- [SLA template](sla-template.md) — availability, support response, maintenance,
  service credits, exclusions, measurement, and escalation.
- [Acceptable-use terms](acceptable-use-terms.md) — permitted and prohibited
  use, scanning authorization, safety limits, and suspension rights.
- [Security addendum](security-addendum.md) — security controls, evidence,
  access, secure development, incidents, resilience, and audit cooperation.
- [Data-processing terms](data-processing-terms.md) — operational processing
  instructions and a schedule that complements the DPA.
- [Confidentiality, IP, liability, and indemnification](confidentiality-ip-liability.md)
  — clause explanations and fallback positions.
- [Termination and data deletion](termination-and-data-deletion.md) — exit,
  transition, export, deletion, backups, and verification.
- [Breach notification terms](breach-notification-terms.md) — incident
  classification, notice, cooperation, communications, and evidence.

### Privacy and data governance

- [Privacy policy](privacy-policy.md) — public-facing notice for website,
  product, account, support, and business-contact data.
- [Data retention schedule](data-retention-schedule.md) — data classes,
  retention defaults, legal holds, deletion, backups, and customer overrides.
- [Subprocessor register](subprocessors.md) — provider inventory, purpose,
  location, data category, transfer mechanism, and change notice.
- [Data residency and international transfers](data-residency-and-transfers.md)
  — deployment location, regional processing, transfer mechanisms, and
  customer responsibilities.

### Assurance and security response

- [Assurance package](assurance-package.md) — how to respond to requests for
  SOC 2, ISO 27001, security architecture, data flow, encryption, policies,
  pen-test summaries, attestations, and compliance mappings.
- [Questionnaire answer-bank operating model](questionnaire-answer-bank.md)
  — how to maintain reusable answers without inventing evidence.
- [Questionnaire answer-bank CSV](questionnaire-answer-bank.csv) — spreadsheet
  starter database for SIG Lite, SIG, CAIQ, VSAQ, CISO, cloud, privacy, and
  third-party-risk questions.
- [Answer-bank schema](questionnaire-answer-bank.schema.json) — machine-readable
  field definition for future database/API implementation.

## 3. What is currently available versus still required

The repository contains substantial technical and policy material, including:

- security architecture and data-flow documentation;
- authentication, RBAC, audit, tenant-scope, and production-guard controls;
- encrypted backup and restore tooling;
- vulnerability, incident, access, privacy, and business-continuity policy
  drafts;
- HSM and release qualification harnesses;
- readiness gates that fail closed on missing external evidence;
- security questionnaire and control-register material.

The following must not be marked available until the real artifact exists and
has an owner and review date:

- SOC 2 report;
- ISO 27001 certificate;
- independent penetration-test report and retest;
- customer/provider HSM qualification;
- customer-approved DPA, SLA, MSA, and support commitments;
- customer-specific residency and transfer decision;
- customer-specific subprocessor approval;
- production topology DR and business-continuity evidence;
- customer pilot validation and accuracy sign-off;
- signed external attestations.

The current product language remains **enterprise-capable and suitable for a
supervised pilot or pre-production evaluation**, not automatically approved for
unattended regulated production.

## 4. How to use this pack for a 400-question assessment

1. Create a copy of the answer-bank CSV or import it into the controlled
   questionnaire database.
2. Load the prospect's questions without changing their original wording.
3. Map each question to a domain, answer ID, evidence tier, owner, and source.
4. Reuse the canonical answer only where the question scope matches.
5. Mark customer-specific, legal, regulatory, residency, and certification
   questions as requiring review rather than guessing.
6. Attach the applicable approved evidence artifact or write `NOT AVAILABLE`.
7. Record questionnaire version, customer, jurisdiction, submission date,
   answer owner, reviewer, and expiry date.
8. Run legal, privacy, security, and executive review for high-risk answers.
9. Export the completed questionnaire and an evidence index together.
10. Retain the submitted version and all approvals as a controlled record.

Never answer a questionnaire from memory or by copying a previous customer's
answer without checking scope, deployment model, region, and evidence date.

## 5. Approval workflow

| Step | Owner | Required result |
|---|---|---|
| Draft | Sales/security questionnaire owner | Question mapped and proposed answer written |
| Technical review | Engineering/security | Product claims and evidence checked |
| Privacy review | Privacy/data owner | Personal data, residency, transfers, and retention checked |
| Legal review | Counsel | Contractual language, liability, IP, indemnity, and law checked |
| Assurance review | Security/compliance | Certification and external evidence status checked |
| Executive approval | Authorized signatory | Exceptions, commitments, and residual risks approved |
| Submission | Account owner | Versioned answer pack sent to prospect |
| Renewal review | Same owners | Expired evidence and changed scope refreshed |

## 6. Placeholders and controlled values

Square-bracket placeholders are intentional. Replace them only after the
responsible owner confirms the value:

- `[VENDOR LEGAL NAME]`
- `[CUSTOMER LEGAL NAME]`
- `[NOTICE EMAIL]`
- `[SECURITY CONTACT]`
- `[PRIVACY CONTACT]`
- `[DPO OR PRIVACY OWNER]`
- `[GOVERNING LAW]`
- `[SERVICE REGION]`
- `[EFFECTIVE DATE]`
- `[RETENTION PERIOD]`
- `[SUBPROCESSOR REGISTER URL]`

Do not replace a placeholder with a plausible-looking value just to make a
questionnaire appear complete.

## 7. Additional customer-readiness templates

- [Missing-document closure plan](missing-documents-and-closure-plan.md) —
  identifies what writing does not solve and the execution evidence still
  required.
- [Order Form](order-form-template.md) — customer-specific scope, pricing,
  regions, support, acceptance, and exit.
- [Statement of Work](statement-of-work-template.md) — implementation,
  pilot, integration, advisory, and acceptance work.
- [Customer responsibility matrix](customer-responsibility-matrix.md) —
  customer, Vendor, cloud, provider, and shared control ownership.
- [Support handbook and escalation](support-handbook-and-escalation.md) —
  actual channels, staffing, ticketing, severity, and escalation.
- [DPIA and transfer assessment](dpia-and-transfer-assessment.md) —
  processing risk, necessity, proportionality, and cross-border assessment.
- [Records of processing](records-of-processing.md) — privacy inventory per
  processing activity.
- [Cookie and website notice](cookie-and-website-privacy-notice.md) — actual
  website technology and consent inventory.
- [Privacy rights/DSAR procedure](privacy-rights-and-dsar-procedure.md) —
  request intake, verification, response, and deletion workflow.
- [Risk acceptance and exception form](risk-acceptance-and-exception.md) —
  owner, residual risk, compensating control, expiry, and approval.
- [Evidence data-room procedure](evidence-data-room-procedure.md) — controlled
  release and archival of sensitive assurance documents.
- [AI and data-use statement](ai-and-data-use-statement.md) — model use,
  customer-data training, human review, and provider disclosure.
- [Open-source and supply-chain policy](open-source-and-supply-chain.md) —
  SBOM, licences, advisories, provenance, signing, and release evidence.
- [Corporate and insurance due diligence](corporate-and-insurance-due-diligence.md)
  — legal entity, financial, insurance, ethics, and supplier records.
- [Accessibility and responsible business](accessibility-and-responsible-business.md)
  — accessibility evidence and responsible-supplier commitments.
- [Personnel and physical security](personnel-and-physical-security.md) —
  workforce, privileged staff, hosting, office, and provider evidence.

## 8. Related repository sources

- [Enterprise readiness gaps](../enterprise-bank-readiness-gaps.md)
- [Production readiness](../../PRODUCTION-READINESS.md)
- [Control register](../compliance/control-register.md)
- [Security questionnaire](../security-questionnaire.md)
- [Security threat model](../security/threat-model.md)
- [Security hardening checklist](../security/hardening-checklist.md)
- [Data flow](../DATAFLOW.md)
- [End-to-end architecture](../END-TO-END-ARCHITECTURE.md)
- [Evidence chain architecture](../architecture/evidence-chain.md)
- [BC/DR policy](../policies/bc-dr-policy.md)
- [Incident response policy](../policies/incident-response-policy.md)
- [Vulnerability management policy](../policies/vulnerability-management-policy.md)
- [Privacy policy draft](../policies/data-protection-privacy-policy.md)
- [Acceptable-use policy draft](../policies/acceptable-use-policy.md)
- [Readiness evidence directory](../readiness-evidence/README.md)
