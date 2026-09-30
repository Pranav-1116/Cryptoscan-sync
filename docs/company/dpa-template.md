# Data Processing Agreement template

**Template status:** counsel and privacy review required; not an executed DPA
**Version:** `DPA-DRAFT-1.0`
**Controller/customer:** `[CUSTOMER LEGAL NAME]`
**Processor/vendor:** `[VENDOR LEGAL NAME]`
**Effective date:** `[EFFECTIVE DATE]`

This template is designed for a customer that determines the purposes and
means of processing and `[VENDOR LEGAL NAME]` that processes Personal Data to
provide CryptoScan. The parties must adapt it for the applicable laws,
including GDPR/UK GDPR, Indian DPDP requirements, US state laws, sector rules,
and customer-specific banking or outsourcing requirements.

## 1. Scope and roles

Customer is the **Controller** or equivalent business responsible for the
Personal Data and processing purposes. Vendor is the **Processor** or
service-provider acting on Customer's documented instructions, except for
limited independent processing needed to secure, administer, invoice, and
comply with law.

The Services, categories, data subjects, purposes, duration, locations, and
special terms are listed in Schedule 1. If Customer acts as a processor for
another controller, Customer must ensure that its instructions and downstream
obligations permit Vendor's processing.

## 2. Documented instructions

Vendor will process Personal Data only:

- to provide, secure, support, maintain, and improve the Services as described
  in the Order Form and this DPA;
- on Customer's documented instructions;
- to comply with applicable law, after notifying Customer unless prohibited; or
- to detect, prevent, investigate, and respond to security, fraud, abuse, or
  availability events necessary to protect the Services.

Vendor will not sell Personal Data, use it for cross-customer advertising, or
use it to train a general-purpose model without Customer's express written
instruction and a lawful basis.

Customer is responsible for lawfulness, transparency, data minimization,
accuracy, retention, consent or other legal basis, and instructions. Vendor
may refuse an instruction that is unlawful, technically unsafe, outside the
agreed scope, or inconsistent with the Agreement, and will explain the reason.

## 3. Confidentiality and personnel

Vendor will ensure that personnel and approved subprocessors authorized to
process Personal Data:

- are bound by confidentiality obligations;
- receive role-appropriate privacy and security training;
- access only the minimum data needed;
- use named or controlled identities; and
- are removed or de-authorized when no longer needed.

## 4. Security of processing

Vendor will maintain appropriate technical and organizational measures,
considering the state of the art, risk, processing context, and nature of the
Personal Data. The Security Addendum is incorporated by reference and covers:

- access control and least privilege;
- authentication and privileged access;
- encryption in transit and at rest where supported;
- secrets and key management;
- vulnerability and patch management;
- secure development and change control;
- logging, monitoring, and incident response;
- backup, recovery, continuity, and deletion;
- tenant and customer scope isolation;
- physical and cloud provider safeguards; and
- security testing and evidence.

Vendor will not claim a certification or control tier that is not supported by
an applicable artifact.

## 5. Subprocessors

Vendor may use the subprocessors listed in
[subprocessors.md](subprocessors.md) or an approved customer-specific annex.
Vendor will:

- assess subprocessors before authorization;
- bind them to materially equivalent privacy and security obligations;
- remain responsible for their processing to the extent required by law and
  contract;
- provide notice of proposed material changes at least `[30]` days in advance;
- provide a reasonable objection path for legally required objections; and
- remove a subprocessor when the service no longer needs it or the objection is
  resolved through a reasonable alternative.

A subprocessor list must state actual provider, service, processing purpose,
data category, location, transfer mechanism, and current status. A generic
cloud-provider logo list is not sufficient.

## 6. Data subject and individual rights

Taking into account the nature of the processing, Vendor will reasonably assist
Customer with requests to access, correct, delete, restrict, export, object,
or otherwise exercise rights. Vendor may route a request received directly to
Customer unless law requires Vendor to respond.

Customer must provide the identity, scope, deadline, and lawful instruction
needed to act. Vendor may charge reasonable documented assistance costs only if
allowed by the Order Form and law.

## 7. Security incidents

Vendor will notify Customer without undue delay after confirming a Security
Incident involving Customer Personal Data and, where agreed, within the
contractual window in [breach-notification-terms.md](breach-notification-terms.md).
The notice will include, to the extent known:

- date and time discovered and estimated occurrence;
- nature and categories of data and individuals;
- affected systems and Customer scope;
- containment and remediation actions;
- likely consequences and risk assessment;
- contact for the incident team; and
- updates as material information becomes available.

Vendor will not notify regulators, individuals, media, or other third parties
on Customer's behalf unless Customer instructs it or law requires it. Vendor
will preserve relevant evidence and cooperate with Customer's investigation.

Unsuccessful attacks, scans, probes, spam, or events that do not compromise
Customer Personal Data may be tracked and summarized without being treated as
a Security Incident, subject to the Security Addendum.

## 8. DPIA, regulator, and audit assistance

Vendor will reasonably assist Customer with data-protection impact assessments,
regulator inquiries, records of processing, and risk assessments using the
information reasonably available for the Services.

Customer may review Vendor's relevant policies, independent reports,
questionnaire answers, and remediation summaries. On-site or technical audits
must be reasonable, risk-based, confidential, non-disruptive, and not expose
another customer's data or Vendor secrets. Customer will first use current
independent reports and certifications where available.

The repository's control register distinguishes repository controls,
operational records, customer attestations, and external certifications.
That distinction applies to every answer supplied under this DPA.

## 9. International transfers

The parties will use the transfer mechanism identified in Schedule 3 for each
cross-border transfer, such as an adequacy decision, Standard Contractual
Clauses, UK Addendum, approved binding corporate rules, or another lawful
mechanism. They will complete transfer impact assessments and supplementary
measures where required.

No transfer mechanism is implied merely because a cloud provider operates in a
region. The customer-specific deployment region, support access, subprocessor
location, backup location, and remote-support path must be recorded.

## 10. Retention, return, and deletion

Vendor will process Personal Data only for the term and retention period in
Schedule 2. At termination or Customer's written request, Vendor will return
or delete Personal Data unless retention is required by law or limited backup
technology. Vendor will:

- provide a documented export opportunity;
- restrict retained copies during a legal hold or backup cycle;
- delete active copies within `[30]` days after the agreed deletion trigger;
- allow residual encrypted backups to expire within `[90]` days unless a
  different period is approved;
- retain only the minimum evidence needed for legal, security, or audit
  obligations; and
- provide a deletion confirmation that states scope, date, method, and any
  retained exception.

Customer remains responsible for deleting source data in Customer-controlled
systems and backups.

## 11. Government and lawful requests

If Vendor receives a legally binding request for Customer Personal Data, it
will notify Customer where legally permitted, challenge or narrow an
unreasonable request where appropriate, and disclose only the minimum required.
Vendor will maintain a record of the request and its response unless law
prohibits it.

## 12. Liability and precedence

DPA liability, indemnification, regulatory fines, and caps must be coordinated
with the MSA and reviewed by counsel. The DPA does not enlarge a party's
liability unless it expressly says so. If privacy law requires a higher
standard, the parties will apply that standard to the affected processing.

## Schedule 1 — Processing description

| Field | Customer-specific value |
|---|---|
| Subject matter | CryptoScan discovery, assessment, reporting, support, and evidence |
| Duration | `[TERM AND POST-TERM DELETION WINDOW]` |
| Nature of processing | Collection, storage, organization, analysis, retrieval, export, deletion |
| Purpose | Security inventory, crypto-agility, risk assessment, remediation, support |
| Customer role | Controller / processor / other: `[CONFIRM]` |
| Vendor role | Processor / service provider: `[CONFIRM]` |
| Data subjects | Customer personnel, application owners, users, support contacts, persons represented in source artifacts if approved |
| Personal Data | Names, work email, user IDs, roles, audit IDs, IP/device metadata, tickets, support correspondence, incidental source/configuration data |
| Sensitive data | `[LIST OR PROHIBIT]` |
| Special-category data | Prohibited unless expressly approved and legally assessed |
| Customer sources | `[REPOSITORIES, CLOUD, CERTIFICATE, LOG, NETWORK, TICKETING SOURCES]` |
| Service region | `[REGION]` |
| Retention | See [data-retention-schedule.md](data-retention-schedule.md) and Order Form |

## Schedule 2 — Retention instructions

Complete the customer-specific retention schedule before production processing.
The default schedule is documented in
[data-retention-schedule.md](data-retention-schedule.md) and is not a promise
until included in the Order Form.

## Schedule 3 — Transfer details

| Transfer | Location | Data | Mechanism | Supplementary measures |
|---|---|---|---|---|
| Vendor support access | `[LOCATION]` | `[CATEGORIES]` | `[SCC/UK ADDENDUM/ADEQUACY/OTHER]` | `[MEASURES]` |
| Cloud hosting | `[LOCATION]` | `[CATEGORIES]` | `[MECHANISM]` | `[MEASURES]` |
| Subprocessor | `[LOCATION]` | `[CATEGORIES]` | `[MECHANISM]` | `[MEASURES]` |
| Backup/DR | `[LOCATION]` | `[CATEGORIES]` | `[MECHANISM]` | `[MEASURES]` |

## Schedule 4 — Technical measures

Attach or reference the approved Security Addendum, security architecture, data
flow, encryption architecture, access-control policy, incident-response
policy, backup architecture, and assurance evidence.

## Signatures

```text
[VENDOR LEGAL NAME]                 [CUSTOMER LEGAL NAME]

By: __________________________      By: __________________________
Name: ________________________      Name: ________________________
Title: _______________________      Title: _______________________
Date: ________________________      Date: ________________________
```
