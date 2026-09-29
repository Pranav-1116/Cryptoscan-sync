# Confidentiality, IP, liability, and indemnification provisions

**Template status:** counsel review required  
**Use:** clause library for the MSA, Order Form, NDA, DPA, and security addendum

This file explains the provisions that usually require the most negotiation. It
is not legal advice and does not replace jurisdiction-specific drafting.

## 1. Confidentiality provisions

### Core obligation

Each party receiving Confidential Information will:

1. use it only for the Agreement and authorized service purpose;
2. disclose it only to people and subprocessors with a need to know;
3. bind recipients to confidentiality obligations;
4. protect it with reasonable care and no less care than its own similar data;
5. notify the disclosing party of unauthorized access or disclosure; and
6. return or delete it when required, subject to legal hold and controlled
   backup exceptions.

### Confidentiality duration

Recommended starting position:

- ordinary Confidential Information: `[5]` years after disclosure or
  termination;
- trade secrets: as long as protected by law;
- Personal Data, credentials, security findings, and regulated records: under
  applicable law and the DPA/security terms;
- executed contracts and customer risk decisions: according to the retention
  schedule and legal hold.

### Required exclusions

Exclude information that is public without breach, previously known lawfully,
received from an unrestricted third party, independently developed, or released
in writing. The burden of proving an exclusion should be on the receiving
party.

### Compelled disclosure

Require advance notice where lawful, minimum necessary disclosure, protective
order cooperation, and a record of the request. Do not promise that the vendor
can prevent a regulator or law-enforcement disclosure.

## 2. Intellectual property ownership

### Vendor owns

Unless an Order Form states otherwise, Vendor owns:

- CryptoScan software and source code;
- detection rules, policies, algorithms, models, templates, and workflows;
- product architecture, documentation, and operational know-how;
- generic improvements and non-customer-specific enhancements;
- security, reliability, and performance improvements; and
- aggregated or de-identified statistics that cannot identify Customer or a
  person and are lawfully created.

### Customer owns

Customer owns:

- Customer Data;
- customer source code, configurations, business records, and reference
  inventories;
- customer trademarks and materials; and
- customer-specific risk decisions, approvals, and confidential reports,
  subject to the licence needed for Vendor to provide the Services.

### Licence to provide the service

Customer grants Vendor a limited, non-exclusive, worldwide licence during the
term to host, copy, transmit, analyze, secure, back up, and display Customer
Data only as needed to provide, support, secure, and improve the contracted
Services under the DPA.

Vendor may not sell Customer Data, use it for unrelated advertising, or train a
general-purpose model without explicit written permission and a lawful basis.

### Feedback and custom work

Customer feedback may be used to improve the Services without transferring
Customer Data. For custom connectors, reports, rules, or integrations, the
Order Form must state whether Customer receives ownership, a perpetual licence,
or a restricted use licence. Do not leave custom-work ownership implied.

### Open source and third party material

Vendor remains responsible for identifying applicable open-source and
third-party licence obligations. Customer receives no broader right than the
applicable licence. Customer remains responsible for content it supplies and
for third-party source authorization.

## 3. IP infringement indemnity

A typical Vendor indemnity covers a third-party claim that the Services, as
provided and used according to the Agreement, infringe a patent, copyright,
trade secret, or trademark.

Standard exclusions:

- Customer Data or Customer instructions;
- modifications not made by Vendor;
- combination with a non-Vendor product where the Services alone would not
  infringe;
- use after notice to stop or use outside the Agreement; and
- open-source or third-party components where the claim arises from their
  separate licence.

Vendor remedies may include obtaining continued rights, modifying or replacing
the affected component, or terminating the affected service and refunding
unused prepaid fees. Counsel must decide whether the indemnity is inside or
outside the general cap.

## 4. Customer indemnity

Customer should indemnify Vendor for third-party claims arising from:

- Customer Data or Customer-provided materials;
- unauthorized scans or access;
- Customer's violation of law, third-party rights, or the Acceptable-Use Terms;
- use of the Services outside written authorization;
- Customer instructions that Vendor reasonably identifies as unlawful or
  unsafe; and
- Customer's products, services, or decisions independent of the Services.

The indemnity should not make Customer responsible for Vendor's own
infringement, wilful misconduct, or failure to follow the DPA.

## 5. Privacy and security indemnity

Privacy/security indemnity may be:

- mutual under the general cap;
- a separate negotiated super-cap;
- limited to direct third-party claims; or
- addressed through regulatory cooperation and liability language rather than
  a broad indemnity.

Do not promise unlimited liability without finance, insurance, and counsel
approval. A regulated customer may require a higher cap for confidentiality,
Personal Data, security incidents, or IP infringement.

## 6. Limitation of liability structure

A clear structure should state:

1. **General cap:** fees paid or payable under the affected Order Form during
   the preceding `[12]` months.
2. **Super-cap:** a separately stated amount or multiplier for agreed categories
   such as confidentiality, privacy, security, or indemnification.
3. **Excluded liabilities:** liabilities that cannot be limited by law or that
   the parties expressly leave uncapped.
4. **Damage exclusion:** no indirect, consequential, special, punitive,
   exemplary, lost-profit, revenue, goodwill, or anticipated-savings damages,
   except where prohibited.
5. **Allocation:** each party's cap applies to all claims arising from the
   same facts, regardless of legal theory, unless counsel chooses otherwise.
6. **Service credits:** credits under the SLA count toward or sit outside the
   cap as expressly stated.

Possible negotiating example, subject to counsel:

```text
General liability: greater of fees paid/payable in the prior 12 months or
$[AMOUNT]. Privacy, confidentiality, security, and IP super-cap: [2x / 3x]
that amount. Uncapped only for liabilities that cannot lawfully be limited,
fraud, wilful misconduct, and Customer's undisputed payment obligations.
```

This is only drafting language. Jurisdiction and insurance may require a
different approach.

## 7. Warranties and remedy alignment

The warranty should be narrow enough to be measurable:

- service materially conforms to Documentation;
- Vendor provides Services professionally;
- Vendor has authority to grant its rights; and
- security and privacy commitments are performed as stated.

Disclaim:

- uninterrupted or error-free service;
- universal detection or complete accuracy;
- legal, regulatory, certification, or audit outcomes;
- third-party service availability;
- Customer's configuration, authorization, or remediation; and
- results outside the approved scope.

Remedies should be ordered: re-performance, workaround, replacement,
service credit, pro-rata refund, or termination for material uncured failure.

## 8. Negotiation positions

| Issue | Preferred position | Fallback |
|---|---|---|
| General cap | Prior 12 months' fees | Fixed amount tied to annual contract |
| Privacy/security | Super-cap with insurance alignment | Separate negotiated incident cap |
| IP indemnity | Vendor defence and replace/modify/refund remedy | Customer may procure continued use |
| Customer indemnity | Scope and authorization-based | Limited to third-party claims |
| Consequential damages | Mutual exclusion | Narrow carve-outs only |
| Feedback | Vendor may use non-confidential feedback | Customer approval for named case study |
| Custom work | Vendor ownership with customer licence | Customer ownership for separately paid work |
| Audit | Reports first, targeted audit second | Independent auditor under NDA |
| Data deletion | Export plus active deletion and backup expiry | Documented technical/legal exception |

## 9. Required approvals

Before including a clause in a customer quote, obtain:

- legal approval for wording and governing law;
- finance approval for cap, credit, discount, and insurance impact;
- security approval for security promises;
- privacy approval for data and transfer promises;
- operations approval for SLA and support promises; and
- executive approval for uncapped or above-policy commitments.
