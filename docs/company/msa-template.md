# Master Services Agreement template

**Template status:** counsel review required; not an executed agreement
**Version:** `MSA-DRAFT-1.0`
**Parties:** `[VENDOR LEGAL NAME]` and `[CUSTOMER LEGAL NAME]`
**Effective date:** `[EFFECTIVE DATE]`

This template describes the commercial structure for CryptoScan. Counsel must
adapt it to the contracting entities, jurisdiction, procurement requirements,
regulated-outsourcing rules, insurance, tax, and customer order form. The
bracketed text is not a commitment.

## 1. Parties and purpose

This Master Services Agreement governs the parties' purchase and use of the
services identified in one or more signed Order Forms. Each Order Form states
the service, deployment model, term, fees, scope, support tier, service region,
data boundary, and customer-specific obligations.

`[VENDOR LEGAL NAME]` is the contracting service provider. `[CUSTOMER LEGAL
NAME]` is the customer. Affiliates may use the service only when named in an
Order Form and only under the same security, privacy, and payment obligations.

## 2. Definitions

- **Authorized User** means an individual authorized by Customer to use the
  service and bound by Customer's access policies.
- **Customer Data** means data submitted to or generated from Customer's
  authorized sources, excluding Vendor Materials and aggregated service
  telemetry that cannot identify Customer or a person.
- **Documentation** means the current product and operating documentation.
- **Order Form** means a signed document defining a specific purchase.
- **Personal Data** means information protected as personal data under
  applicable privacy law.
- **Services** means the CryptoScan software, support, professional services,
  and managed services described in an Order Form.
- **Vendor Materials** means the platform, software, models, rules, templates,
  documentation, improvements, tools, and know-how owned or licensed by Vendor.
- **Security Incident** means a confirmed unauthorized access to or disclosure
  of Customer Data in Vendor's control, excluding unsuccessful attempts and
  events caused solely by Customer.

## 3. Orders and scope

Each Order Form must specify:

1. customer entity and approved affiliates;
2. deployment model and service region;
3. source systems and permitted scan scope;
4. data categories and prohibited data;
5. users, roles, integrations, volume, frequency, and retention;
6. implementation milestones and acceptance criteria;
7. fees, taxes, currency, payment terms, and renewal;
8. support tier and service levels;
9. subprocessors and transfer requirements;
10. exit, export, deletion, and transition requirements; and
11. any approved deviations from this Agreement.

Vendor is not responsible for systems, regions, sources, integrations, or
workloads not listed in the applicable Order Form.

## 4. Access and customer responsibilities

Customer will:

- provide accurate scope, data, configurations, and instructions;
- obtain authorization before Vendor scans any repository, endpoint, cloud
  account, network, or artifact;
- create named, least-privilege accounts and protect credentials;
- configure Customer-side identity, network, firewall, proxy, backup, and HSM
  controls;
- avoid uploading private keys, plaintext credentials, payment secrets, or
  prohibited data unless expressly authorized in writing;
- validate findings and own remediation, exceptions, and regulatory decisions;
- maintain a current incident, security, privacy, and procurement contact;
- comply with the Acceptable-Use Terms; and
- remove or rotate access when personnel, scope, or engagement changes.

Customer remains responsible for its source systems, network, cloud accounts,
identity provider, data classification, legal basis, and decisions made from
Service outputs.

## 5. Vendor responsibilities

Vendor will:

- provide the Services materially as described in the Order Form;
- maintain reasonable administrative, technical, and physical safeguards;
- restrict access to Customer Data to authorized personnel and subprocessors;
- maintain security, vulnerability, incident, change, and continuity processes;
- provide support according to the applicable SLA;
- notify Customer of a qualifying Security Incident under the DPA and Security
  Addendum;
- maintain the evidence, release, and change records applicable to the
  contracted deployment; and
- provide export, deletion, and transition support at termination as agreed.

Vendor does not warrant that scanning discovers every asset or issue,
interpretation is complete, or a customer meets a legal, regulatory, or
certification requirement solely because it uses the Services.

## 6. Fees and payment

Fees are stated in the Order Form. Unless otherwise stated:

- invoices are payable within `[30]` days;
- undisputed late amounts may accrue interest at the lesser of `[1.5%]` per
  month or the maximum lawful rate;
- Customer must raise invoice disputes within `[15]` days with detail;
- taxes, withholding, and approved expenses are Customer's responsibility;
- subscription fees are not reduced because Customer elects not to use an
  included feature; and
- changes in scope require a signed Order Form or change order.

Price changes at renewal, usage bands, pilot credits, and termination fees
must be stated in the Order Form.

## 7. Term and renewal

This Agreement begins on the Effective Date and continues until terminated.
Each Order Form has its own initial term and renewal terms. Automatic renewal,
notice periods, and any price adjustment are effective only if stated in the
Order Form and permitted by applicable law.

## 8. Confidentiality and data protection

Each party will protect the other party's Confidential Information using at
least reasonable care and will use it only for the Agreement. The parties will
execute the NDA or incorporate the confidentiality provisions in
[confidentiality-ip-liability.md](confidentiality-ip-liability.md).

The DPA, Data-Processing Terms, Security Addendum, and applicable privacy
schedule govern Personal Data and security processing. If there is a conflict,
the parties' negotiated data-protection terms control for Personal Data.

## 9. Intellectual property

Vendor owns Vendor Materials, the Services, software, rules, templates,
non-customer-specific improvements, and aggregated or de-identified analytics
that cannot identify Customer or a person. Customer owns Customer Data and
Customer-provided materials.

Customer grants Vendor a limited, non-exclusive right to process Customer Data
only to provide, secure, support, and improve the Services as allowed by the
DPA. Vendor will not sell Customer Data or use it to train a general-purpose
model without Customer's express written permission.

Customer receives a non-exclusive, non-transferable right to use the Services
and Documentation during the applicable Order Form term. Any customer-specific
work product ownership or licence must be stated in the Order Form.

## 10. Warranties and disclaimers

Each party warrants that it has authority to enter the Agreement. Vendor
warrants that it will provide the Services in a professional manner and that
software will materially conform to Documentation during the applicable term.
Customer's exclusive remedy for a material warranty failure is re-performance
or, if re-performance is commercially unreasonable, a pro-rata refund for the
affected period.

Except for express warranties, the Services are provided `AS IS` to the
maximum extent permitted by law. Vendor does not warrant uninterrupted,
error-free, complete, or universally accurate detection; third-party systems;
Customer configurations; or regulatory, certification, or legal outcomes.

## 11. Indemnification

The parties' indemnification obligations are described in
[confidentiality-ip-liability.md](confidentiality-ip-liability.md). An Order
Form may add customer-specific IP, privacy, security, or regulatory
indemnities, subject to the liability cap and exclusions approved by counsel.

The indemnified party must promptly notify the indemnifying party, provide
reasonable control of the defence, and cooperate. No settlement may admit
liability or impose non-monetary obligations on the indemnified party without
its consent.

## 12. Limitation of liability

Subject to mandatory law, each party's aggregate liability arising from an
Order Form is capped at the fees paid or payable under that Order Form during
the `[12]` months before the event giving rise to liability.

A separately negotiated super-cap may apply to confidentiality, data
protection, security incidents, IP infringement, or indemnification. The cap,
amount, trigger, and exclusions must be explicit. Neither party is liable for
indirect, incidental, special, consequential, exemplary, or punitive damages,
or lost profits, revenue, goodwill, or anticipated savings, except to the
extent such exclusion is prohibited by law.

Counsel must confirm treatment of fraud, wilful misconduct, death or personal
injury, unpaid fees, IP infringement, privacy law penalties, and other
non-limitable liabilities in the governing jurisdiction.

## 13. Suspension

Vendor may suspend access narrowly and temporarily when reasonably necessary
to prevent security harm, unlawful use, material breach, or non-payment of
undisputed fees after notice. Vendor will use reasonable efforts to limit the
impact, restore access when the issue is resolved, preserve evidence, and
avoid suspending a regulated customer's critical operation without an
appropriate escalation unless immediate action is required to prevent harm.

## 14. Termination and exit

Termination rights, cure periods, transition support, export format, deletion,
backup treatment, and post-termination access are described in
[termination-and-data-deletion.md](termination-and-data-deletion.md) and the
Order Form.

Termination does not remove accrued payment obligations, confidentiality,
security, privacy, IP, audit, dispute, or other provisions intended to survive.

## 15. Audit and assurance

Vendor will provide the assurance materials reasonably available for the
contracted service, subject to confidentiality, security, and availability
restrictions. Customer audits must be risk-based, reasonable, non-disruptive,
limited to the Services, and not expose another customer's data.

A request for a SOC 2 report, ISO certificate, penetration-test report, or
regulatory evidence must be answered with the actual availability and evidence
tier. Vendor will not represent a draft or gap analysis as an external
attestation.

## 16. Publicity

Neither party may use the other's name, logo, customer identity, or pilot
results publicly without prior written approval. A reference account,
case study, or accuracy claim requires a separate written approval.

## 17. General terms

The parties should complete clauses covering independent contractors,
assignment, subcontracting, force majeure, notices, governing law, dispute
resolution, export controls, anti-bribery, insurance, order of precedence,
severability, waiver, entire agreement, amendments, and counterparts.

Recommended order of precedence for a conflict:

1. negotiated DPA or privacy schedule for Personal Data;
2. negotiated Security Addendum for security controls;
3. Order Form for scope, price, and customer-specific terms;
4. this MSA;
5. Documentation.

## 18. Execution

```text
[VENDOR LEGAL NAME]                 [CUSTOMER LEGAL NAME]

By: __________________________      By: __________________________
Name: ________________________      Name: ________________________
Title: _______________________      Title: _______________________
Date: ________________________      Date: ________________________
```

**Counsel checklist:** confirm entity names, governing law, regulatory
outsourcing language, liability caps, indemnities, insurance, data transfers,
subprocessors, service region, retention, deletion, and signature authority.
