# Questionnaire answer-bank operating model

**Status:** controlled answer-bank design
**Purpose:** answer SIG Lite, SIG, CAIQ, VSAQ, CISO, cloud-security, privacy,
and third-party-risk questionnaires consistently and honestly

A questionnaire answer bank is a controlled knowledge base, not a collection
of optimistic copy-and-paste answers. Every answer must have an owner, evidence
tier, source, review date, scope, and expiry.

## 1. Question types covered

The answer bank should support:

- Shared Assessments SIG Lite;
- Shared Assessments SIG;
- CSA CAIQ;
- vendor security assessment questionnaires (VSAQ);
- custom CISO questionnaires;
- cloud-security questionnaires;
- privacy and data-protection questionnaires;
- banking and regulated-outsourcing assessments;
- business-continuity and disaster-recovery questionnaires;
- subprocessor and supplier assessments; and
- customer-specific risk and procurement questionnaires.

The CSV starter file contains canonical question families and initial answer
positions. It is a flat transport file, not by itself the authoritative
high-volume submission database. Import it into a controlled database and
record the actual review and approval event before reusing an answer externally.

## 2. CSV transport and normalized schema

`questionnaire-answer-bank.csv` must have exactly 17 columns on every data row.
CSV quoting is mandatory when a question or answer contains a comma. Its flat
columns map to the normalized JSON schema as follows:

| CSV column | Normalized value |
|---|---|
| `frameworks` | split on `\|` into a non-empty array |
| `source_documents` | split on `;` into repository paths or controlled artifact IDs |
| `customer_variables` | split on `;` into required customer-supplied values |
| `prohibited_claims` | split on `;` into claims the answer must not make |
| `attachments` | split on `;` into release-approved artifact references |
| `review_cycle_days` | positive integer retained as the review cadence |
| `reviewed_at` | actual review date from the approval record; not present in the starter CSV |
| `expires_at` | actual expiry date from the approval record; null until assigned |

The starter CSV intentionally does not invent `reviewed_at` or `expires_at`.
An importer must set those normalized fields to `null` until a real reviewer
records them; it must never derive them from the file timestamp, commit date,
or the existence of a template. The JSON schema defines the normalized record,
including this explicit review-metadata boundary.

## 3. Required answer fields

| Field | Purpose |
|---|---|
| `answer_id` | Stable identifier that survives questionnaire renumbering |
| `question_family` | Security, privacy, legal, cloud, resilience, etc. |
| `frameworks` | SIG Lite, SIG, CAIQ, VSAQ, CISO, privacy, cloud, or custom |
| `canonical_question` | Normalized question text |
| `answer_status` | APPROVED, PARTIAL, NOT_AVAILABLE, CUSTOMER_SPECIFIC, NOT_APPLICABLE, EXTERNAL_REQUIRED |
| `answer_text` | Reusable answer with scope and limitation |
| `evidence_tier` | Repository control, operational record, customer attestation, external certification |
| `source_documents` | Exact repository or controlled evidence source |
| `owner` | Person/team accountable for correctness |
| `reviewer` | Independent technical, privacy, legal, or assurance reviewer |
| `reviewed_at` | Actual review date from the approval record |
| `review_cycle_days` | Positive interval after which reuse requires another review |
| `expires_at` | Date after which the answer cannot be reused without review |
| `jurisdiction` | Global, country, customer-specific, or not applicable |
| `deployment_scope` | Customer-managed, vendor-managed, SaaS, pilot, production |
| `customer_variables` | Information that must be filled from the Order Form |
| `prohibited_claims` | Claims the answer must not make |
| `attachments` | Evidence artifacts approved for release |
| `notes` | Internal handling and follow-up instructions |

## 4. Answer status rules

### APPROVED

The answer has an owner, reviewer, current evidence, scope, and expiry. It may
be reused when the prospect's question matches the scope.

### PARTIAL

The answer describes an implemented control but has a limitation, missing
operational record, or customer-specific dependency. It must state the gap.

### NOT_AVAILABLE

The requested artifact or commitment does not currently exist. The answer must
say so and may offer a planned action without promising a date unless approved.

### CUSTOMER_SPECIFIC

The answer depends on the customer's deployment, region, identity provider,
subprocessors, data, contract, or risk decision. Route it to the customer
solution and legal/privacy owners.

### NOT_APPLICABLE

The question does not apply. Include the reason and reviewer; do not use N/A
to avoid a difficult question.

### EXTERNAL_REQUIRED

The answer requires an independent report, certificate, customer attestation,
provider record, or regulator decision that the repository cannot create.

## 5. Answer-writing standard

Every answer should follow this form:

1. **Direct answer:** Yes, No, Partial, Not applicable, or Customer-specific.
2. **Scope:** service, release, deployment, and region.
3. **Control explanation:** what the product or company does.
4. **Evidence:** document or controlled artifact.
5. **Limitation:** what the answer does not prove.
6. **Next action:** owner and required follow-up.

Example:

> **Partial — repository control.** CryptoScan implements role-based access,
> API authorization, audit logging, and production configuration guards. The
> exact SSO provider, privileged-access process, and access-review record are
> customer-specific and must be confirmed for the proposed deployment. This
> answer does not claim SOC 2, ISO 27001, or customer production approval.
> Evidence: Security Addendum, access-control policy, and the applicable
> readiness evidence report. Owner: Security. Review before submission.

## 6. Framework mapping

The bank should retain the prospect's original question ID and map it to a
canonical answer:

| Prospect framework | Mapping fields |
|---|---|
| SIG Lite/SIG | section, question ID, canonical `answer_id`, evidence, exceptions |
| CAIQ | CCM domain/control, question ID, answer, implementation evidence |
| VSAQ | vendor questionnaire ID, response, attachment, legal review |
| CISO custom | customer question ID, domain, answer, owner, commitment flag |
| Cloud questionnaire | cloud service, region, account, shared-responsibility answer |
| Privacy questionnaire | controller/processor role, data, transfer, retention, DPA clause |
| Third-party risk | risk domain, control, evidence tier, residual risk, expiry |

Never overwrite the canonical answer with customer-specific wording. Store the
submitted response as a versioned questionnaire instance.

## 7. Database tables

A production answer-bank service should use at least:

### `question_families`

`family_id`, `name`, `description`, `owner`, `review_cycle`.

### `canonical_questions`

`answer_id`, `family_id`, `canonical_question`, `framework_tags`, `default_status`,
`created_at`, `retired_at`.

### `answer_versions`

`answer_id`, `version`, `answer_text`, `evidence_tier`, `scope`, `jurisdiction`,
`deployment_scope`, `owner`, `reviewer`, `reviewed_at`, `expires_at`, `status`.

### `evidence_links`

`answer_id`, `version`, `artifact_path_or_id`, `artifact_sha256`,
`confidentiality`, `release_scope`, `approved_for_external_use`, `expires_at`.

### `questionnaire_instances`

`instance_id`, `customer`, `framework`, `received_at`, `due_at`, `jurisdiction`,
`deployment`, `owner`, `review_status`, `submitted_at`.

### `questionnaire_questions`

`instance_id`, `customer_question_id`, `original_text`, `mapped_answer_id`,
`answer_version`, `answer_text_override`, `status`, `reviewer`, `exception`.

### `approvals`

`instance_id`, `domain`, `reviewer`, `decision`, `comments`, `approved_at`.

### `commitments`

`instance_id`, `commitment_text`, `owner`, `due_date`, `contract_reference`,
`approved_by`, `status`.

### `change_log`

`actor`, `timestamp`, `object`, `old_value_hash`, `new_value_hash`, `reason`.

## 8. Workflow for a 400-question assessment

### Intake

- save the original file unchanged;
- identify framework, customer, entity, jurisdiction, service, and due date;
- record whether the prospect expects attachments, signatures, or portal entry;
- assign one answer-bank owner and one deadline coordinator.

### Triage

Classify each question as technical, privacy, legal, financial, resilience,
subprocessor, product, or customer-specific. Identify duplicates and near-
duplicates but retain the original question IDs.

### Mapping

Map each question to an `answer_id`, attach the current answer version, and
record whether the prospect's wording exceeds the canonical scope.

### Review

Route questions by risk:

- security architecture/control: Security;
- Personal Data, DPA, transfers: Privacy;
- legal commitments, liability, IP, indemnity: Legal;
- uptime, support, RPO/RTO: Operations;
- certifications and independent reports: Assurance/Compliance;
- roadmap or product availability: Product;
- customer topology and permissions: Solutions Engineering.

### Evidence assembly

Use the assurance package matrix. Supply the minimum evidence needed and redact
private keys, credentials, other-customer data, exploit detail, and secrets.

### Commitment review

Highlight words such as `will`, `guarantee`, `always`, `all`, `zero`, `certified`,
`compliant`, `24x7`, `within`, and `unlimited`. These may create legal or
commercial commitments and require Legal/Executive approval.

### Submission and archive

Export the response with:

- questionnaire version;
- answer-bank version;
- evidence index;
- exceptions and unanswered items;
- approvals;
- submission date;
- recipient and secure transfer method; and
- expiry/review date.

Archive the exact submitted response. Do not edit the answer bank to match a
submitted answer after the fact; create a new version with reason and approval.

## 9. Red flags requiring escalation

Escalate instead of guessing when a question asks whether:

- SOC 2, ISO, PCI, FIPS, or another certification exists;
- a regulator approved the product;
- the Vendor guarantees legal compliance;
- the Vendor accepts unlimited liability;
- the Vendor guarantees 24x7 response or a specific RPO/RTO;
- data never leaves a country without a verified deployment;
- no subprocessors exist;
- all vulnerabilities are fixed within a time window;
- the product has 100% accuracy or complete coverage;
- a customer has approved the product;
- the Vendor owns or controls Customer's HSM/KMS;
- deletion is immediate from all backups; or
- the answer requires a customer-side fact.

## 10. Review cadence

- before every external questionnaire submission;
- monthly for high-volume answer changes;
- quarterly for security, privacy, subprocessors, and availability answers;
- on every material release, subprocessor, region, policy, or incident change;
- at least annually for all retained answers; and
- immediately when an answer becomes false, expired, or out of scope.

## 11. Quality metrics

Track:

- questions answered from approved canonical records;
- questions requiring new work;
- expired answers used or blocked;
- evidence attachment rate;
- legal/privacy/security rework rate;
- average completion time;
- contradictory answers across customers;
- customer-specific commitments created;
- unanswered or not-available items; and
- answer changes caused by product or policy changes.

The objective is not a 100% completion score. The objective is accurate,
repeatable, reviewable, and timely answers.
