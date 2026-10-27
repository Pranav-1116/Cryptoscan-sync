# Real-system pilot and customer contact playbook

**Status:** operating runbook for a supervised pre-production evaluation
**Related internal material:** [`docs/pilot-duration-and-phases.md`](../pilot-duration-and-phases.md), [`docs/pilot-standard.md`](../pilot-standard.md), and [`docs/company/customer-responsibility-matrix.md`](../company/customer-responsibility-matrix.md).

## 1. The pilot promise

The honest promise is:

> We will help your named security and platform owners evaluate a bounded,
> read-only CryptoScan workflow against the systems and artifacts you authorize.
> We will show what was observed, what was not evaluated, and what evidence
> supports each material result. At the end you will have a validation record,
> one safe re-scan if agreed, an export, and a documented exit.

Do not promise:

- full enterprise coverage;
- zero false positives or zero false negatives;
- regulatory approval, certification, or audit pass;
- detection of every cryptographic use;
- live network visibility from a static source or binary scan;
- safe operation against an arbitrary production target; or
- a customer reference unless the customer gives written permission.

## 2. Which customer-side people to contact

Start with a **named sponsor plus a technical source owner**. Do not rely on an
innovation department alone.

| Customer person/role | Why they matter | What to ask them to own |
|---|---|---|
| CISO / head of cybersecurity | risk owner and executive sponsor | business decision, risk acceptance, success criteria, stop escalation |
| Head of application/product security | primary technical buyer for repositories and application crypto | repositories, CI evidence, finding validation, remediation owner |
| Cloud/platform/infrastructure owner | source access and deployment owner | read-only accounts, network route, workspace, rate limits |
| PKI/certificate/IAM/HSM owner | validates certificate, key-use, trust-store, and identity findings | safe export/metadata access; no private-key collection |
| DevSecOps or engineering manager | coordinates repositories, build pipelines, and engineers | sample selection, code owners, remediation/re-scan |
| SOC/incident-response lead | owns alerting and operational safety | watch window, alert expectations, escalation if scan misbehaves |
| Data protection/privacy/legal representative | decides classification and contractual basis | DPA/NDA, data minimization, retention/deletion, cross-border review |
| Enterprise architect / technology-risk lead | maps evidence to architecture and risk decisions | scope and risk language, executive report review |
| Procurement/vendor-risk owner | makes the engagement legitimate and repeatable | vendor onboarding, security questionnaire, purchase order |
| Change-management/release owner | prevents an unapproved production change | change ticket, maintenance window, rollback/stop authority |
| Business/economic buyer: CIO/CTO/head of risk | decides whether the result is worth funding | budget, paid expansion, target outcome |

For a small company, one person may hold several roles. Record each role
separately even when the same person fills it.

## 3. How to obtain a legitimate introduction

### Preferred routes

1. Warm introduction from a trusted customer, security consultant, MSSP, cloud
   partner, accelerator mentor, university/incubator, or professional association.
2. Official vendor-registration, innovation, accelerator, or procurement channel.
3. Role-based company contact form followed by a concise, permission-based request
   for the correct owner.
4. A public programme inbox, where the published programme explicitly accepts
   startup/customer enquiries.

Do not scrape private addresses, buy contact lists, impersonate a regulator, or
scan any organization to create a sales lead. A public regulator/agency inbox is
for the stated public purpose; it is not a shortcut around customer procurement.

### First message structure

- one sentence about the customer pain, not a product feature dump;
- one sentence describing the bounded supervised pilot;
- one sentence stating no private keys, no unapproved network scan, and no claim of
  regulatory approval;
- a request for a 20–30 minute discovery call; and
- an easy opt-out/no-response path.

Example:

> Subject: Bounded cryptographic inventory evaluation for [team]
>
> Hello [role/team],
>
> We are speaking with security and platform teams that need to understand where
> cryptographic libraries, certificates, algorithms, and dependencies are used
> before a migration or risk review. CryptoScan can be evaluated in a six-week,
> read-only pilot against a small customer-approved scope. The pilot records
> observed, unknown, unsupported, and truncated states, does not request private
> keys, and does not imply regulator approval. Would [team] be open to a 25-minute
> discovery call to see whether this is a real problem for one bounded system?
>
> If this belongs with another owner, please point us to the appropriate security,
> platform, or PKI contact. If not relevant, no reply is needed and we will not
> follow up repeatedly.

## 4. Discovery before access

The first discovery call is not a scan. Ask:

1. What decision must the team make in the next 90 days?
2. Which systems, repositories, certificates, binaries, or dependencies are part
   of that decision?
3. What evidence does the CISO, auditor, customer, board, or migration programme
   currently lack?
4. What is the smallest representative sample that can prove whether the workflow
   helps?
5. Who owns the source and who can authorize read-only access?
6. What data classification applies? Are there personal data, payment data,
   secrets, source-code restrictions, export controls, or residency constraints?
7. Where may the product and artifacts run? Is customer-controlled deployment
   required?
8. What are the allowed dates, rate limits, maintenance windows, and stop signals?
9. What would make the sponsor say "continue," "change scope," or "stop"?
10. If the pilot succeeds, what budget/procurement step follows?

If the sponsor cannot answer at least the source owner, decision, data boundary,
and success condition, keep the interaction at discovery and do not accept real
inputs.

## 5. Authorization and preparation gates

A real-system pilot begins only after these gates are complete. Verbal permission,
a chat message, or "our engineer said it is fine" is not enough.

### Gate A — signed pilot charter / authorization

The charter should name:

- customer legal entity and vendor legal entity;
- sponsor, source owner, technical operator, privacy/legal owner, and stop
  authority;
- exact systems, repository paths, artifact IDs, account IDs, or IP/CIDR ranges;
- included and excluded sources;
- read-only operations and any explicitly approved active operation;
- approved dates and time zone;
- max file size, file count, recursion/depth, request rate, and concurrency;
- permitted network egress and connectors;
- data classes and prohibited data (especially private keys and secrets);
- deployment/storage location and support-access path;
- retention, export, deletion, and backup treatment;
- success metrics, review cadence, and stop conditions;
- incident/escalation contacts; and
- statement that the pilot does not confer certification, approval, or complete
  coverage.

Legal templates and proposed language are not executed agreements. The customer
must complete its NDA/DPA/vendor terms/change ticket/procurement process as
required.

### Gate B — identity and access

- named accounts only; no shared credential;
- least privilege and read-only by default;
- MFA for human users;
- short-lived or revocable API credentials;
- separate pilot tenant/project;
- credential expiry date in the charter;
- no private-key export or secret-value collection;
- customer-approved secret redaction and log policy; and
- a recorded access-revocation test.

### Gate C — technical safety

- customer has a clean test/staging sample or selects a low-risk production
  read-only sample;
- source/network owner confirms the target and route;
- change ticket and maintenance window exist when required;
- resource/rate limits are configured;
- backup or rollback exists for anything that could change state;
- emergency stop command and named person are tested; and
- scan container/workspace is isolated and has only the required egress.

### Gate D — baseline

Before scanning, record:

- source inventory supplied by the customer;
- expected count/sample label;
- existing known findings or a small hand-reviewed validation set;
- start time and source commit/version/digest;
- ruleset/fingerprint version if used;
- customer success metric baseline; and
- known out-of-scope systems.

## 6. Safe pilot scope options

Choose one narrow option first:

### Option 1: repository/application sample

- one service or two related repositories;
- one branch/commit selected by the owner;
- read-only clone or supplied archive;
- no deployment to customer runtime;
- application owner validates findings.

### Option 2: certificate/crypto-inventory sample

- one approved account, trust store, certificate export, or metadata API;
- no private keys or secret values;
- explicit certificate/algorithm fields allowed;
- PKI/IAM owner validates ownership and lifecycle state.

### Option 3: binary/firmware sample

- 5–20 benign customer-approved files or one bounded build artifact;
- no execution;
- size/file/depth caps;
- checksum and source label recorded;
- static results labelled as static; no live-network inference.

### Option 4: customer-controlled staging scan

- one staging host/repository/container registry path;
- read-only credentials;
- narrow scheduled window and concurrency;
- SOC/platform owner watching the window;
- stop immediately on resource, availability, or boundary anomaly.

Do not combine repository, production network, cloud accounts, OT, and firmware
scanning in the first pilot. A broad catalogue makes a weak result look large and
makes it impossible to know what caused an issue.

## 7. Six-week execution plan

This follows the existing standard pilot documents; a customer-specific charter
may shorten a phase but should not remove the gates.

### Week 0 — prepare and authorize

**Customer:** completes charter, classification, access, source selection, change
management, and success baseline.

**CryptoScan:** confirms architecture, configures tenant, verifies limits, prepares
sanitized fixtures, and runs a no-data connectivity check.

**Exit gate:** both parties sign readiness checklist. If not ready, no scan.

### Week 1 — baseline and first bounded run

- run one agreed source/sample;
- capture counts, parser states, job timing, and errors;
- show the customer what was and was not scanned;
- do not tune rules to make the dashboard look better;
- customer selects a validation sample.

**Exit gate:** customer confirms source and scope match the charter.

### Week 2 — evidence review

- walk through findings one by one;
- link each material finding to evidence and source;
- record true positive, false positive, duplicate, unknown, not evaluated, or
  customer disagreement;
- identify owner and remediation decision;
- add no new scope without a written change.

### Week 3 — quality and workflow iteration

- correct configuration or explain a product limitation;
- rerun only the approved scope/sample;
- measure coverage of the agreed sample, not the customer's whole estate;
- review export/report, RBAC, audit trail, and data handling;
- log open defects and proposed workarounds.

### Week 4 — safe remediation and re-scan

- customer chooses one low-risk remediation or annotation;
- customer approves the change and rollback path;
- re-scan the same source/version where possible;
- show changed evidence and any remaining unknowns;
- never alter a customer system just to produce a success screenshot.

### Week 5 — decision and value review

- compare results with baseline;
- calculate agreed measures;
- security owner reviews evidence and limitations;
- economic buyer reviews the operational value and expansion boundary;
- decide continue, extend with a new charter, or exit.

### Week 6 — final report and exit

- deliver scope, evidence, findings, validation, limitations, and re-scan result;
- deliver approved export and customer-owned hashes/digests where appropriate;
- revoke access and collect customer confirmation;
- delete/retain artifacts per charter and record the result;
- close tickets and document unresolved risks;
- request a testimonial/reference only after explicit written permission.

## 8. Success criteria

Agree numbers before scanning. Examples:

| Measure | Example pilot definition |
|---|---|
| scope fidelity | 100% of observed inputs map to an authorized source; excluded source count is visible |
| evidence usability | security owner can trace every priority finding to source/evidence/status |
| validation quality | customer-reviewed sample records true positive/false positive/unknown outcomes |
| workflow reduction | time to assemble the agreed inventory is lower than the customer's baseline process |
| remediation loop | one customer-approved change or annotation produces a documented re-scan result |
| safety | no unauthorized source, secret/private-key collection, availability incident, or unexplained egress |
| operations | jobs complete or fail visibly; no orphaned job remains without owner/action |
| exit | export, access revocation, and deletion/retention record are complete |

Do not use "100% coverage" as a pilot metric. Use a declared denominator and
coverage statement, for example: "18 of 20 supplied sample artifacts parsed; 2
were unsupported and 1 parser run was truncated."

## 9. Stop conditions

Stop the scan and notify the customer sponsor immediately if any of these occurs:

- target is outside the written scope;
- credential has more privilege than approved;
- private-key or secret material is collected or appears in logs;
- scan rate, CPU, memory, storage, or network traffic exceeds the charter;
- service availability, latency, integrity, or customer safety is at risk;
- parser/connector behaves unexpectedly on a new format;
- data is routed to an unapproved region, storage, subprocess, or support channel;
- tenant isolation, authentication, authorization, or audit behaviour is uncertain;
- customer cannot identify a stop authority; or
- either party believes the evidence is being used to make an unsupported
  regulatory, safety, or security claim.

After a stop: preserve only the minimum diagnostic metadata authorized by the
charter, revoke/rotate credentials if needed, notify the named contacts, document
facts and timeline, and obtain written approval before resuming.

## 10. Evidence handling

### Collect

- source ID/commit/digest and timestamp;
- scanner/version/ruleset/fingerprint digest;
- finding/evidence ID and source location;
- parser status, refusal, truncation, depth, and error metadata;
- actor, tenant, job, and artifact IDs;
- customer validation disposition; and
- deletion/export status.

### Do not collect by default

- private keys;
- plaintext passwords, tokens, connection strings, or secret values;
- full production database contents;
- unrelated customer source code;
- personal data not needed for the pilot; or
- live network data when the charter only authorizes static analysis.

### Handle

- minimize, redact, hash, and label customer data;
- encrypt transport and storage as approved;
- restrict support access and log it;
- use a customer-controlled export for long-term retention when required;
- do not paste findings into public issue trackers or chat; and
- delete temporary workspaces and artifacts on the agreed date.

## 11. How to impress without unsafe demonstrations

The best demonstration is a customer-owned sample and a clear evidence chain:

1. show the exact input list and excluded list;
2. show a result with confirmed, unknown, unsupported, refused, and truncated
   states—not a perfect green dashboard;
3. open one finding and trace it to the source, parser evidence, algorithm/library
   detail, confidence/provenance, and owner;
4. show that a binary-derived NBOM/static indicator is not labelled as live network
   observation;
5. show one safe customer-approved remediation or annotation and a re-scan;
6. show report/export, audit trail, limits, and deletion/revocation record; and
7. answer "what did you not test?" before the customer asks.

Do not run a destructive exploit, port sweep, production load test, secret search,
credential spray, live malware execution, or unapproved network scan to make the
demo memorable. Do not use another customer's data or imply a prospect's whole
estate is represented by a handpicked sample.

## 12. Pilot-to-paid decision

At the final review, ask the sponsor and economic buyer:

- Which decision did the pilot change?
- Which evidence will be reused in the security/risk process?
- Which source should be added next and why?
- What internal owner will operate the workflow?
- What deployment/data-residency terms must change?
- What is the budget and procurement step?
- Would they pay for the same bounded outcome next quarter?

A paid conversion should contain a new scope and service description. It should
not quietly convert a pilot charter into unrestricted production use. If the
customer wants regulated production, require a separate readiness review,
controls/evidence plan, contractual terms, and any required independent assurance.
