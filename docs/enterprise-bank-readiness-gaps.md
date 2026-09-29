# Enterprise and International-Bank Readiness Gap Register

**Reviewed:** 2026-09-29 UTC  
**Audience:** product leadership, security, engineering, operations, legal,
procurement, and a prospective bank's third-party-risk team  
**Status:** planning and evidence register; **not** a certification, legal
opinion, or production approval

## Executive conclusion

CryptoScan is moving toward an enterprise-grade product, but enterprise-grade
and bank-approved are different milestones.

The repository contains substantial implementation evidence: authentication and
RBAC, SSO adapters, audit trails, signed evidence, CBOM/SBOM-related tooling,
PostgreSQL migrations, tenant-scope defenses, cloud and network scanners,
telecom/PQC modules, encrypted-backup paths, a PostgreSQL DR harness, and a
large automated test suite. Those are important foundations.

They do **not** yet answer the questions an international bank must answer to
its board, regulator, internal audit, cyber-insurance provider, and
third-party-risk committee:

- Who independently tested the product and the operating environment?
- Which legal entity, region, subprocessors, and data flows are in scope?
- Which certified cryptographic modules protect keys and evidence?
- Has failover been demonstrated on the topology the bank will actually use?
- Can the vendor prove patch, vulnerability, incident, access-review, and
  support performance over time?
- Has the product been run against real bank code, mainframe artifacts,
  certificates, HSM inventories, logs, and operational workflows?
- What happens if the bank terminates the service, loses an HSM, loses a region,
  or needs its data deleted and independently verified?

The current honest decision remains **supervised pilot or pre-production**, not
unattended production approval. The generated readiness gate is deliberately
fail-closed. The control register also records that repository controls are not
SOC 2, ISO 27001, FIPS 140-3, PCI, customer-attestation, or regulator evidence.

This document turns that conclusion into an actionable closure plan.

## 1. The four maturity levels that must not be conflated

A bank will often use the word "enterprise" to describe several separate
things. CryptoScan should report them separately:

| Level | Meaning | Minimum proof |
|---|---|---|
| **Enterprise-capable** | The product has the architecture and controls needed for serious deployments. | Code, tests, threat model, runbooks, secure defaults, reproducible builds. |
| **Bank-deployable** | A bank can install and operate it in its approved environment. | Customer topology, SSO/HSM/SIEM/ITSM integration, hardening, capacity and recovery evidence. |
| **Bank-approved** | The bank's procurement, security, legal, privacy, and operational-risk teams accept it. | Independent assessments, signed questionnaire answers, contracts, risk acceptances, and customer-specific evidence. |
| **Regulated-production ready** | The deployment satisfies the applicable legal entity, regulator, scheme, and resilience obligations. | Mapped regulatory controls, tested operational resilience, audit trail, attestations, and retained evidence. |

Passing unit tests can help establish the first level. It cannot establish the
last three by itself.

## 2. Current repository position

The following repository documents are the source of truth and should be read
together rather than quoted selectively:

- [`PRODUCTION-READINESS.md`](../PRODUCTION-READINESS.md) — current deployment
  decision and evidence boundary.
- [`docs/readiness-evidence/bank-readiness.md`](readiness-evidence/bank-readiness.md)
  and `.json` — generated gate and its machine-readable status.
- [`config/control-register.yaml`](../config/control-register.yaml) and
  [`docs/compliance/control-register.md`](compliance/control-register.md) —
  evidence tiers and procurement gaps.
- [`ROADMAP-TO-ENTERPRISE.md`](../ROADMAP-TO-ENTERPRISE.md) — implementation and
  pilot sequence.
- [`docs/enterprise-readiness.md`](enterprise-readiness.md) — capability
  inventory, including features that remain partial or unclaimed.
- [`docs/ops/production-checklist.md`](ops/production-checklist.md) — deployment
  tasks, not proof that those tasks have been performed.
- [`docs/hsm-qualification.md`](hsm-qualification.md) and
  [`docs/postgres-drill.md`](postgres-drill.md) — qualification procedures.

The current gap is primarily an **evidence, operational, assurance, and
customer-environment gap**, not simply a missing-feature gap. Building more
scanners before closing these gates would not make the product safer for a
bank.

### 2.1 What the generated gate currently means

The generated artifact must be rerun after every material release and before a
bank receives a status pack. In the current evidence model:

- Engineering checks are static evidence only. They do not prove GitHub branch
  protection, customer validation, registry provenance, or production operation.
- The PostgreSQL DR result is useful qualification evidence, but a local
  two-container/one-host drill with empty tables, asynchronous replication, no
  load, no failback, and no off-host encrypted round trip is not a bank service
  guarantee.
- HSM, live integrations, load/soak, and external-attestation categories stay
  `SKIP` until real provider, customer, or operator artifacts are supplied.
- The control-register `PASS` means only that evidence tiers are internally
  consistent. It does not mean that the controls are certified or complete.
- A documentation check must exclude generated dependency trees such as
  `frontend/node_modules` and `.venv`; otherwise its broken-link result is not
  a trustworthy product-documentation result. The gate itself must be
  hardened so that its evidence is deterministic.

No status should be promoted from `SKIP` to `PASS` merely because a harness
exists or a local command completed without credentials.

The P0/P1 closure contract is now machine-readable in
[`config/readiness-closure-policy.json`](../config/readiness-closure-policy.json)
and enforced by [`scripts/readiness_closure_gate.py`](../scripts/readiness_closure_gate.py).
It requires current evidence for every required kind, release-commit binding,
UTC capture time, scope, limitations, independent review, digest verification,
and explicit separation between operator and reviewer. The checked-in example
manifest is intentionally incomplete and cannot pass. This closes the
repository's ability to accidentally report an undocumented or stale gap as
closed; it cannot manufacture the customer, provider, auditor, legal,
regulatory, or production evidence listed below.

## 3. P0 blockers before international-bank production approval

The following are the minimum blockers. A bank may add stricter requirements.
Each item is closed only when the stated evidence is retained, attributable to
a release and environment, and reviewed by an independent owner.

### P0-1. Independent security assessment and penetration test

**Missing:** an independent assessment of the API, console, workers, scanners,
queue, database, evidence store, deployment manifests, update path, and
administrative workflows.

The most important scope includes:

- cross-tenant reads and writes, tenant resolution refusal paths, worker queue
  propagation, platform-scope escape, object storage prefixes, and
  background jobs;
- authentication, MFA, SAML/OIDC/LDAP/SCIM, session revocation, API keys,
  role changes, break-glass accounts, and authorization on every REST,
  GraphQL, WebSocket, and event surface;
- SSRF, DNS rebinding, unsafe redirects, internal metadata addresses, command
  injection, repository cloning, archive extraction, parser bombs, and
  untrusted scanner input;
- evidence and audit-chain tampering, replay, signing-key rotation,
  revocation, backup confidentiality, and deletion;
- HSM failure, key identifier substitution, provider impersonation, TLS
  downgrade, certificate validation, and secrets exposure;
- Kubernetes/Compose hardening, image provenance, update-bundle verification,
  host escape, container privileges, and denial of service;
- race conditions in scan scheduling, job retries, leases, duplicate events,
  partial writes, and recovery after API/worker/database/Redis failure.

**Closure evidence:** signed scope and rules of engagement, independent
penetration-test report, raw findings, severity ratings, remediation evidence,
retest report, residual-risk acceptances, and a mapping from findings to the
exact release digest. A self-authored test suite is supporting evidence, not a
substitute.

**Owner:** security leadership with an external qualified assessor.  
**Target:** before any shared deployment or production processing of bank data.

### P0-2. Real customer pilot and field-accuracy validation

**Missing:** evidence that the product works on a real bank estate and that its
findings are useful rather than merely plausible.

A pilot should cover, under an agreed data-handling boundary:

- payment switch and card-processing code;
- Java/.NET/mobile/cloud workloads;
- COBOL, PL/I, RPG, JCL, CICS, DB2, RACF, and ICSF artifacts where applicable;
- HSM/KMS inventories, certificate stores, TLS endpoints, network devices,
  telecom/operator evidence, runtime logs, and configuration repositories;
- the bank's actual severity, ownership, remediation, and exception process.

**Closure evidence:** customer-approved scope, input-data classification,
triage workbook, true-positive/false-positive/missed-finding review, blind
validation wave, recall/precision methodology, candidate-miss log, customer
sign-off, and a redacted external-validation record. Synthetic fixtures and
self-scored benchmarks must remain labelled as synthetic.

**Owner:** product plus the bank's crypto/security owner.  
**Target:** at least one reference pilot before claiming bank-proven accuracy;
three materially different bank estates before making broad international
coverage claims.

### P0-3. Certified cryptographic boundary and real HSM qualification

**Missing:** a customer/provider qualification against the HSM or managed key
service that will protect production signing, encryption, or evidence keys.

The qualification must establish:

- the exact HSM/KMS product, firmware/module version, region, tenancy model,
  and certification status where a certification is required;
- non-exportability and key-usage restrictions;
- generation, activation, dual control, quorum/dual custody, rotation,
  retirement, revocation, destruction, and recovery ceremonies;
- PKCS#11 or provider API behavior under timeout, throttling, permission
  failure, network partition, and provider outage;
- audit-log correlation from provider event to CryptoScan evidence record;
- separation between signing keys, encryption keys, customer keys, and
  operator access; and
- recovery or re-key procedures that do not silently make old evidence
  unverifiable.

SoftHSM2, a local software key, or a successful cryptographic unit test is not
FIPS 140-3 validation and is not customer HSM evidence.

**Closure evidence:** provider attestation/certificate where applicable,
customer-controlled qualification output, non-secret key identifiers, audit-log
exports, rotation/revocation results, outage and recovery transcript, key
ceremony record, and a signed control owner review.

**Owner:** cryptography/security engineering plus the bank's key-management
owner.  
**Target:** one real provider per supported deployment pattern; do not claim
all HSM providers from one adapter test.

### P0-4. Production-grade disaster recovery and business continuity

**Missing:** a topology-realistic DR and restore qualification.

The existing local DR result must be extended to the environment that will be
sold. The drill must cover:

- separate failure domains, ideally separate availability zones or sites;
- database streaming, replication lag, WAL durability, promotion, read/write
  fencing, and split-brain prevention;
- API, worker, scheduler, Redis, Neo4j/evidence dependencies, secrets, HSM,
  DNS, certificates, and external connector recovery;
- measured RPO and RTO under realistic data volume and concurrent load;
- clean restore from an encrypted off-host backup;
- failback, rollback, and a second recovery after the first recovery;
- backup retention, immutability, ransomware isolation, destruction, and
  restore authorization;
- audit-chain, signing, tenant, scan, and evidence invariants after restore;
- a customer-approved continuity plan, call tree, decision authority, and
  tabletop exercise.

**Closure evidence:** architecture and failure-domain diagram, target RPO/RTO
with business owner approval, raw database/provider/host logs, backup checksum
and encryption metadata, promotion and failback transcript, load profile,
restore verification, incident timeline, and a signed post-drill report.

**Owner:** SRE/operations with database and security owners.  
**Target:** at least quarterly DR tests for critical deployments, plus tests
after material topology or database changes.

### P0-5. Immutable, verifiable software supply chain

**Missing:** a release path that proves exactly what the bank is running.

Required controls include:

- reproducible or at least repeatable builds with pinned dependencies;
- OCI images referenced by immutable digests, not release tags alone;
- signed images, release manifests, SBOMs, provenance/attestations, and
  verification at deployment;
- protected branches, mandatory review, required CI checks, and no unreviewed
  workflow bypass;
- dependency, container, IaC, secret, SAST, DAST, and license scanning with
  triage and remediation records;
- signed air-gap/update bundles, anti-rollback protection, migration rollback
  plan, and a tested emergency release path;
- separation of build, release approval, registry publication, and production
  deployment duties; and
- a retained mapping from source commit to artifact digest to deployment.

**Closure evidence:** registry digest manifest, signature verification log,
SBOM and provenance, build logs, vulnerability report, branch-protection API
record, approval record, deployment admission log, and rollback transcript.

**Owner:** platform engineering/release management.  
**Target:** before any bank installs a release outside a supervised lab.

### P0-6. Formal vulnerability, patch, and incident-management program

**Missing:** an operating program with deadlines and evidence over time.

Define and operate:

- severity taxonomy and CVSS/business-impact rules;
- maximum remediation times for critical/high/medium/low issues;
- emergency patch and compensating-control procedure;
- customer notification criteria, channels, time windows, and named contacts;
- vulnerability disclosure and security-contact process;
- incident severity, command structure, evidence preservation, legal/privacy
  escalation, regulator notification, and customer communication;
- post-incident review, corrective action, retest, and risk acceptance; and
- a vulnerability exception process with expiry dates and accountable owners.

**Closure evidence:** approved policies, ticket exports over an observation
period, SLA dashboards, sample incident/tabletop reports, notification drill,
penetration-test remediation records, and management review minutes.

**Owner:** CISO/security operations/legal.  
**Target:** policy alone is not enough; demonstrate operation for a sustained
period before seeking Type II assurance.

### P0-7. Bank-grade identity, privileged access, and separation of duties

**Missing:** production evidence that access is controlled by the bank's IdP and
reviewed continuously.

The minimum operating model should include:

- bank SAML/OIDC integration with signed assertions, issuer/audience/expiry and
  clock-skew testing;
- phishing-resistant MFA for privileged users where the bank requires it;
- SCIM joiner/mover/leaver behavior and immediate deprovisioning;
- privileged access management, just-in-time elevation, session recording or
  equivalent oversight, and short-lived credentials;
- separate developer, operator, auditor, support, and break-glass roles;
- dual approval for key ceremonies, production changes, evidence deletion, and
  exceptional platform scope;
- quarterly access recertification and service-account inventory;
- API-key scope, expiry, rotation, revocation, and owner metadata; and
- immutable audit records shipped to the bank's SIEM.

**Closure evidence:** IdP integration test, negative authorization matrix,
SCIM lifecycle transcript, PAM/access-review exports, break-glass exercise,
service-account register, audit-log delivery, and signed quarterly review.

**Owner:** IAM/platform operations and the bank's identity team.

### P0-8. Data protection, privacy, residency, and exit controls

**Missing:** a customer-specific statement of what data is processed, where it
is stored, who can access it, how long it remains, and how it is destroyed.

Complete a data inventory covering source code, scan findings, certificates,
key metadata, evidence, logs, audit records, backups, telemetry, support data,
subprocessors, and temporary workspaces. For each class define:

- classification and allowed purpose;
- collection minimization and masking/redaction;
- encryption in transit and at rest, key ownership, and rotation;
- storage region, support-access region, replication region, and backup region;
- retention, legal hold, deletion, and destruction verification;
- customer export, portability, termination, and clean-room exit procedure;
- cross-border transfer mechanism and privacy/legal review; and
- whether personal data, cardholder data, payment secrets, or regulated
  financial data can enter the system at all.

**Closure evidence:** data-flow diagram, records of processing, DPA and
subprocessor list, residency/deployment attestation, retention schedule,
delete/export test, backup-destruction record, access log, and legal approval.

**Owner:** privacy/legal, product, and operations.  
**Target:** before processing any bank production data.

### P0-9. Contractual and support readiness

**Missing:** a support and accountability model that a bank can rely on during a
security event or service failure.

The commercial pack must define:

- service description and responsibility matrix;
- availability, support response, restoration, and maintenance SLAs;
- severity definitions and 24x7 escalation contacts;
- incident notification time, content, and communication channel;
- planned change, emergency change, and deprecation notice periods;
- subcontractor approval and notification; audit/cooperation rights;
- liability, indemnity, cyber insurance, confidentiality, and data ownership;
- data return/deletion at termination; and
- exit assistance, escrow or continuity options if the vendor becomes
  unavailable.

**Closure evidence:** approved MSA, DPA, SLA, support handbook, escalation
exercise, subprocessor register, insurance evidence, and termination drill.

**Owner:** legal, sales, support, and operations.

## 4. P1 requirements for a credible international rollout

These may be phased by customer, but they cannot be hidden behind a generic
"enterprise" label.

### P1-1. Regulatory and control-framework mapping

Build a control matrix that maps one internal control to the applicable
obligation and to its evidence. Applicability must be decided with counsel and
the bank; the following are examples, not a claim that all apply:

| Framework or regime | Typical concern for this product |
|---|---|
| SOC 2 Type II | Security, availability, confidentiality, processing integrity, privacy controls observed over time. |
| ISO/IEC 27001 | Information-security management system, risk treatment, internal audit, management review, corrective action. |
| ISO/IEC 27701 | Privacy information management where personal-data processing is in scope. |
| PCI DSS / PCI PIN / PCI HSM | Applicable only to the relevant cardholder, payment, PIN, or HSM boundary; a crypto inventory tool is not automatically PCI compliant. |
| EU DORA and related EBA expectations | ICT risk management, incident reporting, resilience testing, third-party and exit risk for in-scope financial entities. |
| NIS2 or national cyber rules | Applicability depends on entity and jurisdiction; incident, governance, supply-chain, and security duties may apply. |
| GDPR and local privacy laws | Personal data, processor obligations, cross-border transfer, deletion, data-subject rights, and breach handling. |
| UK FCA/PRA operational resilience | Important-business-service impact tolerances, mapping, scenario testing, outsourcing and incident governance. |
| US GLBA/FFIEC/NYDFS and contractual bank requirements | Safeguards, risk assessment, incident response, access, testing, third-party oversight, and notification. |
| APRA CPS 234/230, MAS TRM, HKMA, RBI/DPDP and other local regimes | Jurisdiction-specific security, outsourcing, resilience, privacy, and audit obligations. |

**Closure evidence:** applicability decision, control matrix, responsible owner,
evidence location, test frequency, exception process, independent review, and
customer/regulator-approved residual risks. Do not put framework logos or
"compliant" language in marketing without the relevant certification or legal
basis.

### P1-2. Availability, scalability, and soak evidence

**Missing:** capacity evidence for real bank workloads.

Run the release in the target topology with realistic repository sizes,
concurrent users, scheduled scans, queue depth, database volume, evidence
retention, connector failures, and alert volume. Measure:

- API latency and error rates by endpoint class;
- worker throughput, queue age, retries, dead letters, and duplicate work;
- PostgreSQL CPU, locks, connections, WAL, replication lag, vacuum, and disk
  growth;
- Redis memory, eviction, persistence, and recovery;
- scanner memory/CPU behavior on large or hostile inputs;
- report/evidence-store growth and restore time; and
- behavior during dependency loss, rate limiting, node restart, and backpressure.

**Closure evidence:** approved workload model, multi-day or multi-week soak,
raw metrics, thresholds, capacity model, scaling limits, saturation behavior,
known constraints, and a sizing/runbook per deployment tier.

### P1-3. Production observability and security operations

**Missing:** proof that a bank's SOC and operations team can detect and respond
to meaningful events.

Deliver:

- structured application, audit, worker, database, HSM, deployment, and
  security logs;
- clock synchronization and time-source policy;
- SIEM mappings for authentication, privilege, key, tenant, evidence,
  deployment, and data-access events;
- alert rules with severity, deduplication, suppression, escalation, and
  ownership;
- dashboards for health, scan backlog, failed controls, certificate expiry,
  replication lag, HSM state, and audit-chain verification;
- retention and immutability appropriate to the bank's policy; and
- tabletop exercises proving an alert reaches the right people and produces a
  usable incident timeline.

### P1-4. Integration qualification in the bank's environment

Repository adapters are not integration proof. Qualify the exact versions and
network boundary for:

- SAML/OIDC/SCIM identity providers;
- ServiceNow, Jira, Splunk, QRadar, Microsoft Sentinel, or the customer's
  equivalent;
- AWS/Azure/GCP read-only roles and permission boundaries;
- HSM/PKCS#11 or managed HSM;
- PostgreSQL, Redis, Neo4j, object storage, backup, and enterprise proxy;
- Git hosting, artifact registries, air-gap transfer, and certificate PKI;
- mainframe file transfer, RACF/ICSF/DB2/CICS exports, and bank-specific log
  formats; and
- carrier/operator telecom data sources where 5G or payment-network scope
  requires them.

Record network routes, certificates, scopes, owners, timeouts, retries,
rate limits, sample payloads, negative tests, and operational ownership.

### P1-5. Secure product lifecycle and change governance

Banks need to know not only that today's release is safe, but how tomorrow's
release is controlled. Establish:

- threat modeling for new features and material changes;
- security review and approval gates for authentication, cryptography, data,
  parsers, update bundles, and infrastructure;
- release risk classification and rollback criteria;
- database migration compatibility and rollback testing;
- API/schema deprecation policy;
- customer notice and maintenance-window procedure;
- vulnerability and dependency refresh cadence; and
- independent review of high-risk changes.

## 5. Product-specific gaps that remain important

These are not all universal blockers, but they matter to the target banks and
should be scoped honestly:

1. **Mainframe depth:** real COBOL/PL/I/RPG/HLASM, ICSF, RACF, JCL, CICS, DB2,
   SMF, and payShield samples must be validated with a bank or approved data
   provider. Corpus-only support is not bank coverage.
2. **Database and TDE discovery:** Oracle, SQL Server, PostgreSQL, MongoDB and
   other bank data-platform encryption evidence needs customer-safe adapters
   and permission-minimized queries.
3. **Telecom and payment evidence:** N3/N9, SEPP, IMS, ISO 8583, EMV, TR-31,
   PIN, HSM, and operator evidence require real field formats and ownership;
   classifier code is not carrier qualification.
4. **Multi-tenant deployment:** the safer supported posture remains one
   instance per bank unless an independent review qualifies shared tenancy,
   including every API, worker, cache, object-store, export, background job,
   and platform-scope path. Do not enable SaaS signup merely because the code
   has tenant filters.
5. **Evidence integrity:** signing and hash chains need tested key rotation,
   time source, revocation, offline verification, export/import, retention,
   and independent audit procedures.
6. **Air-gapped operation:** prove signed update bundles, dependency/feed
   import, certificate rotation, vulnerability response, rollback, and support
   workflows without outbound connectivity.
7. **Frontend and API authorization:** keep server-side authorization
   authoritative, complete the long-tail action review, and cover REST,
   GraphQL, WebSocket, downloads, exports, and error/oracle behavior in one
   authorization matrix.

## 6. Evidence package a bank should receive

A bank-facing release package should contain, at minimum:

1. product architecture and deployment/data-flow diagrams;
2. versioned security and privacy whitepapers;
3. threat model and independent penetration-test report;
4. control matrix against the applicable bank/regulatory framework;
5. current SOC 2/ISO/PCI/FIPS evidence, or an explicit statement that it does
   not exist;
6. software supply-chain package: image digests, SBOM, provenance, signatures,
   vulnerability report, and release approval;
7. HSM/provider qualification and key-management procedure;
8. DR/BCP, backup/restore, RPO/RTO, failover/failback, and test reports;
9. access-control, SSO, MFA, PAM, SCIM, and audit-log evidence;
10. secure-development, vulnerability, patch, incident, and disclosure
    policies plus observed operating records;
11. privacy/DPA/subprocessor/residency/retention/deletion package;
12. integration, performance, capacity, and soak reports;
13. operational runbooks, on-call/escalation matrix, SLA, support contacts,
    and customer responsibilities;
14. pilot validation workbook with the customer's accepted limitations; and
15. signed residual-risk register with expiry dates and accountable owners.

Every artifact should carry UTC timestamp, release/source commit, environment,
operator or issuer, command or method, digest, scope, limitations, and review
approval. A file hash proves that a file did not change after hashing; it does
not prove that the file is true or that the customer ran it.

## 7. Suggested delivery sequence

### First 30 days — stop making unsupported claims

- Freeze the bank-facing capability and certification language.
- Assign owners and due dates to every `none`, `SKIP`, and `FAIL` row in the
  control/readiness registers.
- Fix readiness-gate determinism, including dependency-directory exclusion and
  immutable image checks.
- Finalize pen-test scope, pilot data rules, DPA, subprocessor list, and the
  first bank's integration matrix.
- Define vulnerability, patch, incident-notification, SLA, support, retention,
  destruction, and access-review policies.
- Select the HSM/provider and the independent assessor.

### Days 31–90 — qualify the deployment, not just the code

- Execute the independent penetration test and remediate/retest.
- Run the first bank pilot and triage workbook.
- Qualify the actual HSM/KMS boundary and IdP/SIEM/ITSM integrations.
- Publish digest-pinned, signed images with SBOM/provenance.
- Run realistic load/soak, encrypted off-host backup/restore, multi-failure DR,
  failback, and incident/tabletop exercises.
- Produce the first customer-specific evidence pack and risk acceptance.

### Months 3–12 — create durable assurance

- Operate vulnerability, access review, incident, change, backup, and support
  processes long enough to show a trend rather than one successful drill.
- Complete the applicable SOC 2 Type II and/or ISO 27001 program; pursue other
  certifications only where the target market requires them.
- Repeat pilot validation on materially different estates and add bank-approved
  mainframe/payment/telecom samples.
- Run recurring DR, restore, HSM, failover, access-review, and recovery tests.
- Close contractual exit, deletion, residency, insurance, and subprocessor
  requirements for each jurisdiction.

## 8. Release decision rule

Do not call a release "international-bank production ready" unless all of the
following are true:

- the applicable regulatory and contractual scope has been approved;
- P0 engineering and operational blockers are closed or explicitly accepted
  by the bank's accountable risk owner;
- independent security testing is complete and high/critical findings are
  remediated or formally accepted;
- real customer/provider evidence exists for the deployment pattern;
- images, updates, keys, backups, and evidence are verifiable and recoverable;
- RPO/RTO, performance, integrations, support, incident, and exit procedures
  have been exercised; and
- the readiness report contains no unexplained `SKIP`, stale artifact, or
  unsupported certification claim.

The correct language while any of these are missing is:

> **Enterprise-capable, under supervised bank pilot; not yet independently
> qualified for unattended regulated production.**

That wording is not a weakness. It is the boundary that protects the product's
credibility while the remaining evidence is earned.
