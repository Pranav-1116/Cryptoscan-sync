# Security addendum

**Template status:** security, legal, privacy, and operations review required  
**Applies to:** CryptoScan Services supplied to `[CUSTOMER LEGAL NAME]`  
**Evidence status:** this schedule describes required controls and available
repository evidence; it does not create a SOC 2 report, ISO certificate, or
customer attestation by itself.

## 1. Purpose and scope

This Security Addendum defines the administrative, technical, and operational
security commitments applicable to the deployment and service in the Order
Form. It must be completed for the actual deployment model: customer-managed,
vendor-managed dedicated, private region, air-gapped, or other.

## 2. Security governance

Vendor will maintain written processes for:

- information security governance;
- risk and control ownership;
- security review of material changes;
- vulnerability and patch management;
- incident response and breach notification;
- access review and privileged access;
- business continuity and disaster recovery;
- backup, restore, retention, and deletion;
- secure development and release;
- supplier and subprocessor risk; and
- security awareness and confidentiality.

The current repository includes policy drafts and machine-readable readiness
checks. Customer-specific approved policies, operational records, and external
attestations must be added to the evidence package before production approval.

## 3. Security architecture

The architecture package must show:

- user and administrator entry points;
- API, frontend, worker, scheduler, queue, database, graph, evidence, and
  storage components;
- trust boundaries and network zones;
- identity-provider and privileged-access paths;
- source-system connectors and outbound routes;
- HSM/KMS or signing-key boundary;
- log, monitoring, alert, and SIEM routes;
- backup and restore path;
- production, staging, development, and support separation; and
- customer versus Vendor responsibilities.

Reference materials:

- [End-to-end architecture](../END-TO-END-ARCHITECTURE.md)
- [Data flow](../DATAFLOW.md)
- [System overview](../architecture/system-overview.md)
- [Service map](../architecture/service-map.md)
- [Threat model](../security/threat-model.md)
- [Network controls](../security/NETWORK-CONTROLS.md)

## 4. Encryption and key management

Vendor will document the actual deployment's:

- encryption in transit and TLS configuration;
- encryption at rest and database/storage controls;
- key generation, storage, rotation, activation, retirement, and destruction;
- signing keys and evidence-chain integrity;
- HSM/KMS product, provider, region, tenancy, and key policy;
- key non-exportability and access restrictions;
- recovery and dual-control procedures;
- certificate validation and renewal; and
- cryptographic algorithm and protocol policy.

The use of a cryptographic library or algorithm does not establish FIPS
validation. HSM qualification must be performed against the actual provider,
firmware, region, key boundary, and customer deployment.

## 5. Identity and access control

Vendor will implement or maintain:

- unique user identities;
- role-based access and least privilege;
- SSO through approved SAML/OIDC or another contracted mechanism where used;
- MFA for privileged access where supported and required;
- API-key scope, rotation, and revocation;
- separate service accounts;
- administrative access logging;
- access approval and periodic review;
- joiner, mover, and leaver processes;
- break-glass control and review; and
- customer-side responsibility for IdP and source-system permissions.

Customer will define the required role matrix in the Order Form. Vendor will
not imply that a customer has completed an access review merely because the
software exposes a role configuration.

## 6. Secure development lifecycle

Vendor will maintain, according to the applicable service maturity:

- threat modelling for security-sensitive changes;
- peer review and code ownership;
- dependency and secret scanning;
- static, dynamic, and security testing appropriate to the change;
- protected release and deployment controls;
- dependency pinning and SBOM generation;
- vulnerability triage and remediation records;
- migration compatibility and rollback planning;
- signed or digest-pinned release evidence where contracted; and
- emergency change and disclosure procedures.

Reference: [release and readiness gates](../readiness-evidence/README.md),
[security hardening checklist](../security/hardening-checklist.md), and
[security campaign](../security-campaign.md).

## 7. Vulnerability management

Vendor will maintain a process to receive, assess, prioritize, remediate, and
communicate vulnerabilities. The customer-specific contract must choose actual
targets, exceptions, and notification windows.

The draft operational baseline proposes internal objectives of seven days for
critical, thirty days for high, ninety days for medium, and one hundred eighty
days for low issues. These are not contractual commitments until approved in
the Order Form or applicable security schedule.

## 8. Logging and monitoring

Vendor will log, as applicable:

- authentication and authorization events;
- privileged actions and role changes;
- source access and data export;
- scan, queue, worker, and connector events;
- evidence generation and verification;
- key and certificate lifecycle events;
- deployment, configuration, and security changes;
- backup, restore, deletion, and retention events; and
- incident and support actions.

Logs must use synchronized UTC timestamps, be access-restricted, protected from
unauthorized alteration, and retained according to the approved schedule.

## 9. Incident response

Vendor will maintain an incident-response process with severity, ownership,
containment, evidence preservation, investigation, notification, remediation,
and lessons-learned steps. Customer-specific notice windows are in the DPA and
[Breach Notification Terms](breach-notification-terms.md).

Security Contact: `[SECURITY CONTACT]`  
Privacy Contact: `[PRIVACY CONTACT]`  
Support Contact: `[SUPPORT CONTACT]`

## 10. Business continuity, DR, and backup

The actual service package must identify:

- target RPO and RTO;
- failure domains and recovery topology;
- API, worker, database, queue, graph, storage, identity, secrets, HSM,
  certificates, DNS, and integration recovery;
- replication, fencing, promotion, failback, and split-brain controls;
- encrypted off-host backup;
- retention, immutability, ransomware isolation, and destruction;
- restore authorization and evidence verification;
- test frequency and last test record; and
- customer versus Vendor recovery responsibilities.

A local sandbox drill is qualification evidence for the harness, not proof of a
customer service guarantee. Reference [BC/DR policy](../policies/bc-dr-policy.md),
[DR recovery runbook](../runbooks/dr-recovery.md), and
[readiness evidence](../readiness-evidence/README.md).

## 11. Personnel and physical security

Complete this section for the actual Vendor hosting and support boundary:

- background screening where lawful and appropriate;
- confidentiality commitments;
- security awareness and role training;
- offboarding and access removal;
- office and data-centre controls;
- device management and endpoint protection;
- remote support controls; and
- physical media destruction.

Do not claim controls performed by a hosting provider as Vendor controls
without the applicable provider evidence.

## 12. Subprocessors and hosting

Vendor will maintain the [subprocessor register](subprocessors.md) and notify
Customer of material changes under the DPA. Hosting/cloud architecture must
identify actual regions, accounts, services, support access, backups, and
transfer routes. Generic cloud diagrams are not customer-specific evidence.

## 13. Security testing and assurance

Vendor will provide the assurance artifacts actually available under the
contract, which may include:

- independent penetration-test executive summary;
- vulnerability remediation or retest summary;
- SOC 2 report, if one exists and applies;
- ISO 27001 certificate, if one exists and applies;
- security questionnaire answers;
- architecture and data-flow diagrams;
- policy excerpts;
- release, SBOM, and evidence verification records; and
- customer-specific qualification evidence.

Confidential reports may be supplied under NDA, in a secure data room, or as a
redacted executive summary. Missing certifications must be stated as missing;
readiness analysis is not certification.

## 14. Customer audit and review

Customer may request reasonable evidence of compliance with this Addendum.
Vendor may satisfy a request with current independent reports, policy
excerpts, control descriptions, questionnaire answers, or a targeted review.
Audits must protect other customers, Vendor secrets, and security-sensitive
configurations.

## 15. Exceptions

Any exception must identify:

- control and scope;
- reason;
- risk and compensating control;
- owner;
- reviewer;
- approval date;
- expiry date; and
- remediation plan.

An exception does not convert `SKIP`, `FAIL`, or unknown evidence into PASS.

## 16. Customer responsibilities

Customer must maintain:

- source authorization;
- customer-side identity and access;
- network, proxy, and firewall controls;
- cloud, database, HSM/KMS, and backup controls it operates;
- data classification and lawful basis;
- remediation and risk acceptance;
- customer-side incident contacts;
- customer-side regulatory and privacy assessment; and
- customer-approved scope changes.

## 17. Signature and precedence

The Addendum becomes effective only when signed or incorporated into an Order
Form. The DPA controls for Personal Data; the SLA controls for measured service
levels; the MSA controls for general commercial terms; and a negotiated Order
Form controls for customer-specific scope.
