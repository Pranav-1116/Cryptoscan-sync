# Security incident and breach notification terms

**Template status:** legal, privacy, security, and operations review required  
**Related:** DPA, Security Addendum, MSA, SLA, and incident-response policy

These terms define how Vendor and Customer cooperate when a security event may
involve Customer Data or the Services. They do not decide whether a legal
breach occurred; that determination depends on the facts, jurisdiction, and
applicable law.

## 1. Event categories

### Security event

An observed or suspected event that may affect confidentiality, integrity, or
availability, including suspicious access, malware, credential exposure,
service abuse, or evidence tampering.

### Security Incident

A confirmed compromise of security controls, service, or Customer Data that
requires investigation or response.

### Personal Data breach

A breach of security leading to accidental or unlawful destruction, loss,
alteration, unauthorized disclosure of, or access to Personal Data, as defined
by applicable law.

### Service outage

Loss or degradation of an agreed service function without necessarily
involving unauthorized access or Personal Data.

These categories can overlap and must not be collapsed into a single support
severity.

## 2. Notification trigger and window

Vendor will notify Customer without undue delay after confirming a Security
Incident affecting Customer Data in Vendor's control and, if the parties agree,
within `[24]` hours after confirmation. The parties may set a stricter window
in the DPA or Order Form.

The notification clock must not be described as starting at first suspicion if
facts are not yet reliable, but Vendor must not delay investigation or
notification while waiting for perfect information.

Customer will notify Vendor promptly when it suspects that Customer systems,
credentials, source integrations, or Customer Data connected to the Services
may be affected.

## 3. Initial notice

The initial notice should state, to the extent known:

- incident identifier;
- date/time discovered and relevant time zone;
- estimated occurrence and duration;
- affected customer, environment, region, and service;
- affected data categories and data subjects;
- whether Customer Data was accessed, changed, lost, or unavailable;
- containment actions taken;
- current service impact;
- known or suspected attack vector;
- actions Customer should take;
- investigation owner and secure contact channel; and
- next update time.

If information is unknown, say `under investigation`; do not guess or state
that no data was affected without a defensible basis.

## 4. Updates and final report

Vendor will provide material updates at `[24]`-hour intervals or another agreed
cadence until containment, then provide a final report when reasonably
available. The final report should include:

- timeline;
- affected assets and scope determination;
- root or contributing causes where known;
- data and access analysis;
- containment, eradication, and recovery;
- notification decisions and legal review owner;
- corrective actions and due dates;
- evidence retained;
- residual risk; and
- prevention and testing plan.

A final report may be redacted to protect another customer, vulnerability
information, law-enforcement activity, legal privilege, or security-sensitive
controls.

## 5. Communication authority

Vendor will not notify regulators, individuals, media, or other third parties
on Customer's behalf unless Customer instructs Vendor or law requires it.
Customer owns its legal, regulatory, customer, employee, and public
communications unless the contract says otherwise.

The parties will coordinate language to avoid misleading statements, admission
of liability, and premature attribution. Communications must identify whether
facts are confirmed, suspected, or still unknown.

## 6. Cooperation

Each party will reasonably cooperate with the other by:

- preserving logs and evidence;
- providing relevant contacts and access;
- supporting forensic analysis;
- containing affected credentials and integrations;
- identifying impacted data and systems;
- supporting regulator or law-enforcement requests;
- maintaining a secure incident channel; and
- participating in a post-incident review.

Customer must provide current scope, source owners, data classification,
contacts, and any special regulatory deadline.

## 7. Customer responsibilities after notice

Customer should:

- confirm the incident contact;
- preserve Customer-side logs and source state;
- avoid destructive cleanup before evidence capture;
- rotate affected credentials when instructed or necessary;
- suspend unsafe integrations;
- assess customer-side systems and downstream recipients;
- decide required regulatory and individual notifications; and
- track customer risk acceptance and remediation.

## 8. Evidence and confidentiality

Incident information is Confidential Information. The parties should use a
restricted channel and preserve chain of custody for relevant records. Sharing
an incident report does not give the recipient a right to share it further.

## 9. Tabletop exercise

For an enterprise or regulated deployment, the parties should test this
process at least annually or after a material change. The exercise should cover:

- credential compromise;
- unauthorized source access;
- evidence-chain tampering;
- HSM/KMS or key-provider outage;
- database or region loss;
- ransomware or destructive source data;
- support impersonation; and
- customer and regulator communication.

Record participants, assumptions, actions, timings, gaps, owners, and retest
dates. A tabletop is not proof that a real incident could never occur.

## 10. Contacts

| Function | Vendor | Customer |
|---|---|---|
| Security incident | `[SECURITY CONTACT]` | `[CUSTOMER SECURITY CONTACT]` |
| Privacy breach | `[PRIVACY CONTACT]` | `[DPO / PRIVACY CONTACT]` |
| Service outage | `[SUPPORT CONTACT]` | `[CUSTOMER OPERATIONS CONTACT]` |
| Executive escalation | `[EXECUTIVE CONTACT]` | `[CUSTOMER SPONSOR]` |
| Secure exchange | `[SECURE CHANNEL]` | `[CUSTOMER SECURE CHANNEL]` |

## 11. No false assurance

The following are not acceptable without evidence:

- "no data was accessed" when investigation is incomplete;
- "the incident was only a scan" when unauthorized access is unassessed;
- "the service is certified" because a policy exists;
- "the customer is compliant" because a report generated PASS; or
- "all systems are recovered" because one component is healthy.
