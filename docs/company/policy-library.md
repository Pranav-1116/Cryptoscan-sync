# Customer policy library index

**Status:** policy index and customer delivery guide  
**Owner:** `[SECURITY GOVERNANCE OWNER]`  
**Important:** a policy in this index is not evidence that the policy operated.
Each delivered policy must have approval, scope, effective date, review date,
exceptions, and operational records where applicable.

## 1. Access-control policy

The approved access policy must define:

- unique identities and least privilege;
- role catalogue and privileged roles;
- SSO, MFA, API keys, service accounts, and break-glass;
- joiner, mover, leaver;
- access approval and periodic review;
- session, token, and credential lifecycle;
- support access and customer approval;
- logging, monitoring, and review;
- separation of duties; and
- exception and emergency access.

Source draft: [access-control-policy.md](../policies/access-control-policy.md).
Customer evidence: IdP configuration, role matrix, negative authorization tests,
access-review export, and deprovisioning record.

## 2. Incident-response policy

The approved incident policy must define:

- event, incident, and breach categories;
- severity and decision authority;
- internal acknowledgement and commander assignment;
- containment, evidence preservation, investigation, and recovery;
- customer, regulator, and individual notification;
- legal privilege and communications;
- vendor/subprocessor escalation;
- tabletop frequency;
- post-incident review; and
- retention and corrective action.

Source draft: [incident-response-policy.md](../policies/incident-response-policy.md).
Customer delivery: approved policy, contact list, exercise record, and breach
terms from [breach-notification-terms.md](breach-notification-terms.md).

## 3. Business-continuity policy

The approved BC policy must define:

- critical services and business processes;
- impact analysis and dependencies;
- people, facilities, communications, and decision authority;
- alternative operating mode;
- customer and supplier dependencies;
- recovery priorities;
- exercise and review cadence; and
- lessons learned.

Source draft: [bc-dr-policy.md](../policies/bc-dr-policy.md). Customer
specificity belongs in the Order Form and continuity plan approval.

## 4. Disaster-recovery policy

The DR policy must define:

- RPO/RTO target and measurement;
- primary and secondary failure domains;
- database replication and promotion;
- API, worker, scheduler, queue, graph, evidence, identity, secrets, HSM,
  DNS, certificate, and connector recovery;
- fencing, split-brain prevention, failback, and rollback;
- encrypted off-host backup;
- restore authorization and evidence invariants;
- customer responsibilities;
- test frequency and pass criteria; and
- raw logs and approval record.

Source runbook: [DR recovery](../runbooks/dr-recovery.md). A local drill is
not a customer service guarantee.

## 5. Vulnerability-management policy

The policy must define:

- intake channels and security contact;
- asset and dependency scope;
- severity methodology;
- remediation targets;
- compensating controls;
- exception and risk-acceptance process;
- disclosure and customer notice;
- verification and retest;
- metrics and trend reporting; and
- independent review.

Source draft: [vulnerability-management-policy.md](../policies/vulnerability-management-policy.md).
The operational baseline proposes targets but does not create a contractual
commitment until approved.

## 6. Secure SDLC policy

The policy must define:

- security ownership and training;
- threat modelling triggers;
- design and code review;
- dependency, secret, SAST, DAST, IaC, container, and license checks;
- test and release gates;
- SBOM/provenance/signature requirements;
- migration and rollback review;
- emergency change;
- vulnerability handling;
- branch protection and separation of duties; and
- retention of source-to-artifact-to-deployment evidence.

Repository evidence includes CI, release-image locks, attestation tooling, and
engineering gates. Provider enforcement and operational duration require
separate evidence.

## 7. Approval record

```text
Policy name/version: ______________________
Scope/entity/region: ______________________
Owner: ___________________________________
Approved by: ______________________________
Effective date: ___________________________
Next review: ______________________________
Exceptions: _______________________________
Evidence location: ________________________
```

## 8. Customer answer rule

If a prospect asks `Do you have a policy?`, answer with policy name, version,
scope, status, and whether it is approved. Do not answer only `yes` when the
file is a draft or when the requested deployment is outside its scope.
