# Bank operating model: 24/7 service, bank monitoring and weekly vendor support

**Prepared:** 2026-10-22 UTC
**Baseline:** `bfc42df0`, with the pending documentation additions; reviewed
application implementation `698beb38`.
**Status:** proposed operating procedure to agree, staff and exercise with the
bank—not an already staffed service, implemented alert integration or contractual SLA.

## 1. The model in plain language

After an authorized on-premises installation and acceptance, **the intended model
is for the bank-hosted CryptoScan service to remain running continuously, day
and night, rather than being started only when our team visits.** The bank's
security operations team monitors the tool and its alerts; the bank's platform,
database and infrastructure teams operate their respective dependencies.

Our product/support team performs an **agreed weekly health and maintenance
review** with the bank: inspect errors, review supported releases and security
advisories, investigate defects, propose fixes, test them and arrange approved
changes. The bank retains production control and accepts the results.

**Urgent incidents must not wait until the weekly review.** The bank needs a
staffed incident/escalation path at all hours it relies on the service. Vendor
out-of-hours help exists only if people, contacts, access and support terms are
actually agreed; a weekly review alone is not vendor 24/7 support.

```text
Continuously running bank-hosted service
        ↓
Bank-approved monitoring detects a problem / bank user reports an error
        ↓
Bank SOC + named platform/database owner triage impact and preserve evidence
        ↓
Urgent incident? → use the agreed immediate escalation/change process
Routine defect? → track it for agreed support handling / weekly review
        ↓
Our team diagnoses, reproduces and prepares a bounded tested fix
        ↓
Bank approves access, exact package, risk and maintenance change
        ↓
Authorized operator deploys → verify service/data/critical journey
        ↓
Bank accepts recovery/fix → retain evidence → prevent recurrence
```

## 2. What 24/7 does and does not mean

| Statement | Correct interpretation |
|---|---|
| Service runs 24 hours a day, seven days a week | Intended operating schedule, subject to actual infrastructure, maintenance, faults and agreed support arrangements. |
| Bank security monitors the tool | Bank SOC watches relevant health/security signals and routes actionable incidents to the correct owner; it is not automatically the database or cluster administrator. |
| Our team checks weekly | Scheduled preventive review and routine follow-up, not a promise to leave a known incident unattended for seven days. |
| Kubernetes can restart a process | Limited recovery behavior; it cannot prove data integrity, reconcile UNKNOWN work or provide qualified HA. |
| The tool is running | Not proof that every scan succeeded, evidence is fresh or all expected targets were observed. |
| Continuous security coverage | Only observations actually authorized, performed and retained for supported scope; installation does not establish this claim. |
| Automatic updates | **Not part of this model.** Review weekly, deploy only through the bank's approved change process. |
| Vendor remote access | Explicitly approved, least-privilege, time-bounded and logged—not a permanent tunnel or standing superadmin entitlement. |

The current controlled production profile remains
`kubernetes-external-services/local-source-v1`. Unqualified live TLS/SSH/cloud/
runtime collectors, monitor loops, realtime/notification interfaces and other
refused surfaces are **not enabled by this operating plan**. Continuous service
availability is separate from continuous collection. Authorized local-source work
is submitted and executed under current grants; this guide does not add a scheduler.

The reference one-replica topology does not prove HA or zero downtime. Planned
maintenance and faults must be handled honestly. **24/7 schedule is not 100%
uptime**, a certified service or an automatic contractual availability commitment.
The existing operating assertion workflow retains `sla_authorized=false`.

## 3. Agree the operating charter before relying on the service

The bank service owner and our support owner must approve:

- exact site/release/profile, allowed workflows and excluded capabilities;
- hours of service and actual bank monitoring/on-call coverage;
- primary/backup humans for each duty and escalation responsibility;
- vendor support hours, after-hours route if purchased/agreed, and contact fallback;
- the weekly review day, time, timezone, attendees, agenda and alternate holiday slot;
- incident severity definitions, notification/response/update objectives and decision authority;
- maintenance windows, emergency-change route, blackout periods and recovery objectives;
- permissible support evidence, remote access, data residency and retention;
- actual monitoring tools, signal ownership, alert routing and failure-of-monitoring checks;
- ticket ownership, evidence/review requirements and closure/requalification rules.

No response time, availability percentage, RPO/RTO or repair deadline is invented
by this document. Record approved objectives separately from actual measured
results. If required staffing or escalation is missing, record a blocker rather
than claim 24/7 support has been established.

## 4. Responsibility matrix

Roles below are required assignments, not claims that any actual person is staffed.
Use the bank's existing ticket/change/security processes; no new support portal is required.

| Activity | Accountable owner | Supporting / reviewing roles |
|---|---|---|
| Overall service health and risk decision | Bank service owner | Bank security, application and platform owners |
| Continuous detection/initial security triage | Bank SOC/monitoring owner | Named after-hours backup and incident commander |
| Cluster/node/ingress/storage operation | Bank platform owner | Our team for product-specific diagnosis; different change reviewer |
| PostgreSQL/Redis/backups/restore | Bank database/cache/backup owners | Platform and product engineering; independent recovery witness |
| Product error investigation and code fix | Our product/support engineering owner | Bank supplies approved evidence; different code/QA reviewer |
| Weekly review and follow-up tracking | Named our-team support lead | Bank service/SOC/platform representatives and backups |
| Production access/change approval | Bank-designated approver | Security/change board or approved emergency authority |
| Deployment and verification | Bank-approved operator | Our team may assist under scoped access; different reviewer |
| Incident communications and legal/regulatory decisions | Bank incident/service/legal authority | Our support lead supplies factual product impact information |
| Final operational incident closure | Bank incident/service owner | Relevant technical owner, reviewer and customer owner |

An operational review is not a replacement for independent security assessment.
A vendor engineer cannot approve their own access/change merely because they
understand the product. Assignment alone does not grant API roles or infrastructure access.

## 5. What the bank monitors continuously

Use the bank's already approved infrastructure/monitoring/logging systems and
available supported health signals. This document does not configure an agent,
SIEM connector, notification channel or new application feature. Every signal
must have a tested route to an actual human owner.

| Signal | Reason to monitor | Initial response |
|---|---|---|
| HTTPS reachability, certificate validity and real login/task path | A running pod does not establish user access | Check ingress/DNS/TLS/auth with the responsible owners. |
| API liveness versus readiness | Process health differs from dependency/schema readiness | Route process issues to platform/product; route real dependency failures to owner. |
| Worker/runtime health and eligible work progress | API can be healthy while dispatch/parser work fails | Inspect queue age, current grants, worker/runtime and durable job state. |
| Failed, refused, deferred and UNKNOWN jobs/attempts | Detect errors without confusing legitimate refusal with an outage | Classify reason; reconcile ambiguous outcomes before retry. |
| SQL/Redis availability, TLS/ACL errors, capacity and persistence | Loss of state or restricted command access can affect correctness | Database/cache owners investigate; preserve prior-ACK evidence. |
| CPU/memory/disk/connections, parser/staging/evidence quotas | Prevent overload and failed cleanup | Respect limits, stop new work if necessary; never remove isolation to restore throughput. |
| Backup success and separately rehearsed restore status | Backup completion does not prove recovery | Escalate failed backup or overdue restore proof to accountable owner. |
| Credentials/certificates/approved-evidence expiry | Expired trust or authority can refuse valid-looking work | Arrange reviewed rotation/renewal, not TLS bypass. |
| Unauthorized attempts, role/membership changes and sensitive access | Protect bank data and decision authority | Bank SOC reviews and follows the existing incident procedure. |
| Coverage/freshness gaps and unavailable required evidence | A quiet system is not a clean estate | Notify application/data owner; do not fabricate observations. |
| Monitoring pipeline failure, missing heartbeat or undelivered alert | The monitor itself can fail | Invoke alternate checks/contact path; do not infer silence means health. |

Use correct API readiness semantics and supported routes; see the
[deployment guide](BANK-ON-PREMISES-DEPLOYMENT.md#17-health-readiness-and-browser-verification).
A login/SPA HTML 200 must not be recorded as JSON readiness. Retain signal scope,
actual collection times and blind spots. Do not enable refused product notification
or realtime adapters to implement this table.

An expected production-profile refusal is not automatically a software fault.
Investigate why it happened. Unexpected authorization loss, repeated failure or
blocked critical work still needs an accountable response.

## 6. Daily bank operating routine

Continuous alerts need human handover and routine inspection:

1. Review open incidents, unsuccessful alerts and service/dependency health.
2. Check failed/UNKNOWN work and oldest queued/deferred items; identify impact.
3. Confirm backups, storage headroom, expiry and required scheduled infrastructure tasks.
4. Check that admitted source work has durable evidence and current expected coverage.
5. Review suspicious access and privilege changes under the bank's security procedure.
6. Assign every actionable exception to an owner with an agreed next update.
7. Hand over unresolved issues, current maintenance and contact responsibility
   to the next staffed shift/backup. Record receipt of the handover.

The bank may automate collection through approved tools, but a successful script
or a quiet dashboard cannot replace ownership. Keep diagnostic details restricted
and never paste passwords, tokens, connection URLs, private keys or raw bank
source into public tickets or logs.

## 7. Our team's weekly review: detailed agenda

The weekly slot is a **review**, not an automatic production installation.
Agree the actual calendar/timezone and backup attendees in the operating charter.
The named lead prepares a sanitized status summary using bank-approved access.

### 7.1 Before the review

- Obtain the bank's open issue list and scoped diagnostics through approved channels.
- Confirm the currently installed exact version/digests and package/configuration identity.
- Check outstanding incidents, workaround expiry, failed changes and prior action items.
- Review available maintained releases, applicable advisories and dependency/support status.
- Ask permission before any remote session, data extraction or test that affects the bank.

### 7.2 During the review

| Topic | Required discussion/output |
|---|---|
| Availability and monitoring | Actual outages/degradation, missed alerts, response timeline and monitoring blind spots—not an invented uptime percentage. |
| Error review | Recurring exceptions, failed/UNKNOWN jobs and root-cause evidence; distinguish product, configuration, infrastructure and authorization issues. |
| Data/evidence quality | Freshness, incomplete receipts, unresolved six-BOM relationships and misleading status/reporting. |
| Capacity | Queue age, resources/storage growth and agreed measured operating envelope; no unsupported scale extrapolation. |
| Security/expiry | Applicable vulnerabilities, anomalous access, certificates/keys/approvals nearing expiry and permitted remediation. |
| Backup/recovery | Actual backup results, restore/exercise evidence, unresolved loss/recovery limitations. |
| Updates | Whether a release applies, what it changes, required compatibility/security testing and proposed maintenance window. |
| Access and operations | Temporary-access closure, owner/backup changes, procedure acknowledgements and overdue exercises. |
| Prior actions | Evidence that a fix actually worked; blocked items keep accountable owners and dates. |

### 7.3 After the review

1. Publish a bank-approved summary in the existing restricted support/change system.
2. Assign each action to our team or the correct bank owner; agree next update/review.
3. State whether the action is investigation, fix, test, approved change or accepted closure.
4. Record upgrade proposals separately; do not deploy because a newer version exists.
5. Verify all temporary sessions/access are closed and sensitive support material
   has approved custody/retention.
6. Escalate a newly identified urgent issue immediately rather than defer to next week.

If the review is missed, the backup lead arranges a replacement and communicates
outstanding risk. A holiday, absent vendor engineer or missed call is not an
acceptable explanation for leaving an active incident unowned.

## 8. Incident priorities and escalation

Use the bank's actual severity policy. This suggested mapping explains routing;
it does not assign contractual deadlines or automatically change product API states.

| Class | Example impact | Required handling |
|---|---|---|
| Critical security/integrity | Suspected cross-estate exposure, leaked secret, unauthorized execution, corrupted evidence or false verification | Immediate bank incident response; restrict/stop affected activity under authority, preserve evidence and invoke the agreed urgent support route. Do not wait for weekly review. |
| Critical availability/recovery | Required service unusable, data recovery uncertain or critical acknowledged work potentially lost | Bank on-call/platform/database response and incident commander; escalate product involvement as agreed. |
| Significant degradation | Repeated job failures, sustained queue growth or impaired critical workflow with limited workaround | Prompt triage under agreed support objectives; track impact and safe workaround, not silent postponement. |
| Routine defect/maintenance | Noncritical display issue, documentation correction or planned supported update | Track and prioritize in routine support/weekly review unless impact worsens. |

If vendor support is closed or unreachable, the bank's documented alternate
on-call/containment/recovery path still applies. Do not promise an unstaffed vendor
will respond instantly. Any around-the-clock vendor commitment requires separately
agreed staffing, rehearsed escalation and service/legal approval.

Detection, acknowledgement, triage, mitigation, recovery, permanent resolution and
independent verification are different timestamps/states. Report each honestly;
acknowledging a ticket is not repairing the product.

## 9. Error-to-fix procedure

1. **Capture:** record actual time/timezone, impact, installed release/profile,
   owning job/attempt reference and restricted secret-free diagnostic evidence.
2. **Triage:** bank owner decides severity, scope, affected users and safe containment.
   Preserve original results and history, including failed attempts.
3. **Reproduce:** our team uses approved sanitized/minimal fixtures in a non-production
   environment. No customer data transfer or production experiment without authorization.
4. **Assign cause/owner:** product defect → our engineering; deployment/dependency
   configuration → bank owner with our guidance; unsupported/unauthorized scope →
   maintain refusal and explain the boundary. More than one team may be involved.
5. **Fix:** prepare the smallest reviewed change with a regression for the actual
   failure. Never remove estate checks, TLS, receipts, isolation or required tests.
6. **Verify before production:** test the adverse case, affected existing workflow,
   supported dependencies and compatibility. Retain exact-candidate results.
7. **Authorize/deploy:** use the bank's normal or emergency change procedure and
   independently verified package—not an unreviewed edit in a running container.
8. **Confirm:** verify health, durable data/receipts, access and the original failing
   journey; bank reviewer accepts recovery and any remaining limitations.
9. **Prevent recurrence:** retain root cause, regression, procedure/monitoring
   follow-up and different review. Keep recurring issues visible in the next review.

A process restart is a possible approved mitigation, not proof of root cause or
safe recovery. UNKNOWN external effects require the existing human reconciliation;
do not blindly retry, release reservations or reset SQL job states.

## 10. Updates and patching: review weekly, deploy with approval

Our team reviews relevant releases/advisories weekly and urgently when an incident
or security bulletin warrants it. The bank decides the actual change window and
risk; weekly reviews do not force weekly updates or permit unattended downloads.

For any accepted update:

1. Bind exact source/dependencies/images, supported profile and compatibility.
2. Assess applicability, security impact, migration and bank blackout constraints.
3. Test in bank-approved staging with representative sanitized input and negative cases.
4. Prepare the signed full operator package and independently verify trust/inventory.
5. Back up and rehearse recovery; agree stop criteria, operator and different witness.
6. Quiesce producers and coordinate API/worker/frontend/parser versions under the
   reviewed procedure. Do not assume zero-downtime rolling upgrades are qualified.
7. Deploy in the approved window; verify actual images/schema, readiness, data
   integrity and the relevant critical workflow before resuming work.
8. Retain bank acceptance, unresolved issues and requalification triggers.

For the current reviewed build, migration head is **0106**; never relabel UNKNOWN
or release its reservations to force downgrade. The earlier0105 long-event guard
also remains: do not truncate event history
to force a downgrade. Use tested compatible forward recovery where required.
Emergency changes follow the approved expedited process; urgency does not remove
bank authorization, independent review, evidence retention or post-change checks.
Air-gapped updates use the same reviewed offline transfer/signature/digest discipline.

### Published quality patch to assess, not auto-install

The quality corrections in source commit `2fd8fc8f` are available on the current
PR branch. They are **not** a signed operator release or a bank deployment. During
weekly review, assess the [current quality-source handoff](runbooks/evidence-assurance-upgrade.md#current-quality-source-handoff-2fd8fc8f)
against the bank's actual version and evidence; use the urgent incident path
instead of waiting a week if active security/integrity impact is suspected.

Plan for explicit source-proof/package refusal, role-store 503 and invalid-identity
403, safe health categories, actual offline-profile requalification, and the rebuilt
frontend's system-font fallback. Do not patch history to clear a refusal, request
raw connection/SQL logs or bypass current authority. Preserve the normal signed
package, staging, bank approval and independent validation process above. This
source update adds no migration beyond the existing 0105 contract and no SLA.

## 11. Remote support and sensitive evidence

Default to bank-controlled diagnosis and approved sanitized evidence. If remote
support is authorized, use the bank's approved access mechanism, actual named
accounts, least privilege and an expiring session. Record approval, purpose,
actions, permitted data and closure. Bank policy governs MFA, session supervision/
recording and emergency access; this document does not claim they are configured.

Do not establish permanent tunnels, shared admin passwords, unsolicited telemetry,
auto-uploaded diagnostics or broad access to another estate. Public GitHub issues/
PRs may contain sanitized code/defect descriptions only—not raw bank source,
customer identities, secrets, confidential infrastructure or restricted incident reports.

A support engineer must not accept their own production change or customer outcome.
Independent security-assessor review remains distinct from vendor support review.

## 12. Maintenance and service health records

Use the existing nine-duty operational ownership model, not a new dashboard or
service. Named primary/backup humans acknowledge retained procedures and perform
fresh actual exercises with a different reviewer. Weekly checks are useful
support activity; they do not automatically fulfill every required restore,
incident, rotation or offboarding exercise.

Preserve procedure changes, owner replacements, missed exercises, actual failures
and review deadlines. New owners/configuration/release/trust or expiry can
invalidate prior assertions. Historical acceptance remains in history without
pretending it is still current.

See [operating ownership](bank-environment/57-operational-ownership-and-demonstrated-service.md)
and [launch handoff](runbooks/launch-assurance-handoff.md).

## 13. Weekly review record template

This is an unexecuted worksheet for the bank's existing restricted support system,
not a default successful report or an API payload.

```text
Review state: NOT_PERFORMED
Bank-approved site/estate/release/profile:
Agreed weekly slot, timezone and backup arrangement:
Actual review date/start/end:
Bank service/SOC/platform/database attendees:
Our support lead and backup:
Open incidents, impact and actual current status:
Monitoring/alert-delivery gaps and daily handover issues:
Errors/jobs/UNKNOWN outcomes reviewed (restricted references):
Evidence quality, freshness and resource/storage observations:
Backup/restore, rotation and operating-exercise status:
Applicable release/advisory review; no automatic deployment:
Actions: owner / proposed priority / agreed next update / evidence required:
Proposed normal/emergency changes and bank approval references:
Verification/closure decisions and different reviewer:
Temporary access granted/revoked and support-data retention:
Unresolved blockers and escalation owner:
Next agreed review / requalification triggers:
```

Do not invent measured uptime, response time, repair completion or actual people
in this template. Populate it only after authorized work has occurred.

## 14. Operating-model acceptance before go-live

The bank and our team should rehearse: alert reaches a real bank operator;
primary absent → backup receives handover; vendor unavailable → alternate path
works; urgent issue → immediate permitted containment; routine issue → weekly
tracking; exact tested fix → approved staged update → verified recovery; temporary
support access → revoked. Include failed alert delivery, dependency outage and
UNKNOWN job reconciliation in approved disposable tests.

Until actual staffing, routes, procedures, exercises and required site/security/
customer gates are accepted, report **planned 24/7 operating model—not a
qualified 24/7 service**. A running installation or weekly calendar invitation
cannot itself establish production readiness, regulatory compliance or an SLA.

Related documents:

- [On-premises deployment and recovery](BANK-ON-PREMISES-DEPLOYMENT.md)
- [Quality-only operations and qualification](product-improvement/07-operations-and-bank-qualification.md)
- [Operator installation/upgrade/recover](runbooks/operator-install-upgrade-recover.md)
- [Existing operational ownership contract](bank-environment/57-operational-ownership-and-demonstrated-service.md)
- [Current production-readiness gate](../PRODUCTION-READINESS.md)
