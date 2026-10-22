# 5.2 — Operational ownership before service promises

## Boundary

The Preview Launch readiness workflow records **who is accountable, who backs
them up, what procedure they acknowledged, what exercise they performed and who
reviewed it**. It does not staff the service, execute backups, patch production,
rotate a credential or negotiate a support contract. No real owners or successful
exercises are seeded. An empty estate correctly shows nine unassigned duties.

The bank's service owner must nominate real people and ensure staffing, training,
segregation of duties, escalation access and cover. Assignments use active durable
User IDs, not free-text names. Primary and backup must differ. They must be active
members of the selected estate (or an active platform superadmin); assigning a
user does not grant that user a role or resource access. Eligible accountable
roles are superadmin, CISO, security analyst, developer, auditor and business owner.
Scanner, machine/API-key and readonly identities cannot acknowledge or perform
human operating duties.

## The nine required duties and minimum procedure/exercise content

| Duty | Procedure must establish | Exercise evidence to retain |
|---|---|---|
| `VULNERABILITY_RESPONSE` | Intake/contact, advisory triage, asset/release exposure, severity prioritization, owner, mitigation vs patch, emergency change and retest; unresolved-risk escalation. | A timed synthetic advisory through exact release identification, approved fix, verified replacement and communications. Include missed inventory and supplier delays. |
| `INCIDENT_RESPONSE` | Detection/triage, command authority, containment, emergency stop, evidence custody, investigation, bank/security/privacy/legal notification decision and post-incident learning. | Tabletop plus permitted technical containment test; timestamps, decisions, escalation failures, retained logs and recovery checks. |
| `BACKUP_RESTORE` | SQL, admitted evidence and external objects, configuration, key/secret dependencies, schedule, encryption, retention, isolated restore and reconciliation. | A real isolated restore at the intended site, hashes/counts and access checks, measured restore interval, evidence loss window, failed dependencies and follow-up. A completed backup job alone is insufficient. |
| `CERTIFICATE_ROTATION` | Inventory of endpoint/SNI/STARTTLS paths and trust bundles, expiry watch, issuer/customer approvals, safe rollout, rollback and post-change observation. | Before/after intended endpoint fingerprints and collector receipts; disclose untouched nodes, trust/revocation and client-path limits. |
| `CREDENTIAL_ROTATION` | Secret inventory, least privilege, custody, issuer procedures, overlap/rollback, revocation, application reload and negative tests for old credentials. | Prove new access works and old credentials no longer do, without placing actual secrets in reports, screenshots or logs. |
| `SUPPORT_ESCALATION` | Service hours/timezone, intake, response ownership, bank/vendor contacts, severity thresholds, on-call handover, out-of-hours and prolonged-outage escalation. | A timed escalation exercise including backup availability, acknowledgements and failed-channel handling; distinguish actual measured responses from objectives. |
| `RELEASE_APPROVAL` | Dependency/image pins, signed package inventory, migrations, security checks, operator change approval, rollout verification and rollback/forward-only recovery. | Rehearsed install/upgrade on representative infrastructure, artifact checksums, migration outcome, failed rollout response and witnessed recovery. |
| `DATA_RETENTION` | Data classes, purposes, approved residency, retention clocks, legal hold, archival/export, deletion of primary/derived caches and backup-expiry policy. | Synthetic record lifecycle through scheduled expiry and approved hold; prove derived artifacts and access controls behave as documented. |
| `CUSTOMER_OFFBOARDING` | Written customer authority, exports/custody, identity/session/API-key revocation, scheduled jobs/integrations, evidence deletion/hold, billing/backup dependencies and completion review. | Tenant-specific rehearsal: access revocation, cancelled collectors, export integrity, deletion/hold evidence and a cross-estate negative check. |

These are minimum contents for human review, **not automated validators of the
procedure's operational adequacy**. Upload the reviewed procedure/evidence bytes
through the existing bounded evidence-blob API and keep sensitive/large material
in the bank's approved evidence repository.

## API flow

Relative prefix: `/api/v1/assurance/launch`.

1. A security manager calls `POST /assignments` with duty, distinct active primary
   and backup IDs, procedure blob ID, escalation reference, honest service window,
   future review deadline and exercise maximum age. A stable duty subject ID
   prevents accidental multiple active assignments. `expected_revision=0` creates
   the duty; later values replace it by appending a new revision.
2. Primary and backup **separately** call
   `POST /assignments/{subject_id}/acknowledge` with current revision, evidence
   reference and rationale. Their current durable human sessions must match the
   designated IDs. The assignment remains awaiting acknowledgement until both act.
3. Either designated operator calls `POST /assignments/{id}/exercises` with the
   exact acknowledged assignment revision, actual start/end, evidence blob,
   PASSED/FAILED/INCONCLUSIVE outcome, checks and mandatory limitations. The
   exercise must start after the acknowledged assignment revision was created,
   finish before intake and not have a future timestamp. Optional measured
   recovery seconds cannot exceed the exercise interval.
4. A **different** review-authorized human calls
   `POST /assignments/{id}/review-exercise`. Only a reported PASSED exercise under
   the unchanged assignment can become `REVIEWED_EXERCISE_ASSERTION`. The review
   retains rationale/evidence reference, not a fabricated measurement.
5. `GET /operations` recomputes all nine duties, including unassigned duties,
   missing acknowledgements, inactive/nonmember owners, overdue procedures,
   assignment/exercise mismatch, unreviewed/failed/inconclusive exercises and
   stale exercise age. Replacement procedure/owners reset acknowledgements;
   old exercises and reviews stay historical, never transfer to a new assignment.

Roles are enforced twice for writes: route authorization plus the current typed
human session, live durable user/session and current permission matrix. An API
key or expired/revoked/legacy session cannot impersonate an assigned human.
Assignment and exercise revisions use separate optimistic-concurrency counters;
exercise review uses the exercise's counter, not the assignment's counter.

See [editable templates](../templates/launch/README.md),
[handoff runbook](../runbooks/launch-assurance-handoff.md) and
[independent security assurance](56-independent-security-assurance.md).

## Demonstrated capability → SLO proposal → approved SLA

The API always returns `sla_authorized=false`. Even when
`all_owner_reviewed_records_current=true`, the evidence is a set of current
human-reviewed records, not a contractual SLA. Before commercial/legal approval:

- Rehearse the real supported deployment profile at the customer's site, with
  production-like SQL/Redis, evidence storage, network/identity integrations,
  restrictions, operator staffing and backup/restore dependencies.
- Measure recovery time and recoverable data loss with a witnessed restore;
  retain start/end clocks, inventory and reconciliation, not only a duration in
  a JSON field. Establish RTO/RPO only for the demonstrated deployment/data set.
- Measure service availability, latency, queue delay, support acknowledgement and
  resolution over a stated period, workload distribution and exclusions. A local
  synthetic benchmark or fake-timer browser test is not site capacity/endurance.
- Set realistic internal objectives based on measured capability, margin,
  maintenance windows, staffing and supplier dependencies. Document failure
  response, escalation and review cadence; do not copy an availability number
  from a hosting provider's contract.
- Have the bank service owner, security owner, commercial/legal and delivery
  owner approve the exact service scope and remedies. A pilot acceptance does
  not authorize a whole-bank SLA. Retain external agreement separately; this
  release deliberately provides no “enable SLA” switch.

## Practical ownership handover

At each handover, the incoming operator verifies exact-estate access, current
procedure checksum, recovery environment, escalation contact reachability,
credential/certificate custody boundaries and open risk/incident backlog. They
acknowledge under their own session. If the backup cannot exercise access,
record FAILED/INCONCLUSIVE and escalate; do not check a “ready” box to satisfy a
presentation. Reassignment starts a new acknowledgement/exercise cycle. Preserve
historical evidence under the approved retention policy and record why prior
records are no longer current.
