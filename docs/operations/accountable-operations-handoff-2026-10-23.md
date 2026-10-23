# Step 10 — accountable operations handoff, not an invented SLA

**2026-10-23 UTC.** This improves the existing operating-evidence workflow.
Desired24/7 monitoring and a weekly joint update are intentions, **not evidence
of staffed24/7 service, guaranteed response times or agreed support terms**.
No real customer roster, alert endpoint, support agreement or meeting acceptance
was supplied. Do not claim this step complete until those are actually agreed
and exercised. Sandbox users are synthetic, not appointed bank responders.

## What the existing product enforces and what changed

The existing Launch readiness screen and `/api/v1/assurance/launch/` API retain
nine duties, exact-estate revision-checked assignments, distinct active primary
and backup users, their separate acknowledgements, procedure/evidence hashes,
exercise reports and a different person's review. See the
[launch handoff](../runbooks/launch-assurance-handoff.md) and
[existing templates](../templates/launch/README.md). No new dashboard, pager
service or automatic SLA declaration was added.

Current status rechecks active users, current assignment binding, evidence
availability/integrity, acknowledgement, review deadline and exercise freshness.
This increment shares intake/current interval validation so a clock rollback
cannot turn a future-reviewed assertion into current operating proof. A new
expiry test shows the reviewed historical record remains retained while current
status becomes blocked. Pilot coverage dependency404/409/503 is now explicitly
unavailable with `coverage_counts:null` and a blocker, **not zero coverage or a
false success**; other error classes are not swallowed.

Even when all retained assertions are current, the field is intentionally
`all_owner_reviewed_records_current`, not “production ready” or “24/7 staffed.”
`REVIEWED_EXERCISE_ASSERTION` is not independent runtime proof.
`independent_runtime_proof:false` and `sla_authorized:false` remain explicit.

## Actual appointment register — open, not filled with invented names

Each row needs actual authorized people, not only a team label. The duty owner
may coordinate other specialists, but must acknowledge responsibility and name
who acts if they cannot respond. Real contact details belong in an access-
controlled roster, not a public GitHub document.

| Existing duty | Primary / backup / acceptance | Procedure and operational review |
|---|---|---|
| VULNERABILITY_RESPONSE | **NOT_APPOINTED** / **NOT_APPOINTED** / pending | Intake severity, affected artifact/digest, mitigation, advisory and fix/retest decisions. |
| INCIDENT_RESPONSE | **NOT_APPOINTED** / **NOT_APPOINTED** / pending | Incident authority, containment, evidence protection, bank security contact and urgent route. |
| BACKUP_RESTORE | **NOT_APPOINTED** / **NOT_APPOINTED** / pending | Failed/missing/stale backups, integrity/key access, demonstrated restore and uncertain outcomes. |
| CERTIFICATE_ROTATION | **NOT_APPOINTED** / **NOT_APPOINTED** / pending | Expiry inventory, issuer/hostname/CA chain, overlap, consumers, post-rotation and rollback check. |
| CREDENTIAL_ROTATION | **NOT_APPOINTED** / **NOT_APPOINTED** / pending | Expiring/revoked credentials, least privilege, separate human/service credentials, consumer retest. |
| SUPPORT_ESCALATION | **NOT_APPOINTED** / **NOT_APPOINTED** / pending | Agreed hours/timezone, intake, customer communication and primary→backup escalation. |
| RELEASE_APPROVAL | **NOT_APPOINTED** / **NOT_APPOINTED** / pending | Separate candidate review, source/image/schema evidence, required CI, go/no-go/rollback authority. |
| DATA_RETENTION | **NOT_APPOINTED** / **NOT_APPOINTED** / pending | Legal/regional retention, storage growth, archive integrity and deletion authority. |
| CUSTOMER_OFFBOARDING | **NOT_APPOINTED** / **NOT_APPOINTED** / pending | Revoke access, stop work, export/retention obligations, deletion evidence and residual copies. |

Review sustained API/worker errors, queue/capacity saturation, SQL/Redis health,
storage growth and certificate/credential expiry through incident, support,
backup/retention and rotation owners; do not create a tenth fictional on-call
service just to fill the table. Agree who monitors each signal and who owns its
runbook before enabling notifications.

### Appointment sequence using the existing workflow

1. Agree actual service hours, timezone, holidays, staffing and coverage gaps;
   response/escalation commitments require the team's and bank's explicit
   approval. If24/7 is required, fund/accept an actual rotation and handover plan.
2. Select the exact estate; resolve actual active authorized primary/backup user
   IDs. Keep contact methods and roster access under the bank's controls.
3. Retain reviewed procedure evidence and an escalation reference pointing to
   the controlled roster; populate the existing assignment template with honest
   `service_window`, `review_due_at`, and agreed exercise age. Do not submit
   placeholder text as if an agreement existed.
4. Submit the revision-checked assignment; read the returned record/revision.
   Primary and backup each acknowledge with their own human authority and actual
   evidence reference. An administrator cannot claim they accepted by typing
   their names into a document.
5. Run a permitted exercise, capture actual start/end, receipt/checks, limitations
   and outcome; failed/inconclusive is not PASSED. A different authorized person
   reviews the passed exercise under the unchanged assignment.
6. Read current operating status again; retain blockers and historical evidence.
   New assignment revisions, disabled people, missing blobs, expiry or future
   time invalidate current status. Do not edit historical records into an all-clear.

## Route an actionable alert to an actual responder

This sandbox did **not** send an external alert or establish route reachability.
Do not equate an `escalation_ref` string or a configured webhook with delivery,
acknowledgement, action or a staffed service.

For each existing approved monitoring/notification integration, the owner and
bank must agree and then witness:

1. **Trigger:** failing condition, exact estate/system and severity; include
   artifact/job/attempt or correlation ID, evidence age and uncertainty. An
   unavailable dependency is not an empty healthy estate.
2. **Action:** a short approved runbook link, safe first diagnostic/containment
   step, authority limits and what **not** to replay. UNKNOWN/lost receipt needs
   reconciliation before re-execution, not a retry button loop.
3. **Route:** approved primary intake and independent backup route, controlled
   contact/roster reference, staffed window and escalation authority. Do not put
   tokens, private keys, raw findings or personal contacts in notification bodies.
4. **Proof:** inject an authorized harmless synthetic condition and retain the
   trigger ID, delivery receipt, actual primary acknowledgement, action record,
   resolution/retest and timestamps. Test unavailable route, failed delivery,
   primary absence and backup escalation too.
5. **Follow-up:** a delivery failure or no acknowledgement is itself an incident
   under the agreed escalation path. Record and repair the route, then retest.
   No response-duration guarantee is created by this document.

A useful alert example is: “Selected estate: bank test scope; encrypted backup
job X failed and last verified backup is older than the agreed window. Outcome:
backup not established. Route to BACKUP_RESTORE duty via controlled roster R;
inspect retained job/error and key access using procedure P; do not delete prior
backup or promote an untested replacement. Escalate using the agreed incident
path if protection is outside agreed bounds.” This is an **example**, not a real
bank alert, measured response or predefined contractual backup window.

## Defect lifecycle — reproduction through retest

Use the team's existing issue/incident tracker, not a new product screen:

- Record the symptom, UTC observation, selected estate, actual build/image/schema,
  affected authorization, bounded sanitized reproduction and expected versus
  observed result. Protect customer evidence and secrets.
- Assign a real fix owner/reviewer and agreed priority; attach adverse test or
  independently reproducible evidence. Record temporary containment and limits.
- Implement the smallest demonstrated fix; retain commit/digest, risk assessment,
  required regression result and before/after evidence. A “completed” developer
  declaration is not independent verification.
- Retest the original failure under the intended deployed conditions; capture
  reviewer, environment and outcome. Link any changed risk/rollback boundary.
- Close only under the agreed acceptance authority; recurrent, stale or
  unavailable evidence reopens/escalates current risk without deleting history.

The local examples already have reproduction→fix→retest evidence: missing shell
language control,320px CSS clipping, repeated feedback focus, future operating
proof and re-signed inconsistent release packages. See the
[maintenance record](../readiness-evidence/quality-maintenance-test-trust-2026-10-23.md).
They are not silently presented as resolved production bank incidents.

## Intended weekly joint review and immediate incidents

**Weekly meeting owner, attendees, weekday/time and timezone: NOT_AGREED.**
Agree a bank security/operations representative, our support/engineering lead,
primary/backup duty coverage and escalation authority. Preserve a controlled
agenda/minutes with evidence links and actual actions:

1. Changes since last review: tested source/image/schema revisions and acceptance
   or rollback decisions; identify the user-owned CI failure and release blocker.
2. Failed/missing backups, restore observations and any acknowledged-data loss;
   do not convert tiny lab timings into production RPO/RTO.
3. Error trends, unavailable/partial services, UNKNOWN jobs, retries, delivery
   failures, capacity/storage growth and agreed capacity thresholds.
4. Expiring certificates/credentials, rotation readiness, disabled owners and
   overdue procedure/exercise reviews.
5. Defects: reproduction, owner, fix, deployed version, retest and closure evidence;
   unresolved customer impact and containment.
6. Customer tasks and six-BOM coverage: **SBOM, CBOM, NBOM, TechBOM, HBOM, VBOM**;
   declared data, historical verification and current evidence remain distinct.
7. Named actions, actual agreed deadlines, residual risks and next meeting.

**Urgent incidents must not wait for the weekly meeting.** Once the actual
incident path is agreed, route immediately to the designated responder and
backup/incident authority with bounded evidence, containment authority and bank
notification obligations. Until that path and staffing are agreed, the absence
of responders is a blocker—not permission to claim24/7 response.

## Completion evidence still required

Actual primary/backup appointments and acknowledgements for all duties; agreed
support hours/staffing/response commitments; witnessed actionable alert receipt
and primary/backup response; failed-backup/error/capacity/expiry reviews; tracked
fixes and deployed retests; real weekly minutes and urgent escalation exercise.
No synthetic username, public template, cron schedule or green local test can
substitute for those. **No SLA, uptime target or bank-operational acceptance is
issued by this handoff.**
