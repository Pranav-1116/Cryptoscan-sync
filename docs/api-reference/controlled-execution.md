# Controlled execution API

**2026-10-21 · migration `0102` · supported adapter `local-source/v1`.**
See [the upgrade/qualification runbook](../runbooks/controlled-execution-upgrade.md)
before deployment. Production has a deliberately restricted API allowlist; the
[full generated schema](rest-api.md) is not a promise that every route is enabled.

## Identity, permission and ownership

Normal session/Bearer or API-key authentication applies. Pre-0102 sessions must
sign in again: a legacy username-only session is not backfilled into authority. The server resolves the
selected estate from durable identity/membership state. A platform administrator
may select an authorized estate with `X-Tenant-ID`; omitting selection addresses
**only platform/NULL-owned history**, never all tenants.

Policy, provider limits, approvals, stop and reconciliation require the current
`platform.configure` permission and a real active **human** user. API keys cannot
perform those operations, even if their role would otherwise permit them.
Provider-budget/global-stop and product-wide ownership-register operations also
require platform estate context, not a bank selection. Reads require current
authentication/estate access; control records always use an explicit owner filter.
Private approvals, attempts, events and job/scan history additionally require
matching configured node region/evidence destination. A stop still allows
in-region incident/history access. Bootstrap policy and ownership-review
metadata have their separate administrative access contract.

Neither owner, principal type/ID, credential incarnation nor approver may be
supplied as trusted enqueue identity. Mutation bodies reject unknown fields,
including forged `tenant_id` and actor fields. An approval's `subject_id` is an
explicit authorization *target*, resolved and checked by the server, not an
impersonation instruction.

## Operations

All paths below are relative to `/api/v1/execution-controls`.

| Method/path | Meaning |
|---|---|
| `PUT /provider-budget` | Platform-human provisioning of shared source-provider capacity and rolling launch rate; a later explicit update resumes a provider stopped at capacity zero |
| `POST /emergency-stop` | Platform-human global source stop; retains live reservations and requires explicit resumption |
| `PUT /policy` | Version-CAS estate/legal entity, runtime/destination/limit policy; `expected_revision=0` creates, current revision replaces |
| `GET /policy` | Selected estate policy; no fallback to a platform policy |
| `POST /approvals` | New immutable approval revision/ID; optional `supersedes_id` atomically revokes an owned previous revision |
| `GET /approvals?limit=100` | Exact-estate bounded approval history, including revoked revisions |
| `POST /approvals/{approval_id}/revoke` | Revoke this estate's approval; missing/foreign is 404 |
| `GET /attempts?limit=100` | Exact-estate bounded attempt/checkpoint/outcome history; no fence token/shared budget identifiers |
| `POST /attempts/{attempt_id}/reconcile` | Human external-outcome confirmation; releases retained reservations once, does not resume the old job |
| `GET /events?limit=100` | Exact-estate durable governance/reconciliation receipts; not an independently tamper-proof audit chain |
| `GET /ownership-register` | Platform-only SQL table/legacy-NULL counts and external-store review inventory; every classification remains unreviewed until independently assessed |

List limits are 1–200. These bounded lists are not complete archive exports.
No API edits immutable approval contracts in place. Supersession uses a new
record ID plus `supersedes_id` and the policy revision/destination snapshot.

## Practical sequence

These JSON examples use illustrative names; replace subject/estate IDs with
actual durable records obtained through your authorized administrative workflow.
Never create guessed credentials or copy bearer secrets into documentation.

1. In platform context, `PUT /provider-budget`:

   ```json
   {"capacity": 4, "requests_per_second": 10}
   ```

2. Select the bank estate and `PUT /policy`:

   ```json
   {
     "expected_revision": 0,
     "legal_entity": "Bank India operating entity",
     "execution_region": "in-south",
     "evidence_region": "in-south",
     "evidence_destination": "regional-sql-a",
     "capacity": 2,
     "requests_per_second": 5,
     "max_runtime_seconds": 120,
     "stopped": false
   }
   ```

   Response revision starts at 1. A stale `expected_revision` returns 409.
   Region/destination values must match exported node bindings at execution and
   private-history read time. A policy update invalidates old approval bindings.
   This is declarative enforcement, not discovery of actual storage geography.

3. In the same selected estate, `POST /approvals` for an approved absolute
   directory under `CRYPTOSCAN_SOURCE_ROOTS`:

   ```json
   {
     "target": "/srv/approved-sources/payments",
     "profile": "local-source/v1",
     "subject_kind": "user",
     "subject_id": "replace-with-existing-executor-user-id",
     "not_before": "2026-10-21T08:00:00Z",
     "expires_at": "2026-10-21T09:00:00Z",
     "max_requests": 10,
     "evidence_ref": "change/BANK-123"
   }
   ```

   Dates are illustrative, **not a reusable approval**. Supply a current approved
   window with explicit timezone, positive duration and at most 30 days. Target
   matching is exact (including spelling/scheme), not arbitrary prefix matching.
   Remote URLs, CIDRs, archive/image imports and requested Git commit attestations
   are not this adapter. Supported subjects are `user`, `api_key` or `repository`;
   non-human subjects must resolve to an owned durable configuration/incarnation.
   A human cannot approve their own user identity. Retain the returned approval ID.

4. Authenticate as the approved executor and `POST /api/v1/scans/trigger`:

   ```json
   {"repo_url": "/srv/approved-sources/payments", "scan_mode": "safe"}
   ```

   The server selects exactly one currently matching approval and pins it,
   trusted original credential identity and execution destination. Overlap is
   refused, not resolved by choosing the newest grant. Revoke or supersede stale
   revisions first. `202` means job/outbox committed, **not parser started or
   transport delivered**. Poll the returned `/api/v1/jobs/{job_id}`.

5. `GET /attempts` exposes `RUNNING`, `SUCCEEDED`, `UNKNOWN` and `RESOLVED`
   attempt states. SQL job status can be **UNKNOWN**; clients must not interpret
   an unfamiliar status as successful or retryable. Ordinary failure before
   execution can still be FAILED without an attempt. Capacity/fairness deferral
   stays QUEUED and is reconciled through the outbox.

6. Stop one estate by writing its current policy with next expected revision
   and `stopped=true`; or, in platform context, `POST /emergency-stop` for all
   source-provider work. It is not a guarantee that packets/effects already sent
   were undone. Checkpoint timing and cleanup are described in the runbook.

7. After independently confirming an UNKNOWN attempt's old work stopped,
   `POST /attempts/{attempt_id}/reconcile`:

   ```json
   {
     "resolution": "CONFIRMED_STOPPED",
     "evidence_ref": "incident/BANK-456/confirmed-container-absent",
     "confirm_external_work_stopped": true
   }
   ```

   `CONFIRMED_COMPLETED` is also accepted after external confirmation; it does
   not manufacture completed findings. A duplicate/concurrent reconciliation
   returns 409; a foreign ID returns 404. Retained capacity is released once.
   The old job becomes FAILED/reconciled, never QUEUED. A subsequent allowed
   `/api/v1/jobs/{job_id}/retry` creates a **new** job under the current retrier
   and approval, not the old credential. Unsettled jobs cannot be retried.

## Error and evidence contract

- **401/403:** missing/revoked credentials, insufficient current role/membership,
  machine approver or forbidden platform operation.
- **404:** missing or foreign control detail IDs; no shared NULL history grant.
- **409:** no adapter/approval, overlapping grants, policy/credential revision
  change, stop, mismatched destination, fenced attempt or unresolved outcome.
- **422:** malformed/extra fields, naive/invalid windows and bounded-value errors.
- **503:** history residency/admission/storage dependencies unavailable; no
  successful empty-history fallback. Existing pre-admission validators can have
  their documented 400/500 behavior; do not infer a universal error taxonomy.

Approval `max_requests` and shared request rates count **parser launches**, not
network connections. Provider/estate concurrency is SQL-shared across workers.
Queue transport is at-least-once; an outbox SQL/queue acknowledgment gap can
produce duplicate delivery but cannot authorize a second RUNNING claim. No
exactly-once external-effect claim is made. Operator-supplied evidence references
remain assertions requiring review, not automatic verification of external facts.
