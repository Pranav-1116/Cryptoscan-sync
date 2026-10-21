# 4.1 — Operator decisions: attention, evidence, coverage, owner and verification

Implemented engineering surface, 2026-10-21. Open `/operator-decisions` from the
Overview navigation. The API is `GET /api/v1/assurance/operator-decisions`.
It is an exact-selected-estate read model, not a cross-bank administrative view
and not another aggregate risk score. It remains inside the existing admitted
assurance metadata boundary; no live acquisition adapter was enabled.

## The five decisions

| Operator question | Concrete surface | What it does not imply |
|---|---|---|
| What needs attention? | Assigned finding tasks; failed/unknown/deferred/queued/running jobs; unsettled execution attempts; approval validity; reported changes and condition proofs | An empty page is not an estate-wide clean result |
| What supports it? | Original finding/scan/job IDs, immutable change and proof hashes, expandable retained before/after histories | A ticket/reference is not an independent observation |
| How complete/fresh? | Independently registered denominators, owner completeness assertion, per-kind coverage counts, target last attempt/success/expiry, explicit NOT_ATTEMPTED/STALE/BLOCKED | Fresh observations of registered targets do not establish that the register is the whole bank |
| Who acts? | Task's assigned owner, job initiator, approval authority, change owner; missing task owner is UNASSIGNED | An owner string is not external identity-system attestation |
| What verifies a fix? | Approved machine predicate (exact site/replacement algorithm or exact TLS endpoint/replacement SHA256), collection receipts and a later independent completed observation | Reporting completion or closing a task cannot satisfy the predicate |

Every section is paginated. Job/task pages have deterministic timestamp/ID
ordering and estate/page indexes. Coverage displays counts for each selected
register and up to 25 attention targets; use the full registered-coverage action
to inspect all its targets in the selected estate. Five registers are shown per
coverage page. **No displayed page claims to be the whole estate.** Offset pages
are not a transactionally frozen export: new inserts may shift later pages;
return to the first page during incident reconciliation.

## Failure/uncertainty handling

- **FAILED jobs:** show the failure and require inspection of collection coverage;
  retry through the original admitted route, not a generic network-job replay.
- **UNKNOWN outcomes:** explicitly reconcile external effects and the execution
  fence before retry/freeing reservations. Timeout/deadline is not cancellation.
- **QUEUED/DEFERRED/RUNNING:** show queue wait, execution age and stage, without
  pretending that observation happened. These are ages, not queue-capacity SLOs.
- **Stale approvals:** revoked, expired/unknown expiry, stopped/missing/changed
  policy are visible. The actual execution path remains the authority. The inbox
  does not reconstruct grants or renew a stale approval.
- **Replay reset/retention gap:** clear/reconcile the view from SQL, display the
  gap until a fresh SQL read is acknowledged. SSE is only a hint, never proof.
- **Unavailable backend/admission:** clear the old successful decision view and
  display failure. No demo/zero-risk substitute and no persistent response cache.
- **Changed tenant/auth:** abort reads and mutations, clear evidence/form state,
  ignore late results from the old generation, and re-read under the new scope.
  Never render the previous estate while a new estate request is pending.
- **Interrupted mutation:** do not assume success and do not auto-retry. Read the
  immutable history before retrying with the current expected revision.

## Reconciliation and browser bounds

At most one poll is in flight; reads time out after 15 seconds. Full SQL reads
run every 30 seconds while visible; hidden tabs stop scheduling collection and
reconcile on becoming visible. Data is replaced, not appended to an unbounded
history. Detail reads and mutations are aborted/ignored on estate/auth change.
No response is shared across estates or persisted in browser storage. Full
reconciliation on every poll also catches events lost outside the SSE replay
window; there is no event-only incremental inventory shortcut.

The new UI has a 24-hour **simulated timer/lifecycle** regression test (2,880
poll periods), tenant-race, replay and unavailable-data tests. This is **not** a
24-hour real browser run, JS heap profile, accessibility certification or
low-bandwidth production endurance result. See [measured workloads](55-measured-workloads-and-capacity-limits.md).

## Practical operator path

1. Select the intended estate and open Operator decisions.
2. Review independent coverage before treating a high-priority task list as
   representative. Resolve missing owner/permission/freshness evidence.
3. Inspect failed jobs and UNKNOWN attempts before submitting more collection.
4. Create an assigned task from an owned source finding, then propose its exact
   replacement condition, owner, expiry and change reference.
5. Have a different authorized reviewer approve it; report actual completion.
6. Collect a new admitted scan **after** the reported change, then verify using
   that scan ID and current proof revision. Inspect the retained comparison.
7. Accept only the predicate actually observed; an unresolved or stale condition
   remains a decision item, not a closed-ticket success.

See [condition verification](54-independent-remediation-verification.md) and the
[install/upgrade/recovery runbook](../runbooks/operator-install-upgrade-recover.md).
