# 3.1 — Durable partial-progress evidence

## Why the completed-result receipt was insufficient

A final batch result can be rolled back after host A answered, policy refused
host B, and host C was never tried. Returning no findings in that situation
would discard the most important distinction: **not observed is not clean**.

`collection_phase_receipts` now records the approved endpoint/phase plan before
metering/contact, then durably checkpoints admission refusal, attempt and bounded
observation before the next phase. Final inventory projections remain atomic,
but their rollback cannot erase already committed per-phase observations.

| Receipt state | Meaning |
|---|---|
| `NOT_ATTEMPTED` | Planned; collector not entered |
| `REFUSED` | Current admission denied this phase; no collector invocation |
| `ATTEMPTING` | Durable checkpoint written before collector; no result yet |
| `UNKNOWN` | Interrupted/error or terminal job with an unfinished attempt; never assumed successful |
| `COMPLETED` | Collector returned and its observation was stored; requested fact can still be absent/failed |

There is no automatic replay of an interrupted phase. SHA-256 commits the
bounded stored observation, not a claim of independently verified network truth.
Observation payloads over 64 KiB refuse completion instead of silently truncating.
The plan is unique and bounded at 10,000 phases. Planned scope cannot be finalized
as a completed batch while any phase remains unprocessed/refused/unknown.

## Four separate conclusions

1. **Recording completed:** the final result/job receipt was committed.
2. **Observation succeeded:** the requested fact was actually returned. SSH
   `status=OK` with an empty key/algorithm list is not enough.
3. **Collection complete:** the approved plan was processed and the batch
   completed. A timeout can be a processed phase without successful observation.
4. **Posture acceptable:** independent policy assessment; this receipt leaves it
   `null`, not PASS. A good key exchange does not erase a weak host-key finding.

Successful SSH responses persist `collection_conclusions`; completed job progress
keeps the same separation. `GET /api/v1/assurance/collections/{job_id}` includes
partial stored observations, failure/refusal reason codes and untouched scope.
A process killed before its final stamp can leave RUNNING/ATTEMPTING; both are
explicitly incomplete. Existing reaping can make the job terminal, at which
point unfinished attempts project UNKNOWN. This is not exactly-once collection.

## Practical interrupted batch

Approved plan: `host-A/host_keys`, `host-A/kex`, `host-B/host_keys`, `host-B/kex`.
After the first observation, emergency stop changes current policy:

```text
A host_keys  COMPLETED   stored observation retained
A kex        REFUSED     CURRENT_ADMISSION_REFUSED
B host_keys  NOT_ATTEMPTED
B kex        NOT_ATTEMPTED
recording_completed=false
collection_complete=false
posture_acceptable=null
```

The final network inventory projection can be absent while A's receipt survives.
Failures to create the initial durable job prevent collection. A storage failure
before a phase checkpoint prevents entering that phase. Failed result storage
never returns a successful HTTP result.

This implementation is wired into SSH's existing admission/receipt flow, not a
parallel collector or new identity model. Other collectors do not automatically
inherit a phase plan. Controlled production still refuses SSH execution until a
qualified execution profile exists; metadata/history access does not bypass it.

See the [upgrade runbook](../runbooks/evidence-assurance-upgrade.md).
