# Runbook — Materialize retained collection snapshots and compare metadata

Use with [Guide 85](../bank-environment/85-shared-collection-snapshots-and-drift.md), [API reference](../api-reference/collection-snapshots.md) and the [engineering evidence report](../readiness-evidence/collection-snapshots-2026-10-26.md).

## Before starting

1. Confirm the exact estate, logical registered target/system/environment and approved collection scope.
2. Complete the existing host or OCI collection workflow. This runbook does **not** authorize targets or execute collectors. Do not rerun privileged collection just to create a snapshot.
3. Use an approved current human account with `assurance.manage` to create records. Auditors/readers can inspect them. Select the estate explicitly when using an administrator account.
4. Use actual job IDs and original source digests. Do not use the illustrative UUIDs/hashes in the API documentation.
5. Do not send credentials, session cookies, bearer tokens, private keys, raw package databases or customer evidence through chat. Keep customer artifacts inside the approved custody/residency boundary.

Production execution admission remains closed for this adapter. Do not disable controls to make these endpoints succeed. The engineering witness uses only disposable synthetic local files and accounts.

## A — Commit the baseline snapshot

- Host source: GET `/api/v1/collection/jobs/{job_id}/evidence`; inspect its original input errors, coverage basis and `envelope_sha256`.
- OCI source: GET `/api/v1/collection/oci/jobs/{job_id}/evidence`; validate the typed original return and compute canonical `.evidence` digest, not a transport-byte hash.
- POST `/api/v1/collection/snapshots` with `family`, `job_id`, `expected_source_sha256`.
- Record returned `subject_id`, `payload_sha256`, `payload.snapshot_sha256`, source hash and original collection time window.
- GET the snapshot with a reader account. The read must reopen the source and reproduce its six views/graph; saving a successful POST response alone is not a later read check.

Baseline selection is an explicit comparison input. Obtain separate business approval if policy requires an approved baseline; this endpoint does not manufacture one.

## B — Commit the candidate

Complete a separately approved later collection through its existing path. Scope changes require normal target update/re-authorization. Do not edit the old intake or snapshot.

Create its snapshot using the new job's actual source commitment. Check:

- same collector family and stable registered logical target;
- same system and environment;
- candidate capture starts at/after the baseline finishes;
- input status/selection differences are visible;
- source authenticity, complete coverage and runtime use have not been promoted.

List snapshots with GET `/api/v1/collection/snapshots?limit=10`, following only returned `next_cursor` values. Listing is bounded and source-revalidated; it is not ordered by time or a global estate inventory.

## C — Commit and inspect drift

POST `/api/v1/collection/metadata-drift` with both actual snapshot subject IDs. Record the new drift `subject_id` and revision hash. GET `/api/v1/collection/metadata-drift/{drift_id}` to reopen both snapshots and recompute.

| Operator sees | Action |
|---|---|
| No changes; nonzero `unchanged_slots` | Metadata facts match within compared scope. Still inspect failed inputs and freshness. This is not whole-estate completeness. |
| `CHANGED_METADATA_RECORD` | Inspect the referenced original facts on both evidence endpoints. Distinguish a version/config change from duplicate record multiplicity. |
| `NEW_METADATA_RECORD` | Investigate newly reported metadata. Do not mark an asset newly installed solely from this event. |
| `NEWLY_OBSERVABLE_METADATA` | Visibility was absent/failed previously. Resolve collection history before attributing a new installation. |
| `UNRESOLVED_COLLECTION_GAP` | Investigate approved source availability/permissions; absence remains unknown. |
| `OUT_OF_COMPARISON_SCOPE` | Review the explicit authorization/input change; do not label omitted assets removed. |
| `NOT_REOBSERVED_IN_PARSED_INPUT` | Review the exact parsed source and prior record. A metadata omission is not proof of physical removal. |

This comparison creates neither a severity score nor a production alert/remediation task. Route findings through the existing reviewed policy/remediation workflows when warranted. Do not use AI to fill missing observations.

## D — Handle refusal without overwriting history

- **401/403:** verify selected estate, current account/session and required permission; do not switch to an unrestricted machine identity.
- **404:** verify the actual subject ID and selected estate. A record in another estate must remain hidden.
- **409 expected hash mismatch:** reopen original retained source and investigate its exact commitment; never patch old stored JSON to force a match.
- **409 nonterminal source:** complete the normal intake/job lifecycle or record the failed collection, rather than inventing a return.
- **409 incompatible comparison:** use snapshots of the same logical target/family/system/environment and nonoverlapping forward capture windows.
- **409 revalidation mismatch:** preserve the response and original IDs; escalate integrity/source closure review. Do not reseal altered JSON or delete snapshots to clear the failure.
- **409 duplicate:** retain/read the successfully created subject ID; do not create revision 2. Identical duplicate writers commit only one materialization and audit record.
- **413 budget:** narrow future approved collection scope under normal authorization. Do not truncate an existing evidence set or silently drop graph nodes to fit.
- **5xx / audit failure:** treat as failure. Inspect transaction outcome with a subsequent authorized read/list; failed audit transactions must not leave materialization rows.

Historical snapshot materialization after revocation does not authorize new work. Handoff/intake continue to enforce their own current admission. Existing source deletion/corruption can make a stored snapshot unreadable; no cached clean verdict is returned in its place.

## Engineering reproduction (disposable sandbox only)

Use approved Python dependencies and the existing service/shared source roots. The checked-in bounded runner configures `PYTHONPATH` for its `--root`:

```bash
python docs/readiness-evidence/collection-snapshots-2026-10-26/run-tests.py models-inventory
python docs/readiness-evidence/collection-snapshots-2026-10-26/run-tests.py graph-drift
python docs/readiness-evidence/collection-snapshots-2026-10-26/run-tests.py workflow
python docs/readiness-evidence/collection-snapshots-2026-10-26/run-tests.py host-compatibility
python docs/readiness-evidence/collection-snapshots-2026-10-26/run-tests.py adapter-compatibility
python docs/readiness-evidence/collection-snapshots-2026-10-26/run-owned-postgres.py
```

These commands overwrite the retained engineering log files in this directory; use a disposable copy, not a protected evidence pack. The workflow suite writes five **public synthetic** witness JSON files. The PostgreSQL helper owns a new local server, creates/drops per-case disposable databases and removes only its temporary data; it never consumes an existing customer database URL. Its output is an engineering contract witness, not a bank review.

For independently selected output in the single synthetic gap test, the test-only `CRYPTOSCAN_COLLECTION_VIEWS_WITNESS_DIR` setting controls artifact retention. It is not a customer capture endpoint or permission to export real evidence.

No new threat-intelligence dashboard, physical asset attestation, actual customer/native-device qualification or SLA is delivered by this runbook. Keep those acceptance decisions separate.
