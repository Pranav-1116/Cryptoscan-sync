# Resource monitoring API — traffic counters, storage and control drafts

Prefix `/api/v1/resource-monitoring`. Exact selected-estate history context and residency apply. A current typed human session with `assurance.manage` is required to register/import/propose; `assurance.trust` is required to approve/revoke. Readonly/auditor users inspect. Administrators explicitly select the estate. Successful responses use `Cache-Control: no-store`.

[Guide 86](../bank-environment/86-network-traffic-storage-and-control.md) · [Runbook](../runbooks/resource-monitoring.md) · [Evidence](../readiness-evidence/resource-monitoring-2026-10-26.md).

| Method / path | Function |
|---|---|
| POST `/plans` | Register explicit read-only `ResourceScope`; returns immutable draft revision, 201 |
| GET `/plans?cursor=…` | Latest revisions of first 10 subject IDs after cursor; follow `next_cursor` |
| GET `/plans/{id}` | Hash-linked scope history |
| POST `/plans/{id}/approve` | Approve current draft, new revision; not remote-execution authorization |
| POST `/plans/{id}/revoke` | Revoke approved scope, new revision; blocks new work |
| GET `/plans/{id}/authorization` | Current approved scope file for local CLI; does not execute collection |
| POST `/captures` | Validate/store original capture and deterministic report, 201 |
| GET `/captures?cursor=…` | First 10 source-revalidated summaries, sorted by subject ID, not time |
| GET `/captures/{id}` | Original capture and reconstructed report |
| POST `/traffic-proposals` | Save evidence-linked egress-limit draft, 201; never apply |
| GET `/traffic-proposals/{id}` | Reopen original capture and recompute the complete draft payload |

Use returned `subject_id` as the path ID, not the internal revision row `id`. Captures/proposals are write-once; scope history has draft/approval/revocation. No update/delete/apply operation exists for captures or drafts. UI refresh lists the first page; API clients can follow cursors for further records.

## Scope registration

```json
{
  "system_id": "existing-system-id",
  "environment": "prod",
  "host_label": "approved-linux-host",
  "interfaces": ["eth0"],
  "mount_paths": ["/", "/data"],
  "interval_seconds": 5,
  "not_before": "2026-10-26T08:00:00Z",
  "expires_at": "2026-10-26T08:30:00Z"
}
```

Dates/names are illustrative, not a current authorization. Use an existing active same-estate system/environment and an actual window. Maximum 16 interfaces and 16 paths; unique exact names, canonical absolute directories, no wildcards or parent traversal; interval 1–30 seconds; scope window at most one hour. Root directory `/` is valid. Symlinks encountered during collection are gaps, not followed.

Approve/revoke body:

```json
{
  "expected_revision": 1,
  "evidence_ref": "change/resource-review-17",
  "reason": "Approved exact ordinary-user interface and filesystem metadata scope"
}
```

Approval requires current draft and window. Revocation uses the current approved revision, normally 2. Interface/filesystem names are not discovered by the API. Download the authorization file and record its `plan_record_sha256` through the approved channel. The nonce/hash are public integrity/binding data, not source authentication.

## Capture intake

```text
{
  "capture": <complete ResourceCapture JSON from CLI>,
  "expected_capture_sha256": <canonical typed capture digest printed by CLI>
}
```

The capture includes its exact `ResourceAuthorization`, original counter pairs/interface indices, context boot/namespace IDs, monotonic sample duration, ordered network/storage dispositions and UTC capture times. Intake checks the current original approval, scope/hash/nonce binding, capture after approval, no future finish, current system/environment and exact typed digest. Limits: 128 KiB stored capture+report, 16 inputs per surface. Raw packets, commands, unknown claim fields and configuration changes are not accepted.

Digest with `shared_models.host_collection.digest(ResourceCapture.model_validate_json(raw))`, **not** SHA256 of pretty-printed JSON bytes. Preserve uint64 numeric tokens during upload; JavaScript parse/re-stringify can lose integer precision. The UI wraps the original file text and accepts the CLI's canonical digest rather than rebuilding counter JSON.

Network status: `MEASURED`, `UNAVAILABLE`, `DENIED`, `INVALID`, `COUNTER_RESET`, `IDENTITY_CHANGED`. Failed observations cannot contain positive counter pairs. Complete pairs must have consistent index/reset status. Counter rates and deltas exist only for `MEASURED`; unknowns are null, not zero. All selected interfaces receive a disposition in the approved order.

Storage status: `MEASURED`, `UNAVAILABLE`, `DENIED`, `UNSUPPORTED`, `INVALID`. Only measured entries carry nonnegative capacity fields satisfying `available <= free <= total`. Used is `total-free`, not `total-available`; reserved free is separate. Zero total gives null used percent. Paths are not added into a global capacity total.

The returned assurance payload contains `capture` and `report`. `report.capture_sha256` commits the typed source. Report rates use decimal Mbps; storage uses exact integer bytes in the API and approximate GiB display. Link speed/utilization, traffic classification, full coverage, end-to-end packet loss and continuous-live status are not inferred.

## Traffic-limit draft

```json
{
  "capture_id": "11111111-1111-1111-1111-111111111111",
  "interface": "eth0",
  "egress_limit_mbps": 50,
  "reason": "Review a proposed egress cap for the selected interface before any device change",
  "direction": "EGRESS"
}
```

Use an actual capture **subject ID**. Limit range 1–100,000 integer Mbps; the API supports only a draft egress direction. The original capture must be no older than five minutes, have measured data for that exact approved interface, and its scope/system must still admit new work. No link-capacity percentage is invented.

The payload pins `source_record_sha256`, `source_capture_sha256`, observed transmit Mbps and whether that sample exceeded the explicit target. It always has `applied=false`, `enforcement_supported=false`, false management-path/rollback verification and state `DRAFT_REQUIRES_DEVICE_ADAPTER_AND_CHANGE_APPROVAL`. Reading an older draft is historical inspection, not current approval or a clearance to execute.

## Refusals and integrity

- 401/403: missing session/current human permission; readers cannot mutate.
- 404: root resource not in selected estate; nonexistent apply endpoint.
- 409: wrong approval/hash/nonce, duplicate capture ID, stale/wrong/missing interface, revoked/expired scope, inactive/reassigned environment, original chain/report/draft mismatch, controlled-production gate.
- 413: stored capture/report exceeds 128 KiB; no truncation.
- 422: malformed scope/model, unknown fields, wrong status/counter values, future finish or impossible dates.

Audit failures roll back mutations. Plan row locks serialize approval/revocation against intake/draft admission. Historical captures remain inspectable after expiry/revocation; no fresh capture or control authority follows from that. Unsigned integrity does not defeat coordinated rewriting of all evidence/commitments or authenticate a machine/operator return.

## Source and schemas

- [Shared models and deterministic report](../../shared/shared_models/shared_models/resource_monitoring.py)
- [Scope schema](../../shared/shared_models/shared_models/schemas/resource-scope-v1.schema.json)
- [Authorization schema](../../shared/shared_models/shared_models/schemas/resource-authorization-v1.schema.json)
- [Capture schema](../../shared/shared_models/shared_models/schemas/resource-capture-v1.schema.json)
- [Draft schema](../../shared/shared_models/shared_models/schemas/resource-traffic-proposal-v1.schema.json)
- [Read-only collector](../../services/inventory/inventory/resource_monitoring.py)
- [CLI](../../scripts/collect_resources.py)
- [Store adapter](../../services/api/api/assurance/resource_monitoring.py)
- [Router](../../services/api/api/routers/resource_monitoring.py)
- [Network panel](../../frontend/src/components/ResourceMonitoring.tsx)

JSON Schema validates structure; typed-model validation and original approval/source checks also enforce relationships, time ordering and consistency. This API never invokes a network/storage configuration command.
