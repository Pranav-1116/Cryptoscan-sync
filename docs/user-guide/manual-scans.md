# Manual scans

In the UI: **New scan** → `local://<authorized-source>` or a `https://github.com/...` URL.

From the CLI:

```
python scripts/trigger_scan.py local://<authorized-source> --inline
```

Poll `GET /api/v1/jobs/{id}` until `COMPLETED`, then open the `scan_id`.

## Current execution authority

The queued descriptor is not a grant. Before any collector the worker reconciles
it with the persisted job, rechecks current initiating authority and policy, and
claims only an eligible QUEUED row. Inline/background execution uses the same
boundary. Disabled users, lost membership, changed/revoked keys, suspended
estates and unpinned legacy jobs cannot continue merely because a job ID exists.

Poll for FAILED/CANCELLED as well as COMPLETED. Do not reset the old row to retry:
an eligible owned `/api/v1/jobs/{id}/retry` creates a new admitted attempt under
the current caller. Recovered RUNNING queue deliveries are refused rather than
automatically replaying potentially completed external effects. Synchronous
network/SSH jobs must be resubmitted through their original route (generic retry
returns 409). See [upgrade/recovery](../runbooks/execution-and-replay-upgrade.md).
