# Baseline approval

A baseline is a completed scan that later scans of the same target are compared against.

```
POST /api/v1/baselines/approve
{ "scan_id": "...", "notes": "prod freeze" }
```

Or: `python scripts/approve_baseline.py <scan_id>`.

The next scan of that `target_location` writes `drift_events` (NEW / REMOVED / MOVED / UPGRADED / DOWNGRADED).
