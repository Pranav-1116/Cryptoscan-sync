# Manual scans

In the UI: **New scan** → `local://demo/vulnerable-app` or a `https://github.com/...` URL.

From the CLI:

```
python scripts/trigger_scan.py local://demo/vulnerable-app --inline
```

Poll `GET /api/v1/jobs/{id}` until `COMPLETED`, then open the `scan_id`.
