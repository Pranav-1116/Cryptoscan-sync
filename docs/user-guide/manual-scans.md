# Manual scans

In the UI: **New scan** → `local://<authorized-source>` or a `https://github.com/...` URL.

From the CLI:

```
python scripts/trigger_scan.py local://<authorized-source> --inline
```

Poll `GET /api/v1/jobs/{id}` until `COMPLETED`, then open the `scan_id`.
