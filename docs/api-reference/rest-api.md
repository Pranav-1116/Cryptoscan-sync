# REST API

Base path: `/api/v1` (also mounted at `/api`). Interactive docs: `/api/docs`.

## Auth

`POST /auth/login` `{username, password}` → cookie `cryptoscan_session` and `token`.

Send `Authorization: Bearer <token>` or rely on the cookie.

## Scans

- `POST /scans/trigger` `{repo_url, branch?}` → 202 `{job_id}`
- `GET /jobs/{job_id}`
- `GET /scans`
- `GET /scans/{scan_id}`
- `GET /scans/{scan_id}/findings`
- `GET /findings/{evidence_id}`
- `GET /drift`
- `POST /drift/{id}/acknowledge`
- `GET /stats/summary`
- `POST /baselines/approve`
- `POST /webhooks/github`

Default login: `admin` / `cryptoscan`.
