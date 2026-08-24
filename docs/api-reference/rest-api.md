# REST API

Base path: `/api/v1` (also accepted by some clients as `/api` when a reverse
proxy strips the prefix). Interactive docs: `/api/docs`.

## Auth

`POST /auth/login` `{username, password}` → cookie `cryptoscan_session` and
`token`. Send `Authorization: Bearer <token>` or rely on the cookie.

Default login: `admin` / `cryptoscan`.

## Scans and jobs

- `POST /scans/trigger` `{repo_url, branch?}` → 202 `{job_id}`
- `GET /jobs` / `GET /jobs/{job_id}` / `GET /jobs/{job_id}/logs`
- `GET /scans` / `GET /scans/{scan_id}`
- `GET /scans/{scan_id}/findings`
- `GET /scans/{scan_id}/export` / `export.csv` / `verify` / `verification-script`
- `GET /scans/{scan_id}/cbom`
- `GET /scans/{scan_id}/evidence-pack` / `audit-pack` / `agility` / `work-orders` / `gate` / `gate.sarif` / `materials`
- `POST /evidence-pack/verify` `{pack, secret?}`
- `POST /ci/gate` `{scan_id, require_baseline?}`

## Findings, assets, systems

- `GET /findings` / `GET /findings/{evidence_id}`
- `GET /assets` / `GET /assets/{asset_id}`
- `GET /systems` / `POST /systems` / `GET /systems/{id}`
- `POST /systems/{id}/assets` / `POST /systems/{id}/dependencies`

## Policy, drift, container, CBOM

- `GET /policy/rules`
- `GET /drift` / `POST /drift/{id}/acknowledge`
- `POST /baselines/approve`
- `GET /stats/summary`
- `GET /container/scans` / `POST /container/scan`
- `GET /vulns`
- `GET /cbom/scan/{scan_id}` / `GET /cbom/system/{system_id}`
- `POST /cbom/custom` `{asset_ids, include_vulnerabilities?}`
- `POST /webhooks/github`

`repo_url` may be a git URL or `local://demo/polyglot-app`.
