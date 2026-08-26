# REST API

Base path: `/api/v1` (also accepted by some clients as `/api` when a reverse
proxy strips the prefix). Interactive docs: `/api/docs`.

## Auth

`POST /auth/login` `{username, password}` → cookie `cryptoscan_session` and
`token`. Send `Authorization: Bearer <token>` or rely on the cookie.

Default login: `admin` / `cryptoscan`.

`GET /discovery/plugins` lists registered source scanners (`static-java-scanner`, `static-python-scanner`, `static-js-scanner`, `static-csharp-scanner`).

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
- `GET /systems` / `POST /systems` / `GET /systems/{id}` / `PATCH /systems/{id}`
- `POST /systems/import` `{csv|systems}` CMDB bulk register
- `POST /systems/{id}/scan` queue a CBOM scan for that system
- `POST /systems/{id}/assets` / `POST /systems/{id}/dependencies`

## Policy, drift, container, CBOM

- `GET /policy/rules`
- `GET /drift` / `POST /drift/{id}/acknowledge`
- `POST /baselines/approve`
- `GET /stats/summary`
- `GET /container/scans` / `POST /container/scan`
- `GET /vulns`
- `GET /cbom` estate catalog (paginated; includes coverage)
- `GET /cbom/coverage` unknown vs scanned systems
- `POST /cbom/scan-uncovered` `{limit?}` queue scans for systems without a current CBOM
- `GET /cbom/search?q=` find an algorithm or path across systems
- `GET /cbom/portfolio` org-wide CycloneDX 1.5 CBOM
- `GET /cbom/scan/{scan_id}` / `GET /cbom/system/{system_id}`
- `POST /cbom/custom` `{asset_ids, include_vulnerabilities?}`
- `POST /cbom/validate` `{bom}` / `POST /cbom/ingest` `{bom, system_name?}`
- `POST /cbom/diff` `{left:{system_id|scan_id|bom}, right:{…}}`
- `POST /webhooks/github`

## Agility, exceptions, OT, analytics, vendors

- `GET /agility` / `GET /systems/{id}/agility` / `POST /systems/{id}/agility/recalculate`
- `GET /readiness`
- `GET /exceptions` / `POST /exceptions` / `POST /exceptions/{id}/approve|reject|revoke|review`
- `POST /exceptions/expire-due`
- `POST /ot/scan` / `GET /ot/devices` / `GET /ot/findings`
- `GET /analytics` / `trends` / `heatmap` / `forecast` / `recommendations` / `executive`
- `GET /vendors/{id}/questionnaire` / `POST /vendors/{id}/questionnaire|cbom|docs`
- `GET /vendors/{id}/risk` / `GET /vendor-risks`
- `GET /network/due` / `POST /network/run-due` / `GET /certificates/{id}/usages`

`repo_url` may be a git URL, `local://demo/polyglot-app`, or a `cloud://aws/<account>` target.

## Cloud estate

Live AWS/Azure/GCP APIs never run unless `live=true` or `CRYPTOSCAN_CLOUD_LIVE` is set. Registering an account is not a scan.

- `POST /cloud/scan` `{path, live?}` IaC preview (no persist)
- `POST /cloud/inventory` `{path?, live?, persist?, account_id?}` persist IaC as systems; `live=true` queues **one CLOUD job per account**
- `POST /cloud/accounts/{id}/inventory` `{live?}` same, for a registered account
- `GET /cloud/accounts` / `POST /cloud/accounts`
- `POST /estate/campaigns` `{limit? 25..100, dry_run?, include_cloud?, include_git?}` coverage campaign
- `GET /estate/campaigns` preview the same plan

Campaigns never enqueue a job per KMS key. Cloud systems share one `CLOUD` job per provider account. Worker skips git clone for `job_type=CLOUD`.
