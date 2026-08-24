# Repository configuration

`POST /api/v1/repos` registers a GitHub repository. When no rows exist, every webhook is accepted (development). In production, only `enabled` repos with `scan_on_push=true` are queued.

Webhook: `POST /api/v1/webhooks/github` with `X-Hub-Signature-256`. Signature is required when `ENVIRONMENT=production`.
