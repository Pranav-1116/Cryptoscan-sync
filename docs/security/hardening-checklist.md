# Production Hardening Checklist

Work through this before exposing CryptoScan beyond a SOC bastion. Items
marked **[evidence]** produce artifacts an auditor will ask for.

## Secrets & configuration

- [ ] `SECRET_KEY` ≥ 32 random chars, from a secret manager (never in git)
- [ ] `POSTGRES_PASSWORD` from vault/env, rotated quarterly
- [ ] `ALERT_WEBHOOK_SECRET` set (HMAC on outbound alert webhooks)
- [ ] `OIDC_*` settings only if SSO is live; delete unused integrations
- [ ] `.env` files absent from images (`.dockerignore` covers them) **[evidence]**

## Network & transport

- [ ] TLS 1.2+ only at nginx (`deploy/ha/nginx.conf` ships this)
- [ ] HSTS on (shipped), CSP reviewed for dashboard deployments
- [ ] `/api/v1/payment-crypto/` restricted to SOC ranges (template in nginx.conf)
- [ ] mTLS for internal callers enabled at the edge when SOC PKI exists
- [ ] Database/Redis never exposed off the compose network (defaults are correct)

## Accounts

- [ ] No shared accounts; each operator named (audit log maps actions to users)
- [ ] MFA enforced for admin/auditor roles (TOTP + recovery codes built in)
- [ ] Session TTL reviewed; `POST /auth/logout` on SOC workstation discipline
- [ ] Viewer-only accounts for dashboards on wall displays

## Application

- [ ] `ENVIRONMENT=production` (auth + rate-limit middleware active)
- [ ] Rate limits sized (default 60 req/min/user) and alerting on 429 spikes
- [ ] Evidence backup scheduled off-host **[evidence]** (`docs/runbooks/dr-recovery.md`)
- [ ] `pip-audit` clean and archived **[evidence]** (`dependency-audit-<date>.md`)
- [ ] Quarterly failover drill executed and filed **[evidence]**

## Monitoring itself

- [ ] Monitor daemon under systemd/container restart policy
- [ ] Alert sinks tested end-to-end (CEF reaches SIEM, webhook returns 2xx)
- [ ] `GET /api/v1/monitor/status` scraped by uptime tooling; alert if
      `needs_attention` grows or `recent_events` stalls

## Not claimed (do not represent as done)

- Third-party penetration test
- SOC 2 / ISO 27001 certification of this tool
- FIPS-validated crypto modules (stdlib/openssl defaults are used)
