# Production go-live checklist

Work top to bottom; every box links the exact command or file. Dedicated host,
docker compose v2.24+ (`!override`/`!reset`), Postgres/Redis/Neo4j not exposed
on the host network.

## 1. Secrets & configuration
- [ ] `cp .env.production.example .env`; fill every required value
- [ ] `python3 scripts/hash_admin_password.py` → `ADMIN_PASSWORD_HASH` (leave `ADMIN_PASSWORD` empty)
- [ ] `SECRET_KEY` / `GITHUB_WEBHOOK_SECRET` = fresh `openssl rand -hex` values
- [ ] `CORS_ORIGINS` = explicit dashboard origin(s) — never `*`
- [ ] Strong `POSTGRES_PASSWORD`, `NEO4J_PASSWORD`
- [ ] Guard check passes: `ENVIRONMENT=production … python3 scripts/check_prod_guard.py`

## 2. Transport
- [ ] Certificates in `deploy/nginx/certs/` (`fullchain.pem`, `privkey.pem`; see the README there)
- [ ] `bash scripts/deploy_prod.sh --tls -d`
- [ ] `curl -sSI https://<host> | head -1` → HTTP/2 200; `http://` → 301

## 3. Post-deploy verification
- [ ] Migrations at head on the real database: `alembic current` shows `0060 (head)` (chain verified on PostgreSQL 16 by `make test-live`; before 2026-09-23 it did not apply on Postgres)
- [ ] Rehearsed on the Docker-free staging stack first: `deploy/staging/staging-up.sh up` then `python scripts/soak.py --cycles 3 --out /tmp/pre-golive` → `cycles_failed: 0`
- [ ] `make smoke BASE=https://<host> USER=admin PASSWORD='…'` (health, ready, metrics, login, BOM/assurance/banking)
- [ ] `GET /api/v1/meta` shows `environment=production`, `docs_enabled=false`

## 4. Data safety
- [ ] `systemd` timer installed: `deploy/systemd/README.md` (`make backup` equivalent nightly)
- [ ] Offsite copy configured (rclone line in the service unit) — **a backup on the same disk is not a backup**
- [ ] First restore drill: `bash scripts/db_restore.sh backups/db/pg-<ts>.dump` on a scratch DB
- [ ] Retention reviewed (`KEEP=14` default)

## 5. Supply chain
- [ ] `make lock` (pin) then `make security-scan` PASS (pip-audit + ruff gate + secret hygiene)
- [ ] `make sbom` → `dist/cryptoscan-sbom.cdx.json` archived with the release
- [ ] pre-commit installed on dev machines: `pip install pre-commit && pre-commit install`

## 6. CI/CD activation (needs a token with `workflows` permission)
- [ ] `cp deploy/ci-workflows/*.yml .github/workflows/ && cp deploy/ci-workflows/dependabot.yml .github/`
- [ ] Commit + push; verify the four workflows on GitHub (ci, scanner-tests, db-migration, docker-build)

## 7. Observability
- [ ] Prometheus scraping `:8080/metrics` (`infra/monitoring/prometheus/prometheus.yml`)
- [ ] Grafana dashboard loaded (`infra/monitoring/grafana/dashboards/cryptoscan_overview.json`)
- [ ] Alert channels configured (`ALERT_WEBHOOK_URL` / `SMTP_HOST` + `ALERT_EMAIL_TO` in the overlay)

## 8. Banking/regulatory readiness (if applicable)
- [ ] Mainframe extracts scheduled (RACDCERT/ICSF/DB2/CICS) → `POST /api/v1/banking/mainframe/ingest`
- [ ] HSM PKCS#11 artifacts loaded (slots/objects text or `/banking/hsm/parse`)
- [ ] FIPS registry seeded from verified CMVP data: `scripts/fips_lookup.py --from <cmvp.csv>`
- [ ] Jurisdiction packs reviewed per legal entity; action-plan export regenerated per reporting cycle
- [ ] SWIFT CSP evidence reviewed (`GET /api/v1/banking/swift-csp`) ahead of attestation window

## 9. Soak evidence
- [ ] 7-day soak on Postgres+Redis staging completed against the release commit and its `REPORT.md` committed under `docs/soak-evidence/` (pass criteria in the README there)
- [ ] `scripts/burn_in.py --target all` with Neo4j, cloud credentials and Docker present — no SKIPs left that the target deployment relies on

## 10. Recovery & change control
- [ ] DR runbook read + drill scheduled: `docs/runbooks/dr-recovery.md`
- [ ] Evidence chain verify scheduled: `scripts/backup_evidence.py --verify`
- [ ] CHANGELOG.md updated per release; VERSION tagged
- [ ] `python3 scripts/release_check.py` PASS (VERSION == API version == `v` tag on HEAD, dated CHANGELOG section, migrations contiguous)
