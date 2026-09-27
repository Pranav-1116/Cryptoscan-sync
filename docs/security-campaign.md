# Security campaign — internal adversarial sweep

_Ran 2026-09-16 as `services/api/tests/security/test_security_campaign.py`
(7 probes, all passing). This is the automated internal layer of the
security push. It is NOT an external penetration test — no substitute for
one; that remains on the roadmap as a vendor engagement._

## Probes and results

| # | Probe | Result |
|---|-------|--------|
| 1 | **Anonymous sweep** — 9 sensitive surfaces (monitor, systems, findings, usage, attacks, priority, CBOM, API keys, evidence) hit without credentials | ✅ zero data leaks, zero 5xx — every path 401/403 |
| 2 | **Cross-tenant isolation — monitor targets only** (tenant B enumerating/reading tenant A's *targets*, incl. forged `X-Tenant-ID`) | ⚠️ A's targets are *absent* (no existence oracle) and a forged header never promotes visibility — but see the correction below: this probe covered one table, not the estate |
| 3 | **Injection sweep** — 9 payload classes (SQLi stack/union/drop, XSS, path traversal, SSTP, JNDI, encoded NUL) through filters, search and path params | ✅ zero 5xx; store stays functional after `DROP TABLE` attempts (parameterized queries) |
| 4 | **Webhook signature enforcement** — GitHub webhooks unsigned/forged; Stripe webhooks unsigned/missigned | ✅ all refused 4xx; validly-signed GitHub delivery accepted; Stripe never 5xx |
| 5 | **Production boot gate** — `ENVIRONMENT=production` with demo secret, short secret, or weak admin password | ✅ `validate_runtime_settings` refuses every variant (fail-closed) |
| 6 | **Login brute-force limiter** — 6 rapid logins from one source (real middleware, dev-mode install) | ✅ 5×401 then **429** — the 5/min/IP lockout fires |
| 7 | **Session invalidation** — logout then reuse | ✅ post-logout requests refused |

### Correction (2026-09-27) — probe 2 was far narrower than it read

Probe 2 passed continuously while the product leaked the entire scan surface
across tenants, and it is worth being precise about why, because the shape of
the mistake is more instructive than the bug.

`monitor_targets` was one of only five tables that carried a `tenant_id` at
all. The other four were also control-plane (tenants, memberships, api_keys,
control_plane). **Every table holding a customer's actual results** — `scans`,
`evidence_records`, `crypto_assets`, `systems`, `drift_events`, `scan_jobs`,
`container_scans`, `certificates`, `network_scan_runs`, `baselines` — had no
tenant column, and their repositories applied no filter.
`ScanRepository.list_scans()` took no tenant argument. Any authenticated member
of any tenant could read every tenant's findings.

So the probe was not wrong; it was scoped to the one surface that happened to
be implemented, and a green row in this table was read as "cross-tenant
isolation: verified". A security probe that covers 1 of 45 tables must say so
in its own title, which is why the row above now does.

Fixed in the same pass: isolation is now an ORM-level filter
(`db/tenancy.py`) applied to every query rather than a per-repository
argument, migration `0061` adds the columns, and `BaseRepository.get_by_id`
no longer uses `Session.get()` — a primary-key lookup that bypasses loader
criteria and still returned another tenant's row when handed a known id.
Self-serve tenant signup now ships disabled. See `BACKEND-DATABASE-GAPS.md` §1.1
and `services/database/tests/unit/test_tenant_isolation.py`.

**The supported topology remains one deployment per customer** until the
remaining ~30 tables are scoped.

## Evidence from the live deployment (same day)

- Full-surface burn: 360 safe operations exercised, **zero 5xx** under an
  authenticated admin session (`deploy-burn.md`).
- Burst limiter observed shedding 43k–67k excess requests during soak runs
  with **0 errors** (`load-soak.md`) — the throttle is real and protects the
  API tier.
- Signed-webhook round trip accepted only with the correct HMAC
  (`burn-in.md`, github target PASS; forged signatures refused by probe #4).

## Honest scope

Covered here: authn/authz posture, tenant isolation, injection resistance,
webhook integrity, config hardening gates, brute-force throttling, session
lifecycle — the auth/tenancy attack surface.

_NOT covered (external pen test territory): business-logic abuse chains,
multi-session race exploitation, infrastructure/manifest review, social
engineering, dependency 0-days, load-edge DoS crafting. Next step remains a
vendor engagement against a real deployment._
