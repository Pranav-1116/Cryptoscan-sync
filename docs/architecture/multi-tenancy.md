# Multi-tenancy (SaaS)

CryptoScan runs one hardened control plane that serves many customer
organizations (tenants) on shared infrastructure. This page is the contract
for how isolation works — what is enforced, where, and how it is tested.

## Model

- **Tenant** = an organization (`tenants`): `slug`, `plan` (FREE / PRO /
  ENTERPRISE), `status` (ACTIVE / SUSPENDED).
- **Membership** links a platform user to a tenant with a **tenant role**
  independent of platform RBAC: `owner > admin > member > viewer`.
  A user may belong to several tenants; the active one is chosen per request.
- **Tenant-scoped rows** carry `tenant_id` (monitor targets, API keys; more
  surfaces join each round). `tenant_id IS NULL` = the **platform estate** —
  the single-tenant world pre-SaaS, still used by on-prem stores.

## Request flow

Every tenant-scoped request resolves a `TenantContext`
(`api.dependencies.get_tenant_context`):

1. API key with a tenant binding → that tenant, always (header cannot
   override it; a mismatching `X-Tenant-ID` is a 403).
2. Platform superadmin → `X-Tenant-ID` selects a tenant to operate on;
   without it the request sees the platform estate only.
3. Everyone else → memberships from the DB **per request** (revocation and
   role changes are effective on the next call; the signed session token is
   never widened). One membership auto-selects; several require the header.
4. No membership → 403. Unknown or foreign tenant → **404, never 403** (no
   existence oracle for the tenant registry).
5. SUSPENDED tenant → 423 on every member request.

## Enforcement layers (defense in depth)

| Layer | What it does |
|---|---|
| Repository | every query filters by `tenant_id` (or `platform=True` for the NULL estate); `get_by_name_scoped` keeps name uniqueness per estate |
| Router | tenant-scoped routes depend on `TenantContext` / `require_tenant_roles`; cross-tenant get/patch/delete is 404 |
| Daemon | `MonitorRepository.due()` skips SUSPENDED tenants; results inherit the target's tenant; every executed pass writes one `scan_run` usage unit |
| Quotas | plan limits enforced at create time: targets, monthly scans, seats → **402 quota_exceeded** with the reason; ENTERPRISE is unlimited |
| Metering | append-only `tenant_usage_events` (SUM per calendar month — deletes never shrink counters) |

## Plans

| Limit | FREE | PRO | ENTERPRISE |
|---|---|---|---|
| Monitor targets | 5 | 100 | unlimited |
| Scan passes / month | 200 | 20 000 | unlimited |
| Seats | 3 | 25 | unlimited |

Plan policy lives in `api/security/tenancy.py` (pure, unit-pinned); unknown
plans degrade to FREE — never to unlimited.

## Invitations

Members join via one-time invite tokens (`csi_…`, 7–30 day expiry, only the
SHA-256 hash stored):

- `POST /saas/invites` (owner/admin, grant ladder enforced) returns the raw
  token **once** — it is delivered out-of-band (chat/email) by the operator;
- `POST /saas/invites/accept` binds the invited username to the tenant:
  a brand-new identity sets its own password there (policy-enforced); an
  EXISTING identity can only be claimed by a session signed in as that
  username — a leaked token can never rebind or reset a live account;
- pending invites hold no seat; the seat quota is enforced at accept;
- `GET /saas/invites` / `DELETE /saas/invites/{id}` manage pending invites;
  dashboard: Tenancy → Pending invites (+ the `/invite` accept page).

## Metering — every scan that costs the platform

`scan_run` units are recorded by ALL scan writers, so plan limits are honest:
daemon passes (one per executed pass), `POST /monitor/targets/{id}/scan-now`
(pre-checked, metered once by the engine), `POST /network-scans` (one unit
per host), and `POST /scans/{id}/retry` (one unit). Platform-estate scans
(on-prem operators) are unmetered.

## Lifecycle

- `POST /saas/signup` provisions org + owner self-serve (password policy
  enforced; an existing username must present matching credentials, so no
  one can graft memberships onto a foreign identity).
- `POST /saas/admin/tenants/{id}/suspend` freezes a tenant: member requests
  423, daemon passes stop, data is retained. `…/restore` and `…/plan`
  complete the platform-admin surface; every lifecycle step is audited
  (platform audit log + per-tenant provision timeline).

## Where it is tested

`services/api/tests/integration/test_saas_tenancy.py` proves the core
guarantees (isolation-as-absence, quotas, suspension, signup, role ladder,
last-owner protection, key binding), `services/api/tests/unit/
test_tenancy_policy.py` pins the pure policy, and the monitor/api-key suites
pin that legacy platform behavior is unchanged.
