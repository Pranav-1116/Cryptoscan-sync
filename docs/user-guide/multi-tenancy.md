# Multi-tenancy — how one organization's data stays one organization's

CryptoScan runs as a multi-tenant SaaS: one deployment, many customer
organizations (tenants), each seeing only its own estate. This page
documents the whole `tenant_id` chain — browser to database — and how you
switch organizations.

## The chain, end to end

```
browser                          API                            database
────────                         ─────                          ────────
org picker (Tenancy page
or the header's organization
button)
   │  GET /saas/memberships ───► membership table ──► your orgs only
   │
   │  every API call carries ──► TenantScopeMiddleware resolves the
   │  X-Tenant-ID: acme           header against memberships:
   │                              not a member → 403/404, never a read
   │                              member of 2+ orgs, no header → 400
   │                                     │
   │                              tenant scope active for the request
   │                                     │
   │                              ORM guard filters every query to
   │                              tenant_id = acme (+ platform rows)
   │                                     │
   │                              writes stamped with tenant_id = acme
   ◄── responses scoped to acme ◄──── rows carry tenant_id in payloads
```

Every link is enforced, not assumed:

- **The picker's options come from the backend.** `GET /api/v1/saas/memberships`
  derives the list from the membership table — never from the current
  header — so a user can only choose organizations they actually belong to.
- **The header is re-validated on every request.** A forged `X-Tenant-ID`
  is refused (403/404) before any query runs; a multi-member user who
  sends no header at all gets 400 rather than a guess.
- **The database stamps and filters.** Every tenant-scoped table carries
  `tenant_id`; the ORM guard (`with_loader_criteria`) reaches every query
  path including lazy loads, and raw SQL that would bypass it fails
  closed. Writes are stamped from the request's scope.
- **Ownership is visible.** Row listings (cascade runs, watches, ...) carry
  `tenant_id` on each entry — `null` means the platform estate.

## Switching organizations

Two entries, one mechanism:

- **Tenancy page → "Switch organization"**: one button per membership
  (role and status shown), plus a "Platform estate" option for platform
  admins. Hidden entirely for single-organization users.
- **Header → organization button**: the same picker as a modal, plus the
  full tenant directory for platform admins.

Picking an organization stores the choice in the browser and attaches
`X-Tenant-ID` to **every** subsequent API call — regular requests,
downloads, and the live SSE streams alike (the shared `tenantFetch`
wrapper owns this, so no endpoint can silently drop it). Signing out, or
signing in as a different user, clears the choice; the next login's
picker is repopulated from that user's memberships.

## What isolation means per surface

| Surface | Rule |
|---|---|
| Database rows | A tenant sees its own rows plus unattributed (platform) rows — the on-prem upgrade path must not hide history. Never another tenant's rows. |
| Event stream + live CBOM (`/stream/*`, `/attacks*`, `/cbom/*`) | Strict partitions per tenant (`<store>/tenants/<id>/`): each scope sees only its own, both directions. |
| Snapshots (twin, technology BOM, ...) | Versions number per tenant; a capture in one org never collides with another's. |
| WebSockets / SSE | Credentials are resolved through the same membership validation; a tenant never receives another tenant's events. |

## For operators: the platform estate

Requests without an organization (single-tenant installs, platform
operators) use the unscoped platform partition — the same paths and
behavior the product had before tenancy. Platform admins additionally see
the tenant registry (suspend/restore/plan) on the Tenancy page, and the
self-check aggregates every partition for bus lag and CBOM freshness.

## Verifying the chain

The connection itself is pinned by tests on both sides:

- `services/api/tests/unit/test_tenant_e2e_flow.py` — over the real HTTP
  stack: memberships → header → whoami → tenant-stamped write → scoped
  list with `tenant_id` → cross-tenant invisibility → header refusals.
- `frontend/src/pages/Tenancy.test.tsx` — the picker renders from
  memberships, switching stores the org, and the next call carries the
  switched header.
