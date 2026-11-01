# Multi-tenant isolation — two tenants, every direction

`cryptoscan.tenant-isolation/1` · generated 2026-11-01T04:59:56.850390+00:00 · **6 pass · 1 partial · 0 fail**

| Question | Verdict | Evidence |
|---|---|---|
| **can tenant A read a row that belongs to tenant B?** | **PASS** | inside tenant A, a plain select returned 1 row(s): ['drill-alpha-only'] |
| **can tenant A write a row into tenant B?** | **PASS** | a row created without a tenant_id was stamped 35da616b-e242-432b-98eb-cd265ee4e49d |
| **can tenant A update or delete a row it cannot see?** | **PASS** | updating B's row from A's scope touched 0 row(s) |
| **does a query that forgets the predicate fail closed?** | **PASS** | refused: raw or Core SQL touching tenant-scoped table 'tenant_usage_events' inside a tenant scope; use the ORM (auto-filtered) or an explicit db.tenancy.platform_scope() block |
| **does a valid session plus a spoofed header buy the other tenant's scope?** | **PASS** | A's session resolved to 35da616b-e242-432b-98eb-cd265ee4e49d |
| **is the isolation the filter's doing, or the data's?** | **PASS** | from a platform scope the same query returns ['drill-alpha-only', 'drill-beta-only'] — so the rows are only separated by the scope, which is exactly what the rows above measure |
| **is the isolation cryptographic, or logical and enforced by code?** | **PARTIAL** | reading the database file directly returns both tenants' rows in plaintext: ['drill-alpha-only', 'drill-beta-only'] — the isolation is logical (a scope applied by code), not cryptographic (a key the tenant holds) |

## Row by row

### `read_filtering` — PASS

*can tenant A read a row that belongs to tenant B?*

- **PASS** `scope-A-sees-only-A` — inside tenant A, a plain select returned 1 row(s): ['drill-alpha-only']
- **PASS** `control-A-sees-its-own-row` — A's own row is visible, so the result is not empty-by-accident
- **PASS** `foreign-primary-key-not-readable` — a primary-key lookup for B's row — the classic cross-tenant read — returns None inside A's scope
- **PASS** `own-primary-key-readable` — the same lookup for A's own row succeeds, so the filter is not rejecting everything
- **PASS** `scope-B-sees-only-B` — inside tenant B: ['drill-beta-only']

### `write_stamping` — PASS

*can tenant A write a row into tenant B?*

- **PASS** `new-row-stamped-with-the-active-tenant` — a row created without a tenant_id was stamped 35da616b-e242-432b-98eb-cd265ee4e49d
- **PASS** `explicit-foreign-tenant-id-refused` — refused: row is attributed to tenant '3512111c-5a24-457f-b3c0-0ae484d0c718', but active scope is '35da616b-e242-432b-98eb-cd265ee4e49d'
- **PASS** `control-forged-row-absent-from-the-store` — 0 forged row(s) persisted

### `cross_tenant_mutation` — PASS

*can tenant A update or delete a row it cannot see?*

- **PASS** `cross-tenant-update-affects-nothing` — updating B's row from A's scope touched 0 row(s)
- **PASS** `cross-tenant-update-left-B-intact` — B's row now reads 'drill-beta-only'

### `raw_statements` — PASS

*does a query that forgets the predicate fail closed?*

- **PASS** `raw-text-sql-refused` — refused: raw or Core SQL touching tenant-scoped table 'tenant_usage_events' inside a tenant scope; use the ORM (auto-filtered) or an explicit db.tenancy.platform_scope() block
- **PASS** `core-select-on-a-tenant-table-refused` — refused: raw or Core SQL touching tenant-scoped table 'tenant_usage_events' inside a tenant scope; use the ORM (auto-filtered) or an explicit db.tenancy.platform_scope() block

### `membership_resolution` — PASS

*does a valid session plus a spoofed header buy the other tenant's scope?*

- **PASS** `member-resolves-own-tenant` — A's session resolved to 35da616b-e242-432b-98eb-cd265ee4e49d
- **PASS** `header-for-another-tenant-does-not-scope` — refused: Unknown tenant
- **PASS** `control-own-header-still-works` — B's own session with B's header resolved to 3512111c-5a24-457f-b3c0-0ae484d0c718
- **PASS** `no-session-no-scope` — an unauthenticated request resolves no tenant — the auth gate refuses it before any query runs

### `controls` — PASS

*is the isolation the filter's doing, or the data's?*

- **PASS** `without-a-scope-both-tenants-are-visible` — from a platform scope the same query returns ['drill-alpha-only', 'drill-beta-only'] — so the rows are only separated by the scope, which is exactly what the rows above measure
- **PASS** `guard-reports-active-inside-a-scope` — inside a tenant scope the guard reports filtering on; in a platform scope it reports off, which is why the rows above are attributed to the scope rather than to luck

### `at_rest` — PARTIAL

*is the isolation cryptographic, or logical and enforced by code?*

- **PASS** `stolen-store-reveals-every-tenant` — reading the database file directly returns both tenants' rows in plaintext: ['drill-alpha-only', 'drill-beta-only'] — the isolation is logical (a scope applied by code), not cryptographic (a key the tenant holds)
- **Not proven:** this is logical isolation, not cryptographic isolation: the store is shared and unencrypted per tenant, so a database dump — or a backup, or a stolen disk — contains every tenant's rows in plaintext. Logical isolation stops a *request*; it does not stop a reader of the file
- **Not proven:** closing this needs per-tenant keys or a database that enforces row-level security with distinct roles per tenant; neither is in place, and no test can substitute for it

## What this does not prove

- executed against SQLite with the same ORM guard and the same tenancy module the API uses; PostgreSQL row-level security is not exercised here because the deployment does not use it
- the drill covers the data layer and the tenant resolution the middleware calls; guide 121 covers the per-route declarations

**The verdict this drill supports:** two tenants cannot read, write or mutate each other's rows, a query that forgets its predicate fails closed, a spoofed `X-Tenant-ID` with a valid session buys nothing, and a foreign primary key is not readable. The isolation is **logical** — one store, one schema, a scope applied by code — and the last row says plainly that this is not cryptographic isolation and must not be sold as such.
