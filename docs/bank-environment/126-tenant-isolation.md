# Multi-tenant isolation — two tenants, every direction

`cryptoscan.tenant-isolation/2` · generated 2026-11-02T10:56:05.172688+00:00 · **7 pass · 1 partial · 0 fail**

| Question | Verdict | Evidence |
|---|---|---|
| **can tenant A read a row that belongs to tenant B?** | **PASS** | inside tenant A, a plain select returned 1 row(s): ['drill-alpha-only'] |
| **can tenant A write a row into tenant B?** | **PASS** | a row created without a tenant_id was stamped 9770632e-2b62-49c2-be91-3bafdcb17726 |
| **can tenant A update or delete a row it cannot see?** | **PASS** | updating B's row from A's scope touched 0 row(s) |
| **does a query that forgets the predicate fail closed?** | **PASS** | refused: raw or Core SQL touching tenant-scoped table 'tenant_usage_events' inside a tenant scope; use the ORM (auto-filtered) or an explicit db.tenancy.platform_scope() block |
| **does a valid session plus a spoofed header buy the other tenant's scope?** | **PASS** | A's session resolved to 9770632e-2b62-49c2-be91-3bafdcb17726 |
| **is the isolation the filter's doing, or the data's?** | **PASS** | from a platform scope the same query returns ['drill-alpha-only', 'drill-beta-only'] — so the rows are only separated by the scope, which is exactly what the rows above measure |
| **does PostgreSQL enforce the boundary, or only the Python scope?** | **PASS** | PostgreSQL 16.2: 157 of 157 table(s) with a tenant_id have RLS enabled and forced, with 157 policy row(s) |
| **is the isolation cryptographic, or logical and enforced by code?** | **PARTIAL** | reading the database file directly returns both tenants' rows in plaintext: ['drill-alpha-only', 'drill-beta-only'] — the isolation is enforced by a scope in code and, on PostgreSQL, by row-level policies, but it is not cryptographic: the file has no key |

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

- **PASS** `new-row-stamped-with-the-active-tenant` — a row created without a tenant_id was stamped 9770632e-2b62-49c2-be91-3bafdcb17726
- **PASS** `explicit-foreign-tenant-id-refused` — refused: row is attributed to tenant 'a0947665-4765-49dd-bda2-f30336b1960e', but active scope is '9770632e-2b62-49c2-be91-3bafdcb17726'
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

- **PASS** `member-resolves-own-tenant` — A's session resolved to 9770632e-2b62-49c2-be91-3bafdcb17726
- **PASS** `header-for-another-tenant-does-not-scope` — refused: Unknown tenant
- **PASS** `control-own-header-still-works` — B's own session with B's header resolved to a0947665-4765-49dd-bda2-f30336b1960e
- **PASS** `no-session-no-scope` — an unauthenticated request resolves no tenant — the auth gate refuses it before any query runs

### `controls` — PASS

*is the isolation the filter's doing, or the data's?*

- **PASS** `without-a-scope-both-tenants-are-visible` — from a platform scope the same query returns ['drill-alpha-only', 'drill-beta-only'] — so the rows are only separated by the scope, which is exactly what the rows above measure
- **PASS** `guard-reports-active-inside-a-scope` — inside a tenant scope the guard reports filtering on; in a platform scope it reports off, which is why the rows above are attributed to the scope rather than to luck

### `database_enforcement` — PASS

*does PostgreSQL enforce the boundary, or only the Python scope?*

- **PASS** `policy-exists-on-every-tenant-table` — PostgreSQL 16.2: 157 of 157 table(s) with a tenant_id have RLS enabled and forced, with 157 policy row(s)
- **PASS** `no-setting-reads-nothing` — a connection carrying no tenant setting reads 0 of the two rows — the policy fails closed instead of defaulting to everything
- **PASS** `setting-scopes-to-one-tenant` — with the setting bound to tenant A the same unqualified query returns 1 row(s)
- **PASS** `platform-wildcard-is-explicit` — the platform wildcard returns 2 rows — a cross-tenant read is a deliberate setting, not the default
- **PASS** `cross-tenant-insert-refused` — an INSERT naming tenant B from a tenant-A setting is refused: (psycopg2.errors.InsufficientPrivilege) new row violates row-level security policy for table "tenant_usage_events"
- **PASS** `cross-tenant-update-affects-nothing` — an UPDATE aimed at tenant B's row from a tenant-A setting touched 0 row(s)
- **PASS** `force-is-what-binds-the-owner` — the table's own owner reads 2 row(s) with RLS enabled but not forced, and 1 with it forced — which is why the migration forces it
- **PASS** `superuser-reads-across-tenants` — a superuser reads all 2 row(s): RLS binds roles, not privileges above it — and a stolen data file is still plaintext
- **Limit:** the policy binds roles, not privilege: a superuser or a role granted BYPASSRLS reads across tenants, and a stolen data file is still plaintext — this is enforcement, not encryption

### `at_rest` — PARTIAL

*is the isolation cryptographic, or logical and enforced by code?*

- **PASS** `stolen-store-reveals-every-tenant` — reading the database file directly returns both tenants' rows in plaintext: ['drill-alpha-only', 'drill-beta-only'] — the isolation is enforced by a scope in code and, on PostgreSQL, by row-level policies, but it is not cryptographic: the file has no key
- **Not proven:** this is not encryption: the store is shared and unencrypted per tenant, so a database dump — or a backup, or a stolen disk — still contains every tenant's rows in plaintext. Isolation stops a *reader through the database*; it does not stop a reader of the file
- **Not proven:** the `database_enforcement` row above closes the part that could be closed here: PostgreSQL's policies bind a role that forgets its predicate. Closing the rest needs per-tenant keys (or per-tenant databases) held by the tenant, which no row in this drill can substitute for

## What this does not prove

- the read/write rows are executed against SQLite with the same ORM guard and the same tenancy module the API uses; the `database_enforcement` row is the PostgreSQL half, and it says SKIP rather than PASS when no server is available
- the drill covers the data layer and the tenant resolution the middleware calls; guide 121 covers the per-route declarations

**The verdict this drill supports:** two tenants cannot read, write or mutate each other's rows, a query that forgets its predicate fails closed, a spoofed `X-Tenant-ID` with a valid session buys nothing, and a foreign primary key is not readable — and on PostgreSQL the boundary is enforced a second time by the database itself: a role that carries no tenant setting reads nothing, a foreign INSERT is refused by the policy, and `FORCE ROW LEVEL SECURITY` binds even the table's owner. What it is **not** is encryption: one store, one schema, plaintext at rest, and a superuser reads across tenants by design. The last two rows say so where a reader cannot miss it. The applying role in this run (`postgres`) is itself a superuser, so `binds_this_role` is False — the policy was measured through the `cryptoscan_tenant` and `drill_owner` roles, not through it.
