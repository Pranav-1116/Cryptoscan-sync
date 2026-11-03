# Bank-owned PostgreSQL runtime identity

**Status:** deployment prerequisite, not an approval or a production qualification. The
bank owns PostgreSQL and its credentials. CryptoScan never provisions a bank DBA
account or writes a runtime password to the repository.

Migration `0132` enables tenant RLS, but a PostgreSQL superuser bypasses it. In the
reference Compose stack, `POSTGRES_USER` bootstraps a superuser and is reserved for
the migration job. The API, worker, monitor, notifications and estate daemon must
use a **different** bank-provisioned login role. Production startup refuses a
superuser, a `BYPASSRLS` role, or a schema with incomplete forced policies.

## Bank DBA sequence

1. In a DBA session, create a distinct login role with `NOSUPERUSER`,
   `NOBYPASSRLS`, `NOCREATEDB`, `NOCREATEROLE` and `NOREPLICATION`. Assign its
   password using the bank secret manager or an interactive `psql \password`
   operation; do **not** put it in shell arguments, SQL files, Git or a Docker
   image. The examples below use the placeholder role `cryptoscan_app`. Supply
   the separate connection privately as `CRYPTOSCAN_APP_DATABASE_URL` before
   rendering the Compose configuration.
2. Apply migrations with the bank-controlled migration owner, without starting
   the API or worker: `bash scripts/deploy_prod.sh --migrate-only`. Do not give
   the migration credential to runtime containers. The command does not grant
   the runtime role permissions; the bank DBA performs the next step.
3. As the migration owner, grant only the runtime table and sequence operations
   needed by the application, after Alembic has created the tables:

```sql
GRANT CONNECT ON DATABASE cryptoscan TO cryptoscan_app;
GRANT USAGE ON SCHEMA public TO cryptoscan_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO cryptoscan_app;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO cryptoscan_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO cryptoscan_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO cryptoscan_app;
```

   Default privileges apply to objects created by **that migration role**. If
   another owner runs later migrations, the bank DBA must review and grant its
   new objects too. This is a starting permission set to measure and tighten,
   not a claim of minimum-permission qualification for every optional collector.
4. Verify from the runtime connection, not the DBA connection: query
   `pg_roles.rolsuper`, `pg_roles.rolbypassrls`, and the RLS report returned by
   `db.rls.enforcement`. Both role flags must be false and `binds_this_role`
   true, with every tenant table enabled and forced. Test a tenant-scoped read
   against two independently seeded test tenants; repeat after a pooled
   connection is reused. A zero-row result without a bound tenant is expected,
   **not** proof that the estate is empty. After the role and grants are verified,
   start the runtime with `bash scripts/deploy_prod.sh -d`. The Compose check
   refuses a URL using the migration username; the API and worker independently
   refuse an actual superuser or incomplete forced-RLS policy.

## Boundary and remaining proof

RLS is defense in depth, **not a database credential sandbox**. The application
binds a custom transaction-local tenant setting; a principal with arbitrary SQL
execution under the runtime credential could set that value themselves (including
the platform wildcard). Prevent SQL injection, restrict direct database access,
rotate a leaked runtime credential, and keep the ORM/request tenant guard. The
bank's DBA must independently test restore, role revocation, connection pooling,
permissions after migrations and backup encryption. None is established by a
passing Compose render or local unit test.

Production Redis is also bank-owned: the reference overlay requires a `rediss://`
ACL URL and a read-only trusted CA mount. The checked-in single-node Redis and
Neo4j services do not themselves prove HA, TLS or bank-site qualification.
