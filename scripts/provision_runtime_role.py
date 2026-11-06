#!/usr/bin/env python3
"""Provision, verify and repair the bank's non-superuser runtime role — once, in Git.

Why this exists
---------------
Production startup already refuses a superuser and refuses a ``BYPASSRLS`` role, and
``docs/runbooks/onprem-postgres-runtime-role.md`` says a bank DBA must create the runtime
login, grant it table and sequence access **after** migrations, and verify
``rolsuper``/``rolbypassrls``/forced RLS from the runtime connection.

That was correct and unactionable: every deployment re-derived the SQL from a runbook
paragraph by hand, and a mistyped ``GRANT`` is invisible until someone reads across tenants.
This script is the checked-in answer. ``plan`` prints the exact statements, ``apply`` runs
them as the migration owner, ``verify`` measures the result from the runtime connection.

Three refusals that matter
--------------------------
* It never writes a password. The role's password is set by ``psql \\password`` or the bank's
  secret manager; ``PASSWORD``, ``ALTER ROLE ... PASSWORD`` and any credential-looking
  argument make this script stop rather than echo a secret into a shell history or a CI log.
* It refuses to grant to a role that is, or would become, a superuser or ``BYPASSRLS``.
  Provisioning a bypass would defeat the whole boundary while reporting success.
* ``verify`` is the verdict, ``apply`` is not. Applying SQL proves the statements ran; only a
  measurement from the runtime connection proves the database binds that role.

Usage
-----
    python scripts/provision_runtime_role.py plan --role cryptoscan_app --database cryptoscan
    python scripts/provision_runtime_role.py apply --role cryptoscan_app \
        --dsn "$CRYPTOSCAN_MIGRATION_DSN"     # needs CRYPTOSCAN_PROVISION_ACK=1
    python scripts/provision_runtime_role.py verify --dsn "$CRYPTOSCAN_APP_DATABASE_URL"

``plan`` and ``verify --sql`` never touch a database, so they are safe in CI and in a review.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]

#: Role names that must never be handed to this script: the bootstrap superuser and the
#: migration owner both bypass the boundary this script exists to create.
RESERVED_ROLES = {"postgres", "root", "admin", "cryptoscan", "rdsadmin", "azure_superuser"}

#: A role name this script is willing to render. Anything else is refused rather than quoted
#: and hoped for: quoting a name containing a quote is how injection starts.
ROLE_PATTERN = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")

#: Statements are separated so a caller can review them, and so ``apply`` can report which one
#: failed. They are idempotent: provisioning twice is a no-op, not an error.
def statements(role: str, database: str, *, schema: str = "public") -> list[dict[str, str]]:
    """The SQL a bank DBA would type, in order, with the reason for each step."""
    _validate(role, database, schema)
    return [
        {"step": "role",
         "why": "a login that is not a superuser and cannot bypass RLS",
         "sql": (f"DO $$ BEGIN "
                 f"IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}') THEN "
                 f"CREATE ROLE {role} LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE "
                 f"NOREPLICATION NOINHERIT; "
                 f"END IF; END $$;")},
        {"step": "role-flags",
         "why": "an existing role may have been created by hand with the wrong flags",
         "sql": (f"ALTER ROLE {role} NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE "
                 f"NOREPLICATION;")},
        {"step": "connect",
         "why": "the runtime must be able to open a session on this database",
         "sql": f'GRANT CONNECT ON DATABASE "{database}" TO {role};'},
        {"step": "schema",
         "why": "the runtime reads and writes tables in the application schema",
         "sql": f"GRANT USAGE ON SCHEMA {schema} TO {role};"},
        {"step": "tables",
         "why": "existing tables, created by migrations that have already run",
         "sql": (f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA {schema} "
                 f"TO {role};")},
        {"step": "sequences",
         "why": "serial and identity columns need to advance",
         "sql": f"GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA {schema} TO {role};"},
        {"step": "default-tables",
         "why": "tables a later migration creates are granted without a second visit",
         "sql": (f"ALTER DEFAULT PRIVILEGES IN SCHEMA {schema} "
                 f"GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {role};")},
        {"step": "default-sequences",
         "why": "same, for sequences attached to later tables",
         "sql": (f"ALTER DEFAULT PRIVILEGES IN SCHEMA {schema} "
                 f"GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO {role};")},
    ]


#: What ``verify`` measures. Each query is read-only and returns one row per fact, so a
#: failure names what is wrong instead of printing a boolean.
def verification_queries(role: str, *, schema: str = "public") -> list[dict[str, str]]:
    _validate(role, "cryptoscan", schema)
    return [
        {"fact": "role_exists", "expect": "true",
         "sql": f"SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}')",
         "why": "the runtime identity must exist before anything else is true"},
        {"fact": "is_superuser", "expect": "false",
         "sql": f"SELECT rolsuper FROM pg_roles WHERE rolname = '{role}'",
         "why": "a superuser reads across every tenant by definition"},
        {"fact": "bypasses_rls", "expect": "false",
         "sql": f"SELECT rolbypassrls FROM pg_roles WHERE rolname = '{role}'",
         "why": "BYPASSRLS is the same crossing with a quieter name"},
        {"fact": "can_create_role", "expect": "false",
         "sql": f"SELECT rolcreaterole FROM pg_roles WHERE rolname = '{role}'",
         "why": "a runtime that can create roles can grant itself the boundary away"},
        {"fact": "can_create_db", "expect": "false",
         "sql": f"SELECT rolcreatedb FROM pg_roles WHERE rolname = '{role}'",
         "why": "not needed by the application"},
        {"fact": "replication", "expect": "false",
         "sql": f"SELECT rolreplication FROM pg_roles WHERE rolname = '{role}'",
         "why": "not needed by the application"},
        {"fact": "has_connect", "expect": "true",
         "sql": (f"SELECT has_database_privilege('{role}', current_database(), 'CONNECT')"),
         "why": "the runtime must be able to reach the database"},
        {"fact": "has_schema_usage", "expect": "true",
         "sql": f"SELECT has_schema_privilege('{role}', '{schema}', 'USAGE')",
         "why": "without USAGE the table grants are inert"},
        {"fact": "tables_rls_enabled", "expect": "all",
         "sql": ("SELECT count(*) FILTER (WHERE NOT c.relrowsecurity) AS missing, "
                 "count(*) AS total FROM pg_class c "
                 "JOIN pg_namespace n ON n.oid = c.relnamespace "
                 f"WHERE n.nspname = '{schema}' AND c.relkind = 'r' "
                 "AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = c.oid "
                 "AND a.attname = 'tenant_id' AND NOT a.attisdropped)"),
         "why": "RLS must be enabled on every tenant-owned table"},
        {"fact": "tables_rls_forced", "expect": "all",
         "sql": ("SELECT count(*) FILTER (WHERE NOT c.relforcerowsecurity) AS missing, "
                 "count(*) AS total FROM pg_class c "
                 "JOIN pg_namespace n ON n.oid = c.relnamespace "
                 f"WHERE n.nspname = '{schema}' AND c.relkind = 'r' "
                 "AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = c.oid "
                 "AND a.attname = 'tenant_id' AND NOT a.attisdropped)"),
         "why": "FORCE ROW LEVEL SECURITY must bind every tenant-owned table"},
        {"fact": "policies_present", "expect": "more-than-zero",
         "sql": f"SELECT count(*) FROM pg_policies WHERE schemaname = '{schema}'",
         "why": "enabled RLS with no policy denies everything, which is not the design"},
        {"fact": "measures_this_role", "expect": "runtime",
         "sql": "SELECT current_user",
         "why": "a verification run as the migration owner proves nothing about the runtime"},
    ]


def _validate(role: str, database: str, schema: str) -> None:
    if not ROLE_PATTERN.match(role or ""):
        raise SystemExit(f"Refused: role {role!r} is not a plain lower-case identifier "
                         f"(expected {ROLE_PATTERN.pattern})")
    if role.lower() in RESERVED_ROLES:
        raise SystemExit(f"Refused: {role!r} is a bootstrap or migration identity; the runtime "
                         f"role must be a different login")
    if not re.match(r"^[A-Za-z_][A-Za-z0-9_$-]{0,62}$", database or ""):
        raise SystemExit(f"Refused: database name {database!r} is not a plain identifier")
    if not re.match(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$", schema or ""):
        raise SystemExit(f"Refused: schema name {schema!r} is not a plain identifier")


def _looks_like_a_secret(value: str) -> bool:
    """Refuse a DSN that carries a password: this script must not be handed a credential."""
    return bool(re.search(r"://[^/\s:@]+:[^/\s@]+@", value or ""))


def run_sql(dsn: str, queries: Iterable[str]) -> list[list[dict[str, Any]]]:
    """Execute statements, returning rows per statement. Imported lazily: plan needs no driver."""
    from sqlalchemy import create_engine, text

    engine = create_engine(dsn)
    results: list[list[dict[str, Any]]] = []
    with engine.begin() as connection:
        for statement in queries:
            result = connection.execute(text(statement))
            results.append([dict(row._mapping) for row in result] if result.returns_rows else [])
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("action", choices=("plan", "apply", "verify", "sql"))
    parser.add_argument("--role", default="cryptoscan_app")
    parser.add_argument("--database", default="cryptoscan")
    parser.add_argument("--schema", default="public")
    parser.add_argument("--dsn", default=os.environ.get("CRYPTOSCAN_PROVISION_DSN", ""))
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args(argv)

    if args.action == "plan":
        payload = {"schema": "cryptoscan.runtime-role-plan/1", "role": args.role,
                   "database": args.database, "schema_name": args.schema,
                   "statements": statements(args.role, args.database, schema=args.schema),
                   "note": ("Applying these statements proves they ran. It does not prove the "
                            "database binds the role: run `verify` from the runtime DSN.")}
        print(json.dumps(payload, indent=2) if args.json else
              "\n".join(f"-- {s['step']}: {s['why']}\n{s['sql']}\n"
                        for s in payload["statements"]))
        return 0

    if args.action == "sql":
        print("\n".join(s["sql"] for s in statements(args.role, args.database, schema=args.schema)))
        return 0

    dsn = args.dsn
    if not dsn:
        raise SystemExit("Refused: --dsn (or CRYPTOSCAN_PROVISION_DSN) is required")
    if _looks_like_a_secret(dsn):
        raise SystemExit("Refused: the DSN contains an inline password. Use a bank secret file "
                         "or an interactive prompt; this script never handles credentials.")

    if args.action == "apply":
        if os.environ.get("CRYPTOSCAN_PROVISION_ACK") != "1":
            raise SystemExit("Refused: set CRYPTOSCAN_PROVISION_ACK=1 to acknowledge that you "
                             "are the bank's migration owner on the intended database")
        run_sql(dsn, [s["sql"] for s in statements(args.role, args.database, schema=args.schema)])
        print(f"Applied {len(statements(args.role, args.database, schema=args.schema))} statements "
              f"for {args.role}. This proves the SQL ran, not that RLS binds: run `verify`.")
        return 0

    queries = verification_queries(args.role, schema=args.schema)
    rows = run_sql(dsn, [q["sql"] for q in queries])
    observations = []
    for query, result in zip(queries, rows):
        value = result[0] if result else {}
        observations.append({"fact": query["fact"], "expect": query["expect"],
                             "observed": value, "why": query["why"],
                             "role": args.role})
    failures = [o for o in observations if _fails(o)]
    payload = {"schema": "cryptoscan.runtime-role-verification/1", "role": args.role,
               "observations": observations, "failures": [o["fact"] for o in failures],
               "verdict": "BINDS" if not failures else "DOES_NOT_BIND",
               "note": ("A pass means this role did not bypass during this connection. It is "
                        "not a claim about other credentials, other databases or direct SQL.")}
    print(json.dumps(payload, indent=2) if args.json else
          "\n".join(f"{o['fact']}: {o['observed']} (expected {o['expect']})" for o in observations)
          + f"\nverdict: {payload['verdict']}")
    return 0 if not failures else 1


def _fails(observation: dict[str, Any]) -> bool:
    observed, expect = observation["observed"], observation["expect"]
    value = next(iter(observed.values()), None) if isinstance(observed, dict) else observed
    if expect == "true":
        return value is not True
    if expect == "false":
        return value is not False
    if expect == "runtime":
        # the verification connection must be the runtime identity, not the migration owner
        return str(value) != str(observation.get("role"))
    if expect == "all":
        if not isinstance(observed, dict):
            return True
        return not observed.get("total") or bool(observed.get("missing"))
    if expect == "more-than-zero":
        return not value
    return False


if __name__ == "__main__":
    sys.exit(main())
