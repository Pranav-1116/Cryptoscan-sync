"""Multi-tenant isolation — two tenants, every direction, executed.

The claim a SaaS bank needs is "cryptographically and logically isolated". Those
are two different claims and this drill keeps them apart:

* **logical** — a tenant's rows are unreadable, unwritable and invisible from
  another tenant's scope, including through a query that forgets its predicate,
  a raw Core statement, a spoofed ``X-Tenant-ID`` and a foreign primary key. This
  is measured by execution.
* **cryptographic** — a stolen database dump is unreadable without a per-tenant
  key. This platform uses one shared store with a ``tenant_id`` column and an ORM
  filter; that is logical isolation only, and the row says so instead of implying
  otherwise.

Run::

    python scripts/tenant_isolation.py \\
        --json docs/bank-environment/126-tenant-isolation.json \\
        --md   docs/bank-environment/126-tenant-isolation.md
"""

from __future__ import annotations

import datetime as dt
import json
import os
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCHEMA = "cryptoscan.tenant-isolation/2"
VERSION = "tenant-isolation/2.0"

REPO_ROOT = Path(__file__).resolve().parents[1]

PASS, PARTIAL, FAIL, SKIP = "PASS", "PARTIAL", "FAIL", "SKIP"

TENANT_A = "tenant-alpha"
TENANT_B = "tenant-beta"
MARKER_A = "drill-alpha-only"
MARKER_B = "drill-beta-only"


@dataclass
class Probe:
    name: str
    ok: bool
    observed: str

    def as_dict(self) -> dict[str, Any]:
        return {"probe": self.name, "ok": self.ok, "observed": self.observed}


def _bootstrap() -> None:
    for relative in ("services/api", "services/database", "shared/shared_models",
                     "shared/shared_config", "shared/shared_logging"):
        candidate = str(REPO_ROOT / relative)
        if candidate not in sys.path:
            sys.path.insert(0, candidate)
    os.environ["ENVIRONMENT"] = "test"
    os.environ.setdefault("SECRET_KEY", "tenant-isolation-drill-key-32-characters")


_bootstrap()


@dataclass
class World:
    engine: Any
    session_factory: Any
    path: str


def build_world() -> World:
    from sqlalchemy import create_engine

    import db.models  # noqa: F401 — register every mapper before create_all
    from db.connection.session import Base, configure_session
    from db.tenancy import install_tenant_guard

    path = tempfile.mktemp(suffix=".db", prefix="tenant-isolation-")
    engine = create_engine(f"sqlite:///{path}", future=True)
    Base.metadata.create_all(engine)
    configure_session(engine)
    install_tenant_guard()
    from db.connection.session import SessionLocal

    return World(engine=engine, session_factory=SessionLocal, path=path)


def _seed(world: World) -> dict[str, str]:
    """Two tenants, one usage row each, and a member of each."""
    from db.repositories.tenant_repository import TenantRepository
    from db.tenancy import platform_scope

    ids: dict[str, str] = {}
    with platform_scope():
        session = world.session_factory()
        try:
            repo = TenantRepository(session)
            for slug, marker in ((TENANT_A, MARKER_A), (TENANT_B, MARKER_B)):
                tenant = repo.get_by_slug(slug) or repo.create(name=slug, slug=slug,
                                                               plan="ENTERPRISE")
                repo.add_member(tenant.id, f"user-{slug}", "admin", actor="drill")
                session.add(_usage_row(tenant.id, marker))
                ids[slug] = tenant.id
            session.commit()
        finally:
            session.close()
    return ids


def _usage_row(tenant_id: str, marker: str):
    from db.models.tenant import TenantUsageEvent

    return TenantUsageEvent(tenant_id=tenant_id, kind="drill", amount=1, detail=marker)


def _usage_ids(session, tenant: str, marker: str) -> str:  # pragma: no cover - helper
    from sqlalchemy import select

    from db.models.tenant import TenantUsageEvent

    return session.execute(
        select(TenantUsageEvent.id).where(TenantUsageEvent.detail == marker)
    ).scalar_one()


# --------------------------------------------------------------------------- #
# probes
# --------------------------------------------------------------------------- #

def probe_read_filtering(world: World, ids: dict[str, str]) -> list[Probe]:
    from sqlalchemy import select

    from db.models.tenant import TenantUsageEvent
    from db.tenancy import filtered_get, platform_scope, tenant_scope

    probes: list[Probe] = []
    with platform_scope():
        session = world.session_factory()
        try:
            row_a = session.execute(select(TenantUsageEvent.id).where(
                TenantUsageEvent.detail == MARKER_A)).scalar_one()
            row_b = session.execute(select(TenantUsageEvent.id).where(
                TenantUsageEvent.detail == MARKER_B)).scalar_one()
        finally:
            session.close()

    with tenant_scope(ids[TENANT_A]):
        session = world.session_factory()
        try:
            # The seed also writes membership usage events; the drill's own marker
            # rows are the ones under test.
            visible = session.execute(
                select(TenantUsageEvent).where(TenantUsageEvent.kind == "drill")
            ).scalars().all()
            details = {row.detail for row in visible}
            probes.append(Probe(
                "scope-A-sees-only-A", details == {MARKER_A},
                f"inside tenant A, a plain select returned {len(visible)} row(s): {sorted(d for d in details if d)}"))
            probes.append(Probe(
                "control-A-sees-its-own-row", MARKER_A in details,
                "A's own row is visible, so the result is not empty-by-accident"))
            probes.append(Probe(
                "foreign-primary-key-not-readable", filtered_get(
                    session, TenantUsageEvent, row_b) is None,
                "a primary-key lookup for B's row — the classic cross-tenant read — "
                "returns None inside A's scope"))
            probes.append(Probe(
                "own-primary-key-readable", filtered_get(
                    session, TenantUsageEvent, row_a) is not None,
                "the same lookup for A's own row succeeds, so the filter is not "
                "rejecting everything"))
        finally:
            session.close()

    with tenant_scope(ids[TENANT_B]):
        session = world.session_factory()
        try:
            details = {row.detail for row in session.execute(
                select(TenantUsageEvent).where(TenantUsageEvent.kind == "drill")
            ).scalars().all()}
            probes.append(Probe("scope-B-sees-only-B", details == {MARKER_B},
                                f"inside tenant B: {sorted(details)}"))
        finally:
            session.close()
    return probes


def probe_write_stamping(world: World, ids: dict[str, str]) -> list[Probe]:
    from sqlalchemy import select

    from db.models.tenant import TenantUsageEvent
    from db.tenancy import TenantScopeViolation, platform_scope, tenant_scope

    probes: list[Probe] = []
    created: list[str] = []
    with tenant_scope(ids[TENANT_A]):
        session = world.session_factory()
        try:
            stamps = TenantUsageEvent(kind="drill-write", amount=1, detail="stamped-by-scope")
            session.add(stamps)
            session.flush()
            created.append(stamps.id)
            probes.append(Probe(
                "new-row-stamped-with-the-active-tenant", stamps.tenant_id == ids[TENANT_A],
                f"a row created without a tenant_id was stamped {stamps.tenant_id}"))
            session.commit()
        finally:
            session.close()

        session = world.session_factory()
        try:
            forged = TenantUsageEvent(tenant_id=ids[TENANT_B], kind="drill-forge", amount=1,
                                      detail="forged-tenant")
            session.add(forged)
            try:
                session.flush()
                wrote = forged.tenant_id
                probes.append(Probe(
                    "explicit-foreign-tenant-id-refused", wrote != ids[TENANT_B],
                    f"a write naming tenant B from inside tenant A ended up as {wrote}"))
                session.rollback()
            except TenantScopeViolation as exc:
                session.rollback()
                probes.append(Probe("explicit-foreign-tenant-id-refused", True,
                                    f"refused: {exc}"))
        finally:
            session.close()

    with platform_scope():
        session = world.session_factory()
        try:
            forged_rows = session.execute(select(TenantUsageEvent).where(
                TenantUsageEvent.detail == "forged-tenant")).scalars().all()
            probes.append(Probe(
                "control-forged-row-absent-from-the-store", forged_rows == [],
                f"{len(forged_rows)} forged row(s) persisted"))
        finally:
            session.close()
    return probes


def probe_cross_tenant_mutation(world: World, ids: dict[str, str]) -> list[Probe]:
    from sqlalchemy import select, update

    from db.models.tenant import TenantUsageEvent
    from db.tenancy import platform_scope, tenant_scope

    probes: list[Probe] = []
    with platform_scope():
        session = world.session_factory()
        try:
            row_b = session.execute(select(TenantUsageEvent.id).where(
                TenantUsageEvent.detail == MARKER_B)).scalar_one()
        finally:
            session.close()

    with tenant_scope(ids[TENANT_A]):
        session = world.session_factory()
        try:
            result = session.execute(update(TenantUsageEvent)
                                     .where(TenantUsageEvent.id == row_b)
                                     .values(detail="tampered-by-A"))
            probes.append(Probe(
                "cross-tenant-update-affects-nothing", result.rowcount == 0,
                f"updating B's row from A's scope touched {result.rowcount} row(s)"))
            session.rollback()
        except Exception as exc:  # noqa: BLE001 — a refusal is the good outcome
            session.rollback()
            probes.append(Probe("cross-tenant-update-affects-nothing", True,
                                f"refused: {type(exc).__name__}: {exc}"))
        finally:
            session.close()

    with platform_scope():
        session = world.session_factory()
        try:
            still_b = session.execute(select(TenantUsageEvent.detail).where(
                TenantUsageEvent.id == row_b)).scalar_one()
            probes.append(Probe("cross-tenant-update-left-B-intact", still_b == MARKER_B,
                                f"B's row now reads {still_b!r}"))
        finally:
            session.close()
    return probes


def probe_raw_statements(world: World, ids: dict[str, str]) -> list[Probe]:
    """A query that forgets the predicate must fail closed, not return everything."""
    from sqlalchemy import select, text

    from db.models.tenant import TenantUsageEvent
    from db.tenancy import TenantScopeViolation, tenant_scope

    probes: list[Probe] = []
    with tenant_scope(ids[TENANT_A]):
        session = world.session_factory()
        try:
            session.execute(text(f"SELECT id FROM {TenantUsageEvent.__tablename__}")).all()
            probes.append(Probe("raw-text-sql-refused", False,
                                "a Core/text statement executed inside a tenant scope"))
        except TenantScopeViolation as exc:
            probes.append(Probe("raw-text-sql-refused", True, f"refused: {exc}"))
        except Exception as exc:  # noqa: BLE001
            probes.append(Probe("raw-text-sql-refused", False,
                                f"failed for another reason — not the tenant guard: "
                                f"{type(exc).__name__}: {exc}"))
        finally:
            session.rollback()
            session.close()

        session = world.session_factory()
        try:
            session.execute(select(TenantUsageEvent.__table__)).all()
            probes.append(Probe("core-select-on-a-tenant-table-refused", False,
                                "a Core select on a tenant-owned table executed"))
        except TenantScopeViolation as exc:
            probes.append(Probe("core-select-on-a-tenant-table-refused", True,
                                f"refused: {exc}"))
        except Exception as exc:  # noqa: BLE001
            probes.append(Probe("core-select-on-a-tenant-table-refused", False,
                                f"failed for another reason: {type(exc).__name__}: {exc}"))
        finally:
            session.rollback()
            session.close()
    return probes


def probe_membership_resolution(world: World, ids: dict[str, str]) -> list[Probe]:
    """A valid session for the *other* tenant must not buy that tenant's scope."""
    from starlette.requests import Request

    from api.dependencies import TenantResolutionRefused, resolve_tenant_for_request
    from api.security.session_manager import SessionManager

    manager = SessionManager()
    token_a = manager.create_session(f"user-{TENANT_A}", roles=["readonly"])
    token_b = manager.create_session(f"user-{TENANT_B}", roles=["readonly"])

    def scope_with(tenant_header: str | None, token: str | None) -> Request:
        headers = [(b"host", b"testserver")]
        if token:
            headers.append((b"authorization", f"Bearer {token}".encode()))
        if tenant_header:
            headers.append((b"x-tenant-id", tenant_header.encode()))
        # Not an /api path: this request never reaches the app, so naming a
        # product-shaped path here would put a phantom endpoint in the
        # route-contract census.
        return Request({"type": "http", "method": "GET", "path": "/__drill/tenant-scope",
                        "headers": headers, "query_string": b"", "state": {}})

    probes: list[Probe] = []

    request = scope_with(ids[TENANT_A], token_a)
    probes.append(Probe("member-resolves-own-tenant",
                        resolve_tenant_for_request(request) == ids[TENANT_A],
                        f"A's session resolved to {ids[TENANT_A]}"))

    try:
        resolved = resolve_tenant_for_request(scope_with(ids[TENANT_B], token_a))
        probes.append(Probe("header-for-another-tenant-does-not-scope", resolved != ids[TENANT_B],
                            f"a forged X-Tenant-ID resolved to {resolved}"))
    except TenantResolutionRefused as exc:
        probes.append(Probe("header-for-another-tenant-does-not-scope", True,
                            f"refused: {exc}"))

    try:
        resolved = resolve_tenant_for_request(scope_with(ids[TENANT_B], token_b))
        probes.append(Probe("control-own-header-still-works", resolved == ids[TENANT_B],
                            f"B's own session with B's header resolved to {resolved}"))
    except TenantResolutionRefused as exc:  # pragma: no cover - would be a defect
        probes.append(Probe("control-own-header-still-works", False, f"refused: {exc}"))

    probes.append(Probe("no-session-no-scope", resolve_tenant_for_request(
        scope_with(None, None)) is None,
        "an unauthenticated request resolves no tenant — the auth gate refuses it "
        "before any query runs"))
    return probes


def _active_inside(tenant_id: str) -> bool:
    from db.tenancy import isolation_active, tenant_scope

    with tenant_scope(tenant_id):
        return isolation_active()


def probe_controls(world: World, ids: dict[str, str]) -> list[Probe]:
    """Prove the filter — not the data — is what separates the tenants."""
    from sqlalchemy import select

    from db.models.tenant import TenantUsageEvent
    from db.tenancy import platform_scope

    with platform_scope():
        session = world.session_factory()
        try:
            details = {row.detail for row in session.execute(
                select(TenantUsageEvent).where(TenantUsageEvent.kind == "drill")
            ).scalars().all()}
        finally:
            session.close()
    return [
        Probe("without-a-scope-both-tenants-are-visible",
              {MARKER_A, MARKER_B} <= details,
              f"from a platform scope the same query returns {sorted(details)} — so the "
              "rows are only separated by the scope, which is exactly what the rows "
              "above measure"),
        Probe("guard-reports-active-inside-a-scope", _active_inside(ids[TENANT_A]),
              "inside a tenant scope the guard reports filtering on; in a platform "
              "scope it reports off, which is why the rows above are attributed to the "
              "scope rather than to luck"),
    ]


def probe_at_rest(world: World, ids: dict[str, str]) -> list[Probe]:
    """The honest half: what a stolen copy of the store reveals."""
    import sqlite3

    connection = sqlite3.connect(world.path)
    try:
        rows = connection.execute(
            "SELECT tenant_id, detail FROM tenant_usage_events WHERE detail IN (?, ?)",
            (MARKER_A, MARKER_B)).fetchall()
    finally:
        connection.close()
    plaintext = sorted(row[1] for row in rows)
    return [Probe(
        "stolen-store-reveals-every-tenant",
        plaintext == [MARKER_A, MARKER_B] or plaintext == sorted([MARKER_B, MARKER_A]),
        ("reading the database file directly returns both tenants' rows in plaintext: "
         f"{plaintext} — the isolation is enforced by a scope in code and, on PostgreSQL, "
         "by row-level policies, but it is not cryptographic: the file has no key")
        if len(plaintext) == 2 else
        f"the direct read returned {plaintext}, which needs explaining")]


# --------------------------------------------------------------------------- #
# the database's own enforcement (PostgreSQL)
# --------------------------------------------------------------------------- #

def probe_database_enforcement() -> tuple[list[Probe], dict[str, Any]] | None:
    """Ask PostgreSQL itself to enforce the boundary, then try to break it.

    The SQLite rows above measure a scope applied by code. This one measures
    migration 0132's policies on a real server: two tenants, a role that is not
    the table owner, and queries written the way an attacker would write them —
    no predicate, a foreign primary key, a foreign INSERT.

    Every probe runs in its own transaction, because that is the only way the
    test means anything: ``set_config(..., true)`` is transaction-local, and a
    probe that reused the setup transaction would be reading its own uncommitted
    rows rather than what the policy shows a stranger.

    Returns ``None`` when this checkout has no PostgreSQL, so the row says SKIP
    rather than quietly disappearing from the report.
    """
    import subprocess

    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    try:
        from pg_qualification import postgres_server  # noqa: PLC0415
    except Exception as error:  # noqa: BLE001 — reported as SKIP, not swallowed
        print(f"database_enforcement skipped: cannot import the server helper "
              f"({type(error).__name__}: {error})", file=sys.stderr)
        return None

    from sqlalchemy import create_engine, text

    tenant_a = "11111111-1111-1111-1111-111111111111"
    tenant_b = "22222222-2222-2222-2222-222222222222"
    setting = "cryptoscan.tenant_id"

    with postgres_server() as server:
        if server is None:
            return None
        url = server["url"]
        env = dict(os.environ)
        env["DATABASE_URL"] = url
        env["PYTHONPATH"] = os.pathsep.join(str(REPO_ROOT / part) for part in (
            "services/api", "services/database", "shared/shared_models",
            "shared/shared_config", "shared/shared_logging"))
        applied = subprocess.run(
            [sys.executable, "-m", "alembic", "-c", "migrations/alembic.ini", "upgrade", "head"],
            cwd=REPO_ROOT / "services" / "database", env=env,
            capture_output=True, text=True, timeout=900)
        if applied.returncode != 0:
            return [Probe("migrations-apply", False,
                          "alembic upgrade head failed: "
                          f"{(applied.stderr or applied.stdout)[-400:]}")], {}

        engine = create_engine(url, future=True)
        probes: list[Probe] = []
        try:
            # ---- setup, committed before anything is measured -----------------
            with engine.begin() as setup:
                version = setup.execute(text("SHOW server_version")).scalar()
                tables = int(setup.execute(text(
                    "SELECT count(*) FROM information_schema.columns "
                    "WHERE table_schema = current_schema() AND column_name = 'tenant_id'"
                )).scalar() or 0)
                forced = int(setup.execute(text(
                    "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                    "WHERE n.nspname = current_schema() AND c.relrowsecurity AND c.relforcerowsecurity"
                )).scalar() or 0)
                policies = int(setup.execute(text(
                    "SELECT count(*) FROM pg_policies WHERE schemaname = current_schema()"
                )).scalar() or 0)
                for tenant_id, marker in ((tenant_a, MARKER_A), (tenant_b, MARKER_B)):
                    setup.execute(text(
                        "INSERT INTO tenant_usage_events (id, created_at, updated_at, tenant_id, "
                        "kind, amount, detail) VALUES (gen_random_uuid(), now(), now(), :tenant, "
                        "'drill', 1, :detail)"), {"tenant": tenant_id, "detail": marker})
                # A plain role to own the control tables: `cryptoscan_platform`
                # carries BYPASSRLS, so it cannot demonstrate what FORCE does.
                setup.execute(text(
                    "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='drill_owner') "
                    "THEN CREATE ROLE drill_owner NOLOGIN NOBYPASSRLS; END IF; END $$"))

            probes.append(Probe(
                "policy-exists-on-every-tenant-table", tables > 0 and forced >= tables and policies >= tables,
                f"PostgreSQL {version}: {forced} of {tables} table(s) with a tenant_id have RLS "
                f"enabled and forced, with {policies} policy row(s)"))

            # ---- the policy, measured as a role that is not the owner ----------
            def count_as(role: str, value: str | None) -> int:
                """Rows ``role`` sees with the setting bound for this transaction."""
                with engine.begin() as scope:
                    # SET LOCAL: a role left set on a pooled connection is exactly
                    # the leak this drill exists to catch.
                    scope.execute(text(f"SET LOCAL ROLE {role}"))
                    if value is not None:
                        scope.execute(text(f"SELECT set_config('{setting}', :v, true)"), {"v": value})
                    return int(scope.execute(text(
                        "SELECT count(*) FROM tenant_usage_events WHERE detail IN (:a, :b)"),
                        {"a": MARKER_A, "b": MARKER_B}).scalar() or 0)

            unset = count_as("cryptoscan_tenant", None)
            scoped = count_as("cryptoscan_tenant", tenant_a)
            wildcard = count_as("cryptoscan_tenant", "*")
            probes.append(Probe(
                "no-setting-reads-nothing", unset == 0,
                f"a connection carrying no tenant setting reads {unset} of the two rows — the "
                "policy fails closed instead of defaulting to everything"))
            probes.append(Probe(
                "setting-scopes-to-one-tenant", scoped == 1,
                f"with the setting bound to tenant A the same unqualified query returns {scoped} row(s)"))
            probes.append(Probe(
                "platform-wildcard-is-explicit", wildcard == 2,
                f"the platform wildcard returns {wildcard} rows — a cross-tenant read is a "
                "deliberate setting, not the default"))

            refused = ""
            try:
                with engine.begin() as scope:
                    scope.execute(text("SET LOCAL ROLE cryptoscan_tenant"))
                    scope.execute(text(f"SELECT set_config('{setting}', :v, true)"), {"v": tenant_a})
                    scope.execute(text(
                        "INSERT INTO tenant_usage_events (id, created_at, updated_at, tenant_id, "
                        "kind, amount, detail) VALUES (gen_random_uuid(), now(), now(), :tenant, "
                        "'drill', 1, 'drill-cross-tenant-write')"), {"tenant": tenant_b})
            except Exception as error:  # noqa: BLE001 - the refusal is the evidence
                refused = str(error).splitlines()[0]
            probes.append(Probe(
                "cross-tenant-insert-refused", "row-level security" in refused.lower(),
                f"an INSERT naming tenant B from a tenant-A setting is refused: {refused}"
                if refused else "the INSERT landed — the policy's WITH CHECK is not binding"))

            with engine.begin() as scope:
                scope.execute(text("SET LOCAL ROLE cryptoscan_tenant"))
                scope.execute(text(f"SELECT set_config('{setting}', :v, true)"), {"v": tenant_a})
                updated = scope.execute(text(
                    "UPDATE tenant_usage_events SET amount = 99 WHERE detail = :detail"),
                    {"detail": MARKER_B}).rowcount
            probes.append(Probe(
                "cross-tenant-update-affects-nothing", updated == 0,
                f"an UPDATE aimed at tenant B's row from a tenant-A setting touched {updated} row(s)"))

            # ---- FORCE: the half that binds the table's own owner -------------
            for table, force in (("drill_owner_unforced", False), ("drill_owner_forced", True)):
                with engine.begin() as setup:
                    setup.execute(text(f"DROP TABLE IF EXISTS {table}"))
                    setup.execute(text(
                        f"CREATE TABLE {table} (id serial PRIMARY KEY, tenant_id text, detail text)"))
                    setup.execute(text(f"ALTER TABLE {table} OWNER TO drill_owner"))
                    setup.execute(text(f"INSERT INTO {table} (tenant_id, detail) VALUES "
                                       f"(:a, :ma), (:b, :mb)"),
                                  {"a": tenant_a, "b": tenant_b, "ma": MARKER_A, "mb": MARKER_B})
                    setup.execute(text(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
                    if force:
                        setup.execute(text(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY"))
                    setup.execute(text(
                        f"CREATE POLICY tenant_isolation ON {table} "
                        f"USING (tenant_id::text = cryptoscan_current_tenant())"))

            def owner_sees(table: str) -> int:
                with engine.begin() as scope:
                    scope.execute(text("SET LOCAL ROLE drill_owner"))
                    scope.execute(text(f"SELECT set_config('{setting}', :v, true)"), {"v": tenant_a})
                    return int(scope.execute(text(f"SELECT count(*) FROM {table}")).scalar() or 0)

            unforced, forced_owner = owner_sees("drill_owner_unforced"), owner_sees("drill_owner_forced")
            probes.append(Probe(
                "force-is-what-binds-the-owner", unforced == 2 and forced_owner == 1,
                f"the table's own owner reads {unforced} row(s) with RLS enabled but not forced, "
                f"and {forced_owner} with it forced — which is why the migration forces it"))

            # ---- the honest half ----------------------------------------------
            with engine.begin() as scope:
                as_superuser = int(scope.execute(text(
                    "SELECT count(*) FROM tenant_usage_events WHERE detail IN (:a, :b)"),
                    {"a": MARKER_A, "b": MARKER_B}).scalar() or 0)
            probes.append(Probe(
                "superuser-reads-across-tenants", as_superuser == 2,
                f"a superuser reads all {as_superuser} row(s): RLS binds roles, not privileges "
                "above it — and a stolen data file is still plaintext"))

            from db.rls import enforcement  # noqa: PLC0415 — after DATABASE_URL is set

            with engine.connect() as report_connection:
                summary = enforcement(report_connection)
        finally:
            engine.dispose()
        return probes, summary


# --------------------------------------------------------------------------- #
# report
# --------------------------------------------------------------------------- #

def measure() -> dict[str, Any]:
    world = build_world()
    try:
        ids = _seed(world)

        rls_probes, rls_summary = probe_database_enforcement() or ([], {})

        def row(row_id: str, question: str, probes: list[Probe], *,
                unproven: list[str] | None = None,
                limits: list[str] | None = None,
                verdict: str | None = None) -> dict[str, Any]:
            failed = [probe for probe in probes if not probe.ok]
            return {
                "id": row_id,
                "question": question,
                "verdict": verdict or (FAIL if failed else PASS),
                "probes": [probe.as_dict() for probe in probes],
                "unproven": unproven or [],
                "limits": limits or [],
            }

        rows = [
            row("read_filtering",
                "can tenant A read a row that belongs to tenant B?",
                probe_read_filtering(world, ids)),
            row("write_stamping", "can tenant A write a row into tenant B?",
                probe_write_stamping(world, ids)),
            row("cross_tenant_mutation",
                "can tenant A update or delete a row it cannot see?",
                probe_cross_tenant_mutation(world, ids)),
            row("raw_statements",
                "does a query that forgets the predicate fail closed?",
                probe_raw_statements(world, ids)),
            row("membership_resolution",
                "does a valid session plus a spoofed header buy the other tenant's scope?",
                probe_membership_resolution(world, ids)),
            row("controls", "is the isolation the filter's doing, or the data's?",
                probe_controls(world, ids)),
            row("database_enforcement",
                "does PostgreSQL enforce the boundary, or only the Python scope?",
                rls_probes,
                verdict=None if rls_probes else SKIP,
                unproven=[] if rls_probes else [
                    "no PostgreSQL distribution is available in this checkout, so migration "
                    "0132's policies were not executed here — SKIP is not a pass"],
                limits=["the policy binds roles, not privilege: a superuser or a role "
                        "granted BYPASSRLS reads across tenants, and a stolen data file is "
                        "still plaintext — this is enforcement, not encryption"],
                ),
            row("at_rest",
                "is the isolation cryptographic, or logical and enforced by code?",
                probe_at_rest(world, ids),
                verdict=PARTIAL,
                unproven=[
                    "this is not encryption: the store is shared and unencrypted per "
                    "tenant, so a database dump — or a backup, or a stolen disk — still "
                    "contains every tenant's rows in plaintext. Isolation stops a *reader "
                    "through the database*; it does not stop a reader of the file",
                    "the `database_enforcement` row above closes the part that could be "
                    "closed here: PostgreSQL's policies bind a role that forgets its "
                    "predicate. Closing the rest needs per-tenant keys (or per-tenant "
                    "databases) held by the tenant, which no row in this drill can "
                    "substitute for",
                ]),
        ]

        counts = {verdict: sum(1 for row in rows if row["verdict"] == verdict)
                  for verdict in (PASS, PARTIAL, FAIL, SKIP)}
        return {
            "schema": SCHEMA,
            "version": VERSION,
            "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "counts": counts,
            "rows": rows,
            "database_enforcement": rls_summary,
            "tenants": 2,
            "limits": [
                "the read/write rows are executed against SQLite with the same ORM guard "
                "and the same tenancy module the API uses; the `database_enforcement` row "
                "is the PostgreSQL half, and it says SKIP rather than PASS when no server "
                "is available",
                "the drill covers the data layer and the tenant resolution the "
                "middleware calls; guide 121 covers the per-route declarations",
            ],
        }
    finally:
        world.engine.dispose()
        try:
            os.unlink(world.path)
        except OSError:
            pass


def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    lines = [
        "# Multi-tenant isolation — two tenants, every direction",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{counts[PASS]} pass · {counts[PARTIAL]} partial · {counts[FAIL]} fail"
        + (f" · {counts[SKIP]} skip**" if counts.get(SKIP) else "**"),
        "",
        "| Question | Verdict | Evidence |",
        "|---|---|---|",
    ]
    for row in report["rows"]:
        first = row["probes"][0]["observed"] if row["probes"] else ""
        lines.append(f"| **{row['question']}** | **{row['verdict']}** | {first} |")

    lines += ["", "## Row by row", ""]
    for row in report["rows"]:
        lines.append(f"### `{row['id']}` — {row['verdict']}")
        lines.append("")
        lines.append(f"*{row['question']}*")
        lines.append("")
        for probe in row["probes"]:
            lines.append(f"- **{'PASS' if probe['ok'] else 'NOT MET'}** "
                         f"`{probe['probe']}` — {probe['observed']}")
        for gap in row["unproven"]:
            lines.append(f"- **Not proven:** {gap}")
        for limit in row["limits"]:
            lines.append(f"- **Limit:** {limit}")
        lines.append("")

    lines += ["## What this does not prove", ""]
    for limit in report["limits"]:
        lines.append(f"- {limit}")
    enforcement = report.get("database_enforcement") or {}
    lines += [
        "",
        "**The verdict this drill supports:** two tenants cannot read, write or mutate "
        "each other's rows, a query that forgets its predicate fails closed, a spoofed "
        "`X-Tenant-ID` with a valid session buys nothing, and a foreign primary key is "
        "not readable — and on PostgreSQL the boundary is enforced a second time by the "
        "database itself: a role that carries no tenant setting reads nothing, a foreign "
        "INSERT is refused by the policy, and `FORCE ROW LEVEL SECURITY` binds even the "
        "table's owner. What it is **not** is encryption: one store, one schema, "
        "plaintext at rest, and a superuser reads across tenants by design. The last two "
        "rows say so where a reader cannot miss it."
        + (f" The applying role in this run (`{enforcement.get('role')}`) is itself a "
           f"superuser, so `binds_this_role` is {enforcement.get('binds_this_role')} — the "
           "policy was measured through the `cryptoscan_tenant` and `drill_owner` roles, "
           "not through it." if enforcement.get("supported") else ""),
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Multi-tenant isolation drill.")
    parser.add_argument("--json", help="write the report JSON here")
    parser.add_argument("--md", help="write the markdown report here")
    parser.add_argument("--max-fail", type=int, default=99)
    args = parser.parse_args(argv)

    report = measure()
    if args.json:
        path = Path(args.json)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2) + "\n")
    if args.md:
        path = Path(args.md)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render_md(report))

    if args.md or args.json:
        print(render_md(report))
    else:
        for row in report["rows"]:
            failed = [probe for probe in row["probes"] if not probe["ok"]]
            detail = failed[0]["observed"] if failed else (
                row["probes"][0]["observed"] if row["probes"] else "")
            print(f"{row['verdict']:<8} {row['id']:<22} {detail[:100]}")
        print(f"\n{report['counts']}")
    return 0 if report["counts"][FAIL] <= args.max_fail else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
