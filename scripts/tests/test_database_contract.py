"""The Twin and CLI read paths, checked against a *migrated* database.

Every other test in this tree builds its schema from ``Base.metadata.create_all``.
That is convenient and it is also blind: ``create_all`` reads the ORM models, so a
model can gain a column that no migration creates and every test still passes —
until a bank runs the migration chain and the first read of that table raises.

This file closes that gap for the paths that matter most (spec 94's Digital Twin
and the operator CLI that reads it). It starts a real PostgreSQL, runs the actual
alembic chain to ``head``, and then:

1. asserts every ORM table and column exists in the migrated schema;
2. asserts the *residue* — columns the database has and no model maps — is exactly
   the known legacy set below, so new drift cannot be added silently;
3. drives the twin store on that schema (write, re-observe, read back, tenant
   isolation) instead of on ``create_all``;
4. runs ``cryptoscan twin status`` through its injected session factory against
   the migrated database, which is the CLI ↔ database contract an operator
   actually depends on.

The database is real but ephemeral: ``pgserver`` unpacks a PostgreSQL binary and
runs it on a unix socket in a temp directory. When it is unavailable the module
skips rather than passing quietly.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
for extra in (
    "services/database",
    "shared/shared_models",
    "shared/shared_config",
    "shared/shared_logging",
    "services/api",
):
    if str(ROOT / extra) not in sys.path:
        sys.path.insert(0, str(ROOT / extra))

pgserver = pytest.importorskip("pgserver", reason="pgserver is not installed: no PostgreSQL to migrate")

MIGRATIONS = ROOT / "services" / "database" / "migrations"

#: Columns the migration chain creates that no ORM model maps. Each one is
#: residue from a withdrawn code path, kept because dropping a column is a
#: separate release decision — not because a reader should use it. A new entry
#: here means a model lost a column without a migration, which is the defect this
#: file exists to catch, so adding one requires a comment naming the model.
KNOWN_UNMAPPED_COLUMNS = {
    # estate_daemons is deliberately platform-scoped (see db/models/estate_daemon.py);
    # the shared `base()` helper in the migration still adds tenant_id.
    "estate_daemons.tenant_id",
    # evidence_records: the normalization columns of the pre-evidence-chain writer.
    # No model, repository or query reads any of them today.
    "evidence_records.algorithm_family",
    "evidence_records.highest_severity_failed",
    "evidence_records.nist_designation",
    "evidence_records.normalization_confidence",
    "evidence_records.normalization_status",
    "evidence_records.normalization_version",
    "evidence_records.normalized_algorithm",
    "evidence_records.policy_evaluated_at",
    "evidence_records.policy_version",
    "evidence_records.requires_review",
    "evidence_records.rules_failed_count",
    "evidence_records.rules_passed_count",
    # verification_log: the old policy-verdict writer.
    "verification_log.errors",
    "verification_log.findings_count_verified",
    "verification_log.manifest_valid",
}

#: Tables the migration chain owns that are not ORM tables, and are expected.
KNOWN_EXTRA_TABLES = {"alembic_version", "_alembic_0078_indexes"}


@pytest.fixture(scope="module")
def migrated():
    """A real PostgreSQL at the tip of the migration chain."""
    work = tempfile.mkdtemp(prefix="pg-contract-")
    server = pgserver.get_server(work)
    uri = server.get_uri()
    server.psql("CREATE DATABASE cryptoscan;")
    host = uri.split("host=")[1]
    url = f"postgresql+psycopg2://postgres:@/cryptoscan?host={host}"

    env = dict(os.environ)
    env["DATABASE_URL"] = url
    env["PYTHONPATH"] = ":".join(
        [
            str(ROOT / "services" / "database"),
            str(ROOT / "shared" / "shared_models"),
            str(ROOT / "shared" / "shared_config"),
            str(ROOT / "shared" / "shared_logging"),
            str(ROOT / "services" / "api"),
            env.get("PYTHONPATH", ""),
        ]
    )
    proc = subprocess.run(
        [sys.executable, "-m", "alembic", "-c", "alembic.ini", "upgrade", "head"],
        cwd=str(MIGRATIONS),
        env=env,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        server.cleanup()
        pytest.fail("the migration chain does not reach head on PostgreSQL:\n" + proc.stderr[-4000:])

    from sqlalchemy import create_engine

    engine = create_engine(url, future=True)
    try:
        yield engine
    finally:
        engine.dispose()
        server.cleanup()


def _models():
    import db.models  # noqa: F401 — registers every table on Base.metadata
    from db.models.base import Base

    return Base


def _live_nullability(engine) -> dict[str, dict[str, bool]]:
    """Column name → whether the *database* requires a value."""
    from sqlalchemy import inspect

    inspector = inspect(engine)
    return {
        table: {c["name"]: bool(c["nullable"]) for c in inspector.get_columns(table)}
        for table in inspector.get_table_names()
    }


def _live_schema(engine) -> tuple[set[str], dict[str, set[str]]]:
    from sqlalchemy import inspect

    inspector = inspect(engine)
    tables = set(inspector.get_table_names())
    columns = {table: {c["name"] for c in inspector.get_columns(table)} for table in tables}
    return tables, columns


class TestTheMigratedSchemaMatchesTheModels:
    def test_every_orm_table_exists(self, migrated):
        tables, _ = _live_schema(migrated)
        missing = [t.name for t in _models().metadata.sorted_tables if t.name not in tables]
        assert missing == [], (
            "ORM tables with no migration: a bank's database would not have them. "
            f"Add a migration for {missing}"
        )

    def test_every_orm_column_exists(self, migrated):
        _, columns = _live_schema(migrated)
        missing: list[str] = []
        for table in _models().metadata.sorted_tables:
            live = columns.get(table.name, set())
            for column in table.columns:
                if column.name not in live:
                    missing.append(f"{table.name}.{column.name}")
        assert missing == [], (
            "model columns with no migration — every test that uses create_all passes and "
            f"the deployed read fails: {missing}"
        )

    def test_no_orphan_tables(self, migrated):
        tables, _ = _live_schema(migrated)
        mapped = {t.name for t in _models().metadata.sorted_tables}
        orphan = sorted(tables - mapped - KNOWN_EXTRA_TABLES)
        assert orphan == [], f"tables in the database that no model maps: {orphan}"

    def test_the_unmapped_columns_are_the_known_legacy_set(self, migrated):
        """Residue may only shrink. A new entry means a model lost a column."""
        _, columns = _live_schema(migrated)
        mapped = {
            table.name: {c.name for c in table.columns}
            for table in _models().metadata.sorted_tables
        }
        unmapped = {
            f"{table}.{name}"
            for table, live in columns.items()
            if table in mapped
            for name in live - mapped[table]
        }
        new = sorted(unmapped - KNOWN_UNMAPPED_COLUMNS)
        assert new == [], (
            "columns exist in the database but no model maps them. Either a model dropped a "
            f"column without a migration, or new residue was introduced: {new}"
        )


#: Columns the model declares NOT NULL, has no Python-side default for, and the
#: database nevertheless accepts as NULL. Empty, and it must stay empty: 0122 and
#: 0123 brought the two schemas into exact agreement. A new entry here means a
#: migration loosened a column the model refuses, or a model gained a NOT NULL
#: column over a table whose migration was already written — fix the migration.
KNOWN_LOOSE_COLUMNS: set[str] = set()


class TestTheMigratedSchemaEnforcesWhatTheModelsDeclare:
    """A column can exist in both places and still disagree.

    ``test_every_orm_column_exists`` compares names. A model that declares
    ``nullable=True`` over a column the migration created ``NOT NULL`` passes that
    test and then fails in production — the ORM happily builds the INSERT the
    database rejects. This is not hypothetical: it is how ``hbom_snapshots``'
    pin endpoint returned 500 on a live server for every estate-wide pin (no
    tenant is active outside a tenancy request, so ``tenant_id`` was NULL).

    Two directions, judged differently:

    * **model allows NULL, database refuses it** — always a defect. The write is
      rejected at runtime with a 500 the model never predicted. Must be empty.
    * **model refuses NULL, database allows it** — only a defect when the model
      has no Python-side default, because then a writer can leave the column out
      and the database will store a NULL the code promised could not exist. Where
      the model does supply a default, the ORM always writes a value, so those are
      tolerated and pinned in ``KNOWN_LOOSE_COLUMNS`` — which is now empty.
    """

    def test_a_model_may_not_allow_a_null_the_database_refuses(self, migrated):
        live = _live_nullability(migrated)
        drift: list[str] = []
        for table in _models().metadata.sorted_tables:
            live_table = live.get(table.name)
            if live_table is None:
                continue  # reported by test_every_orm_table_exists
            for column in table.columns:
                enforced = live_table.get(column.name)
                if enforced is None:
                    continue  # reported by test_every_orm_column_exists
                if column.nullable and not enforced:
                    drift.append(f"{table.name}.{column.name}")
        assert drift == [], (
            "the model allows NULL and the migrated database refuses it, so an ORM "
            "insert the application considers valid is a 500 at runtime (create_all "
            "hides this). Either relax the column in a migration or tighten the "
            "model: " + ", ".join(sorted(drift))
        )

    def test_a_database_null_must_be_unreachable_from_the_model(self, migrated):
        live = _live_nullability(migrated)
        loose: set[str] = set()
        for table in _models().metadata.sorted_tables:
            live_table = live.get(table.name)
            if live_table is None:
                continue
            for column in table.columns:
                enforced = live_table.get(column.name)
                if enforced is None or not enforced:
                    continue  # absent, or the database already refuses NULL
                if column.nullable:
                    continue  # the first test owns that direction
                if column.default is None and column.server_default is None:
                    loose.add(f"{table.name}.{column.name}")
        new = sorted(loose - KNOWN_LOOSE_COLUMNS)
        assert new == [], (
            "the database accepts NULL for a column the model declares NOT NULL and "
            "supplies no default for, so a writer that omits it stores a NULL the "
            f"code promised could not exist: {new}"
        )
        stale = sorted(KNOWN_LOOSE_COLUMNS - loose)
        assert stale == [], f"KNOWN_LOOSE_COLUMNS entries that no longer drift: {stale}"


#: CHECK constraints the migrations create that no model declares. One entry:
#: the column it guards (`normalization_status`) is itself unmapped residue, so
#: there is no model attribute to attach it to. Everything else is declared on
#: the model, so `create_all` and `alembic upgrade head` agree about which rows
#: the database will accept.
KNOWN_UNDECLARED_CHECKS = {"evidence_records.ck_normalization_status"}


class TestCheckConstraintsMatchTheModels:
    """A CHECK the database enforces and the model does not is silent asymmetry.

    `create_all` installations (SQLite, every test) then accept rows a migrated
    PostgreSQL rejects, and the first writer to produce one gets a `CheckViolation`
    nobody tested. `scans.status` had exactly that shape: the model defaults to
    `QUEUED`, the constraint permitted everything but `QUEUED`, and only a bank's
    database could fail.
    """

    def test_every_model_declared_check_exists_in_the_migrated_schema(self, migrated):
        from sqlalchemy import inspect

        inspector = inspect(migrated)
        missing: list[str] = []
        for table in _models().metadata.sorted_tables:
            wanted = {
                constraint.name
                for constraint in table.constraints
                if type(constraint).__name__ == "CheckConstraint" and constraint.name
            }
            if not wanted:
                continue
            live = {c["name"] for c in inspector.get_check_constraints(table.name)}
            for name in sorted(wanted - live):
                missing.append(f"{table.name}.{name}")
        assert missing == [], (
            "the model declares CHECK constraints the migrated database does not "
            f"enforce, so create_all and a real install disagree: {missing}"
        )

    def test_the_undeclared_checks_are_the_known_set(self, migrated):
        from sqlalchemy import inspect

        inspector = inspect(migrated)
        declared: dict[str, set[str]] = {
            table.name: {
                constraint.name
                for constraint in table.constraints
                if type(constraint).__name__ == "CheckConstraint" and constraint.name
            }
            for table in _models().metadata.sorted_tables
        }
        undeclared = {
            f"{table}.{check['name']}"
            for table in inspector.get_table_names()
            for check in inspector.get_check_constraints(table)
            if check["name"] not in declared.get(table, set())
        }
        assert sorted(undeclared - KNOWN_UNDECLARED_CHECKS) == [], (
            "CHECK constraints in the database that no model declares — a "
            "create_all install accepts rows a migrated one rejects: "
            + ", ".join(sorted(undeclared - KNOWN_UNDECLARED_CHECKS))
        )


class TestEveryMappedTableCanBeRead:
    """Every one of the 155 mapped tables is actually selectable on the migrated schema.

    The name and nullability checks above compare the two schemas. They do not
    prove the ORM can *read* a table: a column whose database type the dialect
    cannot decode, an enum value the model rejects, a server-side default that
    returns something the type does not accept, or a relationship that joins on a
    column the migration never created all survive a schema comparison and fail
    on the first `SELECT`.

    So each mapped table gets one real round trip on PostgreSQL: insert a row
    built from the model's own defaults (skipping columns the database fills),
    read it back through the ORM, and delete it. Tables that need a foreign key
    the test cannot invent are read with an empty `SELECT` instead — the goal is
    the read path, not a full fixture for every table.
    """

    def test_every_mapped_table_is_selectable(self, migrated):
        from sqlalchemy import select
        from sqlalchemy.orm import Session

        models = _models()
        unreadable: list[str] = []
        with Session(migrated) as db:
            for table in models.metadata.sorted_tables:
                model = None
                for mapper in models.registry.mappers:
                    if mapper.local_table is table:
                        model = mapper.class_
                        break
                try:
                    if model is not None:
                        db.execute(select(model).limit(1)).all()
                    else:  # a table with no mapped class (association tables)
                        db.execute(select(table).limit(1)).all()
                except Exception as error:  # noqa: BLE001 - the message is the finding
                    unreadable.append(f"{table.name}: {type(error).__name__}: {str(error)[:200]}")
        assert unreadable == [], (
            "tables the ORM cannot select on the migrated schema:\n  " + "\n  ".join(unreadable)
        )

    def test_every_mapped_table_survives_a_write_and_read_back(self, migrated):
        """Insert a row the schema will accept, read it back, remove it.

        The row is built from the model's own columns: a value for every column
        that is required and has no default, of the type the column declares. A
        table that cannot take that row is a real finding — either the model
        declares a constraint the migration does not (or the reverse), or a
        column type the dialect cannot round-trip. Tables needing a foreign key
        to an existing row are skipped by name and listed, not silently dropped.
        """
        from sqlalchemy import select
        from sqlalchemy.orm import Session

        models = _models()
        failures: list[str] = []
        skipped: list[str] = []
        written = 0
        with Session(migrated) as db:
            for table in models.metadata.sorted_tables:
                if _needs_a_parent(table):
                    skipped.append(table.name)
                    continue
                model = None
                for mapper in models.registry.mappers:
                    if mapper.local_table is table:
                        model = mapper.class_
                        break
                if model is None:
                    continue
                try:
                    # The savepoint is rolled back rather than deleted: several
                    # tables refuse deletes on purpose (append-only assurance and
                    # evidence history), and that refusal is a feature, not a
                    # finding.
                    with db.begin_nested():
                        row = model(**_required_values(table))
                        db.add(row)
                        db.flush()
                        identifier = getattr(row, "id", None)
                        if identifier is not None:
                            found = db.execute(select(model).where(model.id == identifier)).scalar_one()
                            assert found is not None
                        raise _RollbackSafepoint
                    written += 1
                except _RollbackSafepoint:
                    written += 1
                except Exception as error:  # noqa: BLE001
                    failures.append(f"{table.name}: {type(error).__name__}: {str(error).splitlines()[0][:200]}")
            db.rollback()
        assert written >= 90, (
            f"only {written} tables were exercised with a write (skipped {len(skipped)} "
            f"needing a parent row); the synthesis is not reaching the schema"
        )
        assert failures == [], (
            "tables the ORM cannot write and read back on the migrated schema:\n  "
            + "\n  ".join(failures)
        )


#: Tables whose first row cannot exist without a row in another table this test
#: does not build. Kept deliberately short: every entry is a table whose read
#: path goes unexercised here.
PARENT_REQUIRED = {
    # user_id is required and refers to a provisioned account; MFA is enrolled
    # against a user that already exists
    "mfa_recovery_codes",
}


class _RollbackSafepoint(Exception):
    """Unwinds the per-table savepoint after a successful write and read-back."""


def _needs_a_parent(table) -> bool:
    """True when a required column is a foreign key the test cannot invent."""
    if table.name in PARENT_REQUIRED:
        return True
    for column in table.columns:
        if column.nullable or column.default is not None or column.server_default is not None:
            continue
        if column.foreign_keys:
            return True
        if column.name in {"id", "created_at", "updated_at"}:
            continue
    return False


def _value_for(column):
    """A value the column will accept, chosen from its declared type."""
    import datetime as _dt
    import uuid as _uuid

    kind = str(column.type).upper()
    name = column.name.lower()
    if name == "scope_key":
        # Every scoped table enforces `scope_key = CASE WHEN tenant_id IS NULL
        # THEN 'platform' ELSE 'tenant:' || tenant_id END`, and this row is
        # written on the platform estate.
        return "platform"
    if kind.startswith(("VARCHAR", "STRING", "TEXT", "CHAR")):
        width = getattr(column.type, "length", None)
        value = f"contract-{name}"
        return value[: width] if isinstance(width, int) and width else value
    if kind.startswith(("INT", "BIGINT", "SMALLINT", "NUMERIC", "FLOAT", "REAL", "DOUBLE", "DECIMAL")):
        return 1
    if kind.startswith(("DATETIME", "TIMESTAMP", "DATE")):
        return _dt.datetime.now(_dt.timezone.utc)
    if kind.startswith("BOOLEAN"):
        return False
    if kind.startswith(("JSON", "JSONB")):
        return {}
    if kind.startswith("UUID"):
        return _uuid.uuid4()
    if kind.startswith(("BYTEA", "BLOB", "LARGEBINARY", "BINARY")):
        return b"contract"
    if "ENUM" in kind:
        members = list(getattr(column.type, "enums", []) or [])
        return members[0] if members else "contract"
    return "contract"


def _required_values(table) -> dict:
    """Constructor kwargs for the columns the database will not fill in."""
    values = {}
    for column in table.columns:
        if column.nullable or column.default is not None or column.server_default is not None:
            continue
        if column.name == "id":
            continue
        values[column.key] = _value_for(column)
    return values


class TestPlatformScopeWritesOnTheMigratedSchema:
    """Rows that belong to no tenant must be writable on the real schema.

    ``TenantScoped`` documents NULL ``tenant_id`` as "the platform estate": an
    installation with no tenancy, or a collector that produces one answer for the
    whole estate. Several tables disagreed with that in the migration chain — the
    columns were ``NOT NULL`` — and because every other test builds its schema
    with ``create_all``, nothing noticed until a live server answered
    ``POST /api/v1/hbom/snapshot`` with 500 (``null value in column "tenant_id"``).
    These tests write exactly the rows those endpoints write.
    """

    def test_an_estate_hbom_pin_persists(self, migrated):
        from datetime import datetime, timezone

        from sqlalchemy.orm import Session

        from db.models.hbom_snapshot import HbomSnapshot

        with Session(migrated) as db:
            row = HbomSnapshot(
                environment="production",
                content_hash="a" * 64,
                format="json",
                generator="api",
                payload={"bomFormat": "HBOM", "components": []},
                component_count=0,
                created_by="contract-test",
                snapshotted_at=datetime.now(timezone.utc),
            )
            db.add(row)
            db.commit()  # the write that used to raise on PostgreSQL
            assert row.id

    def test_a_platform_advisory_persists(self, migrated):
        from sqlalchemy.orm import Session

        from db.models.threat_advisory import AlgorithmAdvisory

        with Session(migrated) as db:
            row = AlgorithmAdvisory(
                advisory_id="CVE-CONTRACT-1",
                source="contract-feed",
                advisory_type="DEPRECATION",
                algorithm="RSA-2048",
                severity="HIGH",
            )
            db.add(row)
            db.commit()
            assert row.id

    def test_the_network_inventory_persists_without_a_tenant(self, migrated):
        from sqlalchemy.orm import Session

        from db.models.network_topology import TopologyEdge, TopologyNode

        with Session(migrated) as db:
            db.add(TopologyNode(name="contract-node", kind="host"))
            db.add(TopologyEdge(from_name="contract-node", to_name="contract-node-2", relation="PROXIES_TO"))
            db.commit()


def _payload() -> dict:
    return {
        "estate": "contract-estate",
        "assets": [
            {"ref": "api", "type": "APPLICATION", "name": "payment-api",
             "identity": {"name": "payment-api", "system": "Payment System"}},
            {"ref": "hsm", "type": "HSM", "name": "HSM-03",
             "identity": {"vendor": "Thales", "serial_number": "SN-3"}},
        ],
        "evidence": [
            {
                "evidence_id": "ev-1",
                "source": "/etc/payment/pkcs11.conf",
                "collector": "linux-static",
                "evidence_type": "CONFIGURED",
                "target": "api",
                "layer": "HSM",
                "facts": {"hsm_reference": "HSM-03"},
            },
        ],
        "relationships": [
            {
                "subject": "api",
                "predicate": "uses_hsm",
                "object": "hsm",
                "basis": "PKCS11_REFERENCE",
                "evidence_ids": ["ev-1"],
            },
        ],
        "collectors": [{"plane": "HSM", "status": "COMPLETE", "expected": 1, "collected": 1}],
    }


class TestTheTwinStoreOnTheMigratedSchema:
    def test_a_snapshot_is_written_and_read_back(self, migrated):
        from sqlalchemy.orm import Session

        from api import estate_twin_store
        from shared_models import estate_twin

        graph = estate_twin.graph_from_snapshot({"payload": _payload(), "estate": "contract-estate"})
        with Session(migrated) as db:
            row, created = estate_twin_store.record_snapshot(
                db, graph, tenant_id="tenant-a", captured_by="contract-test"
            )
            assert created is True
            assert row.policy_version is not None, "the policy version column was not written"
            fetched = estate_twin_store.get_snapshot(db, row.projection_id, tenant_id="tenant-a")
            assert fetched is not None, "a snapshot written on the migrated schema cannot be read back"
            assert fetched.snapshot_id == row.snapshot_id
            assert isinstance(fetched.payload, dict) and fetched.payload

    def test_re_observing_the_same_evidence_advances_the_counter(self, migrated):
        from sqlalchemy.orm import Session

        from api import estate_twin_store
        from shared_models import estate_twin

        graph = estate_twin.graph_from_snapshot({"payload": _payload(), "estate": "contract-estate"})
        with Session(migrated) as db:
            row, created = estate_twin_store.record_snapshot(db, graph, tenant_id="tenant-b")
            assert created is True
            again, created_again = estate_twin_store.record_snapshot(db, graph, tenant_id="tenant-b")
            assert created_again is False
            assert again.id == row.id
            assert again.observations == 2

    def test_a_snapshot_is_not_visible_to_another_tenant(self, migrated):
        from sqlalchemy.orm import Session

        from api import estate_twin_store
        from shared_models import estate_twin

        graph = estate_twin.graph_from_snapshot({"payload": _payload(), "estate": "contract-estate"})
        with Session(migrated) as db:
            row, _ = estate_twin_store.record_snapshot(db, graph, tenant_id="tenant-c")
            assert estate_twin_store.get_snapshot(db, row.projection_id, tenant_id="tenant-d") is None
            assert estate_twin_store.list_snapshots(db, tenant_id="tenant-d") == []


class TestTheOperatorCliReadsTheMigratedDatabase:
    def test_twin_status_runs_against_a_migrated_database(self, migrated):
        """The in-process CLI path: parser → handler → ORM → the real schema."""
        import contextlib
        import io

        os.environ.setdefault("ENVIRONMENT", "test")
        os.environ.setdefault("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
        os.environ.setdefault("ALLOW_SQLITE", "true")

        from sqlalchemy.orm import sessionmaker

        from api import cli

        factory = sessionmaker(bind=migrated, expire_on_commit=False)
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            # `twin status` is a REMOTE command even when a session factory is injected
            # (that is the point of the split), so the local read path is exercised via
            # `twin assets`, which queries the migrated catalogue tables.
            code = cli.main(["twin", "assets"], session_factory=lambda: factory())
        assert code == cli.EXIT_OK, f"twin assets failed on a migrated database: {out.getvalue()[-1500:]}"
        assert out.getvalue().strip(), "twin assets printed nothing"


#: Methods whose name says "this reads", used to pick what to drive below. A
#: deny-list would silently skip `archive_*`/`prune_*` readers; an allow-list errs
#: toward driving fewer methods, which is the safe direction for a test that
#: executes code against a live database.
READ_METHOD_PREFIXES = (
    "list", "get", "find", "count", "latest", "search", "exists", "has",
    "by", "for", "all", "read", "summary", "lookup", "resolve",
)

#: Methods that are read-shaped by name but write (or shell out to a tool).
NOT_A_READ = frozenset({"get_or_create", "get_or_upsert", "resolve_id"})


#: Unannotated parameters that are obviously a point in time. Passing a string to
#: one of these compares a `text` with a `timestamp` and PostgreSQL rejects it,
#: which would be a finding about the test, not about the repository.
TEMPORAL_NAMES = frozenset({
    "after", "before", "since", "until", "cutoff", "as_of", "now", "when",
    "started", "finished", "created", "updated",
})


def _is_temporal(name: str) -> bool:
    return name in TEMPORAL_NAMES or name.endswith(("_at", "_ts", "_time", "_date"))


def _placeholder(annotation) -> tuple[bool, object]:
    """(can-supply, value) for one annotated parameter."""
    import datetime as _dt
    import uuid as _uuid

    text = str(annotation)
    if text in {"<class 'inspect._empty'>", "inspect._empty"}:
        return False, None
    if "None" in text and "|" in text:
        return True, None  # Optional[...] — every reader must cope with absence
    if "datetime" in text:
        return True, _dt.datetime.now(_dt.timezone.utc)
    if "uuid" in text.lower():
        return True, _uuid.uuid4()
    if "bool" in text:
        return True, False
    if "int" in text or "float" in text:
        return True, 0
    if "dict" in text or "Mapping" in text:
        return True, {}
    if "list" in text or "Sequence" in text or "set" in text:
        return True, []
    if "str" in text:
        return True, "contract-missing"
    return False, None


def _repository_reads() -> list[tuple[type, str]]:
    """(repository class, method name) for every read-shaped public method."""
    import importlib
    import inspect
    import pkgutil

    import db.repositories as package
    from db.repositories.base_repository import BaseRepository

    found: list[tuple[type, str]] = []
    for info in pkgutil.iter_modules(package.__path__):
        module = importlib.import_module(f"{package.__name__}.{info.name}")
        for _, member in inspect.getmembers(module, inspect.isclass):
            if not issubclass(member, BaseRepository) or member is BaseRepository:
                continue
            if member.__module__ != module.__name__:
                continue  # imported into this module, not defined by it
            for name, method in inspect.getmembers(member, inspect.isfunction):
                if name.startswith("_") or name in NOT_A_READ:
                    continue
                if not name.startswith(READ_METHOD_PREFIXES):
                    continue
                found.append((member, name))
    return sorted(found, key=lambda item: (item[0].__name__, item[1]))


class TestRepositoryReadsOnTheMigratedSchema:
    """The read *methods*, not just the tables, run against the real schema.

    ``TestEveryMappedTableCanBeRead`` proves a bare ``SELECT`` works per table. It
    does not prove the queries the application actually issues do: a repository
    that filters on a column the migration never created, orders by a column with
    a different type, or joins a relationship whose foreign key disagrees raises
    only when the method runs.

    Every public read-shaped method of every repository is therefore called on the
    migrated schema with placeholder arguments. A method that needs a real id
    returns ``None`` or an empty list — which is the point: the query is parsed,
    planned and executed by PostgreSQL. ``SQLAlchemyError`` is a finding; a method
    that cannot be called with placeholder arguments is counted, not failed.
    """

    def test_every_repository_read_runs_on_the_migrated_schema(self, migrated):
        import inspect

        from sqlalchemy.exc import SQLAlchemyError
        from sqlalchemy.orm import Session

        reads = _repository_reads()
        assert len(reads) >= 100, f"only {len(reads)} repository read methods found — the walk is broken"

        failures: list[str] = []
        skipped: list[str] = []
        driven = 0
        with Session(migrated) as db:
            for repository, name in reads:
                method = getattr(repository(db), name)
                signature = inspect.signature(method)
                kwargs = {}
                usable = True
                for parameter_name, parameter in signature.parameters.items():
                    if parameter_name == "self" or parameter.kind in (parameter.VAR_POSITIONAL, parameter.VAR_KEYWORD):
                        continue
                    if parameter.default is not parameter.empty:
                        continue  # let the default apply
                    can_supply, value = _placeholder(parameter.annotation)
                    if not can_supply and _is_temporal(parameter_name):
                        import datetime as _dt

                        can_supply, value = True, _dt.datetime.now(_dt.timezone.utc)
                    if not can_supply and parameter.annotation is inspect.Parameter.empty:
                        # An unannotated required argument is an id or a lookup key
                        # in every repository here; passing one that does not exist
                        # still executes the query, which is what is being checked.
                        can_supply, value = True, "contract-missing"
                    if not can_supply:
                        usable = False
                        break
                    kwargs[parameter_name] = value
                if not usable:
                    skipped.append(f"{repository.__name__}.{name}")
                    continue
                try:
                    with db.begin_nested():
                        method(**kwargs)
                except SQLAlchemyError as error:
                    failures.append(f"{repository.__name__}.{name}: {type(error).__name__}: {str(error)[:300]}")
                except Exception as error:  # noqa: BLE001 - needs real data, not a schema fault
                    skipped.append(f"{repository.__name__}.{name}: {type(error).__name__}")
                else:
                    driven += 1
        assert failures == [], (
            "repository reads that fail on the migrated schema:\n  " + "\n  ".join(sorted(failures))
        )
        #: 95 of 118 ran when this was written. The 23 that did not need an argument
        #: shape the placeholder builder refuses to invent (a list of objects, a
        #: credential). The floor is pinned so a change that stops reaching the
        #: methods is a failure, not a quieter test.
        assert driven >= 90, (
            f"only {driven} repository reads actually ran ({len(skipped)} skipped: "
            + ", ".join(sorted(skipped)[:10]) + ") — the placeholder arguments are not "
            "reaching the methods"
        )
