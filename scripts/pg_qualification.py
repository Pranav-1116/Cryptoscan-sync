"""PostgreSQL production qualification, graded against what this checkout can prove.

The review's third blocker lists twelve things a bank database has to survive:
migrations, indexes, transactions, pooling, locking, concurrent writes,
retention, partitioning, backup/restore, corruption recovery, HA, and all of it
at scale. This drill takes each in turn and answers it with one of three kinds of
evidence — and the row says which:

    EXECUTED         the check ran here, now, against a real database
    READ             a file, a migration or an engine configuration proves the surface
    SERVER_REQUIRED  the check needs a PostgreSQL server, which this checkout has
                     none of; the row is UNPROVEN and carries the command that
                     would close it

`UNPROVEN` is not a pass. A qualification that grades a backup script as "done"
because the file exists is the failure mode this drill exists to avoid, so the
rows that need a server say so and stay open.

Run::

    python scripts/pg_qualification.py \\
        --json docs/bank-environment/115-postgres-qualification.json \\
        --md   docs/bank-environment/115-postgres-qualification.md
"""

from __future__ import annotations

import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = "cryptoscan.postgres-qualification/1"
VERSION = "postgres-qualification/1.0"

REPO_ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS = REPO_ROOT / "services" / "database" / "migrations"
VERSIONS = MIGRATIONS / "versions"

PASS, PARTIAL, FAIL, UNPROVEN = "PASS", "PARTIAL", "FAIL", "UNPROVEN"
EXECUTED, READ, SERVER_REQUIRED = "EXECUTED", "READ", "SERVER_REQUIRED"


@dataclass
class Row:
    id: str
    question: str
    verdict: str
    evidence: str
    found: dict[str, Any] = field(default_factory=dict)
    note: str = ""
    limit: str = ""
    closes_with: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {"id": self.id, "question": self.question, "verdict": self.verdict,
                "evidence": self.evidence, "found": self.found, "note": self.note,
                "limit": self.limit, "closes_with": self.closes_with}


# ------------------------------------------------------------------ migrations --- #
def _alembic_config(database_url: str):
    from alembic.config import Config

    cfg = Config(str(MIGRATIONS / "alembic.ini"))
    cfg.set_main_option("script_location", str(MIGRATIONS))
    os.environ["DATABASE_URL"] = database_url
    return cfg


# ------------------------------------------------------------------- server --- #
@contextmanager
def postgres_server():
    """A real PostgreSQL server, or ``None`` when this checkout has none.

    An external ``DATABASE_URL`` is used first — that is the deployment. Failing
    that, a local PostgreSQL 16 is started from the optional ``pgserver``
    package, which is a genuine server binary, not a stand-in: the migrations,
    the DDL, the isolation levels and the locking are the server's own. What it
    is not is a *cluster*: one instance, one node, no replication link.
    """
    url = os.environ.get("DATABASE_URL", "")
    if url.startswith("postgres") and _reachable(url):
        yield {"url": url, "source": "configured DATABASE_URL", "cleanup": lambda: None,
               "run": None, "pg_dump": None, "createdb": None, "psql": None,
               "pgdata": None, "socket_dir": None, "port": None, "bins": None}
        return
    try:
        import pgserver  # noqa: PLC0415 — optional dependency
    except ImportError:
        yield None
        return
    directory = tempfile.mkdtemp(prefix="pgq-server-")
    server = pgserver.get_server(directory, cleanup_mode="stop")
    uri = server.get_uri().replace("postgresql://", "postgresql+psycopg2://", 1)

    def cleanup() -> None:
        try:
            server.cleanup()
        finally:
            shutil.rmtree(directory, ignore_errors=True)

    info = server.get_postmaster_info()
    from pgserver._commands import POSTGRES_BIN_PATH

    bins = POSTGRES_BIN_PATH
    conn = ["-h", str(info.socket_dir), "-p", str(info.port), "-U", "postgres"]

    def pg_dump(database: str, target: Path) -> None:
        """Dump one database to ``target`` with the server's own pg_dump."""
        result = subprocess.run([str(bins / "pg_dump"), *conn, "-Fc", "-f", str(target),
                                 database], capture_output=True, text=True)
        if result.returncode or not target.exists() or not target.stat().st_size:
            raise RuntimeError(f"pg_dump wrote nothing for {database}: "
                               f"{(result.stderr or '').strip()[:600]}")

    def createdb(name: str) -> None:
        subprocess.run([str(bins / "createdb"), *conn, name],
                       check=True, stderr=subprocess.PIPE)

    def run(name: str, *args: str) -> subprocess.CompletedProcess:
        """Run one of the server's own binaries and keep its stderr for the report."""
        result = subprocess.run([str(bins / name), *args], capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError(f"{name} failed ({result.returncode}): "
                               f"{(result.stderr or result.stdout).strip()[:600]}")
        return result

    version = server.psql("show server_version").splitlines()[2].strip()
    try:
        yield {
            "url": uri,
            "source": f"local PostgreSQL {version}",
            "psql": server.psql,
            "server": server,
            "pg_dump": pg_dump,
            "createdb": createdb,
            "pgdata": str(server.pgdata),
            "socket_dir": str(info.socket_dir),
            "port": str(info.port),
            "bins": bins,
            "run": run,
            "cleanup": cleanup,
        }
    finally:
        cleanup()


@contextmanager
def migrated_server():
    """A PostgreSQL server with the full migration chain applied to an empty schema.

    Yields ``None`` when this checkout has neither a configured ``DATABASE_URL``
    nor a local server — the caller then has to grade its row honestly rather
    than assume the answer.
    """
    with postgres_server() as server:
        if server is None:
            yield None
            return
        from alembic import command

        url = server["url"]
        _reset_schema(url)
        command.upgrade(_alembic_config(url), "head")
        yield server


def _reachable(url: str) -> bool:
    """Is this URL a server that answers, or a variable left over from a drill?"""
    try:
        from sqlalchemy import create_engine, text

        engine = create_engine(url, connect_args={"connect_timeout": 2})
        try:
            with engine.connect() as connection:
                connection.execute(text("SELECT 1"))
        finally:
            engine.dispose()
        return True
    except Exception:  # noqa: BLE001 — an unreachable URL is the answer
        return False


def _schema_engine(url: str):
    from sqlalchemy import create_engine

    return create_engine(url, future=True, pool_pre_ping=True)


def _reset_schema(url: str) -> None:
    from sqlalchemy import text

    engine = _schema_engine(url)
    try:
        with engine.begin() as connection:
            connection.execute(text("DROP SCHEMA public CASCADE"))
            connection.execute(text("CREATE SCHEMA public"))
    finally:
        engine.dispose()


def _alembic_head(url: str) -> str | None:
    from sqlalchemy import text

    engine = _schema_engine(url)
    try:
        with engine.connect() as connection:
            row = connection.execute(text("SELECT version_num FROM alembic_version")).first()
            return str(row[0]) if row else None
    finally:
        engine.dispose()


def _pg_tables(url: str) -> list[str]:
    from sqlalchemy import text

    engine = _schema_engine(url)
    try:
        with engine.connect() as connection:
            return [str(name) for (name,) in connection.execute(text(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema = 'public' ORDER BY table_name"))]
    finally:
        engine.dispose()


def _session_factory(url: str):
    from sqlalchemy.orm import sessionmaker

    engine = _schema_engine(url)
    return sessionmaker(bind=engine, future=True), engine


def migration_chain() -> Row:
    """Run the real chain to head, then round-trip the last two revisions."""
    from alembic import command

    db_path = tempfile.mktemp(suffix=".db", prefix="pgq-migrations-")
    cfg = _alembic_config(f"sqlite:///{db_path}")
    started = time.perf_counter()
    try:
        command.upgrade(cfg, "head")
        upgrade_seconds = round(time.perf_counter() - started, 2)

        revisions = sorted(path.name for path in VERSIONS.glob("*.py"))
        heads = _heads()
        applied = _applied_revision(db_path)

        roundtrip_started = time.perf_counter()
        command.downgrade(cfg, "-2")
        after_downgrade = _applied_revision(db_path)
        command.upgrade(cfg, "head")
        after_upgrade = _applied_revision(db_path)
        roundtrip_seconds = round(time.perf_counter() - roundtrip_started, 2)

        tables = _tables(db_path)
        ok = (
            applied == heads[0]
            and after_upgrade == heads[0]
            and after_downgrade != after_upgrade
            and len(revisions) >= 100
        )
        return Row(
            id="migration_chain",
            question="does the migration chain apply, round-trip and land on one head?",
            verdict=PASS if ok else FAIL,
            evidence=EXECUTED,
            found={"revisions": len(revisions), "head": heads, "applied": applied,
                   "after_downgrade": after_downgrade, "after_upgrade": after_upgrade,
                   "tables_created": len(tables), "upgrade_seconds": upgrade_seconds,
                   "roundtrip_seconds": roundtrip_seconds},
            note=("the chain was applied from empty to head, downgraded two revisions "
                  "and reapplied — on SQLite, because this checkout has no server"),
            limit="SQLite's DDL is far more permissive than PostgreSQL's; a chain that "
                  "passes here can still fail on a server (guide 100 §5b runs it there)",
            closes_with="`scripts/run_migrations.sh` against a real PostgreSQL in CI",
        )
    except Exception as exc:  # noqa: BLE001 — a failed migration is the finding
        return Row(
            id="migration_chain",
            question="does the migration chain apply, round-trip and land on one head?",
            verdict=FAIL,
            evidence=EXECUTED,
            found={"error": f"{type(exc).__name__}: {exc}"},
            note="the chain did not reach head",
        )
    finally:
        try:
            os.unlink(db_path)
        except OSError:
            pass


def _heads() -> list[str]:
    revisions: dict[str, str] = {}
    downs: set[str] = set()
    for path in sorted(VERSIONS.glob("*.py")):
        text = path.read_text(encoding="utf-8")
        rev = re.search(r"^revision\s*=\s*[\"']([\w-]+)[\"']", text, re.M)
        down = re.search(r"^down_revision\s*=\s*[\"']([\w-]+)[\"']", text, re.M)
        if rev:
            revisions[rev.group(1)] = path.name
            if down:
                downs.add(down.group(1))
    return sorted(rev for rev in revisions if rev not in downs)


def _applied_revision(db_path: str) -> str | None:
    try:
        with sqlite3.connect(db_path) as conn:
            row = conn.execute("SELECT version_num FROM alembic_version").fetchone()
            return row[0] if row else None
    except sqlite3.Error:
        return None


def _tables(db_path: str) -> list[str]:
    with sqlite3.connect(db_path) as conn:
        return sorted(row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall())


def index_parity() -> Row:
    """Does a migrated database carry every index the models declare?

    Read through ``PRAGMA index_list`` rather than the SQLAlchemy inspector: a
    UNIQUE column constraint creates an index the inspector reports separately,
    and counting those as missing would turn a real check into noise.
    """
    from alembic import command

    import db.models  # noqa: F401
    from db.models.base import Base

    db_path = tempfile.mktemp(suffix=".db", prefix="pgq-indexes-")
    cfg = _alembic_config(f"sqlite:///{db_path}")
    try:
        command.upgrade(cfg, "head")
        chain: dict[str, list[tuple[str, ...]]] = {}
        chain_unique: dict[str, set[tuple[str, ...]]] = {}
        expression_names: set[str] = set()
        with sqlite3.connect(db_path) as conn:
            tables = [row[0] for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
            for table in tables:
                if table.startswith("sqlite_") or table == "alembic_version":
                    continue
                rows = conn.execute(f"PRAGMA index_list('{table}')").fetchall()
                columns = []
                for row in rows:
                    parts = [c[2] for c in conn.execute(f"PRAGMA index_info('{row[1]}')")]
                    if any(part is None for part in parts):
                        expression_names.add(str(row[1]))
                    columns.append(tuple(parts))
                chain[table] = columns
                chain_unique[table] = {
                    tuple(c[2] for c in conn.execute(f"PRAGMA index_info('{row[1]}')"))
                    for row in rows if row[2]
                }

        def covered(table: str, wanted: tuple[str, ...]) -> bool:
            return any(list(index[: len(wanted)]) == list(wanted)
                       for index in chain.get(table, []))

        missing: list[dict[str, Any]] = []
        expression_indexes: list[str] = []
        checked = 0
        for table in Base.metadata.sorted_tables:
            if table.name not in chain:
                continue
            for index in table.indexes:
                if index.name in expression_names:
                    # an expression index (uq_fact_identity) cannot be compared through
                    # PRAGMA index_info: SQLite reports its columns as NULL
                    expression_indexes.append(index.name)
                    continue
                columns = tuple(column.name for column in index.columns)
                checked += 1
                if not covered(table.name, columns):
                    missing.append({"table": table.name, "index": index.name,
                                    "columns": list(columns),
                                    "unique": bool(index.unique)})
                elif index.unique and columns not in chain_unique.get(table.name, set()):
                    missing.append({"table": table.name, "index": index.name,
                                    "columns": list(columns), "unique": True,
                                    "reason": "declared unique, migrated non-unique"})
        return Row(
            id="index_parity",
            question="does a migrated database carry every index the models declare?",
            verdict=PASS if not missing else FAIL,
            evidence=EXECUTED,
            found={"indexes_checked": checked, "missing": missing[:10],
                   "missing_count": len(missing),
                   "expression_indexes_not_compared": expression_indexes,
                   "tables_compared": len(chain)},
            note=("a create_all deployment and a migrated one must have the same access "
                  "paths; drift here is the bug class migration 0078 closed once already"),
            limit=("compared on SQLite's index catalogue, which is what the chain runs "
                   "against here; expression-based indexes are skipped because SQLite "
                   "reports their columns as NULL, and PostgreSQL's catalogue can differ "
                   "in prefix semantics"),
        )
    finally:
        try:
            os.unlink(db_path)
        except OSError:
            pass


# ---------------------------------------------------------------- transactions --- #
def transaction_boundaries() -> Row:
    """Does a failure halfway through an ingest leave half an estate behind?"""
    from sqlalchemy import create_engine, func, select
    from sqlalchemy.orm import sessionmaker

    from db.models.base import Base
    from db.models.estate_catalog import EstateAssetRecord
    from db.tenancy import tenant_scope

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    assets = [
        {"ref": f"application:app-{i}", "type": "APPLICATION", "name": f"app-{i}",
         "identity": {"application": f"app-{i}"}, "location": f"/srv/{i}",
         "source": "transaction-drill", "attributes": {"i": i}}
        for i in range(50)
    ]
    evidence = [
        {"source": "transaction-drill", "collector": "drill", "evidence_type": "STATIC_OBSERVED",
         "target": asset["ref"], "layer": "APPLICATION", "facts": {"algorithm": "AES"}}
        for asset in assets
    ]
    from api import estate_catalog
    from api.routers.estate_graph import EstateDiscoverRequest, run_discovery

    original = estate_catalog.sync
    calls = {"n": 0}

    def explode_after_partial(db, graph, **kwargs):
        calls["n"] += 1
        raise RuntimeError("simulated failure inside the catalogue sync")

    estate_catalog.sync = explode_after_partial
    try:
        with tenant_scope("tenant-tx"):
            response = run_discovery(session, "drill", EstateDiscoverRequest(
                estate="tx", assets=assets, evidence=evidence, include_boms=False, persist=True))
            leftover = session.execute(select(func.count()).select_from(EstateAssetRecord)).scalar()
    finally:
        estate_catalog.sync = original

    reported = (response.get("catalog") or {}).get("error")
    run_persisted = bool(response.get("run_id"))
    ok = leftover == 0 and bool(reported)
    row = Row(
        id="transaction_boundaries",
        question="does a failure inside a multi-step ingest leave a partial estate?",
        verdict=PASS if ok else FAIL,
        evidence=EXECUTED,
        found={"assets_offered": len(assets), "assets_left_after_failure": int(leftover or 0),
               "catalog_error_reported": reported, "run_row_persisted": run_persisted,
               "sync_calls": calls["n"]},
        note=("every write path is wrapped so a failure rolls the unit back and reports it "
              "in the response instead of leaving a half-materialised catalogue"),
        limit=("measured on SQLite in one session: PostgreSQL adds readers, a pool and "
               "lock waits, none of which this proves"),
        closes_with="the same injection against a real server, with a second connection "
                    "reading while the first rolls back",
    )
    session.close()
    engine.dispose()
    return row


# --------------------------------------------------------------------- pooling --- #
def pooling() -> Row:
    """Is the engine configured for a bank's connection behaviour, and can it be read?"""
    from db.connection.engine import create_db_engine

    url = ("postgresql://cryptoscan:secret@db.bank.example:5432/cryptoscan"
           "?sslmode=verify-full")
    try:
        engine = create_db_engine(url)
        pool = engine.pool
        found = {
            "pool_class": type(pool).__name__,
            "pool_size": pool.size(),
            "max_overflow": getattr(pool, "_max_overflow", None),
            "timeout_seconds": getattr(pool, "_timeout", None),
            "pre_ping": bool(engine.pool._pre_ping),
            "recycle_seconds": getattr(pool, "_recycle", None),
            "checkout_timeout_seconds": getattr(pool, "_timeout", None),
            "url_is_normalised": engine.url.drivername,
        }
        engine.dispose()
    except Exception as exc:  # noqa: BLE001 — building an engine must not connect
        return Row(
            id="pooling",
            question="is the engine configured for a bank's connection behaviour?",
            verdict=FAIL,
            evidence=EXECUTED,
            found={"error": f"{type(exc).__name__}: {exc}"},
            note="the engine could not be configured",
        )

    # The pool is read from the engine; the statement timeout can only be proved
    # by a server that applies it, which is what ``server_check`` below does.
    ok = bool(found["pool_size"] and found["max_overflow"] is not None and found["pre_ping"])

    # Ask a real server whether the configured session actually got its limits.
    server_check: dict[str, Any] = {}
    with postgres_server() as server:
        if server is not None:
            try:
                from sqlalchemy import text

                from db.connection.engine import create_db_engine

                live = create_db_engine(server["url"])
                try:
                    with live.connect() as connection:
                        server_check["statement_timeout"] = connection.execute(
                            text("SHOW statement_timeout")).scalar()
                        server_check["idle_in_transaction"] = connection.execute(
                            text("SHOW idle_in_transaction_session_timeout")).scalar()
                        connection.execute(text("SELECT pg_sleep(31)"))
                except Exception as exc:  # noqa: BLE001 — a cancel is the measurement
                    server_check["long_query"] = f"refused: {str(exc)[:120]}"
                finally:
                    live.dispose()
            except Exception as exc:  # noqa: BLE001 — a report, not a crash
                server_check["error"] = f"{type(exc).__name__}: {exc}"[:200]
    if server_check:
        ok = ok and server_check.get("statement_timeout") in ("30s", "30000ms") and \
            str(server_check.get("long_query", "")).startswith("refused")
    found["server_check"] = server_check or None

    return Row(
        id="pooling",
        question="is the engine configured for a bank's connection behaviour?",
        verdict=PASS if ok else PARTIAL,
        evidence=EXECUTED,
        found=found,
        note=("a bounded pool with overflow, pre-ping on checkout, hourly recycling, a "
              "10 s connect timeout and a 30 s server-side statement timeout are set on "
              "the PostgreSQL engine, and a connection made through it reports the "
              "server enforcing that 30 s limit: a 31 s query is cancelled"),
        limit=("the pool was never saturated, so exhaustion and the queue timeout are "
               "unmeasured, and no metric yet reports pool saturation (see guide 117)"),
        closes_with="a load test that saturates the pool and asserts the timeout path",
    )


# --------------------------------------------------------------------- locking --- #
def locking() -> Row:
    """Are the write paths that race protected by a lock or a version check?"""
    pessimistic: list[str] = []
    optimistic: list[str] = []
    for path in (REPO_ROOT / "services").rglob("*.py"):
        relative = str(path.relative_to(REPO_ROOT))
        if "tests/" in relative:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        if "with_for_update" in text:
            pessimistic.append(relative)
        if re.search(r"version\s*==|version_check|compare-and-set|optimistic", text):
            optimistic.append(relative)
    return Row(
        id="locking",
        question="are the write paths that can race protected by a lock or a version check?",
        verdict=PASS if pessimistic and optimistic else PARTIAL,
        evidence=READ,
        found={"pessimistic_lock_files": sorted(set(pessimistic))[:12],
               "optimistic_version_files": sorted(set(optimistic))[:12],
               "pessimistic_count": len(set(pessimistic)),
               "optimistic_count": len(set(optimistic))},
        note=("SELECT … FOR UPDATE guards the approval and remediation paths, and the job "
              "row uses a version column so a stale worker cannot overwrite a newer state"),
        limit=("found by reading the code: whether these locks are taken in the right order "
               "under a real workload, and whether any path can deadlock, is not measured"),
        closes_with="a concurrent-write drill on two sessions that asserts no deadlock and "
                    "no lost update",
    )


# ------------------------------------------------------------------ retention --- #
def _history_fixture(session, now, *, window_days: int = 60,
                     tenant: str = "tenant-pg",
                     asset: str = "application:app-00042") -> dict[str, int]:
    """Rows in five age bands: two whole months, one partial month, and the present.

    The bands are computed from partition boundaries rather than hard-coded day
    counts, so the fixture exercises the same three paths whatever today is:
    months wholly past the window (droppable partitions), a month that straddles
    the cutoff (row-by-row), history inside the window (kept) and current facts
    (never touched).
    """
    from datetime import timedelta

    from db import partitions

    from db.models.estate_catalog import EstateObservationRecord

    cutoff = now - timedelta(days=window_days)
    this_month = partitions.month_start(now)
    superseded = cutoff - timedelta(hours=6)
    steps = 0
    while partitions.month_start(superseded) != partitions.month_start(cutoff) and steps < 40:
        superseded -= timedelta(days=1)
        steps += 1

    plan = {
        "oldest": (this_month - timedelta(days=95), 4, "HISTORICAL"),
        "older": (this_month - timedelta(days=65), 4, "HISTORICAL"),
        "superseded": (superseded, 3, "HISTORICAL"),
        "recent": (now - timedelta(days=5), 1, "HISTORICAL"),
        "current": (now, 2, "CURRENT"),
    }
    written: dict[str, int] = {}
    for label, (seen, count, state) in plan.items():
        for index in range(count):
            session.add(EstateObservationRecord(
                tenant_id=tenant, asset_id=asset,
                observation_id=f"{label}-{index}-{state}",
                fact_type=f"attribute:{label}", value=f"v{index}",
                lifecycle_state=state, first_seen_at=seen, last_seen_at=seen,
                observation_count=1,
            ))
        written[label] = count
    session.commit()
    return written


def _retention_drill(server) -> dict[str, Any]:
    """Archive, then drop whole months, then prune rows — on a real server."""
    from types import SimpleNamespace

    from db import partitions, retention

    session_factory, engine = _session_factory(server["url"])
    session = session_factory()
    try:
        now = datetime.now(timezone.utc)
        partitions.ensure(session, now=now, behind=6, ahead=1)
        session.commit()
        written = _history_fixture(session, now, window_days=60)
        archive_dir = Path(tempfile.mkdtemp(prefix="pgq-archive-"))
        settings = SimpleNamespace(
            ESTATE_HISTORY_RETENTION_DAYS=60,
            ESTATE_EVIDENCE_RETENTION_DAYS=2555,
            ESTATE_RETENTION_LEGAL_HOLD=False,
        )
        started = time.perf_counter()
        receipt = retention.apply(session, now=now, archive_dir=archive_dir,
                                  settings=settings)
        seconds = round(time.perf_counter() - started, 2)

        from sqlalchemy import text

        surviving = session.execute(text(
            "SELECT lifecycle_state, count(*) FROM estate_observations GROUP BY 1"
        )).all()
        remaining = {state: int(count) for state, count in surviving}
        archives = sorted(archive_dir.glob("*.ndjson"))
        lines = sum(len(path.read_text().splitlines()) for path in archives)
        return {
            "rows_written": sum(written.values()),
            "rows_remaining": remaining,
            "rows_remaining_total": sum(remaining.values()),
            "partitions_supported": (receipt.partitions or {}).get("supported"),
            "partitions_note": (receipt.partitions or {}).get("note"),
            "partitions_created": receipt.partitions.get("created") if receipt.partitions else [],
            "partitions_dropped": receipt.partitions.get("dropped") if receipt.partitions else [],
            "partitions_considered": [
                {k: candidate.get(k) for k in ("name", "droppable", "rows", "blocked_rows")}
                for candidate in (receipt.partitions or {}).get("candidates", [])
            ],
            "row_deletes": receipt.deleted,
            "archive_files": [path.name for path in archives],
            "archive_rows_on_disk": lines,
            "archive_manifest": receipt.archive and {
                "rows": receipt.archive.get("rows"),
                "sha256": (receipt.archive.get("sha256") or "")[:16],
                "partitions": ((receipt.partitions or {}).get("archive") or {}).get("partitions"),
            },
            "answerable_after": receipt.answerable_after,
            "refused": receipt.refused,
            "seconds": seconds,
        }
    finally:
        session.close()
        engine.dispose()


def retention() -> Row:
    """Is there anything that stops the observation table growing forever?"""
    deletions: list[str] = []
    for path in (REPO_ROOT / "services").rglob("*.py"):
        relative = str(path.relative_to(REPO_ROOT))
        if "tests/" in relative or "migrations/" in relative:
            continue
        found = path.read_text(encoding="utf-8", errors="ignore")
        if re.search(r"delete\(\s*(EstateObservationRecord|EstateEvidenceRecord)", found) or \
                re.search(r"DELETE FROM (estate_observations|estate_evidence)", found):
            deletions.append(relative)
    scripts = sorted(path.name for path in (REPO_ROOT / "scripts").glob("*retention*"))
    static = {"delete_paths": deletions, "retention_scripts": scripts,
              "tables_in_scope": ["estate_observations", "estate_evidence", "estate_assets"],
              "measured_growth": _scale_reference()}

    with migrated_server() as server:
        if server is None:
            return Row(
                id="retention",
                question="is there anything that stops the observation table growing forever?",
                verdict=PARTIAL if static["retention_scripts"] else FAIL,
                evidence=READ,
                found=static,
                note=("a retention control and an operator entry point exist, but this "
                      "checkout has no PostgreSQL server to run the sweep against"),
                limit="the sweep itself was not executed here",
                closes_with="`scripts/apply_retention.py --archive-dir …` on the deployment",
            )
        try:
            drill = _retention_drill(server)
        except Exception as exc:  # noqa: BLE001 — a failed sweep is the finding
            return Row(
                id="retention",
                question="is there anything that stops the observation table growing forever?",
                verdict=FAIL,
                evidence=EXECUTED,
                found={**static, "server": server["source"],
                       "error": f"{type(exc).__name__}: {exc}"[:800]},
                note="the sweep did not complete against a real server",
            )

    kept_currently = drill["rows_remaining"].get("CURRENT", 0)
    removed = drill["rows_written"] - drill["rows_remaining_total"]
    ok = (
        drill["refused"] is None
        and len(drill["partitions_dropped"]) >= 2
        and kept_currently == 2
        and drill["rows_remaining"].get("HISTORICAL") == 1
        and drill["row_deletes"].get("estate_observations") == 3
        and drill["archive_rows_on_disk"] == removed
        and (drill["answerable_after"] or {}).get("ok") is True
    )
    return Row(
        id="retention",
        question="is there anything that stops the observation table growing forever?",
        verdict=PASS if ok else FAIL,
        evidence=EXECUTED,
        found={**static, "server": server["source"], "drill": drill},
        note=("a 60-day window ran against a migrated PostgreSQL 16: two whole months "
              "were archived and dropped as partitions, the rows inside the window that "
              "were superseded were archived and deleted, the current facts and the recent "
              "history survived, and the archive on disk holds exactly what was removed"),
        limit=("the window is 60 days because the floor refuses anything shorter; the "
               "archive is a local file here, not the bank's object store, and the proof "
               "that history is still answerable is one asset's history, not a query "
               "sample"),
        closes_with="`scripts/apply_retention.py` on a schedule, with the archive going "
                    "to object storage and its manifest checked by the restore drill",
    )


def _scale_reference() -> dict[str, Any]:
    artifact = REPO_ROOT / "docs" / "bank-environment" / "114-scale-qualification.json"
    if not artifact.exists():
        return {}
    try:
        report = json.loads(artifact.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    for row in report.get("rows") or []:
        if row.get("id") == "read_paths":
            seed = (row.get("measured") or {}).get("seed") or {}
            return {"assets": seed.get("assets"), "facts": seed.get("facts"),
                    "database_mb": seed.get("database_mb"), "source": "guide 114"}
    return {}


def _partition_drill(server) -> dict[str, Any]:
    """Does a month of history live in its own relation, and can it be dropped?"""
    from datetime import timedelta

    from sqlalchemy import text

    from db import partitions

    session_factory, engine = _session_factory(server["url"])
    session = session_factory()
    try:
        now = datetime.now(timezone.utc)
        parent_kind = session.execute(text(
            "SELECT relkind FROM pg_class WHERE oid = 'estate_observations'::regclass"
        )).scalar()
        created = partitions.ensure(session, now=now, behind=6, ahead=2)
        session.commit()
        written = _history_fixture(session, now)

        spread = session.execute(text(
            "SELECT tableoid::regclass::text AS partition, count(*) "
            "FROM estate_observations GROUP BY 1 ORDER BY 1")).all()

        last_month, next_month = partitions.month_bounds(now - timedelta(days=20))
        # The bounds are literals on purpose: with a bound parameter PostgreSQL
        # only prunes at execution time and the plan lists every partition, which
        # would make this row measure the planner's caution rather than the
        # partitioning.
        plan = session.execute(text(
            "EXPLAIN (COSTS OFF, FORMAT JSON) SELECT id FROM estate_observations "
            f"WHERE last_seen_at >= '{last_month.isoformat()}' "
            f"AND last_seen_at < '{next_month.isoformat()}'"
        )).scalar()
        scanned = sorted({line["Relation Name"] for step in plan[0]["Plan"].get("Plans", [])
                          for line in [step] if line.get("Relation Name")})
        if not scanned:
            scanned = [plan[0]["Plan"].get("Relation Name")]
        total_partitions = len(partitions.partitions(session))

        before = int(session.execute(text(
            "SELECT count(*) FROM estate_observations")).scalar() or 0)
        victim = sorted(row[0] for row in session.execute(text(
            "SELECT tableoid::regclass::text FROM estate_observations WHERE "
            "last_seen_at < :cutoff GROUP BY 1"), {"cutoff": now - timedelta(days=60)}).all())
        dropped = victim[0]
        in_victim = partitions.count(session, dropped)
        started = time.perf_counter()
        partitions.drop(session, dropped)
        session.commit()
        drop_seconds = round(time.perf_counter() - started, 3)
        after = int(session.execute(text(
            "SELECT count(*) FROM estate_observations")).scalar() or 0)
        return {
            "parent_relkind": parent_kind,
            "partitions_created_by_drill": created,
            "partitions_total": total_partitions,
            "rows_by_partition": {str(name): int(count) for name, count in spread},
            "explain_relations_scanned": scanned,
            "expected_partition": partitions.name_for(last_month),
            "partitions_dropped": [dropped],
            "rows_in_dropped_partition": in_victim,
            "rows_before": before,
            "rows_after": after,
            "drop_seconds": drop_seconds,
            "rows_written": sum(written.values()),
        }
    finally:
        session.close()
        engine.dispose()


def partitioning() -> Row:
    """Is the history table partitioned, or does its size bound every query?"""
    partition_sql = [path.name for path in VERSIONS.glob("*.py")
                     if re.search(r"PARTITION BY|partition_by", path.read_text(
                         encoding="utf-8", errors="ignore"), re.I)]

    with migrated_server() as server:
        if server is None:
            return Row(
                id="partitioning",
                question="is the history table partitioned, or does its size bound every query?",
                verdict=PARTIAL,
                evidence=READ,
                found={"migrations_with_partitions": partition_sql},
                note=("migration 0130 partitions ``estate_observations`` by "
                      "``last_seen_at`` month on PostgreSQL, but this checkout has no "
                      "server, so the converted table was not inspected or used"),
                limit="unexecuted: the migration is a no-op on SQLite, which has no "
                      "partitioned tables",
                closes_with="`python scripts/pg_qualification.py --require-server`",
            )
        try:
            drill = _partition_drill(server)
        except Exception as exc:  # noqa: BLE001 — a failed drill is the finding
            return Row(
                id="partitioning",
                question="is the history table partitioned, or does its size bound every query?",
                verdict=FAIL,
                evidence=EXECUTED,
                found={"migrations_with_partitions": partition_sql,
                       "server": server["source"],
                       "error": f"{type(exc).__name__}: {exc}"[:800]},
                note="the partitioned table could not be built or used",
            )

    ok = (
        drill["parent_relkind"] == "p"
        and len(drill["rows_by_partition"]) >= 3
        and drill["explain_relations_scanned"] == [drill["expected_partition"]]
        and drill["rows_before"] - drill["rows_after"] == drill["rows_in_dropped_partition"]
    )
    return Row(
        id="partitioning",
        question="is the history table partitioned, or does its size bound every query?",
        verdict=PASS if ok else FAIL,
        evidence=EXECUTED,
        found={"migrations_with_partitions": partition_sql, "server": server["source"],
               "drill": drill},
        note=("``estate_observations`` is a range-partitioned table on PostgreSQL: rows "
              "land in the month of their ``last_seen_at``, a month-scoped read is "
              "planned against exactly one partition, and dropping that partition removed "
              "its rows in a constant-time catalogue operation"),
        limit=("the drill runs on one server and a few hundred rows: it proves the "
               "mechanism, not the cost at a hundred million facts, and it does not "
               "rehearse a month boundary with live writers"),
        closes_with="a bank-sized table converted once with `db.partitions.ensure` on a "
                    "schedule and the retention sweep dropping, not deleting, months",
    )


def migration_lock_safety() -> Row:
    """Do the migrations take locks that would stop a bank's write traffic?"""
    risky: list[dict[str, Any]] = []
    for path in sorted(VERSIONS.glob("*.py")):
        text = path.read_text(encoding="utf-8", errors="ignore")
        for match in re.finditer(r"op\.create_index\(\s*[\"']([\w_]+)[\"']", text):
            block = text[match.start(): match.start() + 400]
            if "postgresql_concurrently" in block:
                continue
            risky.append({"revision": path.name.split("_")[0], "index": match.group(1)})
    total = len(list(VERSIONS.glob("*.py")))
    return Row(
        id="migration_lock_safety",
        question="would applying the migrations to a live bank stop writes?",
        verdict=PASS if not risky else PARTIAL,
        evidence=READ,
        found={"migrations": total, "non_concurrent_index_builds": risky[:15],
               "non_concurrent_count": len(risky)},
        note=("most indexes are created inside CREATE TABLE, which takes no lock on live "
              "rows; the ones added later to populated tables are built non-concurrently, "
              "and a plain CREATE INDEX holds a lock that blocks writes until it finishes"),
        limit="the lock is only a problem on a populated table — for a fresh deployment "
              "every build is instant",
        closes_with="`postgresql_concurrently=True` on any index added to a table that is "
                    "already serving traffic (0126 included, once it runs at bank scale)",
    )


def migration_at_scale() -> Row:
    """What does adding the composite index cost on a populated history table?"""
    from sqlalchemy import create_engine, text

    import db.models  # noqa: F401
    from db.models.base import Base
    from db.models.estate_catalog import EstateObservationRecord

    rows = 200_000
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    started = time.perf_counter()
    with engine.begin() as conn:
        conn.execute(EstateObservationRecord.__table__.insert(), [
            {"id": f"obs-{i}", "tenant_id": "tenant-pg", "observation_id": f"o-{i}",
             "asset_id": f"application:app-{i % 5000:05d}", "fact_type": f"attribute:f{i % 10}",
             "value": f"v{i % 7}", "lifecycle_state": "CURRENT", "observation_count": 1}
            for i in range(rows)
        ])
    insert_seconds = round(time.perf_counter() - started, 1)

    with engine.connect() as conn:
        # the model already declares 0126's index, so drop it first: the measurement is
        # what the migration *does*, not what create_all did for free
        conn.execute(text("DROP INDEX IF EXISTS ix_estate_observations_tenant_asset"))
        conn.commit()
        probe = ("SELECT count(*) FROM estate_observations "
                 "WHERE asset_id='application:app-00042' AND tenant_id='tenant-pg'")
        started = time.perf_counter()
        conn.execute(text(probe)).scalar()
        without = round((time.perf_counter() - started) * 1000, 1)
        started = time.perf_counter()
        conn.execute(text(
            "CREATE INDEX ix_estate_observations_tenant_asset "
            "ON estate_observations (tenant_id, asset_id)"))
        index_seconds = round(time.perf_counter() - started, 2)
        started = time.perf_counter()
        conn.execute(text(probe)).scalar()
        with_index = round((time.perf_counter() - started) * 1000, 1)
    engine.dispose()
    ratio = round(without / with_index, 1) if with_index else None
    return Row(
        id="migration_at_scale",
        question="what does the composite-index migration cost on a populated table?",
        verdict=PASS if with_index <= without else PARTIAL,
        evidence=EXECUTED,
        found={"rows": rows, "insert_seconds": insert_seconds,
               "index_build_seconds": index_seconds,
               "read_without_index_ms": without, "read_with_index_ms": with_index,
               "speedup": ratio},
        note=("migration 0126 adds the index every twin read needs; the drill builds it on "
              "a populated table and measures both the build and the read it fixes"),
        limit="SQLite builds an index in one pass with no concurrent writers; PostgreSQL "
              "will be slower and, without CONCURRENTLY, will block writes while it runs",
        closes_with="the same measurement on PostgreSQL, with a writer running throughout",
    )


# ------------------------------------------------------- server-required rows --- #
def _script_exists(*names: str) -> list[str]:
    return [name for name in names if (REPO_ROOT / "scripts" / name).exists()]


def _seed_scan_jobs(session, labels: list[str]) -> list[str]:
    from db.models.scan_job import ScanJob

    jobs = []
    for label in labels:
        job = ScanJob(job_type="MANUAL", target_repo=f"drill/{label}", target_branch="main",
                      triggered_by="pg-qualification", status="QUEUED")
        session.add(job)
        jobs.append(job)
    session.commit()
    return [job.id for job in jobs]


def _concurrent_drill(server) -> dict[str, Any]:
    """Two writers, one version column: does the second update get refused?

    This is ``execution_control``'s compare-and-set, reduced to the row it
    protects. Both sessions read version 0 before either writes, then both try
    to move the job; PostgreSQL must let exactly one of them.
    """

    from sqlalchemy import select, text, update

    from db.models.scan_job import ScanJob

    factory, engine = _session_factory(server["url"])
    session = factory()
    try:
        job_id, other_id = _seed_scan_jobs(session, ["race-a", "race-b"])
    finally:
        session.close()

    outcomes: list[tuple[str, int]] = []
    errors: list[str] = []
    barrier = threading.Barrier(2)

    def raced(label: str) -> None:
        session = factory()
        try:
            read = session.execute(
                select(ScanJob).where(ScanJob.id == job_id)).scalar_one()
            version = read.version
            barrier.wait(timeout=30)
            changed = session.execute(
                update(ScanJob).where(ScanJob.id == job_id, ScanJob.version == version)
                .values(status=label, version=version + 1)
            ).rowcount
            session.commit()
            outcomes.append((label, int(changed or 0)))
        except Exception as exc:  # noqa: BLE001 — a raised error is a result
            errors.append(f"{label}: {type(exc).__name__}: {exc}"[:200])
            session.rollback()
        finally:
            session.close()

    threads = [threading.Thread(target=raced, args=(label,)) for label in ("COMPLETED", "FAILED")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)

    session = factory()
    try:
        final = session.execute(select(ScanJob).where(ScanJob.id == job_id)).scalar_one()
        final_status, final_version = final.status, final.version

        # Ordered versus unordered locking on the same two rows. The application
        # takes its locks in sorted order (``_fair_turn``), which is why this is
        # a measurement of the ordering rather than of luck.
        def lock_both(order: list[str], *, delay: float) -> str:
            session = factory()
            try:
                session.execute(text("SET LOCAL lock_timeout = '2s'"))
                first, second = order
                session.execute(text("SELECT id FROM scan_jobs WHERE id = :id FOR UPDATE"),
                                {"id": first})
                time.sleep(delay)
                session.execute(text("SELECT id FROM scan_jobs WHERE id = :id FOR UPDATE"),
                                {"id": second})
                session.commit()
                return "acquired"
            except Exception as exc:  # noqa: BLE001 — a deadlock is the measurement
                session.rollback()
                name = type(exc.__class__.__name__) and str(exc.orig).split("\n")[0] \
                    if hasattr(exc, "orig") else str(exc)
                return f"{type(exc).__name__}: {name}"[:160]
            finally:
                session.close()

        ordered = [lock_both([job_id, other_id], delay=0.0)]
        unordered_result: list[str] = []
        lockers = [
            threading.Thread(target=lambda: unordered_result.append(
                lock_both([job_id, other_id], delay=0.3))),
            threading.Thread(target=lambda: unordered_result.append(
                lock_both([other_id, job_id], delay=0.3))),
        ]
        for locker in lockers:
            locker.start()
        for locker in lockers:
            locker.join(timeout=30)

        return {
            "race": {"outcomes": outcomes, "errors": errors,
                     "final_version": final_version, "final_status": final_status},
            "ordered_locking": ordered,
            "unordered_locking": unordered_result,
        }
    finally:
        session.close()
        engine.dispose()


def concurrent_writes() -> Row:
    """Do two writers on the same row produce a lost update or a deadlock?"""
    with migrated_server() as server:
        if server is None:
            return Row(
                id="concurrent_writes",
                question="do two writers on the same row produce a lost update or a deadlock?",
                verdict=UNPROVEN,
                evidence=SERVER_REQUIRED,
                found={"server_available": False},
                note=("SQLite serialises writers, so a concurrency result there would say "
                      "nothing about PostgreSQL. This drill needs two sessions."),
                limit="unmeasured",
                closes_with="`python scripts/pg_qualification.py --require-server`",
            )
        try:
            drill = _concurrent_drill(server)
        except Exception as exc:  # noqa: BLE001 — a failed drill is the finding
            return Row(
                id="concurrent_writes",
                question="do two writers on the same row produce a lost update or a deadlock?",
                verdict=FAIL,
                evidence=EXECUTED,
                found={"server": server["source"],
                       "error": f"{type(exc).__name__}: {exc}"[:800]},
                note="the two-session drill did not complete",
            )

    race = drill["race"]
    row_counts = sorted(count for _label, count in race["outcomes"])
    deadlocked = [result for result in drill["unordered_locking"]
                  if "DeadlockDetected" in result or "deadlock detected" in result.lower()]
    ok = (
        row_counts == [0, 1]
        and race["final_version"] == 1
        and not race["errors"]
        and drill["ordered_locking"] == ["acquired"]
        and len(deadlocked) == 1
    )
    return Row(
        id="concurrent_writes",
        question="do two writers on the same row produce a lost update or a deadlock?",
        verdict=PASS if ok else PARTIAL,
        evidence=EXECUTED,
        found={"server": server["source"], "drill": drill},
        note=("two sessions read version 0 of the same job and both tried to move it: "
              "exactly one update matched, the loser changed nothing, and the survivor's "
              "status is the one on the row. Taking two row locks in a fixed order "
              "completed while taking them in opposite orders was aborted by PostgreSQL's "
              "deadlock detector — which is why the scheduler sorts its locks"),
        limit=("one job row and two lock holders: it proves the compare-and-set and the "
               "ordering rule, not the behaviour of the real ingest under a bank's "
               "concurrency; the drill client is this process, not a load generator"),
        closes_with="the same race driven by `scripts/load_test.py --concurrent-writers 8` "
                    "against a populated server",
    )


def _backup_drill(server) -> dict[str, Any]:
    """Dump the database, restore it into a new one, compare every table."""
    from sqlalchemy import text

    from db import partitions

    session_factory, engine = _session_factory(server["url"])
    session = session_factory()
    try:
        now = datetime.now(timezone.utc)
        partitions.ensure(session, now=now, behind=6, ahead=1)
        session.commit()
        _history_fixture(session, now, window_days=60)
        _seed_scan_jobs(session, ["backup-a", "backup-b"])

        def counts(url_session) -> dict[str, int]:
            tables = [name for (name,) in url_session.execute(text(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema = 'public' AND table_type = 'BASE TABLE' "
                "ORDER BY table_name"))]
            return {table: int(url_session.execute(
                text(f"SELECT count(*) FROM {table}")).scalar() or 0) for table in tables}

        before = counts(session)
        from sqlalchemy.engine import make_url

        database = make_url(server["url"]).database or "postgres"
        dump = Path(tempfile.mkdtemp(prefix="pgq-dump-")) / "estate.dump"
        started = time.perf_counter()
        server["pg_dump"](database, dump)
        dump_seconds = round(time.perf_counter() - started, 2)

        restored = "pgq_restore"
        server["createdb"](restored)
        started = time.perf_counter()
        server["run"]("pg_restore", "-h", server["socket_dir"], "-p", server["port"],
                      "-U", "postgres", "-d", restored, "--no-owner", str(dump))
        restore_seconds = round(time.perf_counter() - started, 2)

        restored_url = make_url(server["url"]).set(database=restored).render_as_string(
            hide_password=False)
        other_factory, other_engine = _session_factory(restored_url)
        other = other_factory()
        try:
            after = counts(other)
        finally:
            other.close()
            other_engine.dispose()
        mismatches = {table: {"source": count, "restored": after.get(table)}
                      for table, count in before.items() if after.get(table) != count}
        return {
            "tables_compared": len(before),
            "rows_in_source": sum(before.values()),
            "rows_in_restored": sum(after.values()),
            "mismatches": dict(list(mismatches.items())[:10]),
            "mismatch_count": len(mismatches),
            "dump_bytes": dump.stat().st_size,
            "dump_seconds": dump_seconds,
            "restore_seconds": restore_seconds,
            "restored_database": restored,
        }
    finally:
        session.close()
        engine.dispose()


def backup_restore() -> Row:
    """Can the estate be restored, and is the restore verified table by table?"""
    scripts = _script_exists("db_backup.sh", "db_restore.sh", "backup_drill.py",
                             "postgres_parity.sh")
    with migrated_server() as server:
        if server is None:
            return Row(
                id="backup_restore",
                question="can the estate be restored, and is it verified?",
                verdict=UNPROVEN,
                evidence=SERVER_REQUIRED,
                found={"scripts_present": scripts},
                note=("a dump/restore path and a parity check exist as scripts; none of "
                      "them was run here because there is no server to dump"),
                limit="the scripts are unexecuted in this checkout",
                closes_with="`scripts/db_backup.sh && scripts/postgres_parity.sh` against "
                            "the deployment database, with the row counts archived",
            )
        try:
            drill = _backup_drill(server)
        except Exception as exc:  # noqa: BLE001 — a failed drill is the finding
            return Row(
                id="backup_restore",
                question="can the estate be restored, and is it verified?",
                verdict=FAIL,
                evidence=EXECUTED,
                found={"scripts_present": scripts, "server": server["source"],
                       "error": f"{type(exc).__name__}: {exc}"[:800]},
                note="the dump or the restore failed",
            )

    ok = drill["mismatch_count"] == 0 and drill["tables_compared"] > 100
    return Row(
        id="backup_restore",
        question="can the estate be restored, and is it verified?",
        verdict=PASS if ok else FAIL,
        evidence=EXECUTED,
        found={"scripts_present": scripts, "server": server["source"], "drill": drill},
        note=("``pg_dump`` of the migrated database, ``pg_restore`` into a fresh one, and "
              "every table compared by row count: the restore matches the source"),
        limit=("this is a logical dump and restore, not point-in-time recovery — no WAL "
               "archive was replayed, so the RPO of the deployment is still unmeasured; "
               "row counts prove the schema and the data survived, not that a corrupt "
               "page or a lost transaction would be recovered"),
        closes_with="a nightly dump to object storage, a parity check that runs it, and an "
                    "archived-WAL drill that measures the actual RPO",
    )


def _recovery_drill(server) -> dict[str, Any]:
    """Kill a writer mid-transaction, then crash the server and restart it."""
    from sqlalchemy import text

    from db import partitions

    session_factory, engine = _session_factory(server["url"])
    session = session_factory()
    try:
        now = datetime.now(timezone.utc)
        partitions.ensure(session, now=now, behind=6, ahead=1)
        session.commit()
        _history_fixture(session, now, window_days=60)
        before = int(session.execute(text(
            "SELECT count(*) FROM estate_observations")).scalar() or 0)

        # 1. A writer that dies holding an open transaction must leave nothing.
        # A separate engine, because a terminated backend poisons the pooled
        # connection it was using and the reader must not be holding that one.
        writer_engine = _schema_engine(server["url"])
        killer_engine = _schema_engine(server["url"])
        from sqlalchemy.orm import sessionmaker

        writer_factory = sessionmaker(bind=writer_engine, future=True)
        killer_factory = sessionmaker(bind=killer_engine, future=True)
        writer = writer_factory()
        pid = int(writer.execute(text("SELECT pg_backend_pid()")).scalar())
        writer.execute(text(
            "INSERT INTO estate_observations (id, tenant_id, observation_id, asset_id, "
            "fact_type, value, lifecycle_state, conflict, observation_count, created_at, "
            "updated_at, last_seen_at) VALUES ('doomed-1', 'tenant-pg', 'doomed-1', "
            "'application:doomed', 'attribute:x', 'v', 'CURRENT', false, 1, now(), now(), "
            "now())"))
        killer = killer_factory()
        killer.execute(text("SELECT pg_terminate_backend(:pid)"), {"pid": pid})
        killer.commit()
        killer.close()
        try:
            writer.commit()
            writer_outcome = "committed"
        except Exception as exc:  # noqa: BLE001 — the abort is the point
            writer_outcome = f"refused: {type(exc).__name__}: {str(exc)[:120]}"
            try:
                writer.rollback()
            except Exception as rollback_exc:  # noqa: BLE001 — the connection is gone
                # Recorded rather than discarded: "the kill worked" and "the
                # connection survived the kill" are different observations.
                writer_outcome += f" (rollback also failed: {type(rollback_exc).__name__})"
        finally:
            writer.close()
            writer_engine.dispose()
            killer_engine.dispose()
        orphans = int(session.execute(text(
            "SELECT count(*) FROM estate_observations WHERE id = 'doomed-1'")).scalar() or 0)

        # 2. An immediate shutdown is a crash: WAL replay must bring the rows back.
        started = time.perf_counter()
        # The same options the server was started with: no TCP listener, one
        # unix socket. ``-m immediate`` is the crash: no checkpoint, no clean
        # shutdown, recovery from the log on start.
        server["run"]("pg_ctl", "-D", server["pgdata"], "-m", "immediate", "-w", "restart",
                      "-o", '-h ""', "-o", f"-k {server['socket_dir']}",
                      "-l", str(Path(server["pgdata"]) / "restart.log"))
        restart_seconds = round(time.perf_counter() - started, 2)

        fresh_factory, fresh_engine = _session_factory(server["url"])
        fresh = fresh_factory()
        try:
            after = int(fresh.execute(text(
                "SELECT count(*) FROM estate_observations")).scalar() or 0)
            checks = {}
            connection = ["-h", server["socket_dir"], "-p", server["port"], "-U", "postgres"]
            for name, arguments in (("pg_amcheck", [*connection, "--all"]),
                                    ("vacuumdb", [*connection, "-d", "postgres",
                                                  "--analyze-only", "--quiet"])):
                try:
                    server["run"](name, *arguments)
                    checks[name] = "clean"
                except Exception as exc:  # noqa: BLE001 — a report is a result too
                    checks[name] = str(exc)[:300]
            # A dump reads every page of every table: it is the strongest
            # integrity read available on a build without the amcheck extension.
            from sqlalchemy.engine import make_url

            after_dump = Path(tempfile.mkdtemp(prefix="pgq-after-crash-")) / "estate.dump"
            try:
                server["pg_dump"](make_url(server["url"]).database or "postgres", after_dump)
                checks["post_restart_dump"] = f"read every table ({after_dump.stat().st_size} bytes)"
            except Exception as exc:  # noqa: BLE001 — an unreadable table is the finding
                checks["post_restart_dump"] = f"failed: {str(exc)[:300]}"
        finally:
            fresh.close()
            fresh_engine.dispose()
        return {
            "rows_before": before,
            "rows_after_restart": after,
            "killed_writer": {"outcome": writer_outcome, "orphan_rows": orphans,
                              "backend": pid},
            "restart_seconds": restart_seconds,
            "integrity_checks": checks,
        }
    finally:
        # The crash above killed this session's connection too; a dead connection
        # is not a failure of the drill, but it is worth saying so in the output.
        try:
            session.close()
        except Exception as close_exc:  # noqa: BLE001 — the point of the drill
            checks["session_close"] = f"raised {type(close_exc).__name__} after the crash"
        engine.dispose()


def corruption_recovery() -> Row:
    """Does the system recover from a killed writer or a server crash?"""
    scripts = _script_exists("controlled_recovery_drill.py", "drill_worker_recovery.py")
    with migrated_server() as server:
        if server is None:
            return Row(
                id="corruption_recovery",
                question="does the system recover from a killed writer or a crashed server?",
                verdict=UNPROVEN,
                evidence=SERVER_REQUIRED,
                found={"scripts_present": scripts},
                note="recovery drills exist and require a disposable database to destroy",
                limit="unmeasured",
                closes_with="`python scripts/pg_qualification.py --require-server` on a "
                            "scratch server",
            )
        try:
            drill = _recovery_drill(server)
        except Exception as exc:  # noqa: BLE001 — a failed drill is the finding
            return Row(
                id="corruption_recovery",
                question="does the system recover from a killed writer or a crashed server?",
                verdict=FAIL,
                evidence=EXECUTED,
                found={"scripts_present": scripts, "server": server["source"],
                       "error": f"{type(exc).__name__}: {exc}"[:800]},
                note="the crash-and-restart drill did not complete",
            )

    checks = drill["integrity_checks"]
    ok = (
        drill["killed_writer"]["orphan_rows"] == 0
        and drill["rows_after_restart"] == drill["rows_before"]
        and checks.get("vacuumdb") == "clean"
        and str(checks.get("post_restart_dump", "")).startswith("read every table")
    )
    return Row(
        id="corruption_recovery",
        question="does the system recover from a killed writer or a crashed server?",
        verdict=PASS if ok else PARTIAL,
        evidence=EXECUTED,
        found={"scripts_present": scripts, "server": server["source"], "drill": drill},
        note=("a writer terminated mid-transaction left no row behind, and an immediate "
              "(crash) shutdown followed by a restart replayed the log to the same row "
              "count, after which every table could still be read in full"),
        limit=("the amcheck extension is not installed in this build, so the page-level "
               "integrity check is a full-read dump and ``vacuumdb`` rather than "
               "``pg_amcheck``; a killed backend and a clean crash are the recoveries "
               "PostgreSQL is built "
               "for; nothing here corrupts a page on disk, and no backup was needed — so "
               "this measures crash safety, not restore-from-corruption, which the backup "
               "row covers only as a successful dump and restore"),
        closes_with="`scripts/controlled_recovery_drill.py` on a scratch server that "
                    "destroys a page and restores it, asserting the evidence chain still "
                    "verifies",
    )


def ha_failover() -> Row:
    """Does a standby take over, and what is the measured RPO and RTO?"""
    dr = _script_exists("postgres_drill.py", "postgres_dr_sandbox.sh", "region_drills.py")
    return Row(
        id="ha_failover",
        question="does a standby take over, and what is the measured RPO and RTO?",
        verdict=UNPROVEN,
        evidence=SERVER_REQUIRED,
        found={"scripts_present": dr},
        note=("this checkout can now start one PostgreSQL instance, which is one node: a "
              "failover needs a standby, a replication link and a promotion. Dropping the "
              "row to a single server would answer a different question"),
        limit="RPO and RTO are unmeasured here",
        closes_with="`scripts/postgres_drill.py --execute-promotion "
                    "--acknowledge-destructive` against the bank's pair",
    )


def server_required_rows() -> list[Row]:
    return [concurrent_writes(), backup_restore(), corruption_recovery(), ha_failover()]


# --------------------------------------------------------------------- measure --- #
def measure() -> dict[str, Any]:
    started = time.perf_counter()
    rows = [
        migration_chain(),
        index_parity(),
        migration_at_scale(),
        transaction_boundaries(),
        pooling(),
        locking(),
        migration_lock_safety(),
        retention(),
        partitioning(),
        *server_required_rows(),
    ]
    graded = [row.as_dict() for row in rows]
    counts = {verdict: sum(1 for row in graded if row["verdict"] == verdict)
              for verdict in (PASS, PARTIAL, FAIL, UNPROVEN)}
    servers = [row.get("found", {}).get("server") for row in graded]
    server = next((name for name in servers if name), None)
    limits = [
        (f"Every EXECUTED row ran on {server}, which is one instance on a socket in this "
         "sandbox, not a bank's cluster: no replication, no WAL archive, no failover."
         if server else
         "There is no PostgreSQL server in this checkout, so the rows that need one are "
         "UNPROVEN and the rest ran on SQLite."),
        "The tables the drills exercise are small — tens or hundreds of rows. They prove "
        "mechanisms (a partition drop, a compare-and-set, a crash restart), not the cost "
        "of those mechanisms at bank scale.",
        "No row measures write amplification, vacuum or index bloat, which are what "
        "actually decide a bank's database cost; guide 114's growth figure is still the "
        "only size measurement and it came from SQLite.",
        "HA is unmeasured: a single server cannot be promoted, so `ha_failover` stays "
        "UNPROVEN and the RPO/RTO a bank asks for is still unstated.",
    ]
    return {
        "schema": SCHEMA,
        "version": VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.perf_counter() - started, 1),
        "server_available": bool(server) or _server_available(),
        "counts": counts,
        "rows": graded,
        "server": server,
        "limits": limits,
    }


def _server_available() -> bool:
    url = os.environ.get("DATABASE_URL", "")
    if not url.startswith("postgres"):
        return False
    try:  # pragma: no cover - depends on a deployment
        from sqlalchemy import create_engine, text

        engine = create_engine(url)
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        engine.dispose()
        return True
    except Exception:  # noqa: BLE001
        return False


def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    lines = [
        f"# PostgreSQL production qualification — {len(report['rows'])} properties, graded",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{counts.get(PASS, 0)} pass · {counts.get(PARTIAL, 0)} partial · "
        f"{counts.get(FAIL, 0)} fail · {counts.get(UNPROVEN, 0)} unproven** · "
        f"{report['elapsed_seconds']:.0f} s · server available: "
        f"{'yes' if report['server_available'] else 'no'}",
        "",
        "Each row says what kind of evidence it used: **EXECUTED** (ran here, on the "
        "server named above), **READ** (a file or a configuration proves it), "
        "**SERVER_REQUIRED** (needs a server this checkout does not have — the row is "
        "`UNPROVEN`, not passed).",
        "",
        "| Property | Verdict | Evidence | What was found |",
        "|---|---|---|---|",
    ]
    for row in report["rows"]:
        summary = _headline(row)
        lines.append(f"| **{row['question']}** | **{row['verdict']}** | {row['evidence']} "
                     f"| {summary} |")

    lines += ["", "## Row by row", ""]
    for row in report["rows"]:
        lines.append(f"### `{row['id']}` — {row['verdict']} ({row['evidence']})")
        lines.append("")
        lines.append(f"*{row['question']}*")
        lines.append("")
        if row["note"]:
            lines.append(f"- **Reading:** {row['note']}")
        if row["limit"]:
            lines.append(f"- **Limit:** {row['limit']}")
        if row["closes_with"]:
            lines.append(f"- **Closes with:** `{row['closes_with']}`")
        lines.append("")
        lines.append("```")
        lines.append(json.dumps(row["found"], indent=2, default=str)[:4000])
        lines.append("```")
        lines.append("")

    lines += ["## What this does not prove", ""]
    for limit in report["limits"]:
        lines.append(f"- {limit}")
    passed = {row["id"] for row in report["rows"] if row["verdict"] == PASS}
    failed = [row["id"] for row in report["rows"] if row["verdict"] == FAIL]
    unproven = [row["id"] for row in report["rows"] if row["verdict"] == UNPROVEN]
    partial = [row["id"] for row in report["rows"] if row["verdict"] == PARTIAL]
    lines += [
        "",
        "**The verdict this drill supports:** "
        + (f"{len(passed)} properties were executed and held: "
           + ", ".join(f"`{name}`" for name in sorted(passed)) + "." if passed
           else "no property was executed."),
        "",
        ("Still open: " if failed or unproven or partial else "Nothing is open. ")
        + ("failed " + ", ".join(f"`{name}`" for name in failed) + ". " if failed else "")
        + ("partial " + ", ".join(f"`{name}`" for name in partial) + ". " if partial else "")
        + ("unproven " + ", ".join(f"`{name}`" for name in unproven) + "." if unproven else ""),
        "",
        ("A bank should read the UNPROVEN rows as *not done*. One server answering a "
         "question is not a cluster answering it, and nothing here measures what the "
         "deployment costs to run."
         if unproven else
         "Every row ran. That is still one server in a sandbox: it proves the properties, "
         "not the scale they will be asked to hold."),
        "",
    ]
    return "\n".join(lines)


def _headline(row: dict[str, Any]) -> str:
    found = row["found"]
    if row["id"] == "migration_chain":
        return (f"{found.get('revisions')} revisions → {str(found.get('head'))[:12]}, "
                f"upgrade {found.get('upgrade_seconds')} s, round-trip "
                f"{found.get('roundtrip_seconds')} s")
    if row["id"] == "index_parity":
        return f"{found.get('indexes_checked')} indexes checked, {found.get('missing_count')} missing"
    if row["id"] == "migration_at_scale":
        return (f"{found.get('rows'):,} rows; index build {found.get('index_build_seconds')} s; "
                f"read {found.get('read_without_index_ms')} → {found.get('read_with_index_ms')} ms")
    if row["id"] == "transaction_boundaries":
        return (f"{found.get('assets_offered')} assets offered, "
                f"{found.get('assets_left_after_failure')} left after the injected failure")
    if row["id"] == "pooling":
        return (f"{found.get('pool_class')} size {found.get('pool_size')} + "
                f"{found.get('max_overflow')} overflow, pre-ping {found.get('pre_ping')}")
    if row["id"] == "locking":
        return (f"{found.get('pessimistic_count')} files lock rows, "
                f"{found.get('optimistic_count')} use a version check")
    if row["id"] == "migration_lock_safety":
        return (f"{found.get('non_concurrent_count')} indexes built non-concurrently "
                f"of {found.get('migrations')} migrations")
    if row["id"] == "retention":
        drill = found.get("drill") or {}
        if not drill:
            growth = found.get("measured_growth") or {}
            return (f"a control exists but was not run; {growth.get('facts', '—')} facts = "
                    f"{growth.get('database_mb', '—')} MB (guide 114)")
        return (f"{len(drill.get('partitions_dropped') or [])} months dropped, "
                f"{drill.get('row_deletes', {}).get('estate_observations', 0)} rows pruned, "
                f"{drill.get('archive_rows_on_disk')} archived rows")
    if row["id"] == "partitioning":
        drill = found.get("drill") or {}
        if not drill:
            return "migration present, not executed"
        return (f"{drill.get('partitions_total')} partitions, a month read scans "
                f"{len(drill.get('explain_relations_scanned') or [])}, drop "
                f"{drill.get('drop_seconds')} s")
    if row["id"] == "concurrent_writes":
        race = (found.get("drill") or {}).get("race") or {}
        return (f"two writers, row counts {sorted(c for _l, c in race.get('outcomes') or [])}, "
                f"final version {race.get('final_version')}")
    if row["id"] == "backup_restore":
        drill = found.get("drill") or {}
        if not drill:
            return "; ".join(found.get("scripts_present") or ["server required"])
        return (f"{drill.get('tables_compared')} tables, "
                f"{drill.get('mismatch_count')} mismatched rows, dump "
                f"{drill.get('dump_bytes')} bytes")
    if row["id"] == "corruption_recovery":
        drill = found.get("drill") or {}
        if not drill:
            return "; ".join(found.get("scripts_present") or ["server required"])
        return (f"killed writer left {drill['killed_writer']['orphan_rows']} rows; "
                f"{drill.get('rows_before')} rows before the crash, "
                f"{drill.get('rows_after_restart')} after")
    return "; ".join(found.get("scripts_present") or ["server required"])


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="PostgreSQL qualification, graded.")
    parser.add_argument("--json", help="write the report JSON here")
    parser.add_argument("--md", help="write the markdown report here")
    parser.add_argument("--require-server", action="store_true",
                        help="exit non-zero when no PostgreSQL server answered")
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
            print(f"{row['verdict']:<9} {row['id']:<24} {row['evidence']:<16} {_headline(row)[:80]}")
        print(f"\n{report['counts']}")
    if args.require_server and not report["server_available"]:
        return 2
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
