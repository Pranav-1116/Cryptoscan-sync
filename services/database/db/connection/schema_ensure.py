"""Keep existing databases in sync with the models — automatically.

``create_all`` only creates *missing tables*; it never adds columns to
tables that already exist. Deployments that predate a model change used
to depend on a hand-maintained column list here, which drifted. Now the
schema is reconciled straight from ``Base.metadata``:

- every model column missing from an existing table is added with
  dialect-correct DDL (ALTER TABLE ... ADD COLUMN), always nullable —
  adding NOT NULL to populated tables is not portable
- every model-declared index is ensured with CREATE INDEX IF NOT EXISTS
- JSON columns are upgraded to JSONB on PostgreSQL (override map)

The hand list survives only as ``WANTED_OVERRIDES`` for type upgrades
the compiled model type can't express. A unit test asserts the override
map stays a subset of real model columns, so it cannot drift either.
"""

from __future__ import annotations

import logging

from sqlalchemy import inspect, text

logger = logging.getLogger(__name__)

#: type overrides applied on top of the compiled model type:
#: table -> column -> {dialect -> DDL type}
WANTED_OVERRIDES: dict[str, dict[str, dict[str, str]]] = {
    "systems": {
        "extra": {"postgresql": "JSONB"},
    },
    "vendors": {
        "data_classifications": {"postgresql": "JSONB"},
        "extra_json": {"postgresql": "JSONB"},
    },
}

#: legacy seed columns kept for databases that predate their models —
#: the automatic reconciliation covers everything else.
_LEGACY_SEED: dict[str, list[tuple[str, str, str]]] = {
    # table, column, ddl (dialect placeholders {dt}/{json_t})
    "certificates": [
        ("revocation_status", "VARCHAR(30)"),
        ("revocation_method", "VARCHAR(20)"),
        ("revocation_checked_at", "{dt}"),
        ("ocsp_url", "TEXT"),
        ("crl_url", "TEXT"),
    ],
    "network_scan_targets": [("next_scan_time", "{dt}")],
    "scan_jobs": [("system_id", "VARCHAR(36)")],
}


def _dialect_types(dialect_name: str) -> dict[str, str]:
    dt = "TIMESTAMP" if dialect_name == "postgresql" else "DATETIME"
    json_t = "JSONB" if dialect_name == "postgresql" else "TEXT"
    return {"dt": dt, "json_t": json_t}


def ensure_schema_extensions(engine) -> None:
    from db.connection.session import Base
    from db import models  # noqa: F401 — register every model

    dialect_name = engine.dialect.name
    types = _dialect_types(dialect_name)

    try:
        # create_all is idempotent and only creates *missing* tables —
        # existing tables are never touched, columns are reconciled below
        Base.metadata.create_all(bind=engine)
        inspector = inspect(engine)
        tables = set(inspector.get_table_names())
    except Exception:
        logger.debug("schema_inspect_failed", exc_info=True)
        return

    added_columns = 0
    added_indexes = 0
    with engine.begin() as conn:
        for table_name, table in Base.metadata.tables.items():
            if table_name not in tables:
                continue  # create_all already handled missing tables
            try:
                existing_cols = {c["name"] for c in inspect(engine).get_columns(table_name)}
            except Exception as _handler_exc:
                logger.warning(
                    "exception_suppressed",
                    extra={"error_type": type(_handler_exc).__name__},
                )
                continue
            for column in table.columns:
                if column.name in existing_cols:
                    continue
                override = WANTED_OVERRIDES.get(table_name, {}).get(column.name, {})
                ddl_type = override.get(dialect_name)
                if ddl_type is None:
                    try:
                        ddl_type = column.type.compile(engine.dialect)
                    except Exception:
                        ddl_type = "TEXT"
                sql = f"ALTER TABLE {table_name} ADD COLUMN {column.name} {ddl_type}"
                try:
                    conn.execute(text(sql))
                    added_columns += 1
                    logger.info("schema_column_added", extra={"table": table_name, "column": column.name})
                except Exception:
                    logger.debug(
                        "schema_add_column_skipped", extra={"table": table_name, "column": column.name}, exc_info=True
                    )

            # model-declared indexes (IF NOT EXISTS is portable for PG/SQLite)
            for index in table.indexes:
                columns = [f'"{c.name}"' for c in index.columns]
                if not columns:
                    continue
                sql = f"CREATE INDEX IF NOT EXISTS {index.name} ON {table_name} ({', '.join(columns)})"
                try:
                    conn.execute(text(sql))
                    added_indexes += 1
                except Exception:
                    logger.debug("schema_index_skipped", extra={"sql": sql}, exc_info=True)

        # legacy seed for pre-model databases
        for table_name, cols in _LEGACY_SEED.items():
            if table_name not in tables:
                continue
            try:
                existing_cols = {c["name"] for c in inspect(engine).get_columns(table_name)}
            except Exception as _handler_exc:
                logger.warning(
                    "exception_suppressed",
                    extra={"error_type": type(_handler_exc).__name__},
                )
                continue
            for name, ddl in cols:
                if name in existing_cols:
                    continue
                try:
                    conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {name} {ddl.format(**types)}"))
                    added_columns += 1
                except Exception:
                    logger.debug("schema_seed_skipped", extra={"table": table_name, "column": name}, exc_info=True)

        added_indexes += _ensure_extra_indexes(conn)

    if added_columns or added_indexes:
        logger.info(
            "schema_reconciled", extra={"columns_added": added_columns, "indexes_ensured": added_indexes}
        )


def _ensure_extra_indexes(conn) -> int:
    """Hot-path indexes that are not expressed on the models."""
    statements = (
        "CREATE INDEX IF NOT EXISTS ix_systems_coverage_status ON systems (coverage_status)",
        "CREATE INDEX IF NOT EXISTS ix_systems_business_unit ON systems (business_unit)",
        "CREATE INDEX IF NOT EXISTS ix_systems_cloud_provider ON systems (cloud_provider)",
        "CREATE INDEX IF NOT EXISTS ix_systems_cloud_account ON systems (cloud_account)",
        "CREATE INDEX IF NOT EXISTS ix_runtime_findings_last_seen ON runtime_findings (last_seen_at)",
        "CREATE INDEX IF NOT EXISTS ix_runtime_findings_weak ON runtime_findings (weak_tls)",
        "CREATE INDEX IF NOT EXISTS ix_scans_created_at ON scans (created_at)",
    )
    created = 0
    for statement in statements:
        try:
            conn.execute(text(statement))
            created += 1
        except Exception:
            logger.debug("schema_index_skipped", extra={"sql": statement}, exc_info=True)
    return created


def schema_drift_report(engine) -> dict:
    """What is missing between the models and this database (for /health).

    Returns counts plus explicit lists — used by ops to verify a
    reconciliation actually converged.
    """
    from db.connection.session import Base
    from db import models  # noqa: F401

    try:
        inspector = inspect(engine)
        tables = set(inspector.get_table_names())
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)[:200], "missing_tables": [], "missing_columns": []}

    missing_tables = sorted(set(Base.metadata.tables) - tables)
    missing_columns: list[dict] = []
    for table_name, table in Base.metadata.tables.items():
        if table_name not in tables:
            continue
        existing = {c["name"] for c in inspector.get_columns(table_name)}
        gaps = sorted(set(table.columns.keys()) - existing)
        if gaps:
            missing_columns.append({"table": table_name, "columns": gaps})
    return {
        "missing_tables": missing_tables,
        "missing_columns": missing_columns,
        "in_sync": not missing_tables and not missing_columns,
    }
