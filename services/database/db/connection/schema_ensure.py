"""Add missing columns on existing SQLite/Postgres files without reseeding."""

from __future__ import annotations

import logging

from sqlalchemy import inspect, text

logger = logging.getLogger(__name__)


def ensure_schema_extensions(engine) -> None:
    dialect = engine.dialect.name
    dt = "TIMESTAMP" if dialect == "postgresql" else "DATETIME"
    json_t = "JSONB" if dialect == "postgresql" else "TEXT"
    wanted: dict[str, list[tuple[str, str]]] = {
        "certificates": [
            ("revocation_status", "VARCHAR(30)"),
            ("revocation_method", "VARCHAR(20)"),
            ("revocation_checked_at", dt),
            ("ocsp_url", "TEXT"),
            ("crl_url", "TEXT"),
        ],
        "network_scan_targets": [("next_scan_time", dt)],
        "systems": [
            ("current_agility_score", "INTEGER"),
            ("agility_category", "VARCHAR(20)"),
            ("migration_readiness_score", "INTEGER"),
            ("migration_readiness_category", "VARCHAR(50)"),
            ("extra", json_t),
            ("scan_target", "TEXT"),
            ("scan_branch", "VARCHAR(200)"),
            ("last_scan_id", "VARCHAR(36)"),
            ("last_scanned_at", dt),
            ("coverage_status", "VARCHAR(20)"),
            ("business_unit", "VARCHAR(100)"),
            ("criticality", "VARCHAR(20)"),
            ("cloud_provider", "VARCHAR(20)"),
            ("cloud_account", "VARCHAR(200)"),
        ],
        "scan_jobs": [
            ("system_id", "VARCHAR(36)"),
        ],
        "vendors": [
            ("vendor_type", "VARCHAR(50)"),
            ("contract_end_date", dt),
            ("data_classifications", json_t),
            ("integration_type", "VARCHAR(50)"),
            ("primary_contact", "VARCHAR(200)"),
            ("security_contact", "VARCHAR(200)"),
            ("last_assessment_date", dt),
            ("extra_json", json_t),
        ],
    }
    try:
        inspector = inspect(engine)
        tables = set(inspector.get_table_names())
    except Exception:
        logger.debug("schema_inspect_failed", exc_info=True)
        return
    with engine.begin() as conn:
        for table, cols in wanted.items():
            if table not in tables:
                continue
            try:
                existing = {c["name"] for c in inspect(engine).get_columns(table)}
            except Exception:
                continue
            for name, ddl in cols:
                if name in existing:
                    continue
                try:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}"))
                except Exception:
                    logger.debug("schema_add_column_skipped", extra={"table": table, "column": name}, exc_info=True)
        _ensure_indexes(conn)


def _ensure_indexes(conn) -> None:
    statements = (
        "CREATE INDEX IF NOT EXISTS ix_systems_coverage_status ON systems (coverage_status)",
        "CREATE INDEX IF NOT EXISTS ix_systems_business_unit ON systems (business_unit)",
        "CREATE INDEX IF NOT EXISTS ix_systems_cloud_provider ON systems (cloud_provider)",
        "CREATE INDEX IF NOT EXISTS ix_systems_cloud_account ON systems (cloud_account)",
    )
    for statement in statements:
        try:
            conn.execute(text(statement))
        except Exception:
            logger.debug("schema_index_skipped", extra={"sql": statement}, exc_info=True)
