"""0100 preserves existing rows and does not backfill a fictional proof."""

from pathlib import Path
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text


def test_optional_evidence_upgrade_and_downgrade(tmp_path):
    config = Config(str(Path(__file__).resolve().parents[2] / "migrations/alembic.ini"))
    url = f"sqlite:///{tmp_path}/evidence.db"
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "0099")
    engine = create_engine(url)
    with engine.begin() as conn:
        for sid in ("pay", "ledger"):
            conn.execute(
                text(
                    "INSERT INTO systems (id,name,created_at,updated_at) VALUES (:id,:id,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)"
                ),
                {"id": sid},
            )
        conn.execute(
            text(
                "INSERT INTO system_dependencies (id,parent_id,child_id,relation,source,created_at,updated_at) VALUES ('old','pay','ledger','CALLS','manual',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)"
            )
        )
    command.upgrade(config, "0100")
    with engine.begin() as conn:
        row = conn.execute(text("SELECT * FROM system_dependencies WHERE id='old'")).mappings().one()
        assert row["evidence_ref"] is None and row["confidence_meaning"] is None and row["lifecycle_revision"] == 0
        conn.execute(
            text(
                "UPDATE system_dependencies SET evidence_ref='change:1',confidence_meaning='operator rating' WHERE id='old'"
            )
        )
    command.downgrade(config, "0099")
    assert "evidence_ref" not in {c["name"] for c in inspect(engine).get_columns("system_dependencies")}
    with engine.connect() as conn:
        assert conn.execute(text("SELECT relation FROM system_dependencies WHERE id='old'")).scalar() == "CALLS"
    engine.dispose()
