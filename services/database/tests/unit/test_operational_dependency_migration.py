from pathlib import Path
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text


def test_nullable_operational_annotation_preserves_legacy_row_and_downgrades(tmp_path):
    config = Config(str(Path(__file__).resolve().parents[2] / "migrations/alembic.ini"))
    url = f"sqlite:///{tmp_path}/operational.db"
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "0100")
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
    command.upgrade(config, "0101")
    with engine.connect() as conn:
        row = conn.execute(text("SELECT * FROM system_dependencies WHERE id='old'")).mappings().one()
        assert row["operational_dependency"] is None and row["lifecycle_revision"] == 0
    command.downgrade(config, "0100")
    assert "operational_dependency" not in {c["name"] for c in inspect(engine).get_columns("system_dependencies")}
    with engine.connect() as conn:
        assert conn.execute(text("SELECT relation FROM system_dependencies WHERE id='old'")).scalar() == "CALLS"
    engine.dispose()
