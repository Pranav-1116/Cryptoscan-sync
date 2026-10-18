"""0099 preserves legacy evidence without inventing confirmation timestamps."""
from pathlib import Path
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session
from db.models.relationship_lifecycle import RelationshipSource
import pytest
from sqlalchemy.exc import IntegrityError


def test_lifecycle_upgrade_preserves_rows_and_downgrade_is_explicit_evidence_loss(tmp_path):
    config = Config(str(Path(__file__).resolve().parents[2] / "migrations/alembic.ini"))
    url = f"sqlite:///{tmp_path}/lifecycle.db"
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "0098")
    engine = create_engine(url)
    with engine.begin() as conn:
        for sid in ("pay", "ledger"):
            conn.execute(text("INSERT INTO systems (id, name, created_at, updated_at) VALUES (:id, :id, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"), {"id": sid})
        conn.execute(text("INSERT INTO system_dependencies (id,parent_id,child_id,relation,source,created_at,updated_at) VALUES ('old-edge','pay','ledger','CALLS','manual',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)"))
    command.upgrade(config, "0099")
    with engine.connect() as conn:
        row = conn.execute(text("SELECT * FROM system_dependencies WHERE id='old-edge'")).mappings().one()
        assert row["lifecycle_state"] == "ACTIVE" and row["lifecycle_source"] == "manual"
        assert row["lifecycle_revision"] == 0
        assert row["valid_until"] is None and row["last_confirmed_at"] is None
    assert {"relationship_collections", "relationship_sources", "relationship_lifecycle_events"} <= set(inspect(engine).get_table_names())
    with Session(engine) as db:
        db.add(RelationshipSource(scope_key="platform", record_kind="deployment", source_id="cluster", last_sequence=1))
        db.commit()
        db.add(RelationshipSource(scope_key="platform", tenant_id="a", record_kind="deployment", source_id="cluster", last_sequence=2))
        with pytest.raises(IntegrityError):
            db.commit()
        db.rollback()
    command.downgrade(config, "0098")
    assert "relationship_sources" not in inspect(engine).get_table_names()
    with engine.connect() as conn:
        assert conn.execute(text("SELECT relation FROM system_dependencies WHERE id='old-edge'")).scalar() == "CALLS"
    command.upgrade(config, "0099")
    with Session(engine) as db:
        assert db.query(RelationshipSource).count() == 0
    engine.dispose()
