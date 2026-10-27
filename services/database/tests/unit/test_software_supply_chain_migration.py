"""0098 upgrade/downgrade and scope uniqueness on a real SQLite migration."""
from pathlib import Path
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
import pytest
from db.models import System
from db.models.software_supply_chain import SoftwareArtifact


def test_migration_upgrade_idempotency_constraint_and_explicit_rollback(tmp_path):
    config = Config(str(Path(__file__).resolve().parents[2] / "migrations/alembic.ini"))
    url = f"sqlite:///{tmp_path}/supply.db"
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "0097")
    engine = create_engine(url)
    try:
        with Session(engine) as db:
            db.add(System(id="existing", name="Existing bank system"))
            db.commit()
        command.upgrade(config, "head")
        assert {"software_artifacts", "release_sbom_bindings", "software_deployments"} <= set(inspect(engine).get_table_names())
        values = dict(digest="sha256:" + "a" * 64, media_type="application/octet-stream",
                      identity_source="OPERATOR_DECLARED", evidence_ref="build/1", created_by="operator")
        with Session(engine) as db:
            db.add(SoftwareArtifact(scope_key="platform", **values))
            db.commit()
            db.add(SoftwareArtifact(scope_key="platform", **values))
            with pytest.raises(IntegrityError):
                db.commit()
            db.rollback()
            db.add(SoftwareArtifact(scope_key="tenant:a", tenant_id="a", **values))
            db.commit()
            assert db.query(SoftwareArtifact).count() == 2
            db.add(SoftwareArtifact(scope_key="platform", tenant_id="a", **values))
            with pytest.raises(IntegrityError):
                db.commit()
            db.rollback()
        command.downgrade(config, "0097")
        assert "software_artifacts" not in inspect(engine).get_table_names()
        with Session(engine) as db:
            assert db.query(System).filter_by(id="existing").one().name == "Existing bank system"
        command.upgrade(config, "head")
        with Session(engine) as db:
            assert db.query(SoftwareArtifact).count() == 0  # rollback deliberately removes new assertion tables
    finally:
        engine.dispose()
