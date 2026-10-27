"""Real SQLite migration handoff; no SMTP/HTTP/PostgreSQL qualification."""
import json
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session


@pytest.fixture
def migrated(tmp_path):
    ini = Path(__file__).resolve().parents[2] / "migrations" / "alembic.ini"
    config = Config(str(ini))
    url = f"sqlite:///{tmp_path}/handoff.db"
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "0095")
    engine = create_engine(url)
    yield config, engine
    engine.dispose()


def test_legacy_handoff_preserves_unknown_and_successful_destinations(migrated):
    from db.models.app_setting import AppSetting
    from db.models.notification_delivery import NotificationDelivery
    from db.repositories.control_plane_repository import ControlPlaneRepository

    config, engine = migrated
    with Session(engine) as session:
        session.add(AppSetting(key="notification.dispatch.v1", value=json.dumps({"dispatched": ["legacy-failed"]})))
        cp = ControlPlaneRepository(session)
        for status, event, code in (("delivered", "evicted-success", 202), ("failed", "retry-later", 503),
                                    ("skipped", "no-endpoint", None)):
            cp.record_delivery(result={"integration_id": "soc-1", "kind": "siem", "provider": "webhook",
                                       "status": status, "http_status": code},
                               event_type="notification.remediation_verification", event_id=event)
        session.commit()
    command.upgrade(config, "head")
    with Session(engine) as session:
        rows = session.query(NotificationDelivery).all()
        assert {r.event_id: r.status for r in rows} == {"legacy-failed": "legacy_unknown", "evicted-success": "delivered"}
        assert next(r for r in rows if r.status == "delivered").http_status == 202
        assert session.query(AppSetting).one().value == json.dumps({"dispatched": ["legacy-failed"]})
    command.upgrade(config, "head")  # idempotent re-invocation
    with pytest.raises(RuntimeError, match="cannot discard notification receipts"):
        command.downgrade(config, "0095")
    assert "notification_deliveries" in inspect(engine).get_table_names()


def test_malformed_legacy_registry_refuses_before_new_ddl(migrated):
    from db.models.app_setting import AppSetting

    config, engine = migrated
    with Session(engine) as session:
        session.add(AppSetting(key="notification.dispatch.v1", value='{"dispatched":"bad"}'))
        session.commit()
    with pytest.raises(ValueError, match="legacy notification"):
        command.upgrade(config, "head")
    assert "notification_deliveries" not in inspect(engine).get_table_names()
    with engine.connect() as connection:
        assert connection.execute(text("SELECT version_num FROM alembic_version")).scalar() == "0095"


def test_empty_receipt_schema_downgrade_roundtrip(migrated):
    config, engine = migrated
    command.upgrade(config, "head")
    command.downgrade(config, "0095")
    assert "notification_deliveries" not in inspect(engine).get_table_names()
    command.upgrade(config, "head")
    assert "notification_deliveries" in inspect(engine).get_table_names()


def test_downgrade_refuses_to_silently_ignore_scoped_routing(migrated):
    from db.models.app_setting import AppSetting

    config, engine = migrated
    command.upgrade(config, "head")
    with Session(engine) as session:
        session.add(AppSetting(key="notification.routing.v1:platform", value="[]"))
        session.commit()
    with pytest.raises(RuntimeError, match="scoped routing"):
        command.downgrade(config, "0095")
    assert "notification_deliveries" in inspect(engine).get_table_names()
