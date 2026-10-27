"""0105 widens the audit journal without losing old rows or narrowing long ones."""

from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text

from db.models.monitor import MonitorEvent


OLD_TYPE = "SCAN_OK"
LONG_TYPE = "cascade.operational_conditions_changed"


def test_monitor_event_type_upgrade_and_guarded_downgrade(tmp_path):
    cfg = Config(str(Path(__file__).resolve().parents[2] / "migrations/alembic.ini"))
    url = f"sqlite:///{tmp_path / 'monitor.db'}"
    cfg.set_main_option("sqlalchemy.url", url)
    command.upgrade(cfg, "0104")
    engine = create_engine(url)
    try:
        with engine.begin() as connection:
            connection.execute(text(
                "INSERT INTO monitor_events (id, target_name, event_type) "
                "VALUES ('old-event', 'monitor', :event_type)"
            ), {"event_type": OLD_TYPE})

        command.upgrade(cfg, "0105")
        assert next(col for col in inspect(engine).get_columns("monitor_events")
                    if col["name"] == "event_type")["type"].length == 120
        assert MonitorEvent.__table__.c.event_type.type.length == 120
        with engine.begin() as connection:
            connection.execute(text(
                "INSERT INTO monitor_events (id, target_name, event_type) "
                "VALUES ('long-event', 'platform', :event_type)"
            ), {"event_type": LONG_TYPE})
            assert dict(connection.execute(text(
                "SELECT id, event_type FROM monitor_events"
            )).all()) == {"old-event": OLD_TYPE, "long-event": LONG_TYPE}

        with pytest.raises(RuntimeError, match="values exceed 30 characters"):
            command.downgrade(cfg, "0104")
        with engine.begin() as connection:
            assert connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one() == "0105"
            assert connection.execute(text("SELECT COUNT(*) FROM monitor_events")).scalar_one() == 2
            connection.execute(text("DELETE FROM monitor_events WHERE id = 'long-event'"))

        command.downgrade(cfg, "0104")
        assert next(col for col in inspect(engine).get_columns("monitor_events")
                    if col["name"] == "event_type")["type"].length == 30
        with engine.connect() as connection:
            assert connection.execute(text(
                "SELECT event_type FROM monitor_events WHERE id = 'old-event'"
            )).scalar_one() == OLD_TYPE
    finally:
        engine.dispose()
