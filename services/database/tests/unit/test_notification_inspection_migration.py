"""Index-only 0097 rollback preserves populated receipt authority."""
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import Session

from control_plane.notification_dispatch import _values
from db.models.notification_delivery import NotificationDelivery
from datetime import datetime, timezone


def test_populated_receipts_survive_index_upgrade_downgrade(tmp_path):
    config = Config(str(Path(__file__).resolve().parents[2] / "migrations/alembic.ini"))
    url = f"sqlite:///{tmp_path}/inspection.db"
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "0096")
    engine = create_engine(url)
    try:
        with Session(engine) as session:
            session.add(NotificationDelivery(**_values(None, "event", "receiver", "siem", "compliance_failure", {},
                                                        datetime.now(timezone.utc), status="delivered")))
            session.commit()
        name = "ix_notification_deliveries_inspection"
        for revision, indexed in (("head", True), ("0096", False), ("head", True)):
            (command.upgrade if indexed else command.downgrade)(config, revision)
            assert (name in {i["name"] for i in inspect(engine).get_indexes("notification_deliveries")}) is indexed
            with Session(engine) as session:
                receipt = session.query(NotificationDelivery).one()
                assert receipt.status == "delivered" and len(receipt.delivery_key) == 64
    finally:
        engine.dispose()
