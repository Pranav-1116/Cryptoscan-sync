from datetime import datetime, timezone

from db.loader.bulk_inserter import bulk_insert
from db.models.scan import Scan


def test_bulk_insert(db_session):
    bulk_insert(
        db_session,
        [
            Scan(
                scan_start=datetime.now(timezone.utc),
                target_location="a",
                operator="t",
                status="QUEUED",
            )
        ],
    )
    assert db_session.query(Scan).count() == 1
