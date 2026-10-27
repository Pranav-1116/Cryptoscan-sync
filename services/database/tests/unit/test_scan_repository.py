from datetime import datetime, timezone

from db.models.scan import Scan
from db.repositories.scan_repository import ScanRepository


def test_create_and_list_scans(db_session):
    repo = ScanRepository(db_session)
    repo.create(
        Scan(
            scan_start=datetime.now(timezone.utc),
            target_location="local://demo",
            target_type="LOCAL_DIRECTORY",
            operator="test",
            status="COMPLETED",
        )
    )
    rows, total = repo.list_scans()
    assert total == 1
    assert rows[0].target_location == "local://demo"
