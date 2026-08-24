from datetime import datetime, timezone

from db.models.evidence_record import EvidenceRecord
from db.models.scan import Scan
from db.repositories.evidence_repository import EvidenceRepository


def test_list_for_scan(db_session):
    scan = Scan(
        scan_start=datetime.now(timezone.utc),
        target_location="x",
        operator="t",
        status="COMPLETED",
    )
    db_session.add(scan)
    db_session.flush()
    db_session.add(
        EvidenceRecord(
            scan_id=scan.id,
            content_hash="a" * 64,
            chain_hash="b" * 64,
            chain_position=0,
            algorithm="DES",
            confidence="HIGH",
            file_path="A.java",
            line_number=1,
            finding_data={"algorithm": "DES"},
        )
    )
    db_session.flush()
    rows, total = EvidenceRepository(db_session).list_for_scan(scan.id)
    assert total == 1
    assert rows[0].algorithm == "DES"
