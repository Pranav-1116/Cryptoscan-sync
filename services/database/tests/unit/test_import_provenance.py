"""Read projections and SQL review predicates agree, including malformed receipts."""
import pytest
from sqlalchemy import select
from db.import_provenance import import_clause, legacy_import_clause
from db.models.crypto_asset import CryptoAsset
from shared_models.import_provenance import IMPORT_SOURCE_BASIS, is_import, is_legacy_import


CASES = [
    ({}, None), ({}, []), ({}, ["real-scanner"]),
    ({"scan_id":"cbom-ingest:old"}, None), ({}, ["cbom-ingest"]),
    ({"cbom_import":{}}, None), ({"cbom_import":False}, None),
    ({"cbom_import":"malformed"}, None), ({"cbom_import":None}, None),
    ({"cbom_import":{"system_id":"s"}}, None),
    ({"cbom_import":{"system_id":0,"document_sha256":"a"*64,"source_basis":IMPORT_SOURCE_BASIS}}, None),
    ({"cbom_import":{"system_id":"s","document_sha256":int("1"*64),"source_basis":IMPORT_SOURCE_BASIS}}, None),
    ({"cbom_import":{"system_id":"s","document_sha256":"a"*64,"source_basis":IMPORT_SOURCE_BASIS}}, ["cbom-ingest"]),
]


@pytest.mark.parametrize("extra,scanners", CASES)
def test_sql_matches_read_classification(db_session, extra, scanners):
    row = CryptoAsset(algorithm="AES", file_path="synthetic", line_number=0, confidence="HIGH", extra=extra, scanner_ids=scanners)
    db_session.add(row); db_session.flush()
    data = {"extra":extra, "scanner_ids":scanners}
    observed_import, legacy = db_session.execute(select(import_clause(), legacy_import_clause()).select_from(CryptoAsset).where(CryptoAsset.id == row.id)).one()
    assert bool(observed_import) == is_import(data)
    assert bool(legacy) == is_legacy_import(data)
    projected = row.to_dict(exclude={"extra", "scanner_ids"})
    assert projected["confidence"] == ("LOW" if is_import(data) else "HIGH")
    assert row.confidence == "HIGH"
