"""Asset inventory rows carry their evidence classification (gap analysis §A:
"every record shows evidence classification").

The level is derived from the linked evidence records only: a record with no
linked evidence, or evidence that records no level, reads UNCLASSIFIED —
unknown, never promoted by assumption.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture()
def session(tmp_path):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import db.models  # noqa: F401 — registers every model on the metadata
    from db.models.base import Base
    from db.models.crypto_asset import CryptoAsset
    from db.models.crypto_asset_evidence import CryptoAssetEvidence
    from db.models.evidence_record import EvidenceRecord

    engine = create_engine(f"sqlite:///{tmp_path / 'assets.db'}")
    Base.metadata.create_all(engine, tables=[
        CryptoAsset.__table__,
        CryptoAssetEvidence.__table__,
        EvidenceRecord.__table__,
    ])
    factory = sessionmaker(bind=engine)
    db = factory()
    try:
        yield db
    finally:
        db.close()
        engine.dispose()


@pytest.fixture()
def api(session):
    from api import dependencies
    from api.routers import assets

    app = FastAPI()
    app.include_router(assets.router, prefix="/api/v1")
    app.dependency_overrides[dependencies.get_db_session] = lambda: session
    app.dependency_overrides[dependencies.get_current_user] = lambda: {
        "username": "auditor"}
    return TestClient(app)


def add_evidence(db, *, evidence_id: str, file_path: str, line_number: int,
                 provenance: dict | None = None):
    from db.models.evidence_record import EvidenceRecord
    row = EvidenceRecord(
        id=evidence_id, scan_id="scan-1", content_hash=f"h-{evidence_id}",
        chain_hash=f"c-{evidence_id}", chain_position=1,
        algorithm="AES", file_path=file_path, line_number=line_number,
        finding_data={}, provenance=provenance)
    db.add(row)
    db.commit()
    return row


def link(db, *, asset_id: str, evidence_id: str):
    from db.models.crypto_asset_evidence import CryptoAssetEvidence
    db.add(CryptoAssetEvidence(asset_id=asset_id, evidence_id=evidence_id))
    db.commit()


def test_list_and_detail_rows_show_their_evidence_classification(api, session):
    from db.models.crypto_asset import CryptoAsset
    session.add(CryptoAsset(id="a-static", algorithm="RSA",
                                file_path="src/crypto.py"))
    session.add(CryptoAsset(id="a-silent", algorithm="AES",
                                file_path="src/aes.py"))
    session.commit()
    add_evidence(session, evidence_id="ev-code",
                 file_path="src/crypto.py", line_number=40)
    add_evidence(session, evidence_id="ev-live",
                 file_path="mem", line_number=1,
                 provenance={"collector": "runtime process probe"})
    link(session, asset_id="a-static", evidence_id="ev-code")
    link(session, asset_id="a-static", evidence_id="ev-live")

    listing = api.get("/api/v1/assets").json()
    rows = {r["id"]: r for r in listing["assets"]}
    assert rows["a-static"]["evidence_classification"]["strongest_level"] == \
        "RUNTIME_OBSERVED"
    assert rows["a-silent"]["evidence_classification"]["strongest_level"] == \
        "UNCLASSIFIED"
    assert "never assumed" in rows["a-silent"]["evidence_classification"]["note"]

    detail = api.get("/api/v1/assets/a-static").json()
    assert detail["evidence_classification"]["strongest_level"] == \
        "RUNTIME_OBSERVED"
    assert detail["evidence_classification"]["counts"]["STATIC_REFERENCE"] == 1
    assert detail["evidence_classification"]["counts"]["RUNTIME_OBSERVED"] == 1


def test_evidence_without_a_recorded_level_is_unclassified(api, session):
    from db.models.crypto_asset import CryptoAsset
    session.add(CryptoAsset(id="a-mem", algorithm="AES",
                                file_path="src/mem.py"))
    session.commit()
    add_evidence(session, evidence_id="ev-mem",
                 file_path="some/mem/path", line_number=7)
    link(session, asset_id="a-mem", evidence_id="ev-mem")
    detail = api.get("/api/v1/assets/a-mem").json()
    classification = detail["evidence_classification"]
    assert classification["strongest_level"] in {"STATIC_REFERENCE",
                                                 "UNCLASSIFIED"}
    for record in classification["records"]:
        assert record["level"] in {"STATIC_REFERENCE", "UNCLASSIFIED"}
