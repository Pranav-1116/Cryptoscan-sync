"""Round 25 (deep/25 §3.4 / P1#4): graph edges cite the evidence chain.

An edge used to carry only descriptive text ("KeyPairGenerator.initialize
at Pay.java:42") — no cryptographic tie to the evidence records behind
it. The link table (populated by the pipeline's dedup stage) now lets
every USES edge cite evidence id + content_hash + chain_hash, so an edge
is independently verifiable against the chain sweep.
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import db.models  # noqa: F401 — register tables
from api.dependencies import get_current_user, get_db_session
from api.main import create_app
from db.connection.session import Base
from db.models.crypto_asset import CryptoAsset
from db.models.crypto_asset_evidence import CryptoAssetEvidence
from db.models.evidence_record import EvidenceRecord
from db.models.system import System
from db.models.system_asset import SystemAsset


@pytest.fixture()
def app_db():
    from sqlalchemy.pool import StaticPool

    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    session = Session()

    application = create_app()
    application.dependency_overrides[get_current_user] = lambda: "testuser"

    def _session():
        yield session

    application.dependency_overrides[get_db_session] = _session
    return application, session


@pytest.mark.anyio
async def test_graph_edge_carries_evidence_chain_refs(app_db):
    app, session = app_db
    session.add_all(
        [
            System(id="sys-pay", name="payment-api"),
            CryptoAsset(id="ca-rsa", algorithm="RSA-2048", file_path="src/Pay.java", line_number=1),
            SystemAsset(system_id="sys-pay", asset_id="ca-rsa"),
        ]
    )
    session.flush()
    session.add_all(
        [
            EvidenceRecord(
                id="ev-1", scan_id="scan-1", content_hash="a" * 64, chain_hash="b" * 64,
                chain_position=0, algorithm="RSA-2048", confidence="HIGH",
                file_path="src/Pay.java", line_number=1, finding_data={},
            ),
            CryptoAssetEvidence(asset_id="ca-rsa", evidence_id="ev-1"),
        ]
    )
    session.commit()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/graph")

    assert response.status_code == 200
    edges = response.json().get("edges") or []
    uses = [e for e in edges if e.get("label") == "USES"]
    assert uses, f"no USES edge in response; edges={edges}"
    edge = uses[0]
    assert edge["evidence_count"] == 1
    refs = edge["evidence_refs"]
    assert refs == [{"evidence_id": "ev-1", "content_hash": "a" * 64, "chain_hash": "b" * 64}]
    # the descriptive text is still there (backwards compatible)
    assert "evidence" in edge


@pytest.mark.anyio
async def test_graph_edge_without_links_omits_refs_cleanly(app_db):
    """No link rows -> no fabricated refs, no error, old shape intact."""
    app, session = app_db
    session.add_all(
        [
            System(id="sys-web", name="web"),
            CryptoAsset(id="ca-aes", algorithm="AES-256-GCM", file_path="src/Seal.java", line_number=3),
            SystemAsset(system_id="sys-web", asset_id="ca-aes"),
        ]
    )
    session.commit()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/graph")

    assert response.status_code == 200
    edges = response.json().get("edges") or []
    uses = [e for e in edges if e.get("label") == "USES"]
    assert uses
    assert "evidence_refs" not in uses[0]
    assert "evidence_count" not in uses[0]
