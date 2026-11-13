"""CBOM workspace API (docs/boms/01_PRODUCT_SPEC.md §2).

Real sqlite + real sessions. The workspace answers what cryptographic assets
exist and what evidence backs them — and the working rules are pinned as
behaviour: capability_detected, configuration_observed and operation_observed
are distinct states; key metadata is surfaced but key material never is; a
library that supports an algorithm is not evidence of use; empty estates get
honest empty states, never fabricated crypto inventories.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from api.main import create_app
from api.security.passwords import hash_password
from api.security.session_manager import SessionManager
from db.connection.session import Base, SessionLocal, configure_session
from db.models.crypto_asset import CryptoAsset
from db.models.crypto_live import CryptoLiveState
from db.models.cryptographic_fact import CryptographicFact
from db.models.certificate import Certificate
from db.models.pqc_migration import PqcMigrationWave
from db.models.runtime_finding import RuntimeFinding
from db.repositories.user_repository import UserRepository

NOW = datetime.now(timezone.utc)


@pytest.fixture()
def session():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    configure_session(engine)
    s = SessionLocal()
    yield s
    s.close()


@pytest.fixture()
def client(session):
    repo = UserRepository(session)
    repo.create_user("viewer", hash_password("x"), ["viewer"])
    session.commit()
    app = create_app()
    c = TestClient(app)
    token = SessionManager().create_session("viewer", roles=["viewer"])
    repo.create_session(token, "viewer", NOW + timedelta(hours=1), ip="127.0.0.1")
    session.commit()
    c.cookies.set("cryptoscan_session", token)
    return c


SECRET_KEY_BYTES = "AKIA-super-secret-material-MUST-NEVER-LEAVE-STORE"


def _seed_estate(session, *, with_runtime: bool = True):
    # a code reference: configuration observed at most
    session.add(CryptoAsset(
        algorithm="RSA", purpose="sign", key_size=2048,
        file_path="svc/payments/signer.py", line_number=41,
        source_language="python", confidence="HIGH",
        scanner_ids=["tree-sitter"], libraries=["cryptography"],
        asset_key=SECRET_KEY_BYTES, is_hardcoded_key=True))
    # a library that supports ML-KEM: capability only, never use
    session.add(CryptoAsset(
        algorithm="ML-KEM", purpose="exchange", key_size=768,
        file_path="vendor/liboqs/wrap.c", line_number=7,
        source_language="c", confidence="MEDIUM",
        scanner_ids=["tree-sitter"], libraries=["liboqs"]))
    # a second family at the same location as a hash: conflict marker
    session.add(CryptoAsset(
        algorithm="SHA-256", purpose="digest", key_size=None,
        file_path="vendor/liboqs/wrap.c", line_number=9,
        source_language="c", confidence="LOW", scanner_ids=["tree-sitter"]))
    session.add(CryptographicFact(
        algorithm="RSA", purpose="sign", file_path="svc/payments/signer.py",
        key_size=2048, observation_count=12, first_seen=NOW - timedelta(days=400),
        last_seen=NOW - timedelta(days=200), scanners=["runtime-monitor"],
        hardcoded_key_observations=1))
    session.add(Certificate(
        fingerprint_sha256="ab" * 32, subject="CN=payments", issuer="CN=internal-ca",
        public_key_algorithm="RSA", public_key_size=2048,
        not_before=NOW - timedelta(days=100), not_after=NOW + timedelta(days=200),
        expiry_status="VALID", days_until_expiry=200))
    session.add(RuntimeFinding(
        scanner_id="runtime", kind="session", hostname="payments-1",
        tls_version="TLS 1.2", cipher_suite="TLS_RSA_WITH_AES_256_GCM_SHA384",
        algorithm="RSA", key_size=2048, status="registry-verdict",
        weak_tls=True, quantum_impact="CRITICAL", observation_count=3,
        dedup_key="payments-1|TLS 1.2|RSA"))
    session.add(PqcMigrationWave(
        wave_key="wave-1", title="Signer migration", status="planned"))
    if with_runtime:
        session.add(CryptoLiveState(
            asset_id="twin:crypto:payments-1",
            algorithms=["RSA-2048-SIGN", "RSA"]))
    session.commit()


def test_empty_estate_reports_honest_empty_state(client):
    r = client.get("/api/v1/cbom/workspace/overview")
    assert r.status_code == 200
    body = r.json()
    assert body["state"] == "NO_RECORDS"
    assert body["assets"] == 0
    inv = client.get("/api/v1/cbom/workspace/assets").json()
    assert inv["rows"] == []
    assert inv["state"] in {"EMPTY", "NO_RECORDS"}


def test_asset_inventory_carries_the_spec_columns_and_never_key_material(client, session):
    _seed_estate(session)
    r = client.get("/api/v1/cbom/workspace/assets?q=payments")
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 1
    row = body["rows"][0]
    for column in ("asset_id", "algorithm", "operation", "implementation",
                   "location", "key_metadata", "evidence_status", "pqc_family",
                   "last_observed"):
        assert column in row, column
    assert row["algorithm"] == "RSA"
    assert row["location"].startswith("svc/payments/signer.py")
    # key metadata present, key material absent — everywhere
    assert row["key_metadata"]["size"] == 2048
    assert row["key_metadata"]["hardcoded_material_flag"] is True
    assert row["key_metadata"]["named_reference"] == "PRESENT"
    assert SECRET_KEY_BYTES not in r.text
    keys = client.get("/api/v1/cbom/workspace/keys")
    assert SECRET_KEY_BYTES not in keys.text
    assert keys.json()["hardcoded_flagged"] == 1


def test_the_three_usage_states_are_never_equated(client, session):
    _seed_estate(session, with_runtime=False)
    libraries = client.get("/api/v1/cbom/workspace/libraries").json()["rows"]
    by_name = {r["name"]: r for r in libraries}
    # the library that supports ML-KEM stays capability — support is not use
    assert by_name["liboqs"]["usage_state"] == "capability_detected"
    assets = client.get("/api/v1/cbom/workspace/assets").json()["rows"]
    states = {r["algorithm"]: r["usage"]["usage_state"] for r in assets}
    # the code reference is configured, not observed
    assert states["RSA"] == "configuration_observed"
    assert states["ML-KEM"] == "configuration_observed"
    # An algorithm-only observation does not identify the RSA code location.
    session.add(CryptoLiveState(
        asset_id="twin:crypto:payments-1", algorithms=["RSA-2048-SIGN", "RSA"]))
    session.commit()
    assets = client.get("/api/v1/cbom/workspace/assets").json()["rows"]
    assert next(r for r in assets if r["algorithm"] == "RSA")["usage"]["usage_state"] == \
        "configuration_observed"

    rsa = session.query(CryptoAsset).filter_by(file_path="svc/payments/signer.py").one()
    session.add(CryptoAsset(algorithm="RSA", purpose="sign",
                            file_path="svc/other/signer.py", line_number=1,
                            scanner_ids=["tree-sitter"]))
    session.add(CryptoLiveState(
        asset_id=f"crypto:{rsa.id}", algorithms=["RSA"],
        last_event="MONITOR_OBSERVED"))
    session.commit()
    assets = client.get("/api/v1/cbom/workspace/assets").json()["rows"]
    by_location = {r["file_path"]: r for r in assets}
    assert by_location["svc/payments/signer.py"]["usage"]["usage_state"] == \
        "operation_observed"
    assert by_location["svc/other/signer.py"]["usage"]["usage_state"] == \
        "configuration_observed"
    assert next(r for r in assets if r["algorithm"] == "ML-KEM")["usage"]["usage_state"] == \
        "configuration_observed"


def test_evidence_vocabulary_is_one_set_and_conflicts_are_kept(client, session):
    _seed_estate(session)
    rows = client.get("/api/v1/cbom/workspace/evidence").json()["rows"]
    assert rows, "facts must be readable as evidence rows"
    for row in rows:
        assert row["evidence_status"] in {"MEASURED", "IMPORTED", "INFERRED", "UNKNOWN", "CONTRADICTED"}
        assert row["freshness"] in {"CURRENT", "STALE", "EXPIRED", "NOT_COLLECTED"}
    # the stale fact is not silently current
    assert rows[0]["freshness"] == "STALE"
    # contradictory families at one location are surfaced as CONTRADICTED, not merged
    assets = client.get("/api/v1/cbom/workspace/assets").json()["rows"]
    contradicted = [r for r in assets if r["evidence_status"] == "CONTRADICTED"]
    assert contradicted, "the location with SHA-256 and ML-KEM families must flag conflict"


def test_protocols_keep_supported_and_negotiated_apart(client, session):
    _seed_estate(session)
    body = client.get("/api/v1/cbom/workspace/protocols").json()
    assert body["total"] == 1
    row = body["rows"][0]
    assert row["tls_version"] == "TLS 1.2"
    assert row["weak_tls"] is True
    assert row["registry_status"] == "registry-verdict"
    # the stored verdict is echoed, never collapsed into a single safe/unsafe word
    assert row["note"]


def test_pqc_and_unknown_component(client, session):
    _seed_estate(session)
    body = client.get("/api/v1/cbom/workspace/pqc").json()
    assert body["by_family"]["MIGRATION_RELEVANT"] == 1
    assert body["by_family"]["QUANTUM_RESISTANT"] == 1
    assert body["migration_waves"][0]["wave_key"] == "wave-1"
    detail = client.get("/api/v1/cbom/workspace/assets/does-not-exist")
    assert detail.status_code == 404
