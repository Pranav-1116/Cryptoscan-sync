"""Cloud KMS inventory endpoints — collect/dry-run/upsert-idempotency.

The collectors are monkeypatched (endpoint tests must not depend on network
or cloud credentials); the persistence path is REAL — rows land in the
in-memory crypto_assets table through AssetRepository.upsert_cloud_asset.
"""

from __future__ import annotations

import db.models  # noqa: F401 — register all tables
import pytest
from api.dependencies import get_db_session
from api.main import create_app
from db.connection.session import Base, configure_session
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool


@pytest.fixture()
def app_db(tmp_path, monkeypatch):
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    configure_session(engine)
    from sqlalchemy.orm import sessionmaker

    session = sessionmaker(bind=engine, expire_on_commit=False)()
    application = create_app()

    def _session():
        yield session

    application.dependency_overrides[get_db_session] = _session
    application.state.test_session = session
    yield application
    application.dependency_overrides.clear()


def _mint(session, username: str, roles: list[str]) -> str:
    from datetime import datetime, timedelta, timezone

    from api.security.passwords import hash_password
    from api.security.session_manager import SessionManager
    from db.repositories.user_repository import UserRepository

    repo = UserRepository(session)
    if repo.get_by_username(username) is None:
        repo.create_user(username, hash_password("x"), roles)
        session.commit()
    token = SessionManager().create_session(username, roles=roles)
    expires = datetime.now(timezone.utc) + timedelta(hours=1)
    repo.create_session(token, username, expires, ip="127.0.0.1")
    session.commit()
    return token


def _auth(session, roles: list[str]) -> dict[str, str]:
    return {"Authorization": f"Bearer {_mint(session, 'cloud-' + roles[0], roles)}"}


def _aws_result():
    return {
        "provider": "aws-kms",
        "assets": [
            {"algorithm": "RSA-3072", "key_size": 3072, "purpose": "signing",
             "file_path": "aws-kms://us-east-1/key-rsa", "source_language": "aws-kms",
             "confidence": "HIGH",
             "extra": {"collector": "aws-kms", "cloud": "aws", "key_id": "key-rsa"}},
            {"algorithm": "AES-256", "key_size": 256, "purpose": "encryption",
             "file_path": "aws-kms://us-east-1/key-aes", "source_language": "aws-kms",
             "confidence": "HIGH",
             "extra": {"collector": "aws-kms", "cloud": "aws", "key_id": "key-aes"}},
        ],
        "skipped": [{"ref": "k9", "reason": "describe failed: AccessDeniedException"}],
        "seen": 3,
        "truncated": False,
    }


@pytest.fixture()
def _collector(monkeypatch):
    from inventory import cloud_kms

    calls = {}

    def fake_collect(client=None, *, region="", limit=100):
        calls["region"] = region
        return _aws_result()

    monkeypatch.setattr(cloud_kms, "collect_aws_kms", fake_collect)
    return calls


async def _collect(client, headers, **body):
    payload = {"provider": "aws-kms", **body}
    return await client.post("/api/v1/inventory/cloud/collect", json=payload, headers=headers)


@pytest.mark.asyncio
async def test_collect_dry_run_persists_nothing(app_db, _collector):
    session = app_db.state.test_session
    headers = _auth(session, ["ciso"])
    async with AsyncClient(transport=ASGITransport(app=app_db), base_url="http://test") as client:
        response = await _collect(client, headers, dry_run=True, region="us-east-1")
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["created"] == 0 and body["dry_run"] is True
        assert body["seen"] == 3 and body["skipped"]
        listing = (await client.get("/api/v1/inventory/cloud/assets", headers=headers)).json()
        assert listing["total_count"] == 0


@pytest.mark.asyncio
async def test_collect_upserts_and_is_idempotent(app_db, _collector):
    from db.models.crypto_asset import CryptoAsset

    session = app_db.state.test_session
    headers = _auth(session, ["ciso"])
    async with AsyncClient(transport=ASGITransport(app=app_db), base_url="http://test") as client:
        first = (await _collect(client, headers, region="us-east-1")).json()
        assert first["created"] == 2 and first["upserted"] == 2
        second = (await _collect(client, headers, region="us-east-1")).json()
        assert second["created"] == 0 and second["upserted"] == 2  # refs are stable

        assert session.query(CryptoAsset).count() == 2
        listing = (await client.get("/api/v1/inventory/cloud/assets", headers=headers)).json()
        algorithms = sorted(asset["algorithm"] for asset in listing["assets"])
        assert algorithms == ["AES-256", "RSA-3072"]
        paths = [asset["file_path"] for asset in listing["assets"]]
        assert "aws-kms://us-east-1/key-rsa" in paths
        extra = [asset for asset in listing["assets"]
                 if asset["file_path"] == "aws-kms://us-east-1/key-aes"][0]["extra"]
        assert extra["first_seen_at"] and extra["last_seen_at"]


@pytest.mark.asyncio
async def test_collect_requires_crypto_manage(app_db, _collector):
    session = app_db.state.test_session
    async with AsyncClient(transport=ASGITransport(app=app_db), base_url="http://test") as client:
        for roles, expected in ((["readonly"], 403), (["superadmin"], 200)):
            headers = _auth(session, roles)
            response = await _collect(client, headers)
            assert response.status_code == expected, (roles, response.text)


@pytest.mark.asyncio
async def test_collect_reports_provider_failures_honestly(app_db, monkeypatch):
    from inventory import cloud_kms

    def no_sdk(client=None, **kwargs):
        raise RuntimeError("boto3 is required for AWS KMS collection (pip install boto3)")

    def provider_down(client=None, **kwargs):
        raise ConnectionError("kms.us-east-1.amazonaws.com unreachable")

    headers = _auth(app_db.state.test_session, ["ciso"])
    async with AsyncClient(transport=ASGITransport(app=app_db), base_url="http://test") as client:
        monkeypatch.setattr(cloud_kms, "collect_aws_kms", no_sdk)
        response = await _collect(client, headers)
        assert response.status_code == 503
        assert "pip install boto3" in response.json()["detail"]

        monkeypatch.setattr(cloud_kms, "collect_aws_kms", provider_down)
        response = await _collect(client, headers)
        assert response.status_code == 502
        assert "unreachable" in response.json()["detail"]


@pytest.mark.asyncio
async def test_collect_rejects_unknown_provider(app_db, _collector):
    session = app_db.state.test_session
    headers = _auth(session, ["ciso"])
    async with AsyncClient(transport=ASGITransport(app=app_db), base_url="http://test") as client:
        response = await client.post("/api/v1/inventory/cloud/collect",
                                     json={"provider": "ibm-cloud-hsm"}, headers=headers)
        assert response.status_code == 422


@pytest.mark.asyncio
async def test_collect_acm_upserts_certificate_inventory(app_db, monkeypatch):
    """ACM certificates land in the shared certificates table with the real
    SHA-256 fingerprint (generated locally here — a throwaway test key)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    from datetime import datetime, timedelta, timezone as tz

    from inventory import cloud_kms

    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(tz.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "api.bank.example")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Bank CA")]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=90))
        .sign(key, hashes.SHA256())
    )
    fingerprint = cert.fingerprint(hashes.SHA256()).hex()

    def fake_collect(client=None, *, region="", limit=100):
        return {
            "provider": "aws-acm",
            "certificates": [{
                "fingerprint_sha256": fingerprint,
                "subject": "CN=api.bank.example",
                "issuer": "O=Bank CA",
                "serial_number": format(cert.serial_number, "x"),
                "not_before": (now - timedelta(days=1)).isoformat(),
                "not_after": (now + timedelta(days=90)).isoformat(),
                "public_key_algorithm": "ECDSA-P256",
                "public_key_size": 256,
                "expiry_status": "valid",
                "days_until_expiry": 90,
                "is_self_signed": False,
                "san": ["api.bank.example"],
                "usages": ["tls"],
                "extra": {"collector": "aws-acm", "arn": "arn:aws:acm:eu-central-1:1:certificate/x",
                          "region": region, "acm_type": "AMAZON_ISSUED", "acm_status": "ISSUED",
                          "signature_algorithm": "SHA256WITHECDSA",
                          "renewal_eligibility": "ELIGIBLE"},
            }],
            "skipped": [{"ref": "pending.bank.example",
                         "reason": "no PEM issued yet (status PENDING_VALIDATION)"}],
            "seen": 2,
            "truncated": False,
        }

    monkeypatch.setattr(cloud_kms, "collect_aws_acm", fake_collect)
    from db.models.certificate import Certificate

    session = app_db.state.test_session
    headers = _auth(session, ["ciso"])
    async with AsyncClient(transport=ASGITransport(app=app_db), base_url="http://test") as client:
        body = (await client.post("/api/v1/inventory/cloud/collect",
                                  json={"provider": "aws-acm", "region": "eu-central-1"},
                                  headers=headers)).json()
        assert body["created"] == 1 and body["seen"] == 2
        assert body["skipped"][0]["ref"] == "pending.bank.example"

        row = session.query(Certificate).filter(
            Certificate.fingerprint_sha256 == fingerprint).one()
        assert row.public_key_algorithm == "ECDSA-P256"
        assert row.extra["collector"] == "aws-acm"

        # re-collection updates the same fingerprint, never stacks duplicates
        again = (await client.post("/api/v1/inventory/cloud/collect",
                                   json={"provider": "aws-acm"}, headers=headers)).json()
        assert again["created"] == 1  # 1 row upserted
        assert session.query(Certificate).count() == 1


@pytest.mark.asyncio
async def test_collect_gcp_dry_run(app_db, monkeypatch):
    from inventory import cloud_kms

    def fake_collect(client=None, *, project="", location="global", limit=100):
        return {
            "provider": "gcp-kms",
            "assets": [
                {"algorithm": "RSA-3072", "key_size": 3072, "purpose": "signing",
                 "file_path": "gcp-kms://projects/p/locations/global/keyRings/r/signing-key",
                 "source_language": "gcp-kms", "confidence": "HIGH",
                 "extra": {"collector": "gcp-kms", "cloud": "gcp", "key_ring": "r"}},
            ],
            "skipped": [{"ref": "exotic", "reason": "unsupported algorithm 'X' — not classified"}],
            "seen": 2,
            "truncated": False,
        }

    monkeypatch.setattr(cloud_kms, "collect_gcp_kms", fake_collect)
    session = app_db.state.test_session
    headers = _auth(session, ["ciso"])
    async with AsyncClient(transport=ASGITransport(app=app_db), base_url="http://test") as client:
        body = (await client.post("/api/v1/inventory/cloud/collect",
                                  json={"provider": "gcp-kms", "project": "p", "dry_run": True},
                                  headers=headers)).json()
        assert body["dry_run"] is True and body["created"] == 0
        listing = (await client.get("/api/v1/inventory/cloud/assets", headers=headers)).json()
        assert listing["total_count"] == 0
