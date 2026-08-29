"""W43-44 completion: vendor API endpoint scan (discovery method 1) feeds vendor crypto inventory + risk."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401 — register all tables
from api.dependencies import get_current_user, get_db_session
from api.main import create_app
from db.connection.session import Base


def _make_app():
    import os

    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    from api.config.settings import get_settings

    get_settings.cache_clear()
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "analyst"
    app.dependency_overrides[get_db_session] = lambda: (yield session)
    return app, session, engine


def _canned_finding(endpoint="api.vendor.example:443", status="OK", tls="TLSv1.3",
                    cipher="TLS_AES_256_GCM_SHA384", algo="AES-256-GCM", quantum="NONE"):
    return {
        "finding_id": "f1",
        "endpoint": endpoint,
        "status": status,
        "algorithm": algo,
        "metadata": {"confidence": "HIGH", "scan_method": "ACTIVE_PROBE"},
        "crypto": {
            "tls_version": tls,
            "algorithm": "TLS1.0" if "1.0" in tls else "TLS1.1" if "1.1" in tls else "TLS1.2" if "1.2" in tls else "TLS1.3",
            "cipher_suite": cipher,
            "key_exchange_algorithm": "ECDHE",
            "encryption_mode": "GCM",
            "key_size": 256,
            "quantum_impact": quantum,
            "status": "ALLOWED",
        },
        "policy_issues": [],
    }


@pytest.mark.asyncio
async def test_api_scan_stores_observed_vendor_crypto(monkeypatch):
    app, session, engine = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        vendor = (await client.post("/api/v1/vendors", json={"name": "StripePayments"})).json()
        vendor_id = vendor["id"]

        from network_scanner.core.scanner import NetworkTlsScanner

        monkeypatch.setattr(
            NetworkTlsScanner, "scan_hosts",
            lambda self, endpoints, **kwargs: {
                "findings": [_canned_finding(endpoint=str(endpoints[0]))],
                "certificates": [{"fingerprint_sha256": "ab" * 32}],
            },
        )
        scanned = (
            await client.post(f"/api/v1/vendors/{vendor_id}/api-scan",
                              json={"endpoint": "api.vendor.example:443"})
        ).json()
        assert scanned["inventory_added"] == 2
        assert scanned["probes"][0]["tls_version"] == "TLSv1.3"
        assert scanned["probes"][0]["stored"] is True
        protocols_and_ciphers = {row["algorithm"] for row in scanned["inventory"]}
        assert protocols_and_ciphers == {"TLS1.3", "AES-256-GCM"}
        row = scanned["inventory"][0]
        assert row["discovery_method"] == "API_SCAN"
        assert row["confidence"] == "HIGH"
        assert row["verified_at"]  # observed directly, not vendor-claimed
        assert "key exchange: ECDHE" in (row["key_management"] or "")

        # strong observed crypto (TLS1.3 + AES-256-GCM) → low vendor risk
        risk = (await client.get(f"/api/v1/vendors/{vendor_id}/risk")).json()
        assert risk["category"] == "LOW"
        assert {row["algorithm"] for row in risk["inventory"]} == {"TLS1.3", "AES-256-GCM"}


@pytest.mark.asyncio
async def test_api_scan_unreachable_endpoint_stores_nothing(monkeypatch):
    app, session, engine = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        vendor = (await client.post("/api/v1/vendors", json={"name": "LegacyVendor"})).json()
        vendor_id = vendor["id"]

        from network_scanner.core.scanner import NetworkTlsScanner

        dead = _canned_finding(status="DNS_FAILED")
        dead.pop("crypto")
        monkeypatch.setattr(
            NetworkTlsScanner, "scan_hosts",
            lambda self, endpoints, **kwargs: {"findings": [dead], "certificates": []},
        )
        scanned = (
            await client.post(f"/api/v1/vendors/{vendor_id}/api-scan",
                              json={"endpoint": "dead.vendor.example"})
        ).json()
        assert scanned["inventory_added"] == 0  # honest: a dead probe is not vendor crypto
        assert scanned["probes"][0]["stored"] is False
        assert scanned["probes"][0]["status"] == "DNS_FAILED"

        unknown_vendor = await client.post(
            "/api/v1/vendors/nope/api-scan", json={"endpoint": "x.example"}
        )
        assert unknown_vendor.status_code == 404


@pytest.mark.asyncio
async def test_weak_tls_endpoint_drives_high_risk(monkeypatch):
    app, session, engine = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        vendor = (await client.post(
            "/api/v1/vendors",
            json={"name": "LegacyVendor", "data_classifications": ["PCI-DSS"]},
        )).json()
        vendor_id = vendor["id"]

        from network_scanner.core.scanner import NetworkTlsScanner

        weak = _canned_finding(tls="TLSv1.0", cipher="TLS_RSA_WITH_AES_128_CBC_SHA",
                               algo="AES-128-CBC", quantum="CLASSICAL")
        weak["crypto"]["encryption_mode"] = "CBC"
        weak["crypto"]["key_size"] = 128
        weak["policy_issues"] = ["WEAK_TLS_VERSION"]
        monkeypatch.setattr(
            NetworkTlsScanner, "scan_hosts",
            lambda self, endpoints, **kwargs: {"findings": [weak], "certificates": []},
        )
        await client.post(f"/api/v1/vendors/{vendor_id}/api-scan",
                          json={"endpoint": "legacy.vendor.example:443"})
        risk = (await client.get(f"/api/v1/vendors/{vendor_id}/risk")).json()
        # TLS1.0 is disallowed in the shared registry + PCI multiplier → HIGH
        assert risk["category"] == "HIGH"
        assert "TLS1.0" in {row["algorithm"] for row in risk["inventory"]}
